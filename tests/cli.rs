//! End to end through the real binary, the way a shell-only agent uses it.
//! Each `Agent` gets its own runtime directory, standing in for a machine.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;
use speakeasy::crypto::{hex, random};
use speakeasy::relay::{self, Limits, Relay};

struct TestRelay {
    relay: Arc<Relay>,
    url: String,
    _rt: tokio::runtime::Runtime,
}

fn start_relay(limits: Limits) -> TestRelay {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = Relay::new(limits);
    let addr = rt
        .block_on(relay::spawn(relay.clone(), "127.0.0.1:0"))
        .unwrap();
    TestRelay {
        relay,
        url: format!("ws://{addr}"),
        _rt: rt,
    }
}

struct Agent {
    dir: PathBuf,
}

struct Output {
    code: i32,
    lines: Vec<Value>,
}

impl Output {
    fn of_type(&self, t: &str) -> Vec<&Value> {
        self.lines.iter().filter(|l| l["type"] == t).collect()
    }

}

impl Agent {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("spk-test-{}", hex(&random::<6>())));
        std::fs::create_dir_all(&dir).unwrap();
        Agent { dir }
    }

    fn run_with(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let started = Instant::now();
        let mut child = Command::new(env!("CARGO_BIN_EXE_speakeasy"))
            .args(args)
            .env("XDG_RUNTIME_DIR", &self.dir)
            .env_remove("SPEAKEASY_SESSION")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.unwrap_or("").as_bytes())
            .unwrap();
        // If the daemon had inherited these pipes, reading them would block
        // until the daemon exited instead of returning when the command does.
        // So the wait is bounded, and a hang fails the test.
        let (tx, rx) = std::sync::mpsc::channel();
        let pid = child.id() as i32;
        std::thread::spawn(move || tx.send(child.wait_with_output()));
        let out = match rx.recv_timeout(Duration::from_secs(90)) {
            Ok(out) => out.unwrap(),
            Err(_) => {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                panic!("command hung after {:?}: {args:?}", started.elapsed());
            }
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        Output {
            code: out.status.code().unwrap_or(-1),
            lines: stdout
                .lines()
                .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("not JSON: {l}")))
                .collect(),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, None)
    }

    fn create(relay: &TestRelay, name: &str) -> (Agent, String) {
        let a = Agent::new();
        let out = a.run(&["create", "--relay", &relay.url, "--name", name]);
        assert_eq!(out.code, 0, "{:?}", out.lines);
        let invite = out.lines[0]["invite"].as_str().unwrap().to_string();
        (a, invite)
    }

    /// Joins by passing the invitation on stdin, as agents should.
    fn join(invite: &str, name: &str) -> Agent {
        let a = Agent::new();
        let out = a.run_with(&["join", "--name", name], Some(invite));
        assert_eq!(out.code, 0, "{:?}", out.lines);
        a
    }

    /// Sends on stdin, as agents should.
    fn send(&self, text: &str) {
        let out = self.run_with(&["send"], Some(text));
        assert_eq!(out.code, 0, "{:?}", out.lines);
        assert_eq!(out.lines[0]["ok"], true);
    }

    fn recv(&self, wait: &str) -> Output {
        self.run(&["recv", "--wait", wait])
    }

    /// Collect events until one of the given type shows up.
    fn recv_until(&self, t: &str) -> Vec<Value> {
        let mut all = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            let out = self.recv("2");
            let done = !out.of_type(t).is_empty();
            let closed = out.code == 3;
            all.extend(out.lines);
            if done {
                return all;
            }
            assert!(!closed, "closed while waiting for {t}: {all:?}");
        }
        panic!("no {t} event: {all:?}");
    }

    fn pid(&self) -> i32 {
        self.run(&["status"]).lines[0]["pid"].as_i64().unwrap() as i32
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.run(&["leave"]);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn texts(events: &[Value]) -> Vec<&str> {
    events
        .iter()
        .filter(|e| e["type"] == "message")
        .map(|e| e["text"].as_str().unwrap())
        .collect()
}

#[test]
fn agents_talk_and_a_late_joiner_sees_only_later_messages() {
    let relay = start_relay(Limits::default());
    let (alice, invite) = Agent::create(&relay, "alice");
    assert!(invite.starts_with("spk1."));
    let bob = Agent::join(&invite, "bob");

    let joined = alice.recv_until("joined");
    assert_eq!(joined.last().unwrap()["name"], "bob");

    alice.send("one");
    let got = bob.recv_until("message");
    assert_eq!(texts(&got), ["one"]);
    let from_alice = got.iter().find(|e| e["type"] == "message").unwrap();
    assert_eq!(from_alice["from"], "alice");
    assert_eq!(from_alice["key"].as_str().unwrap().len(), 16);

    // A message on the command line is refused, not sent.
    let out = bob.run(&["send", "on the command line"]);
    assert_eq!(out.code, 1, "{:?}", out.lines);
    assert!(out.lines[0]["error"].as_str().unwrap().contains("stdin"));

    bob.send("two");
    assert_eq!(texts(&alice.recv_until("message")), ["two"]);

    let carol = Agent::join(&invite, "carol");
    alice.send("three");
    let got = carol.recv_until("message");
    assert_eq!(texts(&got), ["three"], "carol must not see earlier messages");
    let ready = got.iter().find(|e| e["type"] == "ready").unwrap();
    assert_eq!(ready["members"].as_array().unwrap().len(), 3);

    assert_eq!(texts(&bob.recv_until("message")), ["three"]);
    // Nothing more is waiting: an empty recv returns at once with no output.
    let idle = carol.recv("0");
    assert_eq!((idle.code, idle.lines.len()), (0, 0));
}

#[test]
fn simultaneous_joins_all_get_in() {
    let relay = start_relay(Limits::default());
    let (alice, invite) = Agent::create(&relay, "alice");

    let joiners: Vec<_> = (0..5)
        .map(|n| {
            let invite = invite.clone();
            std::thread::spawn(move || Agent::join(&invite, &format!("j{n}")))
        })
        .collect();
    let joiners: Vec<Agent> = joiners.into_iter().map(|t| t.join().unwrap()).collect();

    // Every member, old and new, ends up in the same group.
    alice.send("hello all");
    for j in &joiners {
        assert_eq!(texts(&j.recv_until("message")), ["hello all"]);
    }
    joiners[4].send("from the last one in");
    let mut seen = Vec::new();
    while !texts(&seen).contains(&"from the last one in") {
        seen.extend(alice.recv_until("message"));
    }
    let joins = seen.iter().filter(|e| e["type"] == "joined").count();
    let rejected = seen.iter().filter(|e| e["type"] == "join_rejected").count();
    assert_eq!((joins, rejected), (5, 0), "{seen:?}");
}

#[test]
fn panic_from_a_non_creator_wakes_waiters_and_kills_the_invitation() {
    let relay = start_relay(Limits::default());
    let (alice, invite) = Agent::create(&relay, "alice");
    let bob = Agent::join(&invite, "bob");
    let carol = Agent::join(&invite, "carol");
    alice.recv_until("joined");

    // Two local waiters on Alice's machine and one on Carol's, all blocked.
    let alice = Arc::new(alice);
    let carol = Arc::new(carol);
    let waiters: Vec<_> = [alice.clone(), alice.clone(), carol.clone()]
        .into_iter()
        .map(|agent| {
            std::thread::spawn(move || loop {
                let started = Instant::now();
                let out = agent.recv("30");
                if out.code == 3 {
                    return (out, started.elapsed());
                }
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));

    let out = bob.run(&["panic"]);
    assert_eq!(out.code, 0, "{:?}", out.lines);
    assert_eq!(out.lines[0]["relay_confirmed"], true);
    // The panicking agent is closed locally straight away.
    let out = bob.recv("0");
    assert_eq!(out.code, 3);
    assert_eq!(out.of_type("closed")[0]["reason"], "panic");

    for w in waiters {
        let (out, took) = w.join().unwrap();
        assert!(took < Duration::from_secs(5), "waiter took {took:?}");
        let closed = out.of_type("closed");
        assert_eq!(closed.len(), 1, "{:?}", out.lines);
        // A real closure from the relay, not the CLI failing to find a session.
        assert_eq!(closed[0]["reason"], "closed", "{:?}", out.lines);
    }
    assert_eq!(relay.relay.room_count(), 0);
    // Sending into the closed room fails with the closed exit code.
    let out = alice.run_with(&["send"], Some("too late"));
    assert_eq!(out.code, 3);
    assert_eq!(out.lines[0]["delivered"], "no");
    // The invitation is dead.
    let late = Agent::new();
    let out = late.run_with(&["join", "--name", "late"], Some(&invite));
    assert_eq!(out.code, 1);
    assert_eq!(out.lines[0]["error"], "closed");
}

#[test]
fn a_dropped_connection_resumes_without_losing_messages() {
    let relay = start_relay(Limits::default());
    let (alice, invite) = Agent::create(&relay, "alice");
    let bob = Agent::join(&invite, "bob");
    alice.recv_until("joined");

    for round in 0..3 {
        relay.relay.disconnect_all();
        alice.send(&format!("after drop {round}"));
        let got = bob.recv_until("message");
        assert_eq!(texts(&got), [format!("after drop {round}")]);
        assert!(got.iter().all(|e| e["type"] != "gap"), "{got:?}");
        // Alice must not see her own message come back as someone else's.
        let echoes = alice.recv("0.3");
        assert!(echoes.lines.is_empty(), "{:?}", echoes.lines);
    }
    bob.send("still here");
    assert_eq!(texts(&alice.recv_until("message")), ["still here"]);
}

#[test]
fn a_member_that_missed_too_much_reports_a_gap_and_rejoins() {
    let relay = start_relay(Limits {
        buffer_frames: 2,
        ..Limits::default()
    });
    let (alice, invite) = Agent::create(&relay, "alice");
    let bob = Agent::join(&invite, "bob");
    alice.recv_until("joined");
    bob.recv_until("ready");

    // Freeze Bob's daemon, cut every connection, and fill the buffer.
    let pid = bob.pid();
    unsafe { libc::kill(pid, libc::SIGSTOP) };
    relay.relay.disconnect_all();
    for i in 0..5 {
        alice.send(&format!("missed {i}"));
    }
    unsafe { libc::kill(pid, libc::SIGCONT) };

    // Bob is told he missed messages, and is readmitted as a fresh member.
    let got = bob.recv_until("ready");
    assert!(got.iter().any(|e| e["type"] == "gap"), "{got:?}");
    assert!(texts(&got).is_empty(), "missed messages must stay unread: {got:?}");
    let ready = got.iter().find(|e| e["type"] == "ready").unwrap();
    assert_eq!(ready["members"].as_array().unwrap().len(), 2, "old leaf replaced");

    alice.recv_until("joined");
    alice.send("welcome back");
    assert_eq!(texts(&bob.recv_until("message")), ["welcome back"]);
    bob.send("thanks");
    assert_eq!(texts(&alice.recv_until("message")), ["thanks"]);
}

#[test]
fn panic_is_terminal_locally_even_when_the_relay_is_unreachable() {
    let relay = start_relay(Limits::default());
    let (alice, invite) = Agent::create(&relay, "alice");
    let bob = Agent::join(&invite, "bob");
    alice.recv_until("joined");

    // A waiter is blocked locally, then the relay disappears entirely.
    let bob = Arc::new(bob);
    let waiter = {
        let bob = bob.clone();
        std::thread::spawn(move || loop {
            let out = bob.recv("30");
            if out.code == 3 {
                return out;
            }
        })
    };
    drop(relay);
    std::thread::sleep(Duration::from_millis(500));

    let started = Instant::now();
    let out = bob.run(&["panic"]);
    assert_eq!(out.code, 0, "{:?}", out.lines);
    assert_eq!(out.lines[0]["relay_confirmed"], false);
    assert!(started.elapsed() < Duration::from_secs(8));
    // The local waiter was released with the real reason.
    let out = waiter.join().unwrap();
    assert_eq!(out.of_type("closed")[0]["reason"], "panic");
    // The keys are gone: nothing can be sent from this session again.
    assert_eq!(bob.run_with(&["send"], Some("x")).code, 3);
}

#[test]
fn events_survive_a_reader_that_dies_before_acknowledging() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let relay = start_relay(Limits::default());
    let (alice, invite) = Agent::create(&relay, "alice");
    let bob = Agent::join(&invite, "bob");
    bob.recv_until("ready");
    alice.send("keep me");

    // Read like the CLI does, but hang up without acknowledging.
    let handle = bob.run(&["status"]).lines[0]["session"]
        .as_str()
        .unwrap()
        .to_string();
    let path = bob.dir.join("speakeasy").join(format!("{handle}.sock"));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut stream = UnixStream::connect(&path).unwrap();
        stream.write_all(b"{\"cmd\":\"recv\",\"wait\":1}\n").unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        if line.contains("keep me") {
            break;
        }
        assert!(Instant::now() < deadline, "message never arrived");
    }
    // The message is still there for the next reader, exactly once.
    assert_eq!(texts(&bob.recv_until("message")), ["keep me"]);
    assert!(bob.recv("0.2").lines.is_empty());
}

#[test]
fn session_handles_cannot_escape_the_private_directory_and_ambiguity_is_an_error() {
    let relay = start_relay(Limits::default());
    let (alice, invite) = Agent::create(&relay, "alice");

    for bad in ["../x", "/tmp/x", "ABCD", ""] {
        let out = alice.run(&["--session", bad, "status"]);
        assert_eq!(out.code, 1, "{bad:?}");
        assert_eq!(out.lines[0]["error"], "invalid session handle", "{bad:?}");
    }

    // A second session on the same machine: commands must be told which.
    let out = alice.run_with(&["join", "--name", "alice-2"], Some(&invite));
    assert_eq!(out.code, 0, "{:?}", out.lines);
    let second = out.lines[0]["session"].as_str().unwrap().to_string();
    let out = alice.recv("0");
    assert_eq!(out.code, 1, "ambiguity is an error, not a closed room");
    assert!(out.lines[0]["error"].as_str().unwrap().contains("--session"));
    let out = alice.run(&["--session", &second, "status"]);
    assert_eq!((out.code, &out.lines[0]["name"]), (0, &serde_json::json!("alice-2")));
    alice.run(&["--session", &second, "leave"]);
}

// ------------------------------------------------------------- scripted relay
//
// Some failures need a relay that misbehaves at an exact moment: one that
// sequences a message and loses the echo, or stalls half way through a
// handshake. These tests play the relay's side of the wire by hand.

mod scripted {
    use std::future::Future;
    use std::time::Duration;

    use futures_util::{SinkExt, StreamExt};
    use speakeasy::crypto::b64;
    use speakeasy::proto::{FromRelay, Kind, ToRelay};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::runtime::Runtime;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Message;
    use uuid::Uuid;

    pub type Sock = WebSocketStream<TcpStream>;

    pub struct Scripted<T> {
        pub url: String,
        rt: Runtime,
        script: JoinHandle<T>,
    }

    impl<T> Scripted<T> {
        /// Wait for the script to finish; a panic inside it fails the test.
        pub fn finish(self) -> T {
            let script = self.script;
            self.rt
                .block_on(async { timeout(Duration::from_secs(20), script).await })
                .expect("relay script did not finish")
                .expect("relay script failed")
        }
    }

    pub fn relay<F, Fut>(script: F) -> Scripted<Fut::Output>
    where
        F: FnOnce(TcpListener) -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let rt = Runtime::new().unwrap();
        let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let script = rt.spawn(script(listener));
        Scripted { url, rt, script }
    }

    async fn accept(l: &TcpListener) -> Sock {
        let (stream, _) = l.accept().await.unwrap();
        tokio_tungstenite::accept_async(stream).await.unwrap()
    }

    async fn rx(ws: &mut Sock) -> ToRelay {
        loop {
            match ws.next().await.expect("daemon hung up").unwrap() {
                Message::Text(t) => return serde_json::from_str(t.as_str()).unwrap(),
                _ => continue,
            }
        }
    }

    async fn tx(ws: &mut Sock, m: FromRelay) {
        let text = serde_json::to_string(&m).unwrap();
        ws.send(Message::Text(text.into())).await.unwrap();
    }

    fn challenge(room: Uuid) -> FromRelay {
        FromRelay::Challenge {
            room,
            nonce: b64(&[7; 32]),
        }
    }

    /// The relay's part of creating a room, up to but not including the
    /// final `attached`. Returns the creator's sealed group info.
    async fn begin_create(l: &TcpListener) -> (Sock, Uuid, String) {
        let mut ws = accept(l).await;
        let ToRelay::Create { .. } = rx(&mut ws).await else {
            panic!("expected create")
        };
        let room = Uuid::new_v4();
        tx(&mut ws, challenge(room)).await;
        let ToRelay::CreateFin { group_info, .. } = rx(&mut ws).await else {
            panic!("expected create_fin")
        };
        (ws, room, group_info)
    }

    fn attached(head: u64, group_info: String) -> FromRelay {
        FromRelay::Attached {
            head,
            last_commit: 0,
            group_info,
        }
    }

    /// What the relay turns out to have done with a message whose echo the
    /// sender never saw.
    #[derive(Clone, Copy)]
    pub enum Fate {
        /// Sequenced: the replay after resume contains it.
        Sequenced,
        /// Not sequenced: the replay is complete and does not contain it.
        NotSequenced,
        /// Unknowable: the relay no longer has the frames to replay.
        Unknowable,
    }

    fn json(m: &ToRelay) -> serde_json::Value {
        serde_json::to_value(m).unwrap()
    }

    /// Take one message from the creator, drop the connection without
    /// echoing it, then answer the reconnect according to `fate`. The next
    /// thing the creator submits after that must be a new message.
    pub async fn lose_an_echo(l: TcpListener, fate: Fate) -> Sock {
        let (mut ws, room, group_info) = begin_create(&l).await;
        tx(&mut ws, attached(0, group_info.clone())).await;
        let first = rx(&mut ws).await;
        let ToRelay::Submit { id, data, kind: Kind::App, .. } = &first else {
            panic!("expected a message")
        };
        let frame = |seq, kind, id: &str, data: &str| FromRelay::Frame {
            seq,
            kind,
            id: id.to_string(),
            data: data.to_string(),
        };
        drop(ws);

        let mut ws = accept(&l).await;
        let ToRelay::Resume { cursor: 0, .. } = rx(&mut ws).await else {
            panic!("expected resume from 0")
        };
        tx(&mut ws, challenge(room)).await;
        let ToRelay::Auth { .. } = rx(&mut ws).await else {
            panic!("expected auth")
        };
        // Where the room stands afterwards: (head, latest commit).
        let (head, commit) = match fate {
            Fate::Sequenced => {
                tx(&mut ws, FromRelay::Resumed { head: 1 }).await;
                tx(&mut ws, frame(1, Kind::App, id, data)).await;
                (1, 0)
            }
            Fate::NotSequenced => {
                tx(&mut ws, FromRelay::Resumed { head: 0 }).await;
                // The same submission, field for field: not a second message.
                assert_eq!(json(&rx(&mut ws).await), json(&first));
                tx(&mut ws, frame(1, Kind::App, id, data)).await;
                (1, 0)
            }
            Fate::Unknowable => {
                tx(&mut ws, FromRelay::Gap).await;
                drop(ws);
                ws = accept(&l).await;
                let ToRelay::Attach { .. } = rx(&mut ws).await else {
                    panic!("expected attach")
                };
                tx(&mut ws, challenge(room)).await;
                let ToRelay::Auth { .. } = rx(&mut ws).await else {
                    panic!("expected auth")
                };
                tx(&mut ws, attached(1, group_info)).await;
                let ToRelay::Submit { id, data, kind: Kind::Commit, .. } = rx(&mut ws).await
                else {
                    panic!("expected the rejoin commit")
                };
                tx(&mut ws, frame(2, Kind::Commit, &id, &data)).await;
                (2, 2)
            }
        };
        // The next submission is the test's second message, so the first
        // was not submitted again in between.
        let ToRelay::Submit { id: next, data, kind: Kind::App, after_commit, .. } =
            rx(&mut ws).await
        else {
            panic!("expected the second message")
        };
        assert_ne!(&next, id);
        assert_eq!(after_commit, commit);
        tx(&mut ws, frame(head + 1, Kind::App, &next, &data)).await;
        ws
    }

    /// Bring the room into being but never say so. The creator, once it
    /// panics, has to come back for the room on a new connection. Returns
    /// what it sent there.
    pub async fn stall_create(l: TcpListener, tell: std::sync::mpsc::Sender<()>) -> ToRelay {
        let (_stalled, room, _) = begin_create(&l).await;
        tell.send(()).unwrap();
        let mut ws = accept(&l).await;
        let ToRelay::Resume { cursor: 0, .. } = rx(&mut ws).await else {
            panic!("expected resume from 0")
        };
        tx(&mut ws, challenge(room)).await;
        let ToRelay::Auth { .. } = rx(&mut ws).await else {
            panic!("expected auth")
        };
        tx(&mut ws, FromRelay::Resumed { head: 0 }).await;
        let next = rx(&mut ws).await;
        tx(&mut ws, FromRelay::Closed).await;
        next
    }
}

use scripted::Fate;

/// Create a room on a relay that loses the echo of the first message, send
/// two messages, and return what the first `send` reported.
fn send_with_lost_echo(fate: Fate) -> Output {
    let relay = scripted::relay(move |l| scripted::lose_an_echo(l, fate));
    let alice = Agent::new();
    let out = alice.run(&["create", "--relay", &relay.url, "--name", "alice"]);
    assert_eq!(out.code, 0, "{:?}", out.lines);
    let out = alice.run_with(&["send"], Some("hello"));
    alice.send("again");
    let _open = relay.finish();
    out
}

#[test]
fn a_send_sequenced_before_the_connection_dropped_is_confirmed_by_the_replay() {
    let out = send_with_lost_echo(Fate::Sequenced);
    assert_eq!(out.code, 0, "{:?}", out.lines);
    assert_eq!((&out.lines[0]["ok"], &out.lines[0]["seq"]), (&true.into(), &1.into()));
}

#[test]
fn a_send_the_replay_proves_unsequenced_is_submitted_again_unchanged() {
    let out = send_with_lost_echo(Fate::NotSequenced);
    assert_eq!(out.code, 0, "{:?}", out.lines);
    assert_eq!(out.lines[0]["ok"], true);
}

#[test]
fn a_send_whose_fate_cannot_be_known_is_reported_as_unknown_and_not_resent() {
    let out = send_with_lost_echo(Fate::Unknowable);
    assert_eq!(out.code, 1, "{:?}", out.lines);
    assert_eq!(out.lines[0]["delivered"], "unknown");
}

#[test]
fn panic_while_the_room_is_being_created_still_closes_it_at_the_relay() {
    let (tell, registered) = std::sync::mpsc::channel();
    let relay = scripted::relay(move |l| scripted::stall_create(l, tell));
    let alice = Arc::new(Agent::new());
    let creating = {
        let (alice, url) = (alice.clone(), relay.url.clone());
        std::thread::spawn(move || alice.run(&["create", "--relay", &url, "--name", "alice"]))
    };
    // The relay now has the room, but the creator has not heard so.
    registered.recv_timeout(Duration::from_secs(10)).unwrap();
    let out = alice.run(&["panic"]);
    assert_eq!(out.code, 0, "{:?}", out.lines);
    assert_eq!(out.lines[0]["relay_confirmed"], true);
    assert!(matches!(relay.finish(), speakeasy::proto::ToRelay::Panic));
    // The launch reports the panic and never prints an invitation.
    let out = creating.join().unwrap();
    assert_eq!(out.code, 1, "{:?}", out.lines);
    assert_eq!(out.lines[0]["error"], "panic");
}
