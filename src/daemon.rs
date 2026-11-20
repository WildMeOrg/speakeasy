//! The per-session daemon. It holds the MLS state and keys in memory only,
//! keeps one WebSocket to the relay, and serves one-shot CLI commands over a
//! private Unix socket.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, interval, sleep, sleep_until, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::crypto::{Blob, Invite, RoomKeys, b64, hex, random, sign, transcript, unb64};
use crate::mls::{Keys, Mls};
use crate::proto::{FromRelay, Kind, ToRelay};

const INBOX_CAP: usize = 1000;
const MAX_TRIES: u32 = 50;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// A send that has not been resolved by then is answered with what is known.
pub const SEND_DEADLINE: Duration = Duration::from_secs(60);
/// No echo for this long on a live connection means the connection is not
/// really live: drop it and resume, which settles what was sequenced.
const ECHO_DEADLINE: Duration = Duration::from_secs(15);
/// Give up and erase keys if the relay stays unreachable this long.
const LOST_AFTER: Duration = Duration::from_secs(120);
/// How long a panic waits for the relay to confirm before answering anyway.
const PANIC_NOTIFY: Duration = Duration::from_secs(3);
/// After closing, keep answering local commands briefly so waiters learn why.
const LINGER: Duration = Duration::from_secs(15);

/// How the daemon is told what to do. Arrives on stdin, so the invitation
/// secret never appears in the process arguments.
#[derive(Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Start {
    Create { relay: String, name: String },
    Join { invite: String, name: String },
}

/// One request line on the local socket.
#[derive(Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    Send { text: String },
    Recv { wait: f64 },
    Panic,
    Leave,
}

// ---------------------------------------------------------------- local state

#[derive(Default)]
struct Inbox {
    /// Events with a local serial number, removed only once a reader has
    /// acknowledged them.
    events: VecDeque<(u64, Value)>,
    next_serial: u64,
    dropped: u64,
    phase: &'static str,
    closed: Option<String>,
    invite: Option<String>,
    room: Option<String>,
    name: String,
}

/// State shared with the local-socket tasks. `tick` wakes every waiter.
struct Shared {
    inbox: Mutex<Inbox>,
    tick: watch::Sender<u64>,
    /// Serialises delivery to readers so two cannot be handed the same batch.
    delivering: tokio::sync::Mutex<()>,
}

impl Shared {
    fn update(&self, f: impl FnOnce(&mut Inbox)) {
        {
            let mut i = self.inbox.lock().unwrap();
            f(&mut i);
            // Closed is terminal: nothing may bring the phase or the
            // invitation back afterwards.
            if i.closed.is_some() {
                i.phase = "closed";
                i.invite = None;
            }
        }
        self.tick.send_modify(|n| *n += 1);
    }

    /// A local panic is published here by the socket task the moment it
    /// arrives, ahead of anything queued for the session.
    fn panicked(&self) -> bool {
        self.inbox.lock().unwrap().closed.as_deref() == Some("panic")
    }

    fn event(&self, e: Value) {
        self.update(|i| {
            if i.events.len() >= INBOX_CAP {
                i.events.pop_front();
                i.dropped += 1;
            }
            i.next_serial += 1;
            let serial = i.next_serial;
            i.events.push_back((serial, e));
        });
    }
}

// ------------------------------------------------------------ relay transport

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn ws_connect(relay: &str) -> Result<Ws, String> {
    let url = format!("{}/ws", relay.trim_end_matches('/'));
    let (ws, _) = timeout(IO_TIMEOUT, tokio_tungstenite::connect_async(url))
        .await
        .map_err(|_| "relay connect timed out".to_string())?
        .map_err(|e| format!("relay connect failed: {e}"))?;
    Ok(ws)
}

async fn ws_send(ws: &mut Ws, m: &ToRelay) -> Result<(), String> {
    let text = serde_json::to_string(m).unwrap();
    timeout(IO_TIMEOUT, ws.send(Message::Text(text.into())))
        .await
        .map_err(|_| "relay write timed out".to_string())?
        .map_err(|e| e.to_string())
}

async fn ws_recv(ws: &mut Ws) -> Result<FromRelay, String> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => {
                return serde_json::from_str(t.as_str()).map_err(|e| e.to_string());
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(_)) | None => return Err("relay connection ended".into()),
            Some(Err(e)) => return Err(e.to_string()),
        }
    }
}

async fn ws_expect(ws: &mut Ws) -> Result<FromRelay, String> {
    timeout(IO_TIMEOUT, ws_recv(ws))
        .await
        .map_err(|_| "relay did not answer".to_string())?
}

/// Why a session could not continue on its current connection.
enum Fail {
    /// Network trouble. Worth retrying.
    Io(String),
    /// The room is closed or the daemon must stop. Terminal.
    Closed(String),
    /// Resume refused: frames were missed. Rejoin as a fresh member.
    Gap,
}

fn io(e: String) -> Fail {
    Fail::Io(e)
}

struct Snapshot {
    last_commit: u64,
    group_info: String,
}

/// A fresh relay session, opened by proving possession of the invitation.
struct Attached {
    ws: Ws,
    relay_session: SigningKey,
    head: u64,
    snapshot: Snapshot,
}

async fn attach(invite: &Invite, keys: &RoomKeys) -> Result<Attached, Fail> {
    let relay_session = SigningKey::from_bytes(&random());
    let session_pub = relay_session.verifying_key().to_bytes();
    let mut ws = ws_connect(&invite.relay).await.map_err(io)?;
    ws_send(
        &mut ws,
        &ToRelay::Attach {
            room: invite.room,
            session_key: b64(&session_pub),
        },
    )
    .await
    .map_err(io)?;
    let nonce = match ws_expect(&mut ws).await.map_err(io)? {
        FromRelay::Challenge { room, nonce } if room == invite.room => unb64(&nonce).map_err(io)?,
        FromRelay::Closed => return Err(Fail::Closed("closed".into())),
        other => return Err(Fail::Closed(format!("relay refused attach: {other:?}"))),
    };
    let t = transcript("attach", &invite.room, &nonce, &session_pub, 0);
    ws_send(
        &mut ws,
        &ToRelay::Auth {
            sig: sign(&keys.invite_key, &t),
        },
    )
    .await
    .map_err(io)?;
    match ws_expect(&mut ws).await.map_err(io)? {
        FromRelay::Attached {
            head,
            last_commit,
            group_info,
        } => Ok(Attached {
            ws,
            relay_session,
            head,
            snapshot: Snapshot {
                last_commit,
                group_info,
            },
        }),
        FromRelay::Closed => Err(Fail::Closed("closed".into())),
        other => Err(Fail::Closed(format!("relay refused attach: {other:?}"))),
    }
}

async fn resume(invite: &Invite, session: &SigningKey, cursor: u64) -> Result<(Ws, u64), Fail> {
    let session_pub = session.verifying_key().to_bytes();
    let mut ws = ws_connect(&invite.relay).await.map_err(io)?;
    ws_send(
        &mut ws,
        &ToRelay::Resume {
            room: invite.room,
            session_key: b64(&session_pub),
            cursor,
        },
    )
    .await
    .map_err(io)?;
    let nonce = match ws_expect(&mut ws).await.map_err(io)? {
        FromRelay::Challenge { room, nonce } if room == invite.room => unb64(&nonce).map_err(io)?,
        // A restarted relay has no rooms, so an unknown room means closed.
        FromRelay::Closed => return Err(Fail::Closed("closed".into())),
        other => return Err(Fail::Closed(format!("relay refused resume: {other:?}"))),
    };
    let t = transcript("resume", &invite.room, &nonce, &session_pub, cursor);
    ws_send(&mut ws, &ToRelay::Auth { sig: sign(session, &t) })
        .await
        .map_err(io)?;
    match ws_expect(&mut ws).await.map_err(io)? {
        FromRelay::Resumed { head } => Ok((ws, head)),
        FromRelay::Gap => Err(Fail::Gap),
        FromRelay::Closed => Err(Fail::Closed("closed".into())),
        // The relay forgot this session (for example a gap it already
        // reported). Rejoining is the safe recovery.
        FromRelay::Error { .. } => Err(Fail::Gap),
        other => Err(Fail::Closed(format!("relay refused resume: {other:?}"))),
    }
}

enum Back {
    Resumed(Ws, u64),
    Fresh(Attached),
}

/// Get back onto the relay, retrying network failures until it works or the
/// room turns out to be closed. Borrows nothing from the session, so the
/// session can keep serving local commands while this runs.
async fn reestablish(
    invite: Arc<Invite>,
    keys: Arc<RoomKeys>,
    session: SigningKey,
    cursor: u64,
    mut fresh: bool,
) -> Result<Back, String> {
    let mut pause = Duration::from_millis(100);
    loop {
        if !fresh {
            match resume(&invite, &session, cursor).await {
                Ok((ws, head)) => return Ok(Back::Resumed(ws, head)),
                Err(Fail::Closed(reason)) => return Err(reason),
                Err(Fail::Gap) => fresh = true,
                Err(Fail::Io(_)) => {}
            }
        }
        if fresh {
            match attach(&invite, &keys).await {
                Ok(a) => return Ok(Back::Fresh(a)),
                Err(Fail::Closed(reason)) => return Err(reason),
                Err(_) => {}
            }
        }
        sleep(pause).await;
        pause = (pause * 2).min(Duration::from_secs(5));
    }
}

// ------------------------------------------------------------------- session

/// Where one local `send` stands. Sends form a queue and only the one at the
/// front is ever in flight, so there is exactly one submission whose fate
/// can be uncertain at a time, and messages cannot overtake each other.
enum SendState {
    /// Never handed to a connection. Definitely not delivered.
    Unsent,
    /// Submitted; the relay's echo will settle it. Until then, unknown.
    Awaiting { after_commit: u64 },
    /// The relay refused it as stale. Definitely not delivered. It becomes
    /// sendable again once we have processed a commit newer than this.
    Stale { after_commit: u64 },
}

struct Outgoing {
    id: String,
    text: Vec<u8>,
    state: SendState,
    /// The ciphertext last submitted and the commit it was encrypted under.
    /// Reused if a replay proves it was never sequenced, so retries do not
    /// burn through MLS sender generations.
    sealed: Option<(u64, String)>,
    tries: u32,
    deadline: Instant,
    reply: oneshot::Sender<Value>,
}

impl Outgoing {
    /// Answer the caller with an error that says whether the message could
    /// have reached anyone.
    fn fail(self, error: &str) {
        let delivered = match self.state {
            SendState::Awaiting { .. } => "unknown",
            _ => "no",
        };
        let _ = self
            .reply
            .send(json!({"error": error, "delivered": delivered, "id": self.id}));
    }
}

enum Phase {
    /// No usable group: between a gap and the next attach.
    Idle,
    /// Our external commit is submitted but not yet sequenced. The group is
    /// provisional until the relay echoes exactly this commit.
    Joining { mls: Mls, commit_id: String, tries: u32 },
    Active { mls: Mls },
}

struct Session {
    shared: Arc<Shared>,
    invite: Arc<Invite>,
    keys: Arc<RoomKeys>,
    me: Keys,
    phase: Phase,
    relay_session: SigningKey,
    /// Seq of the last frame processed.
    cursor: u64,
    /// Seq of the last commit processed: the relay's ordering token.
    last_commit: u64,
    /// Local sends in the order they were made.
    outgoing: Vec<Outgoing>,
    /// Messages for the current connection. Only filled while online.
    outbox: Vec<ToRelay>,
    online: bool,
    /// After a resume: until the cursor reaches this, we cannot know which
    /// of our submissions were sequenced, so nothing is (re)submitted.
    replaying_to: Option<u64>,
    snapshot_at: Option<Instant>,
    /// When we last heard from the relay or started waiting on it.
    quiet_since: Instant,
    /// A send we stopped waiting for while it was in flight. Its echo may
    /// still arrive and must not be mistaken for someone else's message.
    /// Abandoning forces a resume, whose replay settles it.
    abandoned: Option<String>,
    /// The relay told this connection it fell behind: rejoin.
    fell_behind: bool,
    panic_reply: Option<oneshot::Sender<Value>>,
    closed: Option<String>,
}

/// A local command, its reply channel, and when it arrived.
type Command = (Request, oneshot::Sender<Value>, Instant);

impl Session {
    fn new(
        shared: &Arc<Shared>,
        invite: Invite,
        keys: RoomKeys,
        me: Keys,
        relay_session: SigningKey,
        cursor: u64,
    ) -> Self {
        Session {
            shared: shared.clone(),
            invite: Arc::new(invite),
            keys: Arc::new(keys),
            me,
            phase: Phase::Idle,
            relay_session,
            cursor,
            last_commit: 0,
            outgoing: Vec::new(),
            outbox: Vec::new(),
            online: true,
            replaying_to: None,
            snapshot_at: None,
            quiet_since: Instant::now(),
            abandoned: None,
            fell_behind: false,
            panic_reply: None,
            closed: None,
        }
    }

    /// Terminal, and published to local waiters at once: nothing here waits
    /// on the network.
    fn close(&mut self, reason: &str) {
        if self.closed.is_some() {
            return;
        }
        self.closed = Some(reason.to_string());
        self.phase = Phase::Idle; // drops the group and its keys
        self.outbox.clear();
        for out in self.outgoing.drain(..) {
            out.fail("closed");
        }
        let reason = reason.to_string();
        self.shared.update(|i| {
            i.phase = "closed";
            i.closed.get_or_insert(reason); // a local panic got there first
            i.invite = None;
        });
    }

    fn offline(&mut self) {
        self.online = false;
        self.outbox.clear();
        self.snapshot_at = None;
    }

    fn new_id() -> String {
        hex(&random::<16>())
    }

    /// Build a provisional external commit from a relay snapshot and submit it.
    fn begin_join(&mut self, snap: &Snapshot, tries: u32) {
        let built = self
            .keys
            .open(Blob::GroupInfo, &snap.group_info)
            .and_then(|gi| Mls::join(&self.me, &self.invite.room, &self.keys.psk, &gi))
            .and_then(|(mls, commit)| Ok((mls.group_info()?, mls, commit)));
        let (group_info, mls, commit) = match built {
            Ok(x) => x,
            Err(e) => return self.close(&format!("join failed: {e}")),
        };
        let commit_id = Self::new_id();
        self.outbox.push(ToRelay::Submit {
            id: commit_id.clone(),
            kind: Kind::Commit,
            after_commit: snap.last_commit,
            data: self.keys.seal(Blob::Commit, &commit),
            group_info: Some(self.keys.seal(Blob::GroupInfo, &group_info)),
        });
        self.phase = Phase::Joining {
            mls,
            commit_id,
            tries,
        };
        self.quiet_since = Instant::now();
        self.shared.update(|i| i.phase = "joining");
    }

    /// Our join lost a race (or was never sequenced). Ask again after a
    /// short random pause so simultaneous joiners do not keep colliding.
    fn retry_join(&mut self) {
        let Phase::Joining { tries, .. } = self.phase else {
            return;
        };
        if tries >= MAX_TRIES {
            return self.close("join failed: too many simultaneous joins");
        }
        let jitter = u64::from(random::<1>()[0]) * u64::from(tries + 1) / 4;
        self.snapshot_at = Some(Instant::now() + Duration::from_millis(jitter));
    }

    /// Submit the message at the front of the queue, if it is sendable.
    /// Nothing goes out while offline, while joining, or while a resumed
    /// connection is still replaying.
    fn pump(&mut self) {
        if !self.online || self.replaying_to.is_some() || self.abandoned.is_some() {
            return;
        }
        if self.shared.panicked() {
            return; // nothing more leaves this session
        }
        let Phase::Active { mls } = &mut self.phase else {
            return;
        };
        while let Some(out) = self.outgoing.first_mut() {
            match out.state {
                SendState::Awaiting { .. } => return,
                // Still stale until we process the commit that overtook it.
                SendState::Stale { after_commit } if after_commit >= self.last_commit => return,
                SendState::Stale { .. } | SendState::Unsent => {}
            }
            if out.deadline <= Instant::now() {
                self.outgoing.remove(0).fail("timed out"); // not in flight: "no"
                continue;
            }
            if out.tries >= MAX_TRIES {
                self.outgoing.remove(0).fail("room too busy");
                continue;
            }
            let data = match &out.sealed {
                Some((under, data)) if *under == self.last_commit => data.clone(),
                _ => match mls.encrypt(&out.text) {
                    Ok(ct) => b64(&ct),
                    Err(e) => {
                        self.outgoing.remove(0).fail(&format!("could not encrypt: {e}"));
                        continue;
                    }
                },
            };
            out.sealed = Some((self.last_commit, data.clone()));
            out.tries += 1;
            out.state = SendState::Awaiting {
                after_commit: self.last_commit,
            };
            self.outbox.push(ToRelay::Submit {
                id: out.id.clone(),
                kind: Kind::App,
                after_commit: self.last_commit,
                data,
                group_info: None,
            });
            self.quiet_since = Instant::now();
            return;
        }
    }

    fn on_command(&mut self, (req, reply, arrived): Command) {
        // Once a panic has been published, it outranks whatever was queued
        // ahead of it.
        if self.shared.panicked() {
            if matches!(req, Request::Panic) {
                self.panic_reply = Some(reply);
            } else {
                let _ = reply.send(json!({"error": "closed", "delivered": "no"}));
            }
            return self.close("panic");
        }
        match req {
            Request::Send { text } => {
                self.outgoing.push(Outgoing {
                    id: Self::new_id(),
                    text: text.into_bytes(),
                    state: SendState::Unsent,
                    sealed: None,
                    tries: 0,
                    deadline: arrived + SEND_DEADLINE,
                    reply,
                });
                self.pump();
            }
            Request::Panic => {
                self.panic_reply = Some(reply);
                self.close("panic");
            }
            Request::Leave => {
                self.close("left");
                let _ = reply.send(json!({"ok": true}));
            }
            Request::Status | Request::Recv { .. } => {
                let _ = reply.send(json!({"error": "handled elsewhere"}));
            }
        }
    }

    /// Once a second: answer sends that ran out of time. Returns true if the
    /// connection looks dead: we are waiting on the relay for something (an
    /// echo, a replay, our join) and it has said nothing for too long.
    fn on_tick(&mut self) -> bool {
        let now = Instant::now();
        let mut i = 0;
        while i < self.outgoing.len() {
            if self.outgoing[i].deadline <= now {
                let out = self.outgoing.remove(i);
                if matches!(out.state, SendState::Awaiting { .. }) {
                    self.abandoned = Some(out.id.clone());
                }
                out.fail("timed out");
            } else {
                i += 1;
            }
        }
        if self.abandoned.is_some() {
            return self.online; // resume now; the replay settles its fate
        }
        self.pump();
        // Waiting on the relay for one specific thing: an echo, the commit
        // that made a send stale, a replay, or our own join.
        let waiting = self.replaying_to.is_some()
            || matches!(self.phase, Phase::Joining { .. })
            || matches!(
                self.outgoing.first().map(|o| &o.state),
                Some(SendState::Awaiting { .. } | SendState::Stale { .. })
            );
        self.online && waiting && now - self.quiet_since > ECHO_DEADLINE
    }

    fn on_relay(&mut self, msg: FromRelay) {
        if self.shared.panicked() {
            return self.close("panic");
        }
        // The stall clock is reset only by progress on what we are waiting
        // for, not by other participants' traffic.
        let progress = match &msg {
            FromRelay::Frame { .. } => self.replaying_to.is_some(),
            FromRelay::Stale { .. } | FromRelay::Snapshot { .. } => true,
            _ => false,
        };
        if progress {
            self.quiet_since = Instant::now();
        }
        match msg {
            FromRelay::Frame { seq, kind, id, data } => {
                if seq != self.cursor + 1 {
                    // Sequence numbers are only meaningful on an honest relay,
                    // but a visible break is never acceptable.
                    return self.close("relay delivered frames out of order");
                }
                self.cursor = seq;
                match kind {
                    Kind::App => self.on_app(seq, &id, &data),
                    Kind::Commit => self.on_commit(seq, &id, &data),
                }
                self.after_replay();
            }
            FromRelay::Stale { id } => {
                if matches!(&self.phase, Phase::Joining { commit_id, .. } if *commit_id == id) {
                    self.retry_join();
                } else if let Some(out) = self.outgoing.iter_mut().find(|o| o.id == id) {
                    if let SendState::Awaiting { after_commit } = out.state {
                        out.state = SendState::Stale { after_commit };
                    }
                    self.pump();
                } else if self.abandoned.as_deref() == Some(id.as_str()) {
                    self.abandoned = None; // rejected, so it will never be echoed
                }
            }
            FromRelay::Snapshot {
                last_commit,
                group_info,
            } => {
                if let Phase::Joining { tries, .. } = self.phase {
                    self.begin_join(
                        &Snapshot {
                            last_commit,
                            group_info,
                        },
                        tries + 1,
                    );
                }
            }
            FromRelay::Closed => self.close("closed"),
            FromRelay::Gap => self.fell_behind = true,
            FromRelay::Error { msg } => self.close(&format!("relay error: {msg}")),
            other => self.close(&format!("unexpected relay message: {other:?}")),
        }
    }

    fn on_app(&mut self, seq: u64, id: &str, data: &str) {
        if let Some(i) = self.outgoing.iter().position(|o| o.id == id) {
            // Our own message, now sequenced. This is the only acknowledgement.
            let out = self.outgoing.remove(i);
            let _ = out.reply.send(json!({"ok": true, "seq": seq, "id": out.id}));
            return self.pump();
        }
        if self.abandoned.as_deref() == Some(id) {
            self.abandoned = None;
            return self.pump(); // ours; its sender was already told "unknown"
        }
        let Phase::Active { mls } = &mut self.phase else {
            return; // sent before our admission: not ours to read
        };
        match unb64(data).and_then(|ct| mls.process_app(&ct)) {
            Ok((from, text)) => self.shared.event(json!({
                "type": "message",
                "seq": seq,
                "from": from.name,
                "key": from.key,
                "text": String::from_utf8_lossy(&text),
            })),
            Err(_) => self.shared.event(json!({"type": "undecryptable", "seq": seq})),
        }
    }

    fn on_commit(&mut self, seq: u64, id: &str, data: &str) {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Joining { mls, commit_id, .. } if commit_id == id => {
                // Exactly our commit was sequenced: the provisional group is real.
                let members: Vec<Value> = mls
                    .members()
                    .into_iter()
                    .map(|p| json!({"name": p.name, "key": p.key}))
                    .collect();
                self.phase = Phase::Active { mls };
                self.last_commit = seq;
                self.shared.update(|i| i.phase = "active");
                self.shared
                    .event(json!({"type": "ready", "seq": seq, "members": members}));
            }
            // Someone else's commit while we are joining: ours is now stale
            // and the relay will say so.
            joining @ (Phase::Joining { .. } | Phase::Idle) => self.phase = joining,
            Phase::Active { mut mls } => {
                // The relay's ordering token advances whether or not we
                // accept the commit; otherwise one bad join would stop every
                // member sending.
                self.last_commit = seq;
                // Commits are only ever accepted through the invitation seal.
                let admitted = self
                    .keys
                    .open(Blob::Commit, data)
                    .and_then(|commit| mls.process_join(&commit));
                match admitted {
                    Ok(p) => self.shared.event(json!({
                        "type": "joined", "seq": seq, "name": p.name, "key": p.key,
                    })),
                    Err(why) => {
                        self.shared
                            .event(json!({"type": "join_rejected", "seq": seq, "reason": why}));
                        // The relay stored the rejected joiner's group info.
                        // Put the real one back so later joiners do not land
                        // in a phantom group.
                        if let Ok(gi) = mls.group_info() {
                            self.outbox.push(ToRelay::GroupInfo {
                                after_commit: seq,
                                data: self.keys.seal(Blob::GroupInfo, &gi),
                            });
                        }
                    }
                }
                self.phase = Phase::Active { mls };
            }
        }
        self.pump();
    }

    /// Once a resumed connection has replayed up to the relay's head at
    /// resume time, anything of ours still unechoed was never sequenced.
    fn after_replay(&mut self) {
        let Some(head) = self.replaying_to else { return };
        if self.cursor < head {
            return;
        }
        self.replaying_to = None;
        self.abandoned = None; // not in the replay, so never sequenced
        for out in &mut self.outgoing {
            if matches!(out.state, SendState::Awaiting { .. }) {
                out.state = SendState::Unsent;
            }
        }
        if matches!(self.phase, Phase::Joining { .. }) {
            self.retry_join();
        }
        self.pump();
    }

    async fn flush(&mut self, ws: &mut Ws) -> Result<(), String> {
        for m in std::mem::take(&mut self.outbox) {
            ws_send(ws, &m).await?;
        }
        Ok(())
    }

    /// The connection is gone. Get back on while still serving local
    /// commands, so a panic or leave is never stuck behind a dead network.
    async fn reconnect(&mut self, commands: &mut mpsc::Receiver<Command>) -> Result<Ws, String> {
        self.offline();
        let fresh = std::mem::take(&mut self.fell_behind);
        let attempt = reestablish(
            self.invite.clone(),
            self.keys.clone(),
            self.relay_session.clone(),
            self.cursor,
            fresh,
        );
        tokio::pin!(attempt);
        let deadline = sleep(LOST_AFTER);
        tokio::pin!(deadline);
        let mut ticks = interval(Duration::from_secs(1));
        let back = loop {
            tokio::select! {
                back = &mut attempt => break back?,
                _ = &mut deadline => return Err("lost".into()),
                Some(cmd) = commands.recv() => {
                    self.on_command(cmd);
                    if let Some(reason) = &self.closed {
                        return Err(reason.clone());
                    }
                }
                _ = ticks.tick() => { self.on_tick(); }
            }
        };
        self.online = true;
        self.quiet_since = Instant::now();
        match back {
            Back::Resumed(ws, head) => {
                self.replaying_to = Some(head);
                self.after_replay();
                Ok(ws)
            }
            Back::Fresh(a) => {
                // We missed frames for good. Anything submitted but not
                // echoed may or may not have been delivered, and resending
                // it could deliver it twice, so the caller is told instead.
                let mut i = 0;
                while i < self.outgoing.len() {
                    if matches!(self.outgoing[i].state, SendState::Awaiting { .. }) {
                        self.outgoing.remove(i).fail("connection lost before confirmation");
                    } else {
                        i += 1;
                    }
                }
                self.shared.event(json!({"type": "gap"}));
                self.abandoned = None; // a fresh seat never sees old frames
                self.relay_session = a.relay_session;
                self.cursor = a.head;
                self.replaying_to = None;
                self.begin_join(&a.snapshot, 0);
                Ok(a.ws)
            }
        }
    }

    /// Tell the relay about a local panic, best effort, and answer the
    /// caller. The room is already closed locally by the time this runs.
    async fn deliver_panic(&mut self, ws: Option<Ws>, commands: &mut mpsc::Receiver<Command>) {
        if self.closed.as_deref() != Some("panic") {
            return;
        }
        let seat = Some((self.relay_session.clone(), self.cursor));
        let confirmed = notify_panic(ws, &self.invite, &self.keys, seat).await;
        // The panic command itself may still be queued behind others.
        while self.panic_reply.is_none() {
            match commands.try_recv() {
                Ok((Request::Panic, reply, _)) => self.panic_reply = Some(reply),
                Ok((_, reply, _)) => {
                    let _ = reply.send(json!({"error": "closed", "delivered": "no"}));
                }
                Err(_) => break,
            }
        }
        if let Some(reply) = self.panic_reply.take() {
            let _ = reply.send(json!({"ok": true, "relay_confirmed": confirmed}));
        }
    }
}

/// Send a panic to the relay and wait briefly for it to confirm closure.
/// Uses the live connection if there is one, else the session's own seat,
/// else a fresh attach. Returns whether the relay confirmed.
async fn notify_panic(
    ws: Option<Ws>,
    invite: &Invite,
    keys: &RoomKeys,
    seat: Option<(SigningKey, u64)>,
) -> bool {
    /// Send the panic on one connection and wait for `closed`.
    async fn over(mut ws: Ws) -> bool {
        if ws_send(&mut ws, &ToRelay::Panic).await.is_err() {
            return false;
        }
        loop {
            match ws_recv(&mut ws).await {
                Ok(FromRelay::Closed) => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    }
    let attempt = async {
        // Each route falls through to the next if it fails. A relay that
        // says the room is already closed counts as confirmation.
        if let Some(ws) = ws {
            if over(ws).await {
                return true;
            }
        }
        if let Some((session, cursor)) = &seat {
            match resume(invite, session, *cursor).await {
                Ok((ws, _)) => {
                    if over(ws).await {
                        return true;
                    }
                }
                Err(Fail::Closed(reason)) if reason == "closed" => return true,
                Err(_) => {}
            }
        }
        match attach(invite, keys).await {
            Ok(a) => over(a.ws).await,
            Err(Fail::Closed(reason)) => reason == "closed",
            Err(_) => false,
        }
    };
    timeout(PANIC_NOTIFY, attempt).await.unwrap_or(false)
}

/// Create a room: the relay allocates the id, then we register the verifier
/// and the first group info.
async fn create(relay: &str, name: &str, shared: &Arc<Shared>) -> Result<(Ws, Session), String> {
    let me = Keys::new(name);
    let relay_session = SigningKey::from_bytes(&random());
    let session_pub = relay_session.verifying_key().to_bytes();
    let mut ws = ws_connect(relay).await?;
    ws_send(
        &mut ws,
        &ToRelay::Create {
            session_key: b64(&session_pub),
        },
    )
    .await?;
    let (room, nonce) = match ws_expect(&mut ws).await? {
        FromRelay::Challenge { room, nonce } => (room, unb64(&nonce)?),
        other => return Err(format!("relay refused create: {other:?}")),
    };
    let invite = Invite {
        relay: relay.to_string(),
        room,
        secret: random(),
    };
    let keys = RoomKeys::derive(&room, &invite.secret);
    let mls = Mls::create(&me, &room, &keys.psk)?;
    let t = transcript("create", &room, &nonce, &session_pub, 0);
    ws_send(
        &mut ws,
        &ToRelay::CreateFin {
            verifier: b64(&keys.verifier()),
            sig: sign(&keys.invite_key, &t),
            group_info: keys.seal(Blob::GroupInfo, &mls.group_info()?),
        },
    )
    .await?;
    match ws_expect(&mut ws).await? {
        FromRelay::Attached { .. } => {}
        other => return Err(format!("relay refused create: {other:?}")),
    }
    let encoded = invite.encode();
    let mut session = Session::new(shared, invite, keys, me, relay_session, 0);
    session.phase = Phase::Active { mls };
    shared.update(|i| {
        i.phase = "active";
        i.invite = Some(encoded);
        i.room = Some(room.to_string());
    });
    Ok((ws, session))
}

async fn join(invite: &str, name: &str, shared: &Arc<Shared>) -> Result<(Ws, Session), String> {
    let invite = Invite::parse(invite)?;
    let keys = RoomKeys::derive(&invite.room, &invite.secret);
    let a = match attach(&invite, &keys).await {
        Ok(a) => a,
        Err(Fail::Io(e) | Fail::Closed(e)) => return Err(e),
        Err(Fail::Gap) => return Err("relay reported a gap on attach".into()),
    };
    shared.update(|i| i.room = Some(invite.room.to_string()));
    let mut session = Session::new(shared, invite, keys, Keys::new(name), a.relay_session, a.head);
    session.begin_join(&a.snapshot, 0);
    Ok((a.ws, session))
}

/// Run a session until it closes. Returns the reason.
async fn run_session(
    start: Start,
    shared: &Arc<Shared>,
    commands: &mut mpsc::Receiver<Command>,
) -> String {
    // Connect, still answering local commands so a launch can be abandoned.
    let (ws, mut s) = {
        let establishing = async {
            match &start {
                Start::Create { relay, name } => create(relay, name, shared).await,
                Start::Join { invite, name } => join(invite, name, shared).await,
            }
        };
        tokio::pin!(establishing);
        loop {
            tokio::select! {
                done = &mut establishing => match done {
                    Ok(x) => break x,
                    Err(e) => return e,
                },
                Some((req, reply, _)) = commands.recv() => match req {
                    Request::Leave => {
                        let _ = reply.send(json!({"ok": true}));
                        return "left".into();
                    }
                    Request::Panic => {
                        // The handshake in flight may already hold a seat or,
                        // for a creator, have brought the room into being.
                        // Give it a moment to finish, so the panic goes out
                        // on that seat.
                        let confirmed = match timeout(PANIC_NOTIFY, &mut establishing).await {
                            Ok(Ok((ws, s))) => {
                                let seat = Some((s.relay_session.clone(), s.cursor));
                                notify_panic(Some(ws), &s.invite, &s.keys, seat).await
                            }
                            // No seat. A joiner still holds the invitation
                            // and can close the room with it. A creator's
                            // room, if the relay made one, has an invitation
                            // nobody was shown, and expires empty.
                            _ => match &start {
                                Start::Join { invite, .. } => match Invite::parse(invite) {
                                    Ok(invite) => {
                                        let keys = RoomKeys::derive(&invite.room, &invite.secret);
                                        notify_panic(None, &invite, &keys, None).await
                                    }
                                    Err(_) => false,
                                },
                                Start::Create { .. } => false,
                            },
                        };
                        let _ = reply.send(json!({"ok": true, "relay_confirmed": confirmed}));
                        return "panic".into();
                    }
                    _ => { let _ = reply.send(json!({"error": "not ready", "delivered": "no"})); }
                },
            }
        }
    };
    let mut ws = Some(ws);
    let mut ticks = interval(Duration::from_secs(1));
    loop {
        if s.shared.panicked() {
            s.close("panic");
        }
        if s.closed.is_some() {
            break;
        }
        let Some(live) = ws.as_mut() else {
            match s.reconnect(commands).await {
                Ok(new) => ws = Some(new),
                Err(reason) => s.close(&reason),
            }
            continue;
        };
        if s.flush(live).await.is_err() {
            ws = None;
            continue;
        }
        let mut dead = false;
        tokio::select! {
            msg = ws_recv(live) => match msg {
                Ok(m) => s.on_relay(m),
                Err(_) => dead = true,
            },
            Some(cmd) = commands.recv() => s.on_command(cmd),
            _ = sleep_until(s.snapshot_at.unwrap_or_else(Instant::now)), if s.snapshot_at.is_some() => {
                s.snapshot_at = None;
                s.quiet_since = Instant::now();
                s.outbox.push(ToRelay::Snapshot);
            }
            _ = ticks.tick() => dead = s.on_tick(),
        }
        if dead || s.fell_behind {
            ws = None;
        }
    }
    s.deliver_panic(ws, commands).await;
    s.closed.clone().unwrap_or_default()
    // `s` is dropped here: the invitation-derived keys go with it. The MLS
    // group and its key store were dropped when the session closed.
}

// -------------------------------------------------------------- local socket

/// Private per-user directory holding one socket per session.
pub fn socket_dir() -> Result<PathBuf, String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let uid = unsafe { libc::getuid() };
    let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d).join("speakeasy"),
        _ => std::env::temp_dir().join(format!("speakeasy-{uid}")),
    };
    let _ = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir);
    let meta = std::fs::symlink_metadata(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(format!("{} is not a private directory", dir.display()));
    }
    Ok(dir)
}

/// A handle is lowercase hex and nothing else, so it can never name a path
/// outside the private directory.
pub fn socket_path(handle: &str) -> Result<PathBuf, String> {
    let valid = (1..=32).contains(&handle.len())
        && handle.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !valid {
        return Err("invalid session handle".into());
    }
    Ok(socket_dir()?.join(format!("{handle}.sock")))
}

/// Hand a reader whatever is waiting. Events are removed only after the
/// reader acknowledges them, so a reader that dies mid-read loses nothing
/// (the next one may see those events again).
async fn serve_recv(
    wait: f64,
    shared: &Shared,
    lines: &mut tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    write: &mut tokio::net::unix::OwnedWriteHalf,
) {
    let deadline = Instant::now() + Duration::from_secs_f64(wait.clamp(0.0, 86_400.0));
    let mut tick = shared.tick.subscribe();
    loop {
        let ready = {
            let i = shared.inbox.lock().unwrap();
            !i.events.is_empty() || i.dropped > 0 || i.closed.is_some()
        };
        if !ready && Instant::now() < deadline {
            let _ = tokio::time::timeout_at(deadline, tick.changed()).await;
            continue;
        }
        let _turn = shared.delivering.lock().await;
        let (events, last, dropped, closed) = {
            let i = shared.inbox.lock().unwrap();
            let events: Vec<Value> = i.events.iter().map(|(_, e)| e.clone()).collect();
            let last = i.events.back().map(|(n, _)| *n);
            (events, last, i.dropped, i.closed.clone())
        };
        if events.is_empty() && dropped == 0 && closed.is_none() && Instant::now() < deadline {
            continue; // another reader took them first
        }
        let mut out = events;
        if dropped > 0 {
            out.insert(0, json!({"type": "overflow", "dropped": dropped}));
        }
        let reply = json!({"events": out, "closed": closed});
        // Both steps are bounded: a stalled reader must not hold up the
        // others for long. If it is too slow, its batch is simply delivered
        // again to the next reader.
        let line = format!("{reply}\n");
        let written = timeout(Duration::from_secs(5), write.write_all(line.as_bytes())).await;
        if !matches!(written, Ok(Ok(()))) {
            return;
        }
        let acked = matches!(
            timeout(Duration::from_secs(5), lines.next_line()).await,
            Ok(Ok(Some(l))) if l == "ack"
        );
        if acked {
            let mut i = shared.inbox.lock().unwrap();
            if let Some(last) = last {
                while i.events.front().is_some_and(|(n, _)| *n <= last) {
                    i.events.pop_front();
                }
            }
            i.dropped -= dropped.min(i.dropped);
        }
        return;
    }
}

async fn serve_local(
    stream: tokio::net::UnixStream,
    shared: Arc<Shared>,
    commands: mpsc::Sender<Command>,
) {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let Ok(Some(line)) = lines.next_line().await else {
        return;
    };
    let reply = match serde_json::from_str::<Request>(&line) {
        Err(e) => json!({"error": format!("bad request: {e}")}),
        Ok(Request::Status) => {
            let i = shared.inbox.lock().unwrap();
            json!({
                "phase": i.phase, "closed": i.closed, "room": i.room,
                "name": i.name, "invite": i.invite, "waiting": i.events.len(),
                "pid": std::process::id(),
            })
        }
        Ok(Request::Recv { wait }) => {
            return serve_recv(wait, &shared, &mut lines, &mut write).await;
        }
        Ok(req) => {
            if matches!(req, Request::Panic) {
                // Published here, before the session loop even hears of it:
                // local waiters are released no matter what the network or
                // the session is doing.
                shared.update(|i| {
                    i.closed.get_or_insert("panic".into());
                    i.phase = "closed";
                    i.invite = None;
                });
            }
            let (tx, rx) = oneshot::channel();
            if commands.send((req, tx, Instant::now())).await.is_err() {
                json!({"error": "closed", "delivered": "no"})
            } else {
                rx.await
                    .unwrap_or_else(|_| json!({"error": "closed", "delivered": "no"}))
            }
        }
    };
    let _ = write.write_all(format!("{reply}\n").as_bytes()).await;
}

/// Daemon entry point. Binds the socket, runs the session, and lingers
/// briefly after it closes. `ready` is called exactly once, with the outcome
/// of starting up, so the launching command can report it and let go.
pub async fn run(
    handle: &str,
    start: Start,
    ready: impl FnOnce(Value) + Send + 'static,
) -> Result<(), String> {
    let path = socket_path(handle)?;
    let listener = UnixListener::bind(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let name = match &start {
        Start::Create { name, .. } | Start::Join { name, .. } => name.clone(),
    };
    let shared = Arc::new(Shared {
        inbox: Mutex::new(Inbox {
            phase: "starting",
            name,
            ..Default::default()
        }),
        tick: watch::channel(0).0,
        delivering: tokio::sync::Mutex::new(()),
    });
    let (tx, mut rx) = mpsc::channel::<Command>(64);
    let accept_shared = shared.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve_local(stream, accept_shared.clone(), tx.clone()));
        }
    });

    // Report readiness as soon as the session is in the room or has failed.
    let (watch_shared, handle_owned) = (shared.clone(), handle.to_string());
    tokio::spawn(async move {
        let mut tick = watch_shared.tick.subscribe();
        loop {
            let outcome = {
                let i = watch_shared.inbox.lock().unwrap();
                if let Some(reason) = &i.closed {
                    Some(json!({"error": reason}))
                } else if i.phase == "active" {
                    let mut out = json!({"session": handle_owned, "room": i.room, "name": i.name});
                    if let Some(invite) = &i.invite {
                        out["invite"] = json!(invite);
                    }
                    Some(out)
                } else {
                    None
                }
            };
            if let Some(outcome) = outcome {
                return ready(outcome);
            }
            if tick.changed().await.is_err() {
                return;
            }
        }
    });

    let reason = run_session(start, &shared, &mut rx).await;
    shared.update(|i| {
        i.phase = "closed";
        i.closed.get_or_insert(reason);
        i.invite = None;
    });
    // Answer anything still queued instead of leaving callers to time out.
    rx.close();
    while let Ok((_, reply, _)) = rx.try_recv() {
        let _ = reply.send(json!({"error": "closed", "delivered": "no"}));
    }
    sleep(LINGER).await;
    let _ = std::fs::remove_file(&path);
    Ok(())
}
