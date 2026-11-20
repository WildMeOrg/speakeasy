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
/// How often the relay is pinged, and how long it may go without answering
/// before the connection is treated as dead and resumed.
const PING_EVERY: Duration = Duration::from_secs(10);
const PONG_DEADLINE: Duration = Duration::from_secs(30);
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
    /// After a local panic: whether the relay confirmed the closure.
    panic_confirmed: Option<bool>,
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

    /// Wait until `f` yields something.
    async fn wait_for<T>(&self, f: impl Fn(&Inbox) -> Option<T>) -> T {
        let mut tick = self.tick.subscribe();
        loop {
            if let Some(found) = f(&self.inbox.lock().unwrap()) {
                return found;
            }
            let _ = tick.changed().await;
        }
    }

    /// Closing is first come, first kept, and is how a local panic or leave
    /// stops the session: `run` is waiting on exactly this.
    fn close(&self, reason: &str) {
        self.update(|i| {
            i.closed.get_or_insert_with(|| reason.to_string());
        });
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

/// The next thing from the relay: a protocol message, or `None` for the
/// answer to one of our pings.
async fn ws_next(ws: &mut Ws) -> Result<Option<FromRelay>, String> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => {
                return serde_json::from_str(t.as_str()).map(Some).map_err(|e| e.to_string());
            }
            Some(Ok(Message::Pong(_))) => return Ok(None),
            Some(Ok(Message::Ping(_))) => continue,
            Some(Ok(_)) | None => return Err("relay connection ended".into()),
            Some(Err(e)) => return Err(e.to_string()),
        }
    }
}

async fn ws_recv(ws: &mut Ws) -> Result<FromRelay, String> {
    loop {
        if let Some(m) = ws_next(ws).await? {
            return Ok(m);
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
    let mut ws = ws_connect(&invite.relay).await.map_err(Fail::Io)?;
    ws_send(
        &mut ws,
        &ToRelay::Attach {
            room: invite.room,
            session_key: b64(&session_pub),
        },
    )
    .await
    .map_err(Fail::Io)?;
    let nonce = match ws_expect(&mut ws).await.map_err(Fail::Io)? {
        FromRelay::Challenge { room, nonce } if room == invite.room => unb64(&nonce).map_err(Fail::Io)?,
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
    .map_err(Fail::Io)?;
    match ws_expect(&mut ws).await.map_err(Fail::Io)? {
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
    let mut ws = ws_connect(&invite.relay).await.map_err(Fail::Io)?;
    ws_send(
        &mut ws,
        &ToRelay::Resume {
            room: invite.room,
            session_key: b64(&session_pub),
            cursor,
        },
    )
    .await
    .map_err(Fail::Io)?;
    let nonce = match ws_expect(&mut ws).await.map_err(Fail::Io)? {
        FromRelay::Challenge { room, nonce } if room == invite.room => unb64(&nonce).map_err(Fail::Io)?,
        // A restarted relay has no rooms, so an unknown room means closed.
        FromRelay::Closed => return Err(Fail::Closed("closed".into())),
        other => return Err(Fail::Closed(format!("relay refused resume: {other:?}"))),
    };
    let t = transcript("resume", &invite.room, &nonce, &session_pub, cursor);
    ws_send(&mut ws, &ToRelay::Auth { sig: sign(session, &t) })
        .await
        .map_err(Fail::Io)?;
    match ws_expect(&mut ws).await.map_err(Fail::Io)? {
        FromRelay::Resumed { head } => Ok((ws, head)),
        FromRelay::Gap => Err(Fail::Gap),
        FromRelay::Closed => Err(Fail::Closed("closed".into())),
        // The relay forgot this session (for example a gap it already
        // reported). Rejoining is the safe recovery.
        FromRelay::Error { .. } => Err(Fail::Gap),
        other => Err(Fail::Closed(format!("relay refused resume: {other:?}"))),
    }
}

/// Close the room using only the invitation: no seat, no cursor. Returns
/// whether the relay knew the room (true) or had no such room (false).
async fn close_room(invite: &Invite, keys: &RoomKeys) -> Result<bool, String> {
    let mut ws = ws_connect(&invite.relay).await?;
    ws_send(&mut ws, &ToRelay::Close { room: invite.room }).await?;
    let nonce = match ws_expect(&mut ws).await? {
        FromRelay::Challenge { room, nonce } if room == invite.room => unb64(&nonce)?,
        FromRelay::Closed => return Ok(false),
        other => return Err(format!("relay refused close: {other:?}")),
    };
    let t = transcript("close", &invite.room, &nonce, &[], 0);
    let sig = sign(&keys.invite_key, &t);
    ws_send(&mut ws, &ToRelay::Auth { sig }).await?;
    match ws_expect(&mut ws).await? {
        FromRelay::Closed => Ok(true),
        other => Err(format!("relay refused close: {other:?}")),
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
    outgoing: VecDeque<Outgoing>,
    /// Messages for the current connection.
    outbox: Vec<ToRelay>,
    /// After a resume: until the cursor reaches this, we cannot know which
    /// of our submissions were sequenced, so nothing is (re)submitted.
    replaying_to: Option<u64>,
    snapshot_at: Option<Instant>,
    /// When the relay last answered a ping on this connection, and when we
    /// last sent one.
    heard: Instant,
    pinged: Instant,
    ping_due: bool,
    /// When the connection first went wrong, until the relay answers again.
    troubled_since: Option<Instant>,
    /// A send we stopped waiting for while it was in flight. Its echo may
    /// still arrive and must not be mistaken for someone else's message.
    /// Abandoning forces a resume, whose replay settles it.
    abandoned: Option<String>,
    /// The relay told this connection it fell behind: rejoin.
    fell_behind: bool,
    closed: Option<String>,
}

/// A local `send`: its text, its reply channel, and when it arrived.
type Command = (String, oneshot::Sender<Value>, Instant);

fn closed_reply() -> Value {
    json!({"error": "closed", "delivered": "no"})
}

/// What a panic needs to reach the relay. It lives outside the session, so
/// it survives the session being cancelled in the middle of a step.
#[derive(Default)]
struct Link {
    ws: Option<Ws>,
    room: Option<(Arc<Invite>, Arc<RoomKeys>)>,
    /// A request to create the room has been sent and not yet answered.
    creating: bool,
}

impl Session {
    fn new(
        shared: &Arc<Shared>,
        invite: Arc<Invite>,
        keys: Arc<RoomKeys>,
        me: Keys,
        relay_session: SigningKey,
        cursor: u64,
    ) -> Self {
        Session {
            shared: shared.clone(),
            invite,
            keys,
            me,
            phase: Phase::Idle,
            relay_session,
            cursor,
            last_commit: 0,
            outgoing: VecDeque::new(),
            outbox: Vec::new(),
            replaying_to: None,
            snapshot_at: None,
            heard: Instant::now(),
            pinged: Instant::now(),
            ping_due: false,
            troubled_since: None,
            abandoned: None,
            fell_behind: false,
            closed: None,
        }
    }

    /// Terminal. The session loop returns the reason at its next turn.
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

    /// The submission for the message at the front of the queue, if it can
    /// go now. Called only at the moment of writing, so a send that expired
    /// while earlier writes were in progress never leaves. Nothing goes out
    /// while joining or while a resumed connection is still replaying.
    fn next_submission(&mut self) -> Option<ToRelay> {
        if self.replaying_to.is_some() || self.abandoned.is_some() {
            return None;
        }
        let Phase::Active { mls } = &mut self.phase else {
            return None;
        };
        loop {
            let out = self.outgoing.front_mut()?;
            match out.state {
                SendState::Awaiting { .. } => return None,
                // Still stale until we process the commit that overtook it.
                SendState::Stale { after_commit } if after_commit >= self.last_commit => {
                    return None;
                }
                SendState::Stale { .. } | SendState::Unsent => {}
            }
            // Not in flight, so each of these failures means "not delivered".
            let unsendable = if out.deadline <= Instant::now() {
                Some("timed out".to_string())
            } else if out.tries >= MAX_TRIES {
                Some("room too busy".to_string())
            } else {
                None
            };
            let data = match (&out.sealed, unsendable) {
                (_, Some(why)) => Err(why),
                (Some((under, data)), None) if *under == self.last_commit => Ok(data.clone()),
                _ => mls
                    .encrypt(&out.text)
                    .map(|ct| b64(&ct))
                    .map_err(|e| format!("could not encrypt: {e}")),
            };
            let data = match data {
                Ok(data) => data,
                Err(why) => {
                    self.outgoing.pop_front()?.fail(&why);
                    continue;
                }
            };
            out.sealed = Some((self.last_commit, data.clone()));
            out.tries += 1;
            out.state = SendState::Awaiting {
                after_commit: self.last_commit,
            };
            return Some(ToRelay::Submit {
                id: out.id.clone(),
                kind: Kind::App,
                after_commit: self.last_commit,
                data,
                group_info: None,
            });
        }
    }

    fn enqueue(&mut self, (text, reply, arrived): Command) {
        self.outgoing.push_back(Outgoing {
            id: Self::new_id(),
            text: text.into_bytes(),
            state: SendState::Unsent,
            sealed: None,
            tries: 0,
            deadline: arrived + SEND_DEADLINE,
            reply,
        });
    }

    /// Once a second: answer sends that ran out of time and keep the
    /// heartbeat going. Returns true if the connection should be dropped and
    /// resumed: either a send was given up on while in flight (the replay
    /// settles its fate), or the relay has stopped answering pings.
    fn on_tick(&mut self) -> bool {
        let now = Instant::now();
        let mut gave_up_in_flight = false;
        let mut kept = VecDeque::new();
        for out in self.outgoing.drain(..) {
            if out.deadline > now {
                kept.push_back(out);
                continue;
            }
            if matches!(out.state, SendState::Awaiting { .. }) {
                self.abandoned = Some(out.id.clone());
                gave_up_in_flight = true;
            }
            out.fail("timed out");
        }
        self.outgoing = kept;
        if now - self.pinged >= PING_EVERY {
            self.pinged = now;
            self.ping_due = true;
        }
        gave_up_in_flight || now - self.heard > PONG_DEADLINE
    }

    /// The relay answered a ping: the connection works in both directions.
    fn on_pong(&mut self) {
        self.heard = Instant::now();
        self.troubled_since = None;
    }

    fn on_relay(&mut self, msg: FromRelay) {
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
                } else if let Some(out) = self.outgoing.front_mut().filter(|o| o.id == id) {
                    if let SendState::Awaiting { after_commit } = out.state {
                        out.state = SendState::Stale { after_commit };
                    }
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
        if self.outgoing.front().is_some_and(|o| o.id == id) {
            // Our own message, now sequenced. This is the only acknowledgement.
            let out = self.outgoing.pop_front().unwrap();
            let _ = out.reply.send(json!({"ok": true, "seq": seq, "id": out.id}));
            return;
        }
        if self.abandoned.as_deref() == Some(id) {
            self.abandoned = None;
            return; // ours; its sender was already told "unknown"
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
        if let Some(out) = self.outgoing.front_mut() {
            if matches!(out.state, SendState::Awaiting { .. }) {
                out.state = SendState::Unsent;
            }
        }
        if matches!(self.phase, Phase::Joining { .. }) {
            self.retry_join();
        }
    }

    async fn flush(&mut self, ws: &mut Ws) -> Result<(), String> {
        if std::mem::take(&mut self.ping_due) {
            timeout(IO_TIMEOUT, ws.send(Message::Ping(Default::default())))
                .await
                .map_err(|_| "relay write timed out".to_string())?
                .map_err(|e| e.to_string())?;
        }
        for m in std::mem::take(&mut self.outbox) {
            ws_send(ws, &m).await?;
        }
        if let Some(m) = self.next_submission() {
            ws_send(ws, &m).await?;
        }
        Ok(())
    }

    /// The connection is gone. Get back on, still accepting local sends so
    /// their deadlines keep running.
    async fn reconnect(&mut self, commands: &mut mpsc::Receiver<Command>) -> Result<Ws, String> {
        self.outbox.clear();
        self.snapshot_at = None;
        let fresh = std::mem::take(&mut self.fell_behind);
        let attempt = reestablish(
            self.invite.clone(),
            self.keys.clone(),
            self.relay_session.clone(),
            self.cursor,
            fresh,
        );
        tokio::pin!(attempt);
        // Measured from when the trouble started, not from this attempt: a
        // relay that accepts every resume but never answers a ping is lost.
        let since = *self.troubled_since.get_or_insert_with(Instant::now);
        let deadline = sleep_until(since + LOST_AFTER);
        tokio::pin!(deadline);
        let mut ticks = interval(Duration::from_secs(1));
        let back = loop {
            tokio::select! {
                back = &mut attempt => break back?,
                _ = &mut deadline => return Err("lost".into()),
                Some(cmd) = commands.recv() => self.enqueue(cmd),
                _ = ticks.tick() => { self.on_tick(); }
            }
        };
        (self.heard, self.pinged, self.ping_due) = (Instant::now(), Instant::now(), false);
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
                let in_flight = |o: &Outgoing| matches!(o.state, SendState::Awaiting { .. });
                if self.outgoing.front().is_some_and(in_flight) {
                    let out = self.outgoing.pop_front().unwrap();
                    out.fail("connection lost before confirmation");
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
}

/// A session stopped mid-step still answers its senders with what is known
/// about each message.
impl Drop for Session {
    fn drop(&mut self) {
        self.close("closed");
    }
}

/// Tell the relay about a local panic and wait briefly for it to confirm
/// closure. Tries the live connection, then a separate close request that
/// needs only the invitation. Each gets half the time, so a silent
/// connection cannot starve the other route.
async fn notify_panic(link: Link) -> bool {
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
    let Some((invite, keys)) = link.room else {
        return false; // never got as far as knowing a room
    };
    let half = PANIC_NOTIFY / 2;
    if let Some(ws) = link.ws {
        if timeout(half, over(ws)).await == Ok(true) {
            return true;
        }
    }
    match timeout(half, close_room(&invite, &keys)).await {
        // "No such room" is as good as closed, except while our own request
        // to create it may still be on its way.
        Ok(Ok(existed)) => existed || !link.creating,
        _ => false,
    }
}

/// Create a room: the relay allocates the id, then we register the verifier
/// and the first group info.
async fn create(
    relay: &str,
    name: &str,
    shared: &Arc<Shared>,
    link: &mut Link,
) -> Result<Session, String> {
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
    let invite = Arc::new(Invite {
        relay: relay.to_string(),
        room,
        secret: random(),
    });
    let keys = Arc::new(RoomKeys::derive(&room, &invite.secret));
    let mls = Mls::create(&me, &room, &keys.psk)?;
    let t = transcript("create", &room, &nonce, &session_pub, 0);
    // From here the relay may hold the room. If we are cancelled before
    // hearing back, a panic follows the request down this same connection.
    link.room = Some((invite.clone(), keys.clone()));
    link.creating = true;
    let ws = link.ws.insert(ws);
    ws_send(
        ws,
        &ToRelay::CreateFin {
            verifier: b64(&keys.verifier()),
            sig: sign(&keys.invite_key, &t),
            group_info: keys.seal(Blob::GroupInfo, &mls.group_info()?),
        },
    )
    .await?;
    match ws_expect(ws).await? {
        FromRelay::Attached { .. } => {}
        other => return Err(format!("relay refused create: {other:?}")),
    }
    link.creating = false;
    let encoded = invite.encode();
    let mut session = Session::new(shared, invite, keys, me, relay_session, 0);
    session.phase = Phase::Active { mls };
    shared.update(|i| {
        i.phase = "active";
        i.invite = Some(encoded);
        i.room = Some(room.to_string());
    });
    Ok(session)
}

async fn join(
    invite: &str,
    name: &str,
    shared: &Arc<Shared>,
    link: &mut Link,
) -> Result<Session, String> {
    let invite = Arc::new(Invite::parse(invite)?);
    let keys = Arc::new(RoomKeys::derive(&invite.room, &invite.secret));
    // Holding the invitation is enough to close the room, joined or not.
    link.room = Some((invite.clone(), keys.clone()));
    let a = match attach(&invite, &keys).await {
        Ok(a) => a,
        Err(Fail::Io(e) | Fail::Closed(e)) => return Err(e),
        Err(Fail::Gap) => return Err("relay reported a gap on attach".into()),
    };
    link.ws = Some(a.ws);
    shared.update(|i| i.room = Some(invite.room.to_string()));
    let mut session = Session::new(shared, invite, keys, Keys::new(name), a.relay_session, a.head);
    session.begin_join(&a.snapshot, 0);
    Ok(session)
}

/// Run a session until it closes, and return the reason. A local panic or
/// leave does not pass through here at all: the caller simply stops polling
/// this future, at whatever await it had reached, and `link` holds what is
/// needed to tell the relay.
async fn run_session(
    start: Start,
    shared: &Arc<Shared>,
    commands: &mut mpsc::Receiver<Command>,
    link: &mut Link,
) -> String {
    let made = match &start {
        Start::Create { relay, name } => create(relay, name, shared, link).await,
        Start::Join { invite, name } => join(invite, name, shared, link).await,
    };
    let mut s = match made {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut ticks = interval(Duration::from_secs(1));
    loop {
        if let Some(reason) = &s.closed {
            return reason.clone();
        }
        let Some(live) = link.ws.as_mut() else {
            match s.reconnect(commands).await {
                Ok(new) => link.ws = Some(new),
                Err(reason) => s.close(&reason),
            }
            continue;
        };
        if s.flush(live).await.is_err() {
            link.ws = None;
            continue;
        }
        let mut dead = false;
        tokio::select! {
            msg = ws_next(live) => match msg {
                Ok(Some(m)) => s.on_relay(m),
                Ok(None) => s.on_pong(),
                Err(_) => dead = true,
            },
            Some(cmd) = commands.recv() => s.enqueue(cmd),
            _ = sleep_until(s.snapshot_at.unwrap_or_else(Instant::now)), if s.snapshot_at.is_some() => {
                s.snapshot_at = None;
                s.outbox.push(ToRelay::Snapshot);
            }
            _ = ticks.tick() => dead = s.on_tick(),
        }
        if dead || s.fell_behind {
            link.ws = None;
        }
    }
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
        // Panic and leave take effect here, at once, whatever the session
        // or the network is doing.
        Ok(Request::Panic) => {
            shared.close("panic");
            shared
                .wait_for(|i| match (i.closed.as_deref(), i.panic_confirmed) {
                    (Some("panic"), None) => None, // the relay is being told
                    (Some("panic"), Some(c)) => Some(json!({"ok": true, "relay_confirmed": c})),
                    // Someone else's panic got there first.
                    (Some("closed"), _) => Some(json!({"ok": true, "relay_confirmed": true})),
                    (other, _) => Some(json!({
                        "error": format!("session already ended: {}", other.unwrap_or_default()),
                    })),
                })
                .await
        }
        Ok(Request::Leave) => {
            shared.close("left");
            json!({"ok": true})
        }
        Ok(Request::Send { text }) => {
            let (tx, rx) = oneshot::channel();
            if commands.send((text, tx, Instant::now())).await.is_err() {
                closed_reply()
            } else {
                // A reply that never comes means the session was stopped
                // with this send possibly in flight.
                rx.await
                    .unwrap_or_else(|_| json!({"error": "closed", "delivered": "unknown"}))
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
        let outcome = watch_shared.wait_for(|i| {
            if let Some(reason) = &i.closed {
                return Some(json!({"error": reason}));
            }
            (i.phase == "active").then(|| {
                let mut out = json!({"session": handle_owned, "room": i.room, "name": i.name});
                if let Some(invite) = &i.invite {
                    out["invite"] = json!(invite);
                }
                out
            })
        });
        ready(outcome.await);
    });

    // A local panic or leave closes the inbox directly. That wins here and
    // the session is dropped where it stands, keys and all.
    let mut link = Link::default();
    let reason = tokio::select! {
        biased;
        reason = shared.wait_for(|i| i.closed.clone()) => reason,
        reason = run_session(start, &shared, &mut rx, &mut link) => reason,
    };
    shared.close(&reason);
    // Answer anything still queued instead of leaving callers to time out.
    rx.close();
    while let Ok((_, reply, _)) = rx.try_recv() {
        let _ = reply.send(closed_reply());
    }
    // The connection and the room keys go here, one way or the other.
    if shared.inbox.lock().unwrap().closed.as_deref() == Some("panic") {
        let confirmed = notify_panic(link).await;
        shared.update(|i| i.panic_confirmed = Some(confirmed));
    } else {
        drop(link);
    }
    sleep(LINGER).await;
    let _ = std::fs::remove_file(&path);
    Ok(())
}
