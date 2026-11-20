//! The relay. All state is in RAM; payloads are opaque and never logged.
//!
//! Every operation on a room runs under that room's mutex, so operations are
//! totally ordered and nothing can be accepted after a close. Network writes
//! happen outside the lock. Live delivery and replay share one bounded buffer:
//! each connection holds a cursor into it.
//!
//! Lock order: a room's state lock is never held while taking the room map.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{Semaphore, watch};
use tokio::time::{Instant, sleep_until, timeout};
use uuid::Uuid;

use crate::crypto::{b64, random, transcript, unb64, verify};
use crate::proto::{FromRelay, Kind, ToRelay};

/// Longest submission id accepted. Clients use 32 hex characters.
const MAX_ID: usize = 64;
/// Direct replies a connection may have queued behind a slow write.
const MAX_QUEUED_REPLIES: usize = 64;

#[derive(Clone)]
pub struct Limits {
    pub max_rooms: usize,
    /// Open connections, including ones that have not authenticated yet.
    pub max_connections: usize,
    /// Session keys remembered per room (attached or resumable).
    pub max_sessions: usize,
    /// Largest WebSocket message accepted, in bytes.
    pub max_message: usize,
    pub buffer_frames: usize,
    pub buffer_bytes: usize,
    /// How long a room with no connections survives.
    pub empty_grace: Duration,
    pub handshake_timeout: Duration,
    pub write_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_rooms: 10_000,
            max_connections: 20_000,
            max_sessions: 256,
            max_message: 1 << 20,
            buffer_frames: 1024,
            buffer_bytes: 8 << 20,
            empty_grace: Duration::from_secs(120),
            handshake_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
        }
    }
}

struct Frame {
    seq: u64,
    kind: Kind,
    id: String,
    data: String,
}

impl Frame {
    fn size(&self) -> usize {
        self.data.len() + self.id.len()
    }
}

struct Session {
    /// Head of the room when this session attached. It may never read earlier.
    attached_at: u64,
    /// Bumped on resume; an older connection for the same session is fenced.
    generation: u64,
}

struct Room {
    verifier: Vec<u8>,
    sessions: HashMap<Vec<u8>, Session>,
    /// Contiguous run of the most recent frames.
    buffer: VecDeque<Frame>,
    buffer_bytes: usize,
    head: u64,
    last_commit: u64,
    group_info: String,
    connections: usize,
    /// Source of seat generations. Room-wide and never reused, so a seat
    /// left over from a removed session can never look current again.
    next_generation: u64,
    /// Counts the times the room has become empty, so a stale expiry timer
    /// cannot close a room that was reoccupied and emptied again.
    empty_epoch: u64,
    closed: bool,
}

impl Room {
    fn is_current(&self, seat: &Seat) -> bool {
        !self.closed
            && self.sessions.get(&seat.session_key).map(|s| s.generation) == Some(seat.generation)
    }

    /// Whether everything after `cursor` is still buffered.
    fn covers(&self, cursor: u64) -> bool {
        cursor == self.head || self.buffer.front().is_some_and(|f| f.seq - 1 <= cursor)
    }

    fn new_generation(&mut self) -> u64 {
        self.next_generation += 1;
        self.next_generation
    }
}

struct RoomHandle {
    state: Mutex<Room>,
    /// Bumped whenever there is something new for connections to look at.
    tick: watch::Sender<u64>,
}

impl RoomHandle {
    fn wake(&self) {
        self.tick.send_modify(|n| *n += 1);
    }
}

pub struct Relay {
    rooms: Mutex<HashMap<Uuid, Arc<RoomHandle>>>,
    /// Room ids handed to a creator whose handshake has not finished. Such a
    /// room may still come into existence, so it is not yet "closed".
    pending: Mutex<HashSet<Uuid>>,
    /// One permit per open connection, taken before the WebSocket upgrade.
    permits: Arc<Semaphore>,
    limits: Limits,
}

impl Relay {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Relay {
            rooms: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashSet::new()),
            permits: Arc::new(Semaphore::new(limits.max_connections)),
            limits,
        })
    }

    pub fn room_count(&self) -> usize {
        self.rooms.lock().unwrap().len()
    }

    /// Drop every connection without closing rooms. Sessions can resume.
    pub fn disconnect_all(&self) {
        let rooms: Vec<_> = self.rooms.lock().unwrap().values().cloned().collect();
        for room in rooms {
            {
                let mut r = room.state.lock().unwrap();
                let keys: Vec<_> = r.sessions.keys().cloned().collect();
                for key in keys {
                    let generation = r.new_generation();
                    r.sessions.get_mut(&key).unwrap().generation = generation;
                }
            }
            room.wake();
        }
    }

    /// The room, or the refusal to send: `Closed` only when the id is
    /// neither a room nor about to become one. Pending is checked first and
    /// a creator clears it only after inserting the room, so a room cannot
    /// slip between the two checks.
    fn lookup(&self, id: &Uuid) -> Result<Arc<RoomHandle>, FromRelay> {
        if self.pending.lock().unwrap().contains(id) {
            return Err(err("room is still being created"));
        }
        self.rooms.lock().unwrap().get(id).cloned().ok_or(FromRelay::Closed)
    }

    /// Close the room if `allowed` still holds, deciding and closing in one
    /// critical section. The room is marked closed before it leaves the map,
    /// so there is no moment when it is findable-but-gone or gone-but-open.
    /// Returns whether the room is closed afterwards.
    fn close_if(&self, id: &Uuid, room: &RoomHandle, allowed: impl FnOnce(&Room) -> bool) -> bool {
        {
            let mut r = room.state.lock().unwrap();
            if r.closed {
                return true;
            }
            if !allowed(&r) {
                return false;
            }
            r.closed = true;
            r.buffer.clear();
            r.buffer_bytes = 0;
            r.sessions.clear();
            r.group_info.clear();
            r.verifier.clear();
        }
        self.rooms.lock().unwrap().remove(id);
        room.wake();
        true
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/ws", get(upgrade))
            .with_state(self.clone())
    }

    pub async fn serve(self: Arc<Self>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
        axum::serve(listener, self.router()).await
    }
}

/// Bind and serve in the background. Returns the bound address.
pub async fn spawn(relay: Arc<Relay>, addr: &str) -> std::io::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(relay.serve(listener));
    Ok(local)
}

async fn upgrade(State(relay): State<Arc<Relay>>, ws: WebSocketUpgrade) -> Response {
    // Refuse before upgrading, so a full relay does no per-connection work.
    let Ok(permit) = relay.permits.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let max = relay.limits.max_message;
    ws.max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| async move {
            connection(relay, socket).await;
            drop(permit);
        })
}

fn text(m: &FromRelay) -> Message {
    Message::Text(serde_json::to_string(m).unwrap().into())
}

fn parse(m: Option<Result<Message, axum::Error>>) -> Inbound {
    match m {
        Some(Ok(Message::Text(t))) => match serde_json::from_str(t.as_str()) {
            Ok(m) => Inbound::Msg(m),
            Err(_) => Inbound::Gone,
        },
        Some(Ok(Message::Ping(_) | Message::Pong(_))) => Inbound::Skip,
        _ => Inbound::Gone,
    }
}

enum Inbound {
    Msg(ToRelay),
    Skip,
    Gone,
}

/// The socket is split so a connection can still be read (for a panic, say)
/// while a write to it is stuck.
struct Conn {
    tx: SplitSink<WebSocket, Message>,
    rx: SplitStream<WebSocket>,
    write_timeout: Duration,
}

impl Conn {
    async fn send(&mut self, m: &FromRelay) -> bool {
        matches!(
            timeout(self.write_timeout, self.tx.send(text(m))).await,
            Ok(Ok(()))
        )
    }

    /// Deliver a terminal message and then close gracefully. Dropping the
    /// socket while the peer is still sending makes the kernel reset the
    /// connection, which can discard the terminal message before it is read.
    /// So: send it, send a close frame, and swallow input until the peer
    /// hangs up or a short deadline passes.
    async fn finish(&mut self, last: &FromRelay) {
        if !self.send(last).await {
            return;
        }
        let _ = timeout(self.write_timeout, self.tx.send(Message::Close(None))).await;
        let _ = timeout(Duration::from_secs(3), async {
            while let Some(Ok(_)) = self.rx.next().await {}
        })
        .await;
    }

    /// Next protocol message, or None if the peer is gone or sent garbage.
    async fn recv(&mut self) -> Option<ToRelay> {
        loop {
            match parse(self.rx.next().await) {
                Inbound::Msg(m) => return Some(m),
                Inbound::Skip => continue,
                Inbound::Gone => return None,
            }
        }
    }
}

/// An authenticated connection's place in a room. Dropping it is what
/// releases the place, so no early return or cancelled future can leak one.
struct Seat {
    relay: Arc<Relay>,
    id: Uuid,
    room: Arc<RoomHandle>,
    session_key: Vec<u8>,
    generation: u64,
    cursor: u64,
}

impl Drop for Seat {
    fn drop(&mut self) {
        let emptied = {
            let mut r = self.room.state.lock().unwrap();
            r.connections = r.connections.saturating_sub(1);
            if r.connections == 0 && !r.closed {
                r.empty_epoch += 1;
                Some(r.empty_epoch)
            } else {
                None
            }
        };
        // Start the empty-room timer. It only fires if the room stayed empty
        // for the whole grace period.
        if let Some(epoch) = emptied {
            let (relay, id, room) = (self.relay.clone(), self.id, self.room.clone());
            tokio::spawn(async move {
                tokio::time::sleep(relay.limits.empty_grace).await;
                relay.close_if(&id, &room, |r| r.connections == 0 && r.empty_epoch == epoch);
            });
        }
    }
}

async fn connection(relay: Arc<Relay>, ws: WebSocket) {
    let (tx, rx) = ws.split();
    let mut conn = Conn {
        tx,
        rx,
        write_timeout: relay.limits.write_timeout,
    };
    match timeout(relay.limits.handshake_timeout, handshake(&relay, &mut conn)).await {
        Ok(Ok((seat, reply))) => {
            if conn.send(&reply).await {
                serve_seat(&relay, &mut conn, seat).await;
            }
        }
        Ok(Err(reply)) => conn.finish(&reply).await,
        Err(_) => {}
    }
}

fn err(msg: &str) -> FromRelay {
    FromRelay::Error { msg: msg.into() }
}

fn session_key(b64_key: &str) -> Result<Vec<u8>, FromRelay> {
    match unb64(b64_key) {
        Ok(k) if k.len() == 32 => Ok(k),
        _ => Err(err("bad session key")),
    }
}

/// A fresh single-use challenge, bound to this connection by construction.
async fn challenge(conn: &mut Conn, room: Uuid) -> Result<[u8; 32], FromRelay> {
    let nonce: [u8; 32] = random();
    let sent = conn
        .send(&FromRelay::Challenge {
            room,
            nonce: b64(&nonce),
        })
        .await;
    if sent { Ok(nonce) } else { Err(err("gone")) }
}

/// Clears a pending room id when the creating handshake ends, either way.
struct Pending<'a>(&'a Relay, Uuid);

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.pending.lock().unwrap().remove(&self.1);
    }
}

/// Authenticate and take a seat. Returns the seat with the reply to send.
async fn handshake(relay: &Arc<Relay>, conn: &mut Conn) -> Result<(Seat, FromRelay), FromRelay> {
    let first = conn.recv().await.ok_or_else(|| err("bad hello"))?;
    match first {
        ToRelay::Create { session_key: key } => {
            let key = session_key(&key)?;
            if relay.room_count() >= relay.limits.max_rooms {
                return Err(err("relay is full"));
            }
            // The relay picks the room id, so an id that is not in the map
            // either never existed or is closed. No tombstones needed.
            let id = Uuid::new_v4();
            relay.pending.lock().unwrap().insert(id);
            let _pending = Pending(relay, id);
            let nonce = challenge(conn, id).await?;
            let Some(ToRelay::CreateFin {
                verifier,
                sig,
                group_info,
            }) = conn.recv().await
            else {
                return Err(err("expected create_fin"));
            };
            let verifier = unb64(&verifier).map_err(|e| err(&e))?;
            if !verify(&verifier, &transcript("create", &id, &nonce, &key, 0), &sig) {
                return Err(err("bad signature"));
            }
            let room = Arc::new(RoomHandle {
                state: Mutex::new(Room {
                    verifier,
                    sessions: HashMap::from([(
                        key.clone(),
                        Session {
                            attached_at: 0,
                            generation: 0,
                        },
                    )]),
                    buffer: VecDeque::new(),
                    buffer_bytes: 0,
                    head: 0,
                    last_commit: 0,
                    group_info: group_info.clone(),
                    connections: 1,
                    next_generation: 0,
                    empty_epoch: 0,
                    closed: false,
                }),
                tick: watch::channel(0).0,
            });
            {
                let mut rooms = relay.rooms.lock().unwrap();
                if rooms.len() >= relay.limits.max_rooms {
                    return Err(err("relay is full"));
                }
                rooms.insert(id, room.clone());
            }
            let seat = Seat {
                relay: relay.clone(),
                id,
                room,
                session_key: key,
                generation: 0,
                cursor: 0,
            };
            let attached = FromRelay::Attached {
                head: 0,
                last_commit: 0,
                group_info,
            };
            Ok((seat, attached))
        }

        ToRelay::Attach { room: id, session_key: key } => {
            let key = session_key(&key)?;
            let room = relay.lookup(&id)?;
            let nonce = challenge(conn, id).await?;
            let Some(ToRelay::Auth { sig }) = conn.recv().await else {
                return Err(err("expected auth"));
            };
            let mut r = room.state.lock().unwrap();
            if r.closed {
                return Err(FromRelay::Closed);
            }
            if !verify(&r.verifier, &transcript("attach", &id, &nonce, &key, 0), &sig) {
                return Err(err("bad signature"));
            }
            if r.sessions.contains_key(&key) {
                return Err(err("session key already in use"));
            }
            if r.sessions.len() >= relay.limits.max_sessions {
                return Err(err("room is full"));
            }
            let head = r.head;
            let generation = r.new_generation();
            r.sessions.insert(
                key.clone(),
                Session {
                    attached_at: head,
                    generation,
                },
            );
            r.connections += 1;
            let attached = FromRelay::Attached {
                head,
                last_commit: r.last_commit,
                group_info: r.group_info.clone(),
            };
            drop(r);
            let seat = Seat {
                relay: relay.clone(),
                id,
                room,
                session_key: key,
                generation,
                cursor: head,
            };
            Ok((seat, attached))
        }

        ToRelay::Resume {
            room: id,
            session_key: key,
            cursor,
        } => {
            let key = session_key(&key)?;
            let room = relay.lookup(&id)?;
            let nonce = challenge(conn, id).await?;
            let Some(ToRelay::Auth { sig }) = conn.recv().await else {
                return Err(err("expected auth"));
            };
            // Proof of the session's private key, covering the cursor.
            if !verify(&key, &transcript("resume", &id, &nonce, &key, cursor), &sig) {
                return Err(err("bad signature"));
            }
            let mut r = room.state.lock().unwrap();
            if r.closed {
                return Err(FromRelay::Closed);
            }
            let head = r.head;
            let Some(s) = r.sessions.get(&key) else {
                return Err(err("unknown session"));
            };
            if cursor < s.attached_at || cursor > head {
                return Err(err("cursor out of range"));
            }
            // Only the suffix this session still needs has to be buffered.
            if !r.covers(cursor) {
                r.sessions.remove(&key);
                drop(r);
                room.wake(); // the connection being replaced must notice
                return Err(FromRelay::Gap);
            }
            let generation = r.new_generation();
            r.sessions.get_mut(&key).unwrap().generation = generation;
            r.connections += 1;
            drop(r);
            let seat = Seat {
                relay: relay.clone(),
                id,
                room: room.clone(),
                session_key: key,
                generation,
                cursor,
            };
            // Wake the connection this one replaces so it notices the fence.
            room.wake();
            Ok((seat, FromRelay::Resumed { head }))
        }

        ToRelay::Close { room: id } => {
            let room = relay.lookup(&id)?;
            let nonce = challenge(conn, id).await?;
            let Some(ToRelay::Auth { sig }) = conn.recv().await else {
                return Err(err("expected auth"));
            };
            let t = transcript("close", &id, &nonce, &[], 0);
            // Shut by this request, or by someone else's just before it.
            if relay.close_if(&id, &room, |r| verify(&r.verifier, &t, &sig)) {
                Err(FromRelay::Closed)
            } else {
                Err(err("bad signature"))
            }
        }

        _ => Err(err("expected create, attach, resume or close")),
    }
}

enum Next {
    Closed,
    Fenced,
    Gap,
    Idle,
    Write(FromRelay, Option<u64>),
}

async fn serve_seat(relay: &Arc<Relay>, conn: &mut Conn, mut seat: Seat) {
    let mut tick = seat.room.tick.subscribe();
    let mut replies: VecDeque<FromRelay> = VecDeque::new();
    loop {
        // Decide the next step under the lock. Closure is room state, not a
        // queued frame, so it cannot be lost behind a backlog, and it is
        // looked at again before every single write.
        let next = {
            let mut r = seat.room.state.lock().unwrap();
            if r.closed {
                Next::Closed
            } else if !r.is_current(&seat) {
                Next::Fenced
            } else if let Some(reply) = replies.pop_front() {
                Next::Write(reply, None)
            } else if seat.cursor == r.head {
                Next::Idle
            } else if r.covers(seat.cursor) {
                let first = r.buffer.front().unwrap().seq;
                let f = &r.buffer[(seat.cursor + 1 - first) as usize];
                let frame = FromRelay::Frame {
                    seq: f.seq,
                    kind: f.kind,
                    id: f.id.clone(),
                    data: f.data.clone(),
                };
                Next::Write(frame, Some(f.seq))
            } else {
                // Checked and removed under one lock, so this cannot undo a
                // resume that replaced this connection in between.
                r.sessions.remove(&seat.session_key);
                Next::Gap
            }
        };
        match next {
            Next::Closed => return conn.finish(&FromRelay::Closed).await,
            Next::Fenced => return,
            Next::Gap => return conn.finish(&FromRelay::Gap).await,
            Next::Idle => {
                tokio::select! {
                    changed = tick.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    m = conn.rx.next() => match parse(m) {
                        Inbound::Msg(m) => replies.extend(handle(relay, &seat, m)),
                        Inbound::Skip => {}
                        Inbound::Gone => return,
                    },
                }
            }
            Next::Write(msg, seq) => {
                // One message in flight at a time. While it is being written
                // the connection is still read, and a closed room abandons a
                // write that does not finish promptly.
                let write = timeout(conn.write_timeout, conn.tx.send(text(&msg)));
                tokio::pin!(write);
                let mut abandon_at: Option<Instant> = None;
                let written = loop {
                    tokio::select! {
                        r = &mut write => break matches!(r, Ok(Ok(()))),
                        _ = sleep_until(abandon_at.unwrap_or_else(Instant::now)),
                            if abandon_at.is_some() => break false,
                        changed = tick.changed(), if abandon_at.is_none() => {
                            if changed.is_err() || seat.room.state.lock().unwrap().closed {
                                abandon_at = Some(Instant::now() + Duration::from_secs(2));
                            }
                        }
                        m = conn.rx.next() => match parse(m) {
                            Inbound::Msg(m) => {
                                replies.extend(handle(relay, &seat, m));
                                if replies.len() > MAX_QUEUED_REPLIES {
                                    break false;
                                }
                            }
                            Inbound::Skip => {}
                            Inbound::Gone => break false,
                        },
                    }
                };
                if !written {
                    return;
                }
                if let Some(seq) = seq {
                    seat.cursor = seq;
                }
            }
        }
    }
}

/// Apply one request under the room lock. Returns a direct reply, if any.
fn handle(relay: &Arc<Relay>, seat: &Seat, msg: ToRelay) -> Option<FromRelay> {
    if matches!(msg, ToRelay::Panic) {
        // A replaced connection has no authority, so the check and the close
        // happen together.
        relay.close_if(&seat.id, &seat.room, |r| r.is_current(seat));
        return None; // the serve loop sees `closed` on its next pass
    }
    let mut r = seat.room.state.lock().unwrap();
    // Closed rooms and fenced connections accept nothing; the serve loop
    // reports why on its next pass.
    if !r.is_current(seat) {
        return None;
    }
    match msg {
        ToRelay::Submit {
            id,
            kind,
            after_commit,
            data,
            group_info,
        } => {
            if id.len() > MAX_ID {
                return Some(err("id too long"));
            }
            if after_commit != r.last_commit {
                return Some(FromRelay::Stale { id });
            }
            if kind == Kind::Commit && group_info.is_none() {
                return Some(err("commit without group info"));
            }
            r.head += 1;
            let seq = r.head;
            if kind == Kind::Commit {
                r.last_commit = seq;
                r.group_info = group_info.unwrap();
            }
            let frame = Frame {
                seq,
                kind,
                id,
                data,
            };
            r.buffer_bytes += frame.size();
            r.buffer.push_back(frame);
            while r.buffer.len() > relay.limits.buffer_frames
                || r.buffer_bytes > relay.limits.buffer_bytes
            {
                let Some(old) = r.buffer.pop_front() else { break };
                r.buffer_bytes -= old.size();
            }
            drop(r);
            seat.room.wake();
            None
        }
        ToRelay::GroupInfo { after_commit, data } => {
            if after_commit == r.last_commit {
                r.group_info = data;
            }
            None
        }
        ToRelay::Snapshot => Some(FromRelay::Snapshot {
            last_commit: r.last_commit,
            group_info: r.group_info.clone(),
        }),
        _ => Some(err("unexpected message")),
    }
}
