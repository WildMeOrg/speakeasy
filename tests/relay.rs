//! Relay behaviour at the wire level. The relay treats payloads as opaque, so
//! these tests use placeholder blobs and no MLS.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use speakeasy::crypto::{RoomKeys, b64, random, sign, transcript, unb64};
use speakeasy::proto::{FromRelay, Kind, ToRelay};
use speakeasy::relay::{self, Limits, Relay};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn start(limits: Limits) -> (Arc<Relay>, String) {
    let relay = Relay::new(limits);
    let addr = relay::spawn(relay.clone(), "127.0.0.1:0").await.unwrap();
    (relay, format!("ws://{addr}/ws"))
}

struct Client {
    ws: Ws,
    session: SigningKey,
}

impl Client {
    async fn open(url: &str) -> Ws {
        tokio_tungstenite::connect_async(url).await.unwrap().0
    }

    async fn send(&mut self, m: ToRelay) {
        let _ = self
            .ws
            .send(Message::Text(serde_json::to_string(&m).unwrap().into()))
            .await;
    }

    /// Next protocol message, or None when the connection has ended.
    async fn recv(&mut self) -> Option<FromRelay> {
        loop {
            match timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("relay went quiet")
            {
                Some(Ok(Message::Text(t))) => return Some(serde_json::from_str(t.as_str()).unwrap()),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                _ => return None,
            }
        }
    }

    async fn submit(&mut self, id: &str, kind: Kind, after_commit: u64) {
        self.send(ToRelay::Submit {
            id: id.into(),
            kind,
            after_commit,
            data: b64(id.as_bytes()),
            group_info: (kind == Kind::Commit).then(|| format!("gi-after-{id}")),
        })
        .await;
    }

    async fn frame(&mut self) -> (u64, String) {
        match self.recv().await {
            Some(FromRelay::Frame { seq, id, .. }) => (seq, id),
            other => panic!("expected a frame, got {other:?}"),
        }
    }
}

async fn create(url: &str) -> (Client, RoomKeys) {
    let session = SigningKey::from_bytes(&random());
    let spub = session.verifying_key().to_bytes();
    let mut c = Client {
        ws: Client::open(url).await,
        session,
    };
    c.send(ToRelay::Create {
        session_key: b64(&spub),
    })
    .await;
    let Some(FromRelay::Challenge { room, nonce }) = c.recv().await else {
        panic!("no challenge")
    };
    let keys = RoomKeys::derive(&room, &random());
    let t = transcript("create", &room, &unb64(&nonce).unwrap(), &spub, 0);
    c.send(ToRelay::CreateFin {
        verifier: b64(&keys.verifier()),
        sig: sign(&keys.invite_key, &t),
        group_info: "gi-0".into(),
    })
    .await;
    assert!(matches!(c.recv().await, Some(FromRelay::Attached { head: 0, .. })));
    (c, keys)
}

/// Attach using `signer` as the invitation key. Returns the relay's answer.
async fn attach_with(url: &str, room: Uuid, signer: &SigningKey) -> (Client, FromRelay) {
    let session = SigningKey::from_bytes(&random());
    let spub = session.verifying_key().to_bytes();
    let mut c = Client {
        ws: Client::open(url).await,
        session,
    };
    c.send(ToRelay::Attach {
        room,
        session_key: b64(&spub),
    })
    .await;
    let nonce = match c.recv().await {
        Some(FromRelay::Challenge { nonce, .. }) => nonce,
        Some(other) => return (c, other),
        None => panic!("connection ended"),
    };
    let t = transcript("attach", &room, &unb64(&nonce).unwrap(), &spub, 0);
    c.send(ToRelay::Auth { sig: sign(signer, &t) }).await;
    let answer = c.recv().await.expect("no answer to auth");
    (c, answer)
}

async fn attach(url: &str, keys: &RoomKeys) -> (Client, u64) {
    let (c, answer) = attach_with(url, keys.room, &keys.invite_key).await;
    match answer {
        FromRelay::Attached { head, .. } => (c, head),
        other => panic!("attach refused: {other:?}"),
    }
}

async fn resume(url: &str, room: Uuid, session: &SigningKey, cursor: u64) -> (Client, FromRelay) {
    let spub = session.verifying_key().to_bytes();
    let mut c = Client {
        ws: Client::open(url).await,
        session: session.clone(),
    };
    c.send(ToRelay::Resume {
        room,
        session_key: b64(&spub),
        cursor,
    })
    .await;
    let nonce = match c.recv().await {
        Some(FromRelay::Challenge { nonce, .. }) => nonce,
        Some(other) => return (c, other),
        None => panic!("connection ended"),
    };
    let t = transcript("resume", &room, &unb64(&nonce).unwrap(), &spub, cursor);
    c.send(ToRelay::Auth { sig: sign(session, &t) }).await;
    let answer = c.recv().await.expect("no answer to auth");
    (c, answer)
}

#[tokio::test]
async fn attach_requires_the_invitation_key() {
    let (_relay, url) = start(Limits::default()).await;
    let (_creator, keys) = create(&url).await;

    let stranger = SigningKey::from_bytes(&random());
    let (_, answer) = attach_with(&url, keys.room, &stranger).await;
    assert!(matches!(answer, FromRelay::Error { .. }), "got {answer:?}");

    // A room id the relay never issued is indistinguishable from a closed room.
    let (_, answer) = attach_with(&url, Uuid::new_v4(), &keys.invite_key).await;
    assert!(matches!(answer, FromRelay::Closed), "got {answer:?}");
}

#[tokio::test]
async fn submissions_must_name_exactly_the_latest_commit() {
    let (_relay, url) = start(Limits::default()).await;
    let (mut a, keys) = create(&url).await;
    let (mut b, _) = attach(&url, &keys).await;

    a.submit("app1", Kind::App, 0).await;
    assert_eq!(a.frame().await, (1, "app1".into()));
    assert_eq!(b.frame().await, (1, "app1".into()));

    // Two commits race from the same parent: one wins, one is stale. The
    // loser may hear `stale` before or after it sees the winning frame.
    a.submit("commitA", Kind::Commit, 0).await;
    b.submit("commitB", Kind::Commit, 0).await;
    let mut winner = String::new();
    let mut stale = Vec::new();
    for c in [&mut a, &mut b] {
        // Read until this client has seen the winning commit frame.
        loop {
            match c.recv().await {
                Some(FromRelay::Frame { seq: 2, id, .. }) => break winner = id,
                Some(FromRelay::Stale { id }) => stale.push(id),
                other => panic!("got {other:?}"),
            }
        }
    }
    let loser = if winner == "commitA" { "commitB" } else { "commitA" };
    // The loser's `stale` may still be in flight on its own connection.
    if stale.is_empty() {
        let c = if loser == "commitA" { &mut a } else { &mut b };
        match c.recv().await {
            Some(FromRelay::Stale { id }) => stale.push(id),
            other => panic!("got {other:?}"),
        }
    }
    assert_eq!(stale, [loser]);

    // An app message encrypted before that commit is refused...
    a.submit("old-epoch", Kind::App, 0).await;
    assert!(matches!(a.recv().await, Some(FromRelay::Stale { id }) if id == "old-epoch"));
    // ...as is one naming a commit that does not exist yet...
    a.submit("future", Kind::App, 99).await;
    assert!(matches!(a.recv().await, Some(FromRelay::Stale { id }) if id == "future"));
    // ...or the seq of an app frame.
    a.submit("app-seq", Kind::App, 1).await;
    assert!(matches!(a.recv().await, Some(FromRelay::Stale { id }) if id == "app-seq"));
    // Naming the commit itself works.
    a.submit("current", Kind::App, 2).await;
    assert_eq!(a.frame().await, (3, "current".into()));

    // The snapshot is the winner's group info with its commit reference.
    a.send(ToRelay::Snapshot).await;
    match a.recv().await {
        Some(FromRelay::Snapshot {
            last_commit,
            group_info,
        }) => {
            assert_eq!(last_commit, 2);
            assert_eq!(group_info, format!("gi-after-{winner}"));
        }
        other => panic!("got {other:?}"),
    }
}

#[tokio::test]
async fn fresh_attach_sees_only_later_frames_and_resume_replays() {
    let (_relay, url) = start(Limits::default()).await;
    let (mut a, keys) = create(&url).await;
    a.submit("one", Kind::App, 0).await;
    a.frame().await;

    let (mut b, head) = attach(&url, &keys).await;
    assert_eq!(head, 1);
    a.submit("two", Kind::App, 0).await;
    assert_eq!(b.frame().await, (2, "two".into()));

    // B drops; two frames are sequenced while it is away.
    let b_session = b.session.clone();
    drop(b);
    a.submit("three", Kind::App, 0).await;
    a.submit("four", Kind::App, 0).await;

    // B may not rewind to before it attached.
    let (_, answer) = resume(&url, keys.room, &b_session, 0).await;
    assert!(matches!(answer, FromRelay::Error { .. }), "got {answer:?}");
    // A session key that never attached cannot resume.
    let (_, answer) = resume(&url, keys.room, &SigningKey::from_bytes(&random()), 2).await;
    assert!(matches!(answer, FromRelay::Error { .. }), "got {answer:?}");

    let (mut b, answer) = resume(&url, keys.room, &b_session, 2).await;
    assert!(matches!(answer, FromRelay::Resumed { head: 4 }), "got {answer:?}");
    assert_eq!(b.frame().await, (3, "three".into()));
    assert_eq!(b.frame().await, (4, "four".into()));
}

#[tokio::test]
async fn resume_reports_a_gap_when_needed_frames_were_evicted() {
    let (_relay, url) = start(Limits {
        buffer_frames: 2,
        ..Limits::default()
    })
    .await;
    let (mut a, keys) = create(&url).await;
    let (b, head) = attach(&url, &keys).await;
    let b_session = b.session.clone();
    drop(b);
    for i in 0..5 {
        a.submit(&format!("m{i}"), Kind::App, 0).await;
        a.frame().await;
    }
    let (_, answer) = resume(&url, keys.room, &b_session, head).await;
    assert!(matches!(answer, FromRelay::Gap), "got {answer:?}");
    // The session is gone after a gap; only a fresh attach gets back in.
    let (_, answer) = resume(&url, keys.room, &b_session, 5).await;
    assert!(matches!(answer, FromRelay::Error { .. }), "got {answer:?}");
}

#[tokio::test]
async fn resume_fences_the_connection_it_replaces() {
    let (relay, url) = start(Limits::default()).await;
    let (mut a, keys) = create(&url).await;
    let (mut old, head) = attach(&url, &keys).await;
    let (mut new, answer) = resume(&url, keys.room, &old.session.clone(), head).await;
    assert!(matches!(answer, FromRelay::Resumed { .. }));

    // The replaced connection is cut off: it can neither submit nor panic.
    old.submit("from-old", Kind::App, 0).await;
    old.send(ToRelay::Panic).await;
    assert!(old.recv().await.is_none());
    new.submit("from-new", Kind::App, 0).await;
    assert_eq!(a.frame().await, (1, "from-new".into()));
    assert_eq!(relay.room_count(), 1);
}

#[tokio::test]
async fn panic_closes_the_room_for_everyone_and_nothing_is_sequenced_after() {
    let (relay, url) = start(Limits::default()).await;
    let (mut creator, keys) = create(&url).await;
    let keys = Arc::new(keys);

    // Senders flood the room while joiners keep attaching.
    let mut senders = Vec::new();
    for n in 0..4 {
        let (mut c, head) = attach(&url, &keys).await;
        senders.push(tokio::spawn(async move {
            let mut last_seq = head;
            let mut i = 0u64;
            loop {
                let mine = format!("s{n}-{i}");
                c.submit(&mine, Kind::App, 0).await;
                i += 1;
                // Read everything up to our own echo, so we never fall behind.
                loop {
                    match c.recv().await {
                        Some(FromRelay::Frame { seq, id, .. }) => {
                            assert_eq!(seq, last_seq + 1, "frames must be contiguous");
                            last_seq = seq;
                            if id == mine {
                                break;
                            }
                        }
                        Some(FromRelay::Closed) => {
                            // Closure is terminal: the connection just ends.
                            while let Some(m) = c.recv().await {
                                assert!(matches!(m, FromRelay::Closed), "after close: {m:?}");
                            }
                            return (c.session.clone(), last_seq);
                        }
                        other => panic!("sender got {other:?}"),
                    }
                }
            }
        }));
    }
    let (join_url, join_keys) = (url.clone(), keys.clone());
    let joiner = tokio::spawn(async move {
        loop {
            let (_, answer) =
                attach_with(&join_url, join_keys.room, &join_keys.invite_key).await;
            match answer {
                FromRelay::Attached { .. } => continue,
                other => return other,
            }
        }
    });
    // One participant stops reading entirely; it must not delay closure.
    let (mut stalled, _) = attach(&url, &keys).await;

    tokio::time::sleep(Duration::from_millis(150)).await;
    let (mut panicker, _) = attach(&url, &keys).await;
    panicker.send(ToRelay::Panic).await;

    // Every sender is told, promptly, and none saw a frame after closure.
    let mut sessions = Vec::new();
    for s in senders {
        let (session, last_seq) = timeout(Duration::from_secs(5), s).await.unwrap().unwrap();
        assert!(last_seq > 0);
        sessions.push((session, last_seq));
    }
    // The mid-join participant is refused.
    let refused = timeout(Duration::from_secs(5), joiner).await.unwrap().unwrap();
    assert!(matches!(refused, FromRelay::Closed), "got {refused:?}");
    assert_eq!(relay.room_count(), 0);

    // The creator's backlog ends in closure too.
    loop {
        match creator.recv().await {
            Some(FromRelay::Frame { .. }) => continue,
            Some(FromRelay::Closed) => break,
            other => panic!("creator got {other:?}"),
        }
    }
    // Neither the invitation nor a resume credential works any more.
    let (_, answer) = attach_with(&url, keys.room, &keys.invite_key).await;
    assert!(matches!(answer, FromRelay::Closed), "got {answer:?}");
    for (session, last_seq) in &sessions {
        let (_, answer) = resume(&url, keys.room, session, *last_seq).await;
        assert!(matches!(answer, FromRelay::Closed), "got {answer:?}");
    }
    // The panicker has now seen the relay confirm closure. A participant
    // that submits after that point, on a connection that was open all
    // along, must never see its submission sequenced.
    loop {
        match panicker.recv().await {
            Some(FromRelay::Frame { .. }) => continue,
            Some(FromRelay::Closed) => break,
            other => panic!("panicker got {other:?}"),
        }
    }
    stalled.submit("after-close", Kind::App, 0).await;
    loop {
        match stalled.recv().await {
            Some(FromRelay::Frame { id, .. }) => assert_ne!(id, "after-close"),
            Some(FromRelay::Closed) | None => break,
            other => panic!("stalled got {other:?}"),
        }
    }
}

#[tokio::test]
async fn empty_rooms_expire() {
    let (relay, url) = start(Limits {
        empty_grace: Duration::from_millis(100),
        ..Limits::default()
    })
    .await;
    let (creator, keys) = create(&url).await;
    assert_eq!(relay.room_count(), 1);
    drop(creator);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(relay.room_count(), 0);
    let (_, answer) = attach_with(&url, keys.room, &keys.invite_key).await;
    assert!(matches!(answer, FromRelay::Closed));
}

#[tokio::test]
async fn a_connection_stuck_on_a_write_can_still_panic() {
    let (relay, url) = start(Limits {
        buffer_bytes: 256 << 20,
        ..Limits::default()
    })
    .await;
    let (mut a, keys) = create(&url).await;
    let (mut stuck, _) = attach(&url, &keys).await;

    // Far more than socket buffers hold, to a participant that is not reading.
    let big = b64(&vec![0u8; 300_000]);
    for i in 0..80 {
        a.send(ToRelay::Submit {
            id: format!("big{i}"),
            kind: Kind::App,
            after_commit: 0,
            data: big.clone(),
            group_info: None,
        })
        .await;
        a.frame().await;
    }
    // Its write is blocked, yet its panic is read and closes the room at once.
    stuck.send(ToRelay::Panic).await;
    let closed = timeout(Duration::from_secs(2), async {
        loop {
            if matches!(a.recv().await, Some(FromRelay::Closed)) {
                break;
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "panic was stuck behind a blocked write");
    assert_eq!(relay.room_count(), 0);
}

#[tokio::test]
async fn a_room_reoccupied_during_the_grace_period_is_not_expired_by_the_old_timer() {
    let (relay, url) = start(Limits {
        empty_grace: Duration::from_millis(400),
        ..Limits::default()
    })
    .await;
    let (creator, keys) = create(&url).await;
    let session = creator.session.clone();
    drop(creator); // empty: first timer starts
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (back, answer) = resume(&url, keys.room, &session, 0).await;
    assert!(matches!(answer, FromRelay::Resumed { .. }), "got {answer:?}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(back); // empty again: a second, later timer
    // The first timer fires here and must not close the room early.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(relay.room_count(), 1);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(relay.room_count(), 0);
}

#[tokio::test]
async fn rooms_and_sessions_are_capped() {
    let (_relay, url) = start(Limits {
        max_rooms: 1,
        max_sessions: 2,
        ..Limits::default()
    })
    .await;
    let (_a, keys) = create(&url).await;
    let (_b, _) = attach(&url, &keys).await;
    let (_, answer) = attach_with(&url, keys.room, &keys.invite_key).await;
    assert!(matches!(answer, FromRelay::Error { .. }), "got {answer:?}");

    // A second room is refused before any state is kept for it.
    let mut c = Client {
        ws: Client::open(&url).await,
        session: SigningKey::from_bytes(&random()),
    };
    c.send(ToRelay::Create {
        session_key: b64(&c.session.verifying_key().to_bytes()),
    })
    .await;
    assert!(matches!(c.recv().await, Some(FromRelay::Error { .. })));
}

#[tokio::test]
async fn connections_beyond_the_cap_are_refused_before_the_upgrade() {
    let (_relay, url) = start(Limits {
        max_connections: 2,
        ..Limits::default()
    })
    .await;
    let (a, keys) = create(&url).await;
    let (_b, _) = attach(&url, &keys).await;
    assert!(tokio_tungstenite::connect_async(&url).await.is_err());
    // A freed slot can be used again.
    drop(a);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (_c, _) = attach(&url, &keys).await;
}
