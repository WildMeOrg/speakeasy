//! `speakeasy ui`: a page on this machine for a person to take part in a room.
//!
//! The page is built into the binary and served on 127.0.0.1 only. It talks
//! to this process, which talks to the session's daemon over the same private
//! socket the other commands use. Nothing new reaches the relay.
//!
//! What keeps other things on the machine and in the browser out:
//! - every `/api` call must carry a token that is only in the printed link,
//!   after the `#`, where browsers keep it to themselves;
//! - a request must be addressed to 127.0.0.1 or localhost by name, so a
//!   website cannot reach the page by pointing its own name at this machine;
//! - no cross-origin access is granted, and the token travels in a header a
//!   website cannot set without that grant.
//!
//! The conversation is held in this process's memory so the page can be
//! reloaded, and is gone when the process stops.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, Request as HttpRequest, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use speakeasy::crypto::{hex, random};
use speakeasy::daemon::Request;
use subtle::ConstantTimeEq;
use tokio::sync::watch;

use crate::{CLOSED, NO_SESSION, SEND_WAIT, call, invite_text, recv_batch};

/// How long a request for events is held open when there are none.
const HOLD: Duration = Duration::from_secs(25);
/// What is kept for a page that reloads: this many events and this much
/// message text, whichever is reached first. Older ones are forgotten, so a
/// talkative member cannot grow this process without limit.
const KEEP: usize = 5000;
const KEEP_BYTES: usize = 8 << 20;
/// Most events in one answer to the page.
const BATCH: usize = 500;
/// Longest message the page may submit, in bytes.
const MAX_TEXT: usize = 64 * 1024;
const OLD_DAEMON: &str = "this session was started by an older speakeasy; \
                          read it with `speakeasy recv`, or start a new session";

struct Page {
    handle: String,
    token: String,
    html: String,
    csp: HeaderValue,
    /// The names this server answers to.
    hosts: Vec<String>,
    me: Value,
    /// Everything the page shows. Watched, so held requests wake on change.
    log: watch::Sender<Log>,
}

#[derive(Default)]
struct Log {
    /// The number of the oldest event still held.
    first: u64,
    /// Each with its size, as counted against `KEEP_BYTES`.
    events: VecDeque<(usize, Value)>,
    bytes: usize,
    /// Who is in the room, as the daemon last reported it.
    members: Value,
    /// The daemon's number for the newest event taken from it.
    taken: u64,
}

impl Log {
    fn next(&self) -> u64 {
        self.first + self.events.len() as u64
    }

    fn push(&mut self, event: Value) {
        // The whole event, since a member chooses its name as well as its text.
        let size = event.to_string().len();
        self.bytes += size;
        self.events.push_back((size, event));
        while self.events.len() > KEEP || self.bytes > KEEP_BYTES {
            let Some((size, _)) = self.events.pop_front() else { break };
            self.bytes -= size;
            self.first += 1;
        }
    }

    /// Take one batch from the daemon. Its events are numbered, ending at
    /// `last`, so a batch handed over twice (because the acknowledgement
    /// went missing) adds nothing the second time.
    fn take(&mut self, reply: &Value) -> Result<(), String> {
        let events = reply["events"].as_array().map(Vec::as_slice).unwrap_or_default();
        // The notice of dropped events is not one of the numbered ones.
        let numbered = events.iter().any(|e| e["type"] != "overflow");
        let last = match reply["last"].as_u64() {
            Some(last) => last,
            // A daemon from before batches were numbered. Refused before
            // the acknowledgement, so its events are not thrown away.
            None if numbered => return Err(OLD_DAEMON.into()),
            None => self.taken,
        };
        self.members = reply["members"].clone();
        for (i, e) in events.iter().enumerate() {
            let number = last.saturating_sub((events.len() - 1 - i) as u64);
            if number > self.taken || e["type"] == "overflow" {
                self.push(e.clone());
            }
        }
        self.taken = last;
        Ok(())
    }
}

impl Page {
    fn push(&self, event: Value) {
        self.log.send_modify(|log| log.push(event));
    }

    /// One request to the session's daemon, off the async threads. Once
    /// started it runs to the end, whether or not anyone waits for the answer.
    async fn daemon(self: Arc<Self>, req: Request, wait: Duration) -> Value {
        let work = tokio::task::spawn_blocking(move || {
            let reply = call(&self.handle, &req, wait).unwrap_or_else(|e| json!({"error": e}));
            // The daemon does not echo a member's own messages, so the page's
            // copy is recorded here, once the relay has placed it in the
            // order, even if the browser has given up on the request.
            if let (Request::Send { text }, true) = (req, reply["ok"] == true) {
                self.push(json!({"type": "sent", "seq": reply["seq"], "text": text}));
            }
            reply
        });
        work.await.unwrap_or_else(|e| json!({"error": e.to_string()}))
    }
}

/// Move the session's events into the page's log until the room is over.
fn follow(page: &Page) {
    let reason = loop {
        let batch = recv_batch(&page.handle, HOLD.as_secs_f64(), |reply| {
            let mut taken = Ok(());
            page.log.send_modify(|log| taken = log.take(reply));
            taken
        });
        match batch {
            Err(e) => break e,
            Ok(reply) => {
                if let Some(reason) = reply["closed"].as_str() {
                    break reason.to_string();
                }
            }
        }
    };
    page.push(json!({"type": "closed", "reason": reason}));
}

pub fn run(handle: String, port: u16) -> Result<u8, String> {
    let status = call(&handle, &Request::Status, Duration::from_secs(5))?;
    if !status["closed"].is_null() {
        println!("{}", json!({"type": "closed", "reason": status["closed"]}));
        return Ok(CLOSED);
    }
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| format!("127.0.0.1:{port}: {e}"))?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let nonce = hex(&random::<16>());
        let csp = format!(
            "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; \
             connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        );
        let mut hosts = vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")];
        if port == 80 {
            // Browsers leave the default port out.
            hosts.extend(["127.0.0.1".to_string(), "localhost".to_string()]);
        }
        let page = Arc::new(Page {
            handle,
            token: hex(&random::<32>()),
            html: include_str!("ui.html").replace("__NONCE__", &nonce),
            csp: HeaderValue::from_str(&csp).unwrap(),
            hosts,
            me: json!({"name": status["name"], "key": status["key"], "room": status["room"]}),
            log: watch::channel(Log {
                members: status["members"].clone(),
                ..Log::default()
            })
            .0,
        });
        println!("Speakeasy page for room {}:\n", status["room"].as_str().unwrap_or("?"));
        println!("  http://127.0.0.1:{port}/#{}\n", page.token);
        println!("Open it in a browser on this machine. The link is a secret while this");
        println!("command runs, so do not run it where others can see the output.");
        println!("Ctrl-C stops the page; it does not leave the room.");

        let follower = page.clone();
        std::thread::spawn(move || follow(&follower));
        axum::serve(listener, router(page))
            .await
            .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

fn router(page: Arc<Page>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/events", get(events))
        .route("/api/send", post(send))
        .route("/api/invite", get(invite))
        .route("/api/panic", post(panic))
        .route("/api/leave", post(leave))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_TEXT))
        .layer(middleware::from_fn_with_state(page.clone(), guard))
        .with_state(page)
}

/// Refuse anything not addressed to this machine by name, and any `/api`
/// call without the token. Runs before every handler.
async fn guard(State(page): State<Arc<Page>>, req: HttpRequest, next: Next) -> Response {
    let (host_ok, token_ok) = {
        let header = |name: header::HeaderName| req.headers().get(name).and_then(|v| v.to_str().ok());
        (
            header(header::HOST).is_some_and(|h| page.hosts.iter().any(|ours| ours == h)),
            header(header::AUTHORIZATION)
                .and_then(|a| a.strip_prefix("Bearer "))
                .is_some_and(|t| t.as_bytes().ct_eq(page.token.as_bytes()).into()),
        )
    };
    if !host_ok {
        return StatusCode::FORBIDDEN.into_response();
    }
    if req.uri().path().starts_with("/api/") && !token_ok {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::CONTENT_SECURITY_POLICY, page.csp.clone());
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    res
}

async fn index(State(page): State<Arc<Page>>) -> Html<String> {
    Html(page.html.clone())
}

#[derive(Deserialize)]
struct After {
    /// Absent on a page's first request, which is answered at once so the
    /// page learns who it is and who is in the room.
    after: Option<u64>,
}

/// Events numbered `after` and up. Held open for a while if there are none.
async fn events(State(page): State<Arc<Page>>, Query(q): Query<After>) -> Json<Value> {
    let mut log = page.log.subscribe();
    if let Some(after) = q.after {
        let _ = tokio::time::timeout(HOLD, log.wait_for(|log| log.next() > after)).await;
    }
    let log = log.borrow();
    // `first` tells a page that fell behind how much it can no longer get.
    let from = q.after.unwrap_or(0).clamp(log.first, log.next());
    let events: Vec<&Value> = log
        .events
        .iter()
        .skip((from - log.first) as usize)
        .take(BATCH)
        .map(|(_, e)| e)
        .collect();
    Json(json!({
        "me": page.me,
        "members": log.members,
        "first": from,
        "next": from + events.len() as u64,
        "events": events,
    }))
}

async fn send(State(page): State<Arc<Page>>, text: String) -> Json<Value> {
    Json(page.daemon(Request::Send { text }, SEND_WAIT).await)
}

async fn invite(State(page): State<Arc<Page>>) -> Json<Value> {
    let handle = page.handle.clone();
    let text = tokio::task::spawn_blocking(move || invite_text(&handle)).await;
    Json(match text {
        Ok(Ok(Ok(text))) => json!({"text": text}),
        Ok(Ok(Err(_))) => json!({"error": "closed"}),
        Ok(Err(e)) if e == NO_SESSION => json!({"error": "closed"}),
        Ok(Err(e)) => json!({"error": e}),
        Err(e) => json!({"error": e.to_string()}),
    })
}

async fn panic(State(page): State<Arc<Page>>) -> Json<Value> {
    Json(page.daemon(Request::Panic, Duration::from_secs(15)).await)
}

async fn leave(State(page): State<Arc<Page>>) -> Json<Value> {
    Json(page.daemon(Request::Leave, Duration::from_secs(15)).await)
}
