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
use std::sync::{Arc, Mutex};
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
use speakeasy::daemon::{Request, SEND_DEADLINE};
use tokio::sync::watch;

use crate::{CLOSED, NO_SESSION, call, connect, exchange, invite_text};

/// How long a request for events is held open when there are none.
const HOLD: Duration = Duration::from_secs(25);
/// Events kept for a page that reloads. Older ones are forgotten.
const KEEP: usize = 5000;
/// Longest message the page may submit, in bytes.
const MAX_TEXT: usize = 64 * 1024;

struct Page {
    handle: String,
    token: String,
    html: String,
    csp: HeaderValue,
    /// The two names this server answers to.
    hosts: [String; 2],
    me: Value,
    /// Who is in the room, from the daemon, which knows even when this
    /// process started after they joined.
    members: Mutex<Value>,
    log: Mutex<Log>,
    /// The number of the next event; wakes held requests.
    count: watch::Sender<u64>,
}

#[derive(Default)]
struct Log {
    /// The number of the oldest event still held.
    first: u64,
    events: VecDeque<Value>,
}

impl Page {
    fn push(&self, event: Value) {
        let mut log = self.log.lock().unwrap();
        log.events.push_back(event);
        if log.events.len() > KEEP {
            log.events.pop_front();
            log.first += 1;
        }
        self.count.send_replace(log.first + log.events.len() as u64);
    }

    /// One request to the session's daemon, off the async threads.
    async fn daemon(self: &Arc<Self>, req: Request, wait: Duration) -> Value {
        let handle = self.handle.clone();
        tokio::task::spawn_blocking(move || call(&handle, &req, wait))
            .await
            .unwrap_or_else(|e| Err(e.to_string()))
            .unwrap_or_else(|e| json!({"error": e}))
    }
}

/// Move the session's events into the page's log until the room is over.
/// This is the same read-then-acknowledge exchange `speakeasy recv` makes.
fn follow(page: &Page) {
    let reason = loop {
        let stream = match connect(&page.handle, HOLD + Duration::from_secs(20)) {
            Ok(s) => s,
            Err(e) => break e,
        };
        let wait = HOLD.as_secs_f64();
        let reply = match exchange(&stream, &Request::Recv { wait }) {
            Ok(r) => r,
            Err(e) => break e,
        };
        let events = reply["events"].as_array().map(Vec::as_slice).unwrap_or_default();
        // Before the events, so a page woken by them is told the new list.
        if !events.is_empty()
            && let Ok(status) = call(&page.handle, &Request::Status, Duration::from_secs(5))
        {
            *page.members.lock().unwrap() = status["members"].clone();
        }
        for e in events {
            page.push(e.clone());
        }
        use std::io::Write;
        let _ = (&stream).write_all(b"ack\n");
        if let Some(reason) = reply["closed"].as_str() {
            break reason.to_string();
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
        let page = Arc::new(Page {
            handle,
            token: hex(&random::<32>()),
            html: include_str!("ui.html").replace("__NONCE__", &nonce),
            csp: HeaderValue::from_str(&csp).unwrap(),
            hosts: [format!("127.0.0.1:{port}"), format!("localhost:{port}")],
            me: json!({"name": status["name"], "key": status["key"], "room": status["room"]}),
            members: Mutex::new(status["members"].clone()),
            log: Mutex::default(),
            count: watch::channel(0).0,
        });
        println!("Speakeasy page for room {}:\n", status["room"].as_str().unwrap_or("?"));
        println!("  http://127.0.0.1:{port}/#{}\n", page.token);
        println!("Open it in a browser on this machine. The link is a secret while this");
        println!("command runs. Ctrl-C stops the page; it does not leave the room.");

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

/// Compare without stopping at the first difference.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y)) == 0
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
                .is_some_and(|t| same(t.as_bytes(), page.token.as_bytes())),
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
    #[serde(default)]
    after: u64,
}

/// Events numbered `after` and up. Held open for a while if there are none.
async fn events(State(page): State<Arc<Page>>, Query(q): Query<After>) -> Json<Value> {
    let mut count = page.count.subscribe();
    let _ = tokio::time::timeout(HOLD, count.wait_for(|n| *n > q.after)).await;
    let log = page.log.lock().unwrap();
    let skip = q.after.saturating_sub(log.first) as usize;
    let events: Vec<&Value> = log.events.iter().skip(skip).collect();
    Json(json!({
        "me": page.me,
        "members": *page.members.lock().unwrap(),
        "events": events,
        "next": log.first + log.events.len() as u64,
    }))
}

async fn send(State(page): State<Arc<Page>>, text: String) -> Json<Value> {
    let wait = SEND_DEADLINE + Duration::from_secs(15);
    let reply = page.daemon(Request::Send { text: text.clone() }, wait).await;
    // The daemon does not echo a member's own messages, so the page's copy
    // is recorded here, once the relay has given it a place in the order.
    if reply["ok"] == true {
        page.push(json!({"type": "sent", "seq": reply["seq"], "text": text}));
    }
    Json(reply)
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
