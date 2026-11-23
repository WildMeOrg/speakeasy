//! `speakeasy`: one binary for the relay, the per-session daemon, and the
//! one-shot commands agents run from a shell.
//!
//! Exit codes: 0 ok, 1 error, 3 the room is closed (or there is no session).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use speakeasy::crypto::{hex, random};
use speakeasy::daemon::{self, Request, SEND_DEADLINE, Start};
use speakeasy::dist;
use speakeasy::relay::{Limits, Relay};

mod ui;

#[derive(Parser)]
#[command(version, about = "Ephemeral end-to-end encrypted rooms for agents")]
struct Cli {
    /// Session handle printed by `create` or `join`. Needed only when more
    /// than one session is running for this user. Also SPEAKEASY_SESSION.
    #[arg(long, global = true, env = "SPEAKEASY_SESSION")]
    session: Option<String>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a room and print its invitation
    Create {
        /// Relay address, for example wss://relay.example.org
        #[arg(long)]
        relay: String,
        /// Name shown to other participants (self-asserted)
        #[arg(long)]
        name: Option<String>,
    },
    /// Join a room. The invitation is read from stdin, never the command
    /// line, where other local users could see it
    Join {
        #[arg(long)]
        name: Option<String>,
    },
    /// Send a message, read from stdin (for example `echo hello | speakeasy
    /// send`). Never the command line, where other local users could see it
    Send {
        #[arg(hide = true, trailing_var_arg = true, allow_hyphen_values = true)]
        text: Vec<String>,
    },
    /// Print new messages and events as JSON lines
    Recv {
        /// Wait up to this many seconds for something to arrive
        #[arg(long, default_value_t = 0.0)]
        wait: f64,
    },
    /// Show session state
    Status,
    /// Print what to paste to another agent so it can join: how to fetch
    /// this client, the checksum to check it against, and the invitation.
    /// Treat the output as a secret
    Invite,
    /// Print the guide to taking part in a room, written for agents
    Guide,
    /// Serve a page on this machine for a person to read and write in the
    /// room, with a button that closes it. Prints the link to open
    Ui {
        /// Port on 127.0.0.1. The default picks a free one
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Close the room for everyone, immediately
    Panic,
    /// Leave quietly without closing the room
    Leave,
    /// Run a relay
    Relay {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
    },
    #[command(hide = true)]
    Daemon,
}

const CLOSED: u8 = 3;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            println!("{}", json!({"type": "error", "error": e}));
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Cmd::Relay { listen } => tokio::runtime::Runtime::new()
            .map_err(|e| e.to_string())?
            .block_on(async {
                let listener = tokio::net::TcpListener::bind(&listen)
                    .await
                    .map_err(|e| format!("{listen}: {e}"))?;
                eprintln!("speakeasy relay listening on {}", listener.local_addr().unwrap());
                Relay::new(Limits::default())
                    .serve(listener)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(0)
            }),
        Cmd::Daemon => {
            let handle = cli.session.ok_or("daemon needs --session")?;
            // Any startup failure is reported to the launcher the same way
            // success is: one line on stdout.
            if let Err(e) = run_daemon(&handle) {
                report_ready(json!({"error": e}));
            }
            Ok(0)
        }
        Cmd::Create { relay, name } => launch(Start::Create {
            relay,
            name: name.unwrap_or_else(default_name),
        }),
        Cmd::Join { name } => launch(Start::Join {
            invite: stdin_text()?.trim().to_string(),
            name: name.unwrap_or_else(default_name),
        }),
        Cmd::Send { text } => {
            // Refused rather than sent, so the habit does not form: the
            // argument list is readable by other local users.
            if !text.is_empty() {
                return Err("pass the message on stdin, not as an argument: \
                            echo \"...\" | speakeasy send"
                    .into());
            }
            let text = stdin_text()?;
            let handle = resolve(cli.session)?;
            // The daemon answers within its own deadline; allow a margin.
            let wait = SEND_DEADLINE + Duration::from_secs(15);
            let reply = call(&handle, &Request::Send { text }, wait)?;
            println!("{reply}");
            Ok(match reply["error"].as_str() {
                None => 0,
                Some("closed") => CLOSED,
                Some(_) => 1,
            })
        }
        Cmd::Recv { wait } => {
            if !(0.0..=86_400.0).contains(&wait) {
                return Err("--wait must be between 0 and 86400 seconds".into());
            }
            let handle = match resolve(cli.session) {
                Ok(h) => h,
                Err(e) if e == NO_SESSION => return Ok(no_session()),
                Err(e) => return Err(e),
            };
            recv(&handle, wait)
        }
        Cmd::Status => {
            let handle = resolve(cli.session)?;
            let mut reply = call(&handle, &Request::Status, Duration::from_secs(5))?;
            reply["session"] = json!(handle);
            println!("{reply}");
            Ok(if reply["closed"].is_null() { 0 } else { CLOSED })
        }
        Cmd::Guide => {
            print!("{}", dist::GUIDE);
            Ok(0)
        }
        Cmd::Invite => {
            let handle = resolve(cli.session)?;
            match invite_text(&handle)? {
                Ok(text) => {
                    print!("{text}");
                    Ok(0)
                }
                Err(reason) => {
                    println!("{}", json!({"type": "closed", "reason": reason}));
                    Ok(CLOSED)
                }
            }
        }
        Cmd::Ui { port } => ui::run(resolve(cli.session)?, port),
        Cmd::Panic => {
            let handle = resolve(cli.session)?;
            let reply = call(&handle, &Request::Panic, Duration::from_secs(15))?;
            println!("{reply}");
            Ok(if reply["ok"] == true { 0 } else { 1 })
        }
        Cmd::Leave => {
            let handle = resolve(cli.session)?;
            println!("{}", call(&handle, &Request::Leave, Duration::from_secs(15))?);
            Ok(0)
        }
    }
}

/// What to paste to another agent, or why the room is closed.
fn invite_text(handle: &str) -> Result<Result<String, Value>, String> {
    let reply = call(handle, &Request::Status, Duration::from_secs(5))?;
    let Some(invite) = reply["invite"].as_str() else {
        return Ok(Err(reply["closed"].clone()));
    };
    let version = env!("CARGO_PKG_VERSION");
    let sums = dist::installed_sums();
    let url = dist::release_url(version);
    let release = url.as_deref().zip(sums.as_deref());
    Ok(Ok(dist::instructions(invite, version, release)))
}

fn default_name() -> String {
    format!("agent-{}", hex(&random::<2>()))
}

fn stdin_text() -> Result<String, String> {
    let mut s = String::new();
    std::io::stdin()
        .read_to_string(&mut s)
        .map_err(|e| e.to_string())?;
    Ok(s)
}

const NO_SESSION: &str = "no session";

fn no_session() -> u8 {
    println!("{}", json!({"type": "closed", "reason": NO_SESSION}));
    CLOSED
}

/// Only a missing or dead socket means "no session"; anything else is a
/// real error and is reported as one.
fn connect(handle: &str, wait: Duration) -> Result<UnixStream, String> {
    use std::io::ErrorKind::{ConnectionRefused, NotFound};
    let path = daemon::socket_path(handle)?;
    let stream = UnixStream::connect(&path).map_err(|e| match e.kind() {
        NotFound | ConnectionRefused => NO_SESSION.to_string(),
        _ => format!("{}: {e}", path.display()),
    })?;
    stream.set_read_timeout(Some(wait)).ok();
    Ok(stream)
}

fn exchange(stream: &UnixStream, req: &Request) -> Result<Value, String> {
    let line = serde_json::to_string(req).unwrap();
    (&*stream)
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&reply).map_err(|_| "session did not answer".to_string())
}

/// Send one request to a session's daemon and read its one-line reply.
fn call(handle: &str, req: &Request, wait: Duration) -> Result<Value, String> {
    exchange(&connect(handle, wait)?, req)
}

/// Print waiting events, then acknowledge them. The daemon only forgets
/// events once acknowledged, so dying before this point loses nothing.
fn recv(handle: &str, wait: f64) -> Result<u8, String> {
    let stream = match connect(handle, Duration::from_secs_f64(wait + 20.0)) {
        Ok(s) => s,
        Err(e) if e == NO_SESSION => return Ok(no_session()),
        Err(e) => return Err(e),
    };
    let reply = exchange(&stream, &Request::Recv { wait })?;
    let mut out = std::io::stdout().lock();
    for e in reply["events"].as_array().into_iter().flatten() {
        writeln!(out, "{e}").map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())?;
    let _ = (&stream).write_all(b"ack\n");
    if let Some(reason) = reply["closed"].as_str() {
        writeln!(out, "{}", json!({"type": "closed", "reason": reason})).ok();
        return Ok(CLOSED);
    }
    Ok(0)
}

/// Pick the session: the one named, or the only one running.
fn resolve(named: Option<String>) -> Result<String, String> {
    use std::io::ErrorKind::{ConnectionRefused, NotFound};
    if let Some(h) = named {
        return Ok(h);
    }
    let dir = daemon::socket_dir()?;
    let mut live = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|x| x == "sock") {
            match UnixStream::connect(&path) {
                Ok(_) => live.push(path.file_stem().unwrap().to_string_lossy().into_owned()),
                // Nothing is listening (left behind by a dead daemon), or it
                // went away while we were looking.
                Err(e) if matches!(e.kind(), ConnectionRefused | NotFound) => {}
                Err(e) => return Err(format!("{}: {e}", path.display())),
            }
        }
    }
    match live.len() {
        0 => Err(NO_SESSION.into()),
        1 => Ok(live.remove(0)),
        _ => Err(format!(
            "several sessions are running ({}); pass --session",
            live.join(", ")
        )),
    }
}

// ------------------------------------------------------------ daemon launch

fn run_daemon(handle: &str) -> Result<(), String> {
    let start: Start = serde_json::from_str(&stdin_text()?).map_err(|e| e.to_string())?;
    // One thread is plenty for a daemon that serves a single session.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(daemon::run(handle, start, report_ready))
}

/// Daemon side of the launch handshake: write the outcome on stdout, then
/// let go of the pipe so the shell that launched us is not kept waiting.
fn report_ready(outcome: Value) {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{outcome}");
    let _ = out.flush();
    if let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") {
        use std::os::fd::AsRawFd;
        unsafe { libc::dup2(null.as_raw_fd(), 1) };
    }
}

/// Start a detached daemon and wait until it is in the room (or has failed).
fn launch(start: Start) -> Result<u8, String> {
    let handle = hex(&random::<8>());
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // The daemon gets its own process group. Its stdout is a pipe it closes
    // as soon as it has reported readiness, and the invitation goes over
    // stdin, never the argument list.
    let mut child = Command::new(exe)
        .args(["--session", &handle, "daemon"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("could not start daemon: {e}"))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&start).unwrap().as_bytes())
        .map_err(|e| e.to_string())?;

    // Read the one readiness line, but do not wait on it forever.
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = match rx.recv_timeout(Duration::from_secs(45)) {
        Ok(line) => line,
        Err(_) => {
            let _ = child.kill();
            return Err("timed out joining the room".into());
        }
    };
    let outcome: Value = serde_json::from_str(&line)
        .map_err(|_| "daemon exited before it was ready".to_string())?;
    if let Some(e) = outcome["error"].as_str() {
        return Err(e.to_string());
    }
    println!("{outcome}");
    Ok(0)
}
