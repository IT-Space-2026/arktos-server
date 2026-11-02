//! The supervisor + admin UI: spawns `arktos-server serve` as a child,
//! watches it, and exposes a tiny HTTP page on 127.0.0.1:8080 with
//! Start / Stop / Restart controls, status, the onion address, and a
//! live log tail.  No framework — the whole page is three routes.

use anyhow::{Context, Result};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const BIND: &str = "127.0.0.1:8080";
const LOG_FILE: &str = "relay.log";
const ONION_FILE: &str = "relay-onion.txt";
const LOG_TAIL_LINES: usize = 40;

struct Managed {
    child: Option<Child>,
    started: Option<Instant>,
}

/// Entry point for `arktos-server` (default mode).
pub async fn run() -> Result<()> {
    let state = Arc::new(Mutex::new(Managed {
        child: None,
        started: None,
    }));
    spawn_serve(&state).await?;
    eprintln!("arktos-server: admin on http://{BIND}");

    let listener = TcpListener::bind(BIND).await.context("bind admin")?;
    loop {
        let (socket, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = handle_conn(socket, state).await;
        });
    }
}

/// Spawn the relay child, piping its output into relay.log.
async fn spawn_serve(state: &Arc<Mutex<Managed>>) -> Result<()> {
    let exe = std::env::current_exe().context("current exe")?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .context("open relay.log")?;
    let log_err = log.try_clone().context("clone log fd")?;
    let child = Command::new(exe)
        .arg("serve")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .context("spawn serve")?;
    let pid = child.id();
    let mut m = state.lock().await;
    m.child = Some(child);
    m.started = Some(Instant::now());
    eprintln!("arktos-server: serve spawned (pid {pid})");
    Ok(())
}

/// Kill the relay child if running.
async fn stop_serve(state: &Arc<Mutex<Managed>>) {
    let mut m = state.lock().await;
    if let Some(mut c) = m.child.take() {
        let _ = c.kill();
        let _ = c.wait();
        eprintln!("arktos-server: serve stopped");
    }
    m.started = None;
}

/// One HTTP connection — parse the request line, route, respond.
async fn handle_conn(mut socket: tokio::net::TcpStream, state: Arc<Mutex<Managed>>) -> Result<()> {
    let (rd, mut wr) = socket.split();
    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    // Drain the rest of the headers (small requests only).
    let mut h = String::new();
    loop {
        h.clear();
        reader.read_line(&mut h).await?;
        if h == "\r\n" || h.is_empty() {
            break;
        }
    }
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));

    match (method, path) {
        ("POST", "/start") => {
            if state.lock().await.child.is_none() {
                spawn_serve(&state).await.ok();
            }
            redirect(&mut wr).await
        }
        ("POST", "/stop") => {
            stop_serve(&state).await;
            redirect(&mut wr).await
        }
        ("POST", "/restart") => {
            stop_serve(&state).await;
            spawn_serve(&state).await.ok();
            redirect(&mut wr).await
        }
        _ => {
            let body = page(&state).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            wr.write_all(resp.as_bytes()).await?;
            Ok(())
        }
    }
}

async fn redirect(wr: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
    wr.write_all(b"HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n")
        .await?;
    Ok(())
}

/// The admin page — status, controls, onion addr, log tail.
async fn page(state: &Arc<Mutex<Managed>>) -> String {
    let (running, pid, uptime) = {
        let mut m = state.lock().await;
        // Reap silently if the child exited on its own.
        let mut dead = false;
        if let Some(c) = m.child.as_mut() {
            if matches!(c.try_wait(), Ok(Some(_))) {
                dead = true;
            }
        }
        if dead {
            m.child = None;
            m.started = None;
        }
        match &m.child {
            Some(c) => (
                "running",
                c.id().to_string(),
                m.started.map(|t| format!("{:?}", t.elapsed())).unwrap_or_default(),
            ),
            None => ("stopped", "-".into(), "-".into()),
        }
    };
    let onion = std::fs::read_to_string(ONION_FILE)
        .unwrap_or_else(|_| "(not published yet)".into())
        .trim()
        .to_string();
    let log = tail(LOG_FILE, LOG_TAIL_LINES);
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8">
<title>arktos-server</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem;color:#222}}
h1{{font-size:1.3rem}} .card{{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}}
.status{{font-weight:600}} .status.on{{color:#0a7}} .status.off{{color:#c33}}
.onion{{font-family:monospace;font-size:.85rem;word-break:break-all}}
pre{{background:#f6f6f6;padding:.75rem;border-radius:6px;overflow:auto;font-size:.72rem;max-height:20rem}}
button{{padding:.5rem 1.1rem;border:1px solid #bbb;border-radius:6px;background:#fff;cursor:pointer;margin-right:.5rem}}
</style></head><body>
<h1>arktos-server</h1>
<div class="card">
  <p>Status: <span class="status {onoff}">{status}</span> &nbsp; pid {pid} &nbsp; uptime {uptime}</p>
  <p>Relay onion: <span class="onion">{onion}</span></p>
  <form method="post" action="/start" style="display:inline"><button>Start</button></form>
  <form method="post" action="/stop" style="display:inline"><button>Stop</button></form>
  <form method="post" action="/restart" style="display:inline"><button>Restart</button></form>
</div>
<h2>log tail</h2><pre>{log}</pre>
</body></html>"#,
        onoff = if running == "running" { "on" } else { "off" },
        status = running,
        pid = pid,
        uptime = uptime,
        onion = onion,
        log = html_escape(&log),
    )
}

/// Last `n` lines of a file, small-read.
fn tail(path: &str, n: usize) -> String {
    let Ok(s) = std::fs::read_to_string(path) else {
        return "(no log yet)".into();
    };
    let lines: Vec<&str> = s.lines().collect();
    lines.iter().rev().take(n).rev().cloned().collect::<Vec<_>>().join("\n")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
