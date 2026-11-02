//! The rendezvous relay: one Arti onion service that splices pairing
//! streams.  Both devices connect out; only the server hosts.
//!
//! Protocol per inbound stream — one header line, then opaque bytes:
//!   OFFER <64-hex>   park the stream under H(token); await a CLAIM
//!   CLAIM <64-hex>   splice to the parked OFFER stream, or close
//!
//! The hash is SHA-256 of the pairing token — the code itself never
//! reaches us.  Everything after the header is end-to-end Noise
//! ciphertext; we forward it verbatim.  Nothing persists: the pending
//! table is memory-only and entries expire after OFFER_TTL.

use anyhow::{Context, Result};
use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient, TorClientConfig};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use safelog::DisplayRedacted;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{handle_rend_requests, HsNickname, OnionServiceConfig, RunningOnionService};
use tor_rtcompat::PreferredRuntime;

/// The service's hidden-service nickname (not its address).
const SVC_NICKNAME: &str = "arktos-relay";
/// How long a parked OFFER waits for its CLAIM.
const OFFER_TTL: Duration = Duration::from_secs(300);
/// Sweeper cadence for expired offers.
const SWEEP_SECS: u64 = 5;
/// Cap on simultaneously parked offers — a simple DoS bound.
const MAX_PENDING: usize = 1024;
/// Where the admin page finds the published onion address.
const ONION_FILE: &str = "relay-onion.txt";
/// Arti state/cache — persistent, so the onion address survives restarts.
const STATE_DIR: &str = "relay-state";

type Pending = Arc<Mutex<HashMap<String, (DataStream, Instant)>>>;

/// Entry point for `arktos-server serve`.
pub async fn run() -> Result<()> {
    // Arti's rustls feature doesn't pick a provider — ring, like the
    // desktop/mobile rustcores.
    let _ = rustls::crypto::ring::default_provider().install_default();
    ensure_dir_700(Path::new(STATE_DIR))?;
    ensure_dir_700(&Path::new(STATE_DIR).join("state"))?;
    ensure_dir_700(&Path::new(STATE_DIR).join("cache"))?;

    let cfg: TorClientConfig = TorClientConfigBuilder::from_directories(
        Path::new(STATE_DIR).join("state"),
        Path::new(STATE_DIR).join("cache"),
    )
    .build()
    .context("arti client config")?;
    let client = TorClient::with_runtime(PreferredRuntime::current()?)
        .config(cfg)
        .create_unbootstrapped()
        .context("create tor client")?;
    eprintln!("arktos-relay: bootstrap started");
    client.bootstrap().await.context("tor bootstrap")?;
    eprintln!("arktos-relay: bootstrap done");

    let svc_cfg = svc_config().context("onion service config")?;
    let (running, rend) = match client.launch_onion_service(svc_cfg)? {
        Some(l) => l,
        None => anyhow::bail!("onion service disabled by config"),
    };
    eprintln!("arktos-relay: onion service launched — publishing");

    {
        let svc = running.clone();
        tokio::spawn(async move {
            let mut evs = svc.status_events();
            while let Some(s) = evs.next().await {
                eprintln!("arktos-relay: onion status {:?}", s.state());
            }
        });
    }
    {
        let onion = onion_name(&running);
        eprintln!("arktos-relay: listening on {onion}");
        let _ = std::fs::write(ONION_FILE, &onion);
    }

    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    {
        let pending = Arc::clone(&pending);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(SWEEP_SECS)).await;
                let mut map = pending.lock().await;
                let before = map.len();
                map.retain(|_, (_, at)| at.elapsed() < OFFER_TTL);
                if map.len() < before {
                    eprintln!("arktos-relay: expired {} offer(s)", before - map.len());
                }
            }
        });
    }

    let mut reqs = Box::pin(handle_rend_requests(rend));
    while let Some(req) = reqs.next().await {
        let pending = Arc::clone(&pending);
        tokio::spawn(async move {
            match req.accept(Connected::new_empty()).await {
                Ok(stream) => {
                    if let Err(e) = handle(stream, pending).await {
                        eprintln!("arktos-relay: stream: {e:#}");
                    }
                }
                Err(e) => eprintln!("arktos-relay: rendezvous accept: {e}"),
            }
        });
    }
    Ok(())
}

/// One inbound stream: read the OFFER/CLAIM header, then park or splice.
async fn handle(mut stream: DataStream, pending: Pending) -> Result<()> {
    // Header: one line — read byte-wise until '\n' (≤200B).
    let mut buf = Vec::with_capacity(80);
    let mut b = [0u8; 1];
    loop {
        stream.read_exact(&mut b).await.context("header read")?;
        if b[0] == b'\n' {
            break;
        }
        if b[0] != b'\r' {
            buf.push(b[0]);
        }
        if buf.len() > 200 {
            anyhow::bail!("header too long");
        }
    }
    let line = String::from_utf8_lossy(&buf);
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    let key = parts.next().unwrap_or("");
    if key.len() != 64 || !key.bytes().all(|c| c.is_ascii_hexdigit()) {
        stream.write_all(b"ERR bad key\n").await.ok();
        anyhow::bail!("bad key from peer");
    }
    match cmd {
        "OFFER" => {
            let mut map = pending.lock().await;
            if map.len() >= MAX_PENDING || map.contains_key(key) {
                stream.write_all(b"ERR busy\n").await.ok();
                anyhow::bail!("offer rejected (busy or dup)");
            }
            map.insert(key.to_string(), (stream, Instant::now()));
            eprintln!("arktos-relay: offer parked ({} pending)", map.len());
            Ok(())
        }
        "CLAIM" => {
            let slot = { pending.lock().await.remove(key) };
            let Some((mut offer, _)) = slot else {
                stream.write_all(b"ERR no offer\n").await.ok();
                anyhow::bail!("no offer for key");
            };
            stream.write_all(b"OK\n").await.ok();
            eprintln!("arktos-relay: splicing pair");
            // Byte-for-byte splice — ciphertext only, nothing parsed.
            let (mut ar, mut aw) = offer.split();
            let (mut cr, mut cw) = stream.split();
            let _ = futures::join!(
                futures::io::copy(&mut ar, &mut cw),
                futures::io::copy(&mut cr, &mut aw)
            );
            eprintln!("arktos-relay: pair closed");
            Ok(())
        }
        _ => {
            stream.write_all(b"ERR unknown\n").await.ok();
            anyhow::bail!("unknown command {cmd:?}")
        }
    }
}

/// The onion service config — unrestricted discovery (the token
/// hash IS the gate; clients need no pre-shared key).
fn svc_config() -> Result<OnionServiceConfig> {
    let mut b = OnionServiceConfigBuilder::default();
    b.nickname(HsNickname::from_str(SVC_NICKNAME).context("service nickname")?);
    b.build().context("onion service config")
}

/// "<hex>.onion" for the running service.
fn onion_name(running: &RunningOnionService) -> String {
    match running.onion_name() {
        Some(id) => format!("{}", id.display_unredacted()),
        None => "(publishing…)".to_string(),
    }
}

/// Arti's fs_mistrust wants private dirs.
fn ensure_dir_700(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    Ok(())
}
