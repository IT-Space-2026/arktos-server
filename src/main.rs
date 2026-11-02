//! arktos-server — the Arktos rendezvous relay.
//!
//! Two modes in one binary:
//!   `arktos-server`        supervisor + admin UI on 127.0.0.1:8080,
//!                          spawns and manages `serve` as a child.
//!   `arktos-server serve`  the relay itself: an Arti onion service
//!                          that splices OFFER/CLAIM stream pairs.

mod admin;
mod relay;

fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("serve") => {
            // The managed child — the supervisor owns its lifecycle.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(relay::run())
        }
        Some("admin") | None => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(admin::run())
        }
        Some(other) => {
            eprintln!("unknown command {other:?} — expected `serve` or `admin` (default)");
            std::process::exit(2);
        }
    }
}
