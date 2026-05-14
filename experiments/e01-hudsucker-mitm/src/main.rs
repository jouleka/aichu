// e01-hudsucker-mitm — binary entry point.
//
// Wires together a local CA, a logging handler, and the hudsucker proxy.
// See README.md for usage. The interesting code lives in lib.rs and its
// modules.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use e01_hudsucker_mitm::{ca::load_or_create_ca, handler::AichuHandler, run_proxy};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let ca_dir = PathBuf::from("./ca");
    let ca = load_or_create_ca(&ca_dir)?;
    tracing::info!(
        "loaded CA — public cert at {}",
        ca_dir.join("aichu-ca.pem").display()
    );

    let addr: SocketAddr = "127.0.0.1:8788".parse()?;
    let handler = AichuHandler::new();

    tracing::info!(%addr, "proxy listening — ctrl-c to stop");
    run_proxy(addr, ca.authority, handler, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}
