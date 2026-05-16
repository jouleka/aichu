// proxy-mitm — hudsucker-based HTTPS MITM proxy with a local rcgen CA.
//
// Library surface consumed by the `aichu` CLI binary and the integration
// tests. Production code lives in `ca`, `handler`, and the proxy wiring
// below.
//
// Risk-validation history: this crate started as the Week-1 experiment
// `experiments/e01-hudsucker-mitm` testing whether a Hudsucker proxy could
// MITM Claude Code CLI's streaming `/v1/messages` traffic end-to-end. That
// risk was validated for the CLI scope; the experiment's README is preserved
// at `experiments/e01-hudsucker-mitm/README.md` as the historical record.

pub mod ca;
pub mod handler;

use std::future::Future;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use hudsucker::{Proxy, certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};

use crate::handler::AichuHandler;

/// Spawn the MITM proxy on `addr` and run until `shutdown` resolves.
///
/// Returns when the proxy stops accepting connections.
pub async fn run_proxy<S>(
    addr: SocketAddr,
    ca: RcgenAuthority,
    handler: AichuHandler,
    shutdown: S,
) -> Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    // Idempotent — already called by `load_or_create_ca` on the typical
    // path. Repeated here so callers that construct the authority via a
    // different route still get a working rustls connector.
    ensure_rustls_provider();

    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(shutdown)
        .build()
        .context("build hudsucker proxy")?;

    proxy.start().await.context("hudsucker proxy stopped with error")
}

/// Install the aws-lc-rs rustls crypto provider as the process default,
/// exactly once. Safe to call from anywhere; subsequent calls are no-ops.
///
/// Rustls 0.23 requires a default provider be installed before any TLS
/// operation; hudsucker's rcgen authority and rustls connector both rely
/// on this. We hide that requirement behind a single idempotent helper so
/// callers don't have to remember the order.
pub(crate) fn ensure_rustls_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = aws_lc_rs::default_provider().install_default();
    });
}
