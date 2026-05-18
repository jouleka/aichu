// proxy-server — Mode A localhost HTTP server (base-URL relay).
//
// Forwards OpenAI- and Anthropic-shaped requests to their real upstreams
// over HTTPS, preserving streaming SSE responses byte-for-byte. No CA
// install required — clients reach this server by setting their base URL.
//
// Library surface consumed by future CLI wiring and the integration tests.
// Production code lives in `handler` and the wiring below.
//
// Risk-validation history: this crate started as the Week-1 experiment
// `experiments/e02-base-url-relay` testing whether a localhost HTTP server
// can stand in for the real Anthropic / OpenAI APIs with intact SSE. That
// risk was validated for the headline endpoints; the experiment's README
// is preserved at `experiments/e02-base-url-relay/README.md` as the
// historical record.

pub mod handler;

use std::future::Future;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::Router;
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Base URL forwarded to for `POST /v1/messages` (no trailing slash).
    /// Example: `https://api.anthropic.com`.
    pub anthropic_upstream: String,
    /// Base URL forwarded to for `POST /v1/chat/completions`.
    /// Example: `https://api.openai.com`.
    pub openai_upstream: String,
}

/// Build the relay's axum router. Exposed for tests that want to spawn the
/// app on an already-bound listener without going through `run_relay`.
pub fn build_router(config: RelayConfig) -> Router {
    handler::router(config)
}

/// Bind on `addr` and run the relay until `shutdown` resolves.
pub async fn run_relay<S>(addr: SocketAddr, config: RelayConfig, shutdown: S) -> Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    let app = build_router(config);
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("relay server stopped with error")
}
