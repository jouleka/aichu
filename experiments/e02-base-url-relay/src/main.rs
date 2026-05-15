// e02-base-url-relay — binary entry point.
//
// Reads upstream URLs from env (or uses defaults), binds the relay on
// 127.0.0.1:8788, runs until ctrl-c. See README for usage.

use std::net::SocketAddr;

use anyhow::Result;
use e02_base_url_relay::{RelayConfig, run_relay};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = RelayConfig {
        anthropic_upstream: std::env::var("AICHU_ANTHROPIC_UPSTREAM")
            .unwrap_or_else(|_| "https://api.anthropic.com".to_string()),
        openai_upstream: std::env::var("AICHU_OPENAI_UPSTREAM")
            .unwrap_or_else(|_| "https://api.openai.com".to_string()),
    };

    let addr: SocketAddr = "127.0.0.1:8788".parse()?;
    tracing::info!(%addr, "relay listening — ctrl-c to stop");
    tracing::info!(anthropic = %config.anthropic_upstream, openai = %config.openai_upstream, "upstream targets");

    run_relay(addr, config, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}
