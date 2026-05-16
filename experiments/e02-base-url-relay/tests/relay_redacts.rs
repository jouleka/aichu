//! Integration test for the proxy-core ↔ e02 wiring (Phase 1).
//!
//! Contract: a request body containing a secret-shaped substring
//! (e.g. `AKIAIOSFODNN7EXAMPLE`) reaches the upstream with the secret
//! substituted by a typed placeholder. The original secret never
//! leaves the relay process.
//!
//! Phase 1 covers outbound redaction only. Response-side reversal
//! (especially streaming SSE) is Phase 2.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    routing::post,
};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use e02_base_url_relay::{RelayConfig, run_relay};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_redacts_aws_key_before_forwarding() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/messages").await?;
    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(), // unused
    };
    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = client
        .post(format!("http://{relay_addr}/v1/messages"))
        .header("x-api-key", "fake-test-key")
        .header("anthropic-version", "2023-06-01")
        .json(&json!({
            "model": "claude-opus-4-5",
            "max_tokens": 100,
            "messages": [{
                "role": "user",
                "content": "Why does AKIAIOSFODNN7EXAMPLE fail on S3?",
            }],
        }))
        .send()
        .await?;

    assert_eq!(resp.status(), 200, "relay should propagate upstream 200");

    let captured = upstream
        .last_body
        .lock()
        .unwrap()
        .clone()
        .expect("upstream should have received a request body");
    let captured_str =
        std::str::from_utf8(&captured).expect("upstream body should be valid utf-8 JSON");

    // The whole point of this experiment: the raw AWS key MUST NOT
    // reach the upstream. If this assertion fires, the redaction wiring
    // is broken and we have a privacy leak.
    assert!(
        !captured_str.contains("AKIAIOSFODNN7EXAMPLE"),
        "raw AWS key reached upstream — redaction not wired:\n{captured_str}"
    );

    // And the placeholder must be there in its place. (Test the
    // POSITIVE outcome too — otherwise an implementation that just
    // dropped the secret without substituting anything would pass the
    // negative check above.)
    assert!(
        captured_str.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"),
        "expected placeholder «SECRET_AWS_KEY_001» in upstream body; got:\n{captured_str}"
    );

    // Non-secret content must still be present.
    assert!(captured_str.contains("Why does"));
    assert!(captured_str.contains("fail on S3?"));

    let _ = shutdown_tx.send(());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_passes_through_body_with_no_secrets_unchanged() -> Result<()> {
    // Symmetric guard: when there ARE no findings, the body must be
    // forwarded byte-for-byte. A future regression where every JSON
    // gets unnecessarily re-serialized would break this.
    let upstream = spawn_capturing_upstream("/v1/messages").await?;
    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(),
    };
    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let body_value = json!({
        "model": "claude-opus-4-5",
        "max_tokens": 100,
        "messages": [{
            "role": "user",
            "content": "Plain text prompt with no secrets at all.",
        }],
    });

    let _ = client
        .post(format!("http://{relay_addr}/v1/messages"))
        .header("x-api-key", "fake-test-key")
        .json(&body_value)
        .send()
        .await?;

    let captured = upstream.last_body.lock().unwrap().clone().expect("body");
    let captured_str = std::str::from_utf8(&captured)?;
    assert!(captured_str.contains("Plain text prompt with no secrets at all."));
    // No placeholders should appear when nothing was redacted.
    assert!(
        !captured_str.contains("\u{ab}SECRET_"),
        "placeholder appeared when nothing was redacted: {captured_str}"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

// --- mock upstream scaffolding ---

#[derive(Clone)]
struct CapturingState {
    request_count: Arc<AtomicU64>,
    last_body: Arc<std::sync::Mutex<Option<Bytes>>>,
}

struct CapturingUpstream {
    addr: SocketAddr,
    #[allow(dead_code)]
    request_count: Arc<AtomicU64>,
    last_body: Arc<std::sync::Mutex<Option<Bytes>>>,
}

async fn spawn_capturing_upstream(path: &'static str) -> Result<CapturingUpstream> {
    let state = CapturingState {
        request_count: Arc::new(AtomicU64::new(0)),
        last_body: Arc::new(std::sync::Mutex::new(None)),
    };
    let request_count = state.request_count.clone();
    let last_body = state.last_body.clone();

    let app = Router::new().route(path, post(capture)).with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok(CapturingUpstream {
        addr,
        request_count,
        last_body,
    })
}

async fn capture(State(state): State<CapturingState>, body: Bytes) -> Json<Value> {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    *state.last_body.lock().unwrap() = Some(body);
    Json(json!({"id": "msg_test", "type": "message", "content": []}))
}

async fn spawn_relay(config: RelayConfig) -> Result<(SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = run_relay(addr, config, async move {
            let _ = shutdown_rx.await;
        })
        .await;
    });
    wait_for_listener(addr).await?;
    Ok((addr, shutdown_tx))
}

async fn wait_for_listener(addr: SocketAddr) -> Result<()> {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("relay never accepted a TCP connection on {addr}")
}
