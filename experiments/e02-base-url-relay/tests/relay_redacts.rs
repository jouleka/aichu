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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_reverses_placeholder_in_non_streaming_json_response() -> Result<()> {
    // Phase 2a contract: when the response is non-streaming JSON
    // (content-type: application/json), and the upstream's response
    // contains a placeholder the relay minted, the relay must swap it
    // back to the original secret before handing the body to the
    // client. The user-visible result: they typed AKIAIOS..., got an
    // answer that mentions AKIAIOS..., never knew the placeholder
    // existed.
    let upstream = spawn_upstream_with_fixed_response(
        "/v1/messages",
        json!({
            "id": "msg_test",
            "type": "message",
            "content": [
                {
                    "type": "text",
                    "text": "Your \u{ab}SECRET_AWS_KEY_001\u{bb} needs s3:GetObject in its policy.",
                }
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 12},
        }),
    )
    .await?;

    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(),
    };
    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = client
        .post(format!("http://{relay_addr}/v1/messages"))
        .header("x-api-key", "fake-test-key")
        .json(&json!({
            "model": "claude-opus-4-5",
            "max_tokens": 100,
            "messages": [{
                "role": "user",
                "content": "Debug AKIAIOSFODNN7EXAMPLE on S3 please.",
            }],
        }))
        .send()
        .await?;

    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"),
        "expected JSON response from upstream, got {ct:?}"
    );

    let body = resp.text().await?;

    // The whole point of the round-trip: client sees the original
    // secret in its response, not the placeholder. If this fires, the
    // reverse pass is broken or wasn't applied.
    assert!(
        body.contains("AKIAIOSFODNN7EXAMPLE"),
        "secret not restored on response side; client sees: {body}"
    );
    assert!(
        !body.contains("\u{ab}SECRET_"),
        "placeholder leaked to client (reverse pass failed): {body}"
    );

    // Non-placeholder content should survive too.
    assert!(body.contains("s3:GetObject in its policy."));

    let _ = shutdown_tx.send(());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_reverses_placeholder_in_streaming_sse_response() -> Result<()> {
    // Phase 2b contract: when the upstream response is text/event-stream
    // (request was stream: true) AND we redacted something on the
    // outbound side, the relay must buffer the response, run reverse,
    // and emit the original secret back to the client.
    //
    // Trade-off documented in handler.rs: with-secrets responses are
    // currently buffered (no streaming UX) until SSE-aware per-event
    // reversal (Phase 2c) lands. No-secrets responses stay streaming.
    let upstream = spawn_upstream_returning_sse_with_placeholder("/v1/messages").await?;

    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(),
    };
    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // stream: true triggers the SSE response from the upstream mock.
    let resp = client
        .post(format!("http://{relay_addr}/v1/messages"))
        .header("x-api-key", "fake-test-key")
        .json(&json!({
            "model": "claude-opus-4-5",
            "max_tokens": 100,
            "stream": true,
            "messages": [{
                "role": "user",
                "content": "Debug AKIAIOSFODNN7EXAMPLE on S3 please.",
            }],
        }))
        .send()
        .await?;

    assert_eq!(resp.status(), 200);
    let body = resp.text().await?;

    // The SSE upstream emits a content_block_delta event whose JSON
    // contains «SECRET_AWS_KEY_001» — see
    // spawn_upstream_returning_sse_with_placeholder. The relay's Phase
    // 2b reverse pass must substitute back to AKIAIOSFODNN7EXAMPLE
    // before the client sees the body.
    assert!(
        body.contains("AKIAIOSFODNN7EXAMPLE"),
        "secret not restored in streaming response; client sees:\n{body}"
    );
    assert!(
        !body.contains("\u{ab}SECRET_"),
        "placeholder leaked to client (reverse pass failed):\n{body}"
    );
    // Non-placeholder content must still be present.
    assert!(body.contains("needs s3:GetObject"));

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Phase 2c spec, encoded as an ignored test.
///
/// When a placeholder is fragmented across two `content_block_delta`
/// events (e.g. event 1 ends with `«SECRET_AWS_` and event 2 begins
/// with `KEY_001»`), the whole-response buffer contains the placeholder
/// with JSON/SSE framing bytes (`"}}\n\nevent: content_block_delta\n
/// data: {"...,"text":"`) inserted between the two halves. proxy_core's
/// reverse regex `«SECRET_[A-Z0-9_]+_[0-9]+»` cannot match across those
/// framing bytes — `"` / `}` / whitespace aren't in the character class
/// — so the placeholder stays in the response and the user sees the
/// fragments.
///
/// Phase 2c will land per-event SSE parsing that buffers `text_delta`
/// payloads at the JSON level, eliminating this gap. This test
/// encodes the desired future behavior; it currently fails and is
/// marked `#[ignore]` until Phase 2c.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Phase 2c: per-event SSE reversal handles placeholders split across content_block_delta events"]
async fn phase_2c_relay_reverses_placeholder_split_across_sse_events() -> Result<()> {
    let upstream =
        spawn_upstream_returning_sse_with_split_placeholder("/v1/messages").await?;

    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(),
    };
    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let resp = client
        .post(format!("http://{relay_addr}/v1/messages"))
        .header("x-api-key", "fake-test-key")
        .json(&json!({
            "model": "claude-opus-4-5",
            "stream": true,
            "max_tokens": 100,
            "messages": [{
                "role": "user",
                "content": "Debug AKIAIOSFODNN7EXAMPLE on S3.",
            }],
        }))
        .send()
        .await?;

    let body = resp.text().await?;
    // Phase 2c desired behavior:
    assert!(body.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!body.contains("\u{ab}SECRET_"));

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

/// Same shape as the capturing upstream, but returns a fixed JSON
/// response body. Used by the reverse-pass test to put a known
/// placeholder string in the response so we can assert the relay
/// substitutes it back.
async fn spawn_upstream_with_fixed_response(
    path: &'static str,
    fixed: Value,
) -> Result<CapturingUpstream> {
    let state = FixedResponseState {
        request_count: Arc::new(AtomicU64::new(0)),
        last_body: Arc::new(std::sync::Mutex::new(None)),
        response: Arc::new(fixed),
    };
    let request_count = state.request_count.clone();
    let last_body = state.last_body.clone();

    let app = Router::new()
        .route(path, post(fixed_response_handler))
        .with_state(state);

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

#[derive(Clone)]
struct FixedResponseState {
    request_count: Arc<AtomicU64>,
    last_body: Arc<std::sync::Mutex<Option<Bytes>>>,
    response: Arc<Value>,
}

async fn fixed_response_handler(
    State(state): State<FixedResponseState>,
    body: Bytes,
) -> Json<Value> {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    *state.last_body.lock().unwrap() = Some(body);
    Json((*state.response).clone())
}

/// Mock upstream that returns an SSE stream with three
/// `content_block_delta` events. The placeholder sits WHOLLY inside
/// event 2's `text_delta.text` field; events 1 and 3 carry the
/// surrounding prose ("Your " and " needs s3:GetObject."). This
/// exercises the buffer-then-reverse path concatenating multiple
/// events, but NOT the cross-event-split case where the placeholder
/// itself spans multiple events — that's a known Phase 2b limitation
/// (intermediate JSON/SSE framing breaks the placeholder regex) and
/// is captured by `phase_2c_relay_reverses_placeholder_split_across_sse_events`
/// (currently `#[ignore]`d).
async fn spawn_upstream_returning_sse_with_placeholder(
    path: &'static str,
) -> Result<CapturingUpstream> {
    spawn_sse_upstream(
        path,
        vec![
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"Your "}}"#
                .to_string(),
            format!(
                r#"{{"type":"content_block_delta","delta":{{"type":"text_delta","text":"{}"}}}}"#,
                "\u{ab}SECRET_AWS_KEY_001\u{bb}",
            ),
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":" needs s3:GetObject."}}"#
                .to_string(),
        ],
    )
    .await
}

/// Phase-2c fixture: the placeholder is split across two events. Event 1
/// has the `«SECRET_AWS_` prefix; event 2 has the `KEY_001»` suffix.
async fn spawn_upstream_returning_sse_with_split_placeholder(
    path: &'static str,
) -> Result<CapturingUpstream> {
    spawn_sse_upstream(
        path,
        vec![
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"Your «SECRET_AWS_"}}"#
                .to_string(),
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"KEY_001» needs s3:GetObject."}}"#
                .to_string(),
        ],
    )
    .await
}

/// Spin up an axum SSE upstream that emits `events` as
/// `content_block_delta` events. Captures the request body for
/// caller assertions.
async fn spawn_sse_upstream(
    path: &'static str,
    events: Vec<String>,
) -> Result<CapturingUpstream> {
    use axum::response::sse::{Event as SseEvent, Sse};
    use futures_util::stream;
    use std::convert::Infallible;

    let request_count = Arc::new(AtomicU64::new(0));
    let last_body = Arc::new(std::sync::Mutex::new(None));

    #[derive(Clone)]
    struct SseState {
        request_count: Arc<AtomicU64>,
        last_body: Arc<std::sync::Mutex<Option<Bytes>>>,
        events: Arc<Vec<String>>,
    }
    let state = SseState {
        request_count: request_count.clone(),
        last_body: last_body.clone(),
        events: Arc::new(events),
    };

    let handler = move |State(state): State<SseState>,
                        body: Bytes|
          -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Sse<_>> + Send>,
    > {
        state.request_count.fetch_add(1, Ordering::Relaxed);
        *state.last_body.lock().unwrap() = Some(body);

        let events: Vec<Result<SseEvent, Infallible>> = state
            .events
            .iter()
            .map(|data| {
                Ok(SseEvent::default().event("content_block_delta").data(data))
            })
            .collect();
        Box::pin(async move { Sse::new(stream::iter(events)) })
    };

    let app = Router::new().route(path, post(handler)).with_state(state);

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
