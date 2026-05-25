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

use proxy_server::{RelayConfig, run_relay};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_redacts_aws_key_before_forwarding() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/messages").await?;
    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(), // unused
        // Pre-existing tests pin redaction/reverse contracts that
        // pre-date the preserve-tokens injection feature. Disabling
        // injection here keeps each test focused on its named
        // contract (a body-content assertion that searches for
        // `«SECRET_` substrings would otherwise hit the schema text
        // in our injected prompt). The injection feature has its
        // own dedicated tests below.
        inject_system_prompt: false,
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
        // See the first test's rationale: pre-existing tests opt
        // out of injection so their body-content assertions don't
        // need updating.
        inject_system_prompt: false,
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
        // See the first test's rationale: pre-existing tests opt
        // out of injection so their body-content assertions don't
        // need updating.
        inject_system_prompt: false,
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
        // See the first test's rationale: pre-existing tests opt
        // out of injection so their body-content assertions don't
        // need updating.
        inject_system_prompt: false,
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

/// Phase 2c contract: when a placeholder is fragmented across two
/// `content_block_delta` events (e.g. event 1 ends with `«SECRET_AWS_`
/// and event 2 begins with `KEY_001»`), the streaming SSE reverser
/// must accumulate `text_delta` payloads across events and substitute
/// the original secret back before it reaches the client.
///
/// Phase 2b's whole-response buffering couldn't match across the
/// intervening JSON/SSE framing bytes (`"}}\n\nevent: ...,
/// "text":"`); proxy_core::reverse's `«SECRET_[A-Z0-9_]+_[0-9]+»`
/// regex character class rejected the punctuation in between. Phase
/// 2c moves the reversal up the stack to per-event JSON
/// re-serialization (see `proxy_core::sse::SseReverser`), so the
/// placeholder is recognized even when its bytes arrive in separate
/// events.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase_2c_relay_reverses_placeholder_split_across_sse_events() -> Result<()> {
    let upstream =
        spawn_upstream_returning_sse_with_split_placeholder("/v1/messages").await?;

    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(),
        // See the first test's rationale: pre-existing tests opt
        // out of injection so their body-content assertions don't
        // need updating.
        inject_system_prompt: false,
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

/// Mode A counterpart to proxy-mitm's
/// `mitm_injects_preserve_tokens_system_prompt_into_anthropic_request`.
/// When `inject_system_prompt: true`, the forwarded Anthropic body
/// must carry `PRESERVE_TOKENS_PROMPT` in the `system` field. End-to-
/// end-equivalent: a user running the relay (Mode A) gets the same
/// e03-measured preservation boost as a user running the MITM proxy
/// (Mode B).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_injects_preserve_tokens_system_prompt_into_anthropic_request() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/messages").await?;
    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(),
        inject_system_prompt: true,
    };
    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let _ = client
        .post(format!("http://{relay_addr}/v1/messages"))
        .header("x-api-key", "fake-test-key")
        .json(&json!({
            "model": "claude-opus-4-5",
            "max_tokens": 100,
            "messages": [{
                "role": "user",
                "content": "Debug AKIAIOSFODNN7EXAMPLE on S3.",
            }],
        }))
        .send()
        .await?;

    let captured = upstream.last_body.lock().unwrap().clone().expect("body");
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&captured)?)?;

    // System field present and starts with our prompt (preserves any
    // future client-supplied tail via the inject helper's prepend).
    let system_text = parsed["system"].as_str().expect("system is string");
    assert!(
        system_text.starts_with(proxy_core::PRESERVE_TOKENS_PROMPT),
        "preserve-tokens prompt must be at the front of `system`; got: {system_text}"
    );

    // Redaction still works alongside injection. The pair pins
    // ordering: redact first, then inject.
    let user_content = parsed["messages"][0]["content"]
        .as_str()
        .expect("user content is string");
    assert!(user_content.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"));
    assert!(!user_content.contains("AKIAIOSFODNN7EXAMPLE"));

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Mode A counterpart for OpenAI Chat Completions. Inserts a new
/// system message at index 0 when no client system message exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_injects_preserve_tokens_system_prompt_into_openai_chat_request() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/chat/completions").await?;
    let config = RelayConfig {
        anthropic_upstream: "http://127.0.0.1:1".to_string(),
        openai_upstream: format!("http://{}", upstream.addr),
        inject_system_prompt: true,
    };
    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let _ = client
        .post(format!("http://{relay_addr}/v1/chat/completions"))
        .header("authorization", "Bearer fake-test-key")
        .json(&json!({
            "model": "gpt-5-mini",
            "messages": [{
                "role": "user",
                "content": "Debug AKIAIOSFODNN7EXAMPLE on S3.",
            }],
        }))
        .send()
        .await?;

    let captured = upstream.last_body.lock().unwrap().clone().expect("body");
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&captured)?)?;
    let messages = parsed["messages"].as_array().expect("messages is array");

    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[0]["content"], proxy_core::PRESERVE_TOKENS_PROMPT);
    assert_eq!(messages[1]["role"], "user");
    let user_content = messages[1]["content"].as_str().expect("user content is string");
    assert!(user_content.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"));
    assert!(!user_content.contains("AKIAIOSFODNN7EXAMPLE"));

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Mode A counterpart for the OpenAI Responses API. The relay must
/// (1) route `/v1/responses` to the OpenAI upstream, (2) redact
/// secret-shaped substrings out of the body, and (3) prepend
/// `PRESERVE_TOKENS_PROMPT` into the top-level `instructions`
/// string (the canonical Responses-API system-message slot per the
/// OpenAI Node SDK `ResponseCreateParamsBase`).
///
/// Why both routing AND injection are pinned here: without the
/// route, the new `InjectionShape::OpenAiResponses` variant would
/// be dead code in Mode A — Codex CLI users on the localhost
/// relay would silently get no preserve-tokens lift.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_injects_preserve_tokens_system_prompt_into_responses_request() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/responses").await?;
    let config = RelayConfig {
        anthropic_upstream: "http://127.0.0.1:1".to_string(),
        openai_upstream: format!("http://{}", upstream.addr),
        inject_system_prompt: true,
    };
    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let _ = client
        .post(format!("http://{relay_addr}/v1/responses"))
        .header("authorization", "Bearer fake-test-key")
        .json(&json!({
            "model": "gpt-5-mini",
            "input": "Debug AKIAIOSFODNN7EXAMPLE on S3.",
        }))
        .send()
        .await?;

    let captured = upstream.last_body.lock().unwrap().clone().expect("body");
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&captured)?)?;

    // Top-level `instructions` carries our prompt as a string.
    let instructions = parsed["instructions"].as_str().expect("instructions is string");
    assert!(
        instructions.starts_with(proxy_core::PRESERVE_TOKENS_PROMPT),
        "preserve-tokens prompt must be at the front of `instructions`; got: {instructions}",
    );

    // Redaction still ran ahead of injection — pair pins ordering.
    let user_input = parsed["input"].as_str().expect("input is string");
    assert!(user_input.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"));
    assert!(!user_input.contains("AKIAIOSFODNN7EXAMPLE"));

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Pins the `--no-system-prompt` opt-out for Mode A. With injection
/// off, the forwarded body must NOT contain our preserve-tokens
/// text — redaction still runs. Mirrors the Mode B
/// `mitm_does_not_inject_when_disabled` test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_does_not_inject_when_disabled() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/messages").await?;
    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(),
        inject_system_prompt: false,
    };
    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let _ = client
        .post(format!("http://{relay_addr}/v1/messages"))
        .header("x-api-key", "fake-test-key")
        .json(&json!({
            "model": "claude-opus-4-5",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"}],
        }))
        .send()
        .await?;

    let captured = upstream.last_body.lock().unwrap().clone().expect("body");
    let captured_str = std::str::from_utf8(&captured)?;
    let parsed: Value = serde_json::from_str(captured_str)?;
    assert!(
        parsed.get("system").is_none(),
        "system field must be absent when injection is off; got: {captured_str}"
    );
    assert!(
        captured_str.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"),
        "redaction must still run when injection is off"
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
/// surrounding prose ("Your " and " needs s3:GetObject."). The
/// cross-event-split case (placeholder fragments span events) is
/// the harder failure mode and is captured by
/// `phase_2c_relay_reverses_placeholder_split_across_sse_events`
/// (uses `spawn_upstream_returning_sse_with_split_placeholder`).
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
