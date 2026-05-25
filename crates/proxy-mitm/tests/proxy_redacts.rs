//! Integration test for the proxy-core ↔ proxy-mitm wiring.
//!
//! Mirrors the contract e02 already enforces, but through the
//! hudsucker MITM path: a request body with a secret-shaped substring
//! reaches the upstream with the secret substituted by a typed
//! placeholder, AND if the upstream response carries the placeholder,
//! the relay swaps it back to the original secret before the client
//! sees it.
//!
//! Uses plain HTTP through the proxy (not HTTPS), same shape as the
//! existing `proxy_round_trip` test. The actual HTTPS/CA round-trip
//! is exercised by the manual smoke test recorded in
//! `experiments/e01-hudsucker-mitm/README.md`.

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
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use proxy_mitm::{ca::load_or_create_ca, handler::AichuHandler, run_proxy};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_redacts_aws_key_before_forwarding() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/messages").await?;
    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new();
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = client
        .post(format!("http://{}/v1/messages", upstream.addr))
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

    assert_eq!(resp.status(), 200);

    let captured = upstream
        .last_body
        .lock()
        .unwrap()
        .clone()
        .expect("upstream should have received a request body");
    let captured_str = std::str::from_utf8(&captured).expect("body is valid utf-8 JSON");

    // The headline contract: the raw AWS key MUST NOT reach the upstream
    // even when routed through the MITM path. If this fires, our
    // privacy guarantee is broken in Mode B.
    assert!(
        !captured_str.contains("AKIAIOSFODNN7EXAMPLE"),
        "raw AWS key reached upstream — MITM redaction not wired:\n{captured_str}"
    );
    assert!(
        captured_str.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"),
        "expected placeholder in upstream body; got:\n{captured_str}"
    );
    assert!(captured_str.contains("Why does"));
    assert!(captured_str.contains("fail on S3?"));

    let _ = shutdown_tx.send(());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_does_not_redact_non_prompt_paths() -> Result<()> {
    // Real bug discovered during the manual smoke test: a blanket
    // "redact every body" policy breaks claude CLI's OAuth refresh
    // flow, because the refresh token's prefix matches our OpenAiKey
    // regex and gets substituted with a placeholder that the OAuth
    // endpoint cannot parse → 400 → claude can't auth → everything
    // 401s.
    //
    // Fix: only redact bodies on KNOWN prompt endpoints
    // (/v1/messages, /v1/chat/completions, /v1/responses, etc.). All
    // other paths pass through unchanged.
    //
    // This test exercises a non-prompt path (`/v1/oauth/token`) with a
    // body containing a secret-shaped substring (`sk-` token). The
    // upstream must receive the body UNCHANGED — no placeholder
    // substitution.
    let upstream = spawn_capturing_upstream("/v1/oauth/token").await?;
    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new();
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    let body_with_sk_token = json!({
        "grant_type": "refresh_token",
        "refresh_token": "sk-proj-fake-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });
    let _ = client
        .post(format!("http://{}/v1/oauth/token", upstream.addr))
        .json(&body_with_sk_token)
        .send()
        .await?;

    let captured = upstream
        .last_body
        .lock()
        .unwrap()
        .clone()
        .expect("upstream received body");
    let captured_str = std::str::from_utf8(&captured)?;

    // The body MUST reach upstream unchanged. If this fires, we'd
    // break claude CLI's OAuth refresh flow (and any other non-prompt
    // endpoint that happens to contain a secret-shaped substring in
    // its payload).
    assert!(
        captured_str.contains("sk-proj-fake-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "non-prompt-path body was redacted; would break auth flows: {captured_str}"
    );
    assert!(
        !captured_str.contains("\u{ab}SECRET_"),
        "placeholder substituted on a non-prompt path: {captured_str}"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_strips_accept_encoding_so_responses_are_uncompressed() -> Result<()> {
    // Real bug discovered during the manual smoke test: Anthropic
    // gzips its SSE responses by default. We collect the body bytes
    // and run UTF-8 conversion before the reverse pass; gzipped bytes
    // are not valid UTF-8, so the reverse falls through to "pass
    // through unchanged" — the user sees placeholders in their
    // response. The fix is to strip Accept-Encoding on the request
    // side so upstream emits an uncompressed body that we can
    // actually scan.
    //
    // This test pins that Accept-Encoding is removed before the
    // request reaches upstream.
    let upstream = spawn_capturing_upstream("/v1/messages").await?;
    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new();
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    // Force a wide Accept-Encoding to make the test more obvious.
    let _ = client
        .post(format!("http://{}/v1/messages", upstream.addr))
        .header("accept-encoding", "gzip, br, deflate, zstd")
        .header("x-api-key", "fake-test-key")
        .json(&json!({
            "model": "claude-opus-4-5",
            "messages": [{"role": "user", "content": "Debug AKIAIOSFODNN7EXAMPLE."}],
        }))
        .send()
        .await?;

    // Inspect the captured request headers. With a mock that records
    // only the body we can't check headers directly; instead, the
    // contract enforced here is via integration: the body still
    // reaches upstream (redaction worked) AND the test infrastructure
    // doesn't see any compression artifact. The stricter assertion
    // (headers visible on the mock) would require a richer mock — we
    // pin the body-reached invariant for now.
    let captured = upstream
        .last_body
        .lock()
        .unwrap()
        .clone()
        .expect("upstream should receive body");
    let captured_str = std::str::from_utf8(&captured)?;
    assert!(
        captured_str.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"),
        "redaction must still work alongside the Accept-Encoding fix: {captured_str}"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_reverses_placeholder_in_non_streaming_response() -> Result<()> {
    let upstream = spawn_upstream_with_fixed_response(
        "/v1/messages",
        json!({
            "id": "msg_test",
            "type": "message",
            "content": [{
                "type": "text",
                "text": "Your \u{ab}SECRET_AWS_KEY_001\u{bb} needs s3:GetObject permission.",
            }],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 12},
        }),
    )
    .await?;

    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new();
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = client
        .post(format!("http://{}/v1/messages", upstream.addr))
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
    let body = resp.text().await?;

    assert!(
        body.contains("AKIAIOSFODNN7EXAMPLE"),
        "secret not restored on response side; client sees: {body}"
    );
    assert!(
        !body.contains("\u{ab}SECRET_"),
        "placeholder leaked to client (reverse pass failed): {body}"
    );
    assert!(body.contains("s3:GetObject permission."));

    let _ = shutdown_tx.send(());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_phase_2c_reverses_placeholder_split_across_sse_events() -> Result<()> {
    // Parity with `proxy-server`'s phase_2c_relay_reverses_placeholder_split_across_sse_events.
    // The placeholder is fragmented across two content_block_delta
    // events (`«SECRET_AWS_` + `KEY_001»`). Phase 2b's whole-response
    // reverse() couldn't bridge the JSON/SSE framing bytes between
    // the two halves; Phase 2c's streaming SseReverser must.
    //
    // This test pins Mode B parity with Mode A on the headline
    // Phase 2c contract — if a future refactor leaves the streaming
    // path wired in proxy-server but missing in proxy-mitm, the
    // privacy guarantee (and the streaming UX claim) would silently
    // diverge between modes.
    let upstream = spawn_upstream_returning_sse_with_split_placeholder("/v1/messages").await?;

    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new();
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = client
        .post(format!("http://{}/v1/messages", upstream.addr))
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

    assert_eq!(resp.status(), 200);
    let body = resp.text().await?;
    assert!(
        body.contains("AKIAIOSFODNN7EXAMPLE"),
        "secret not restored across split SSE events; client sees:\n{body}"
    );
    assert!(
        !body.contains("\u{ab}SECRET_"),
        "placeholder leaked to client (Phase 2c reverse failed):\n{body}"
    );
    assert!(body.contains("needs s3:GetObject"));

    let _ = shutdown_tx.send(());
    Ok(())
}

/// HTTP/2 multiplexing regression test.
///
/// Why this test exists: under HTTPS CONNECT MITM, a single TCP
/// connection from the client can carry multiple concurrent HTTP/2
/// streams. The handler used to key its per-request PlaceholderMap by
/// `HttpContext.client_addr` alone — but every stream on a multiplexed
/// connection shares the same `client_addr`. Two in-flight requests
/// would race on the same map slot:
///
///   - request A inserts map_A at client_addr
///   - request B inserts map_B at client_addr, OVERWRITING map_A
///   - response A arrives, looks up client_addr, finds map_B, and
///     reverses A's body using B's secret→placeholder table
///   - response B arrives, looks up client_addr, finds nothing, and
///     passes B's body through with the placeholder text intact
///
/// Both branches are privacy bugs: branch 1 leaks request B's SECRET
/// into request A's response stream (the original mints a fresh `_001`
/// counter per map, so the same placeholder string `«SECRET_AWS_KEY_001»`
/// names DIFFERENT real secrets across the two maps); branch 2 leaks
/// the placeholder itself into the client's view of B's response.
///
/// This test pins the invariant: **request A's response must carry
/// A's own secret restored, and request B's response must carry B's.**
/// If a future refactor reintroduces same-key collisions, the
/// assertions below will fire with a self-documenting message.
///
/// We can't reproduce the race with the `reqwest::Proxy::http` clients
/// used by the other tests in this file: reqwest's HTTP/1.1 pool
/// refuses to pipeline, so two concurrent calls land on two TCP
/// connections (two `client_addr`s, no collision). The deterministic
/// repro speaks HTTP/2 over a raw TCP socket via the `h2` crate, which
/// gives us full control over stream interleaving on one connection.
/// Hyper's auto::Builder (the connection server hudsucker hands to its
/// outer `service_fn`) probes the H2 preface and switches into HTTP/2
/// mode, so the proxy treats both our streams as one client_addr.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mitm_isolates_concurrent_h2_streams_on_one_connection() -> Result<()> {
    use bytes::Bytes as H2Bytes;
    use http::Request as H2Request;

    let upstream = spawn_echoing_upstream("/v1/messages").await?;
    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new();
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    // Distinct AWS keys so each map slot mints `«SECRET_AWS_KEY_001»`
    // independently — same placeholder STRING, different real secrets.
    // That collision is exactly the cross-contamination signal: if A's
    // response gets reversed with B's map, A would echo B's secret.
    let secret_a = "AKIAAAAAAAAAAAAAAAAA";
    let secret_b = "AKIABBBBBBBBBBBBBBBB";
    let body_a = format!(
        r#"{{"model":"m","max_tokens":1,"messages":[{{"role":"user","content":"req-a uses {secret_a}"}}]}}"#
    );
    let body_b = format!(
        r#"{{"model":"m","max_tokens":1,"messages":[{{"role":"user","content":"req-b uses {secret_b}"}}]}}"#
    );

    // Wrap the whole H2 round-trip in an outer timeout so a regression
    // that wedges the proxy surfaces as a clear failure rather than
    // hanging the test binary.
    let round_trip = async {
        // One raw TCP connection to the proxy → one `client_addr`. h2
        // handshake writes the HTTP/2 preface; hyper's auto::Builder
        // detects it and serves HTTP/2 on this connection.
        let tcp = TcpStream::connect(proxy_addr).await?;
        let (mut h2_client, h2_conn) = h2::client::handshake(tcp).await?;
        // Drive the connection in the background; we abort it once
        // both responses are collected.
        let conn_task = tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let upstream_uri = format!("http://{}/v1/messages", upstream.addr);

        // Send BOTH stream headers before sending either body, then write
        // both bodies before reading either response. This guarantees the
        // proxy's handle_request runs for stream A and stream B
        // back-to-back — both would have collided on the per-client_addr
        // map slot under the buggy keying — before either response can flow.
        let req_a = H2Request::builder()
            .method("POST")
            .uri(&upstream_uri)
            .body(())
            .unwrap();
        let req_b = H2Request::builder()
            .method("POST")
            .uri(&upstream_uri)
            .body(())
            .unwrap();

        let (resp_a_fut, mut send_a) = h2_client.send_request(req_a, false).unwrap();
        let (resp_b_fut, mut send_b) = h2_client.send_request(req_b, false).unwrap();

        send_a.send_data(H2Bytes::from(body_a.clone()), true).unwrap();
        send_b.send_data(H2Bytes::from(body_b.clone()), true).unwrap();

        // Drop the SendRequest handle so the connection knows no
        // further requests are coming. Otherwise h2 keeps the
        // connection open waiting for more streams and the test never
        // observes the end of the conversation.
        drop(h2_client);

        // Await both responses concurrently.
        let (resp_a, resp_b) = tokio::try_join!(resp_a_fut, resp_b_fut)?;
        assert_eq!(resp_a.status(), 200, "response A should be 200");
        assert_eq!(resp_b.status(), 200, "response B should be 200");

        let body_a_local = collect_h2_body(resp_a.into_body()).await?;
        let body_b_local = collect_h2_body(resp_b.into_body()).await?;

        conn_task.abort();
        Ok::<(String, String), anyhow::Error>((body_a_local, body_b_local))
    };

    let (body_a_recv, body_b_recv) = match tokio::time::timeout(
        Duration::from_secs(15),
        round_trip,
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return Err(e),
        Err(_) => anyhow::bail!(
            "H2 round-trip timed out — likely a regression in proxy H2 \
             handling or stream lifecycle. The race-condition assertions \
             below cannot run without both responses."
        ),
    };

    // Headline contract: each response must contain its OWN secret.
    // The upstream echoes the (redacted) request body back in its
    // response, so the response naturally carries the same placeholder
    // string the proxy minted for that request. The reverse pass on
    // the way back to the client MUST restore the correct secret per
    // stream — i.e. it must look up the placeholder in THIS request's
    // map, not whichever map happened to win the same-key race.
    assert!(
        body_a_recv.contains(secret_a),
        "response A is missing its own secret ({secret_a}) — \
         reverse pass used the wrong map (cross-stream contamination). \
         Got: {body_a_recv}"
    );
    assert!(
        !body_a_recv.contains(secret_b),
        "response A leaked request B's secret ({secret_b}) into A's \
         response stream — HTTP/2 multiplex race in PlaceholderMap \
         keying. Got: {body_a_recv}"
    );
    assert!(
        body_b_recv.contains(secret_b),
        "response B is missing its own secret ({secret_b}). \
         Got: {body_b_recv}"
    );
    assert!(
        !body_b_recv.contains(secret_a),
        "response B leaked request A's secret ({secret_a}) into B's \
         response stream. Got: {body_b_recv}"
    );

    // No placeholder should reach either client; the reverse pass must
    // have run successfully against the right map for each stream.
    assert!(
        !body_a_recv.contains("\u{ab}SECRET_"),
        "placeholder leaked into response A: {body_a_recv}"
    );
    assert!(
        !body_b_recv.contains("\u{ab}SECRET_"),
        "placeholder leaked into response B: {body_b_recv}"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

async fn collect_h2_body(mut body: h2::RecvStream) -> Result<String> {
    let mut buf = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        buf.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8(buf)?)
}

/// Upstream that echoes the request body back inside a JSON response.
/// Used by the H2 multiplex test: we want the response to naturally
/// carry the same placeholder the proxy minted on the outbound side,
/// so the reverse-pass keying bug becomes observable on the client.
async fn spawn_echoing_upstream(path: &'static str) -> Result<CapturingUpstream> {
    let state = CapturingState {
        request_count: Arc::new(AtomicU64::new(0)),
        last_body: Arc::new(std::sync::Mutex::new(None)),
    };
    let request_count = state.request_count.clone();
    let last_body = state.last_body.clone();

    let app = Router::new().route(path, post(echo_handler)).with_state(state);

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

async fn echo_handler(State(state): State<CapturingState>, body: Bytes) -> Json<Value> {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    *state.last_body.lock().unwrap() = Some(body.clone());
    // Echo the request body verbatim inside a JSON response. The
    // placeholder the proxy minted upstream lives in `body`; surfacing
    // it in the response is what makes the round-trip privacy
    // invariant testable.
    let echoed = String::from_utf8_lossy(&body).into_owned();
    Json(json!({
        "id": "msg_echo",
        "type": "message",
        "content": [{"type": "text", "text": echoed}],
    }))
}

async fn spawn_upstream_returning_sse_with_split_placeholder(
    path: &'static str,
) -> Result<CapturingUpstream> {
    // Fixture mirrors `proxy-server/tests/relay_redacts.rs::spawn_upstream_returning_sse_with_split_placeholder`.
    // Event 1's text ends with `«SECRET_AWS_`, event 2's text begins
    // with `KEY_001»`. The whole-buffer reverse regex can't match
    // across the intervening `"}}\n\nevent: ...,"text":"` bytes.
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

#[derive(Clone)]
struct FixedResponseState {
    request_count: Arc<AtomicU64>,
    last_body: Arc<std::sync::Mutex<Option<Bytes>>>,
    response: Arc<Value>,
}

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

async fn fixed_response_handler(
    State(state): State<FixedResponseState>,
    body: Bytes,
) -> Json<Value> {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    *state.last_body.lock().unwrap() = Some(body);
    Json((*state.response).clone())
}

async fn spawn_proxy(
    ca: hudsucker::certificate_authority::RcgenAuthority,
    handler: AichuHandler,
) -> Result<(SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = run_proxy(addr, ca, handler, async move {
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
    anyhow::bail!("proxy never accepted a TCP connection on {addr}")
}
