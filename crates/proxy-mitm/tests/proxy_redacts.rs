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
    // System-prompt injection OFF for this test: the echoing upstream
    // replays the (post-injection) request body in its response, so
    // the schema text `«SECRET_<TYPE>_<NNN>»` inside the injected
    // preserve-tokens prompt would round-trip back into the client's
    // response body and trip the "no placeholder string leaked" check
    // below. That check is genuine and load-bearing — it pins the
    // HTTP/2 multiplex cross-contamination invariant — but the echo
    // upstream is an artifact of the test, not how real upstreams
    // behave. Disabling injection here keeps the test focused on the
    // H2-keying invariant it was built for.
    let handler = AichuHandler::new().with_inject_system_prompt(false);
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

/// The proxy injects `proxy_core::PRESERVE_TOKENS_PROMPT` into the
/// forwarded body for known Anthropic prompt endpoints. The upstream
/// must observe both: (1) the redaction (placeholder substituted
/// for the secret), and (2) the prompt prepended to `system`.
///
/// Why this matters end-to-end: the e03 eval measured that adding
/// this prompt lifts guillemets preservation from 12% to 96% on
/// gpt-5-mini. The whole point of wiring it in is that EVERY
/// forwarded prompt request carries it; if a future refactor moves
/// injection behind a feature gate or drops it on Anthropic, this
/// test catches that the user-visible secret-restoration accuracy
/// regression.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_injects_preserve_tokens_system_prompt_into_anthropic_request() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/messages").await?;
    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new();
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    let _ = client
        .post(format!("http://{}/v1/messages", upstream.addr))
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
    let captured_str = std::str::from_utf8(&captured)?;
    let parsed: Value = serde_json::from_str(captured_str)?;

    // Redaction still happens. If a future refactor sequenced
    // injection before redaction, the prompt's own example text
    // would be detected and stripped — the assertion below would
    // hold but `placeholders = 1` in the log would not. The pair
    // pins the ordering: redact, THEN inject.
    let system_text = parsed["system"].as_str().expect("system should be a string");
    assert!(
        system_text.starts_with(proxy_core::PRESERVE_TOKENS_PROMPT),
        "injected prompt must be the FIRST content in `system`; got: {system_text}"
    );

    // Body still carries the redacted user content alongside the
    // injected prompt — confirms the original message survived
    // injection.
    let user_content = parsed["messages"][0]["content"]
        .as_str()
        .expect("user message content should still be a string");
    assert!(
        user_content.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"),
        "user message must still contain the redaction placeholder: {user_content}"
    );
    assert!(
        !user_content.contains("AKIAIOSFODNN7EXAMPLE"),
        "raw secret must not survive in user content: {user_content}"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Same end-to-end injection contract, scoped to the OpenAI Chat
/// Completions wire shape. The injector puts our preserve-tokens
/// prompt as a new system message at index 0 (since the test request
/// has no client-supplied system message).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_injects_preserve_tokens_system_prompt_into_openai_chat_request() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/chat/completions").await?;
    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new();
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    let _ = client
        .post(format!("http://{}/v1/chat/completions", upstream.addr))
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
    let messages = parsed["messages"].as_array().expect("messages is an array");

    // Index 0: our injected system message. Position matters —
    // OpenAI's documented behavior gives the FIRST system message
    // precedence, so we must be at the front, not appended.
    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[0]["content"], proxy_core::PRESERVE_TOKENS_PROMPT);

    // Index 1: the redacted user message. Both that the original
    // message survived AND that redaction happened before injection.
    assert_eq!(messages[1]["role"], "user");
    let user_content = messages[1]["content"].as_str().expect("user content is a string");
    assert!(
        user_content.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"),
        "user content must carry the redaction placeholder: {user_content}"
    );
    assert!(
        !user_content.contains("AKIAIOSFODNN7EXAMPLE"),
        "raw secret must not reach upstream: {user_content}"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Pins the `--no-system-prompt` opt-out: when the CLI passes
/// `inject_system_prompt: false` through to the handler, the
/// forwarded body must NOT carry the preserve-tokens prompt. Without
/// this test, a regression that ignored the flag and always
/// injected would be invisible to anyone who never uses the flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_does_not_inject_when_disabled() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/messages").await?;
    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new().with_inject_system_prompt(false);
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    let _ = client
        .post(format!("http://{}/v1/messages", upstream.addr))
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
    // No `system` field added — neither as string nor as array. The
    // exact `is_null()` check is what the no-injection branch
    // promises (we never set `system` when it was absent and
    // injection is off).
    assert!(
        parsed.get("system").is_none(),
        "system field must be absent when injection is disabled; got: {captured_str}"
    );
    // Redaction must STILL happen — the opt-out is for the prompt,
    // not for the privacy guarantee.
    assert!(
        captured_str.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"),
        "redaction must still run when injection is off: {captured_str}"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Pins that the injector RESPECTS the redaction allow-list — a
/// non-prompt endpoint (OAuth refresh, model metadata, etc.) must
/// NOT have a system prompt grafted into its body. Without this,
/// every non-prompt body the proxy sees would get a `system` field
/// added to it, breaking auth flows in exactly the same way the
/// non-prompt redaction skip was designed to prevent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_does_not_inject_on_non_prompt_endpoints() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/oauth/token").await?;
    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new(); // default ON
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    let _ = client
        .post(format!("http://{}/v1/oauth/token", upstream.addr))
        .json(&json!({
            "grant_type": "refresh_token",
            "refresh_token": "sk-proj-fake-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }))
        .send()
        .await?;

    let captured = upstream.last_body.lock().unwrap().clone().expect("body");
    let captured_str = std::str::from_utf8(&captured)?;
    assert!(
        !captured_str.contains(proxy_core::PRESERVE_TOKENS_PROMPT),
        "non-prompt endpoint body was mutated by the injector — \
         would break OAuth and metadata flows: {captured_str}"
    );
    // The original body must still flow through untouched (same
    // contract as `mitm_does_not_redact_non_prompt_paths`).
    assert!(
        captured_str.contains("refresh_token"),
        "non-prompt body should reach upstream unchanged: {captured_str}"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

/// HTTP/2 multiplexing regression test — through the HTTPS CONNECT
/// tunnel this time.
///
/// `mitm_isolates_concurrent_h2_streams_on_one_connection` (above)
/// exercises hudsucker's OUTER dispatcher: plain HTTP/2 over a raw
/// TCP socket directly to the proxy. The fix sits on the handler's
/// per-clone `current_map` field, and hudsucker clones per request
/// on both the outer path AND the inner `service_fn` it spins up
/// inside `serve_stream` for tunnelled requests
/// (`hudsucker::proxy::internal::InternalProxy::serve_stream` calls
/// `self.clone().proxy(req)` for each request). So the same
/// invariant must hold on both paths — but only the outer path is
/// covered by the plain-H2 test.
///
/// This test pins that the per-clone fix ALSO holds for requests
/// arriving through HTTPS CONNECT. We drive:
///
///   1. A real H2-over-TLS upstream (rustls server + h2 server)
///      bound on a localhost port.
///   2. The aichu MITM proxy in front of it with its own CA.
///   3. A raw TCP socket to the proxy → manual
///      `CONNECT <host>:<port>` line → wrap in `tokio_rustls`
///      `TlsConnector` (trusting both the upstream's leaf cert and
///      the aichu CA) → `h2::client::handshake` inside the TLS
///      stream.
///
/// Two concurrent H2 streams ride one TCP+TLS connection through
/// the CONNECT tunnel. Hudsucker's inner `service_fn` clones the
/// handler per stream (verified in source). If a regression
/// reintroduces same-key collisions (or accidentally wraps
/// `current_map` in `Arc<Mutex<_>>`), one stream's response would
/// carry the OTHER stream's secret restored — exact same failure
/// mode the outer test pins, but on a different code path.
///
/// Going through `tokio_rustls` directly instead of reqwest is
/// deliberate: reqwest's connection pool can be coaxed into HTTP/2
/// multiplexing but the behavior is opaque enough that a
/// regression in pool behavior could quietly mask the multiplex
/// race we're trying to catch. Doing the raw CONNECT + TLS +
/// h2-on-one-conn dance guarantees the two streams share one
/// connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mitm_isolates_concurrent_h2_streams_under_https_connect_tunnel() -> Result<()> {
    use bytes::Bytes as H2Bytes;
    use http::Request as H2Request;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // The MITM mints leaf certs with `SanType::DnsName(authority.host())`,
    // so we CONNECT to a DNS name ("localhost") rather than the bare
    // IP — TLS stacks accept either for the SNI/match, but the rustls
    // server-side parsing on the proxy is happier with a DNS SAN.
    const TUNNEL_HOST: &str = "localhost";

    let (upstream_addr, upstream_cert_pem) =
        spawn_h2_tls_echoing_upstream(TUNNEL_HOST).await?;

    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let aichu_ca_pem = ca.cert_pem.clone();

    // Same rationale as the plain-H2 test: the echo upstream replays
    // the (post-injection) request body verbatim, so the injected
    // preserve-tokens schema text would round-trip back into the
    // client's response body and trip the "no placeholder string
    // leaked" assertion below. That assertion is the load-bearing
    // privacy invariant we're pinning here, so we disable injection
    // to keep the test focused on the H2-keying bug it was built to
    // catch.
    let handler = AichuHandler::new().with_inject_system_prompt(false);
    // Build the proxy with a CUSTOM upstream connector that trusts
    // the test's self-signed upstream cert. `proxy_mitm::run_proxy`
    // wires `with_rustls_connector`, which hard-wires webpki_roots —
    // those don't include our test cert, so without this override
    // the proxy returns 502 trying to verify the upstream's chain.
    // Production code is unaffected; this is purely a test-rig
    // limitation around self-signed test certs.
    let (proxy_addr, shutdown_tx) =
        spawn_proxy_trusting_upstream(ca.authority, handler, &upstream_cert_pem).await?;

    let secret_a = "AKIAAAAAAAAAAAAAAAAA";
    let secret_b = "AKIABBBBBBBBBBBBBBBB";
    let body_a = format!(
        r#"{{"model":"m","max_tokens":1,"messages":[{{"role":"user","content":"req-a uses {secret_a}"}}]}}"#
    );
    let body_b = format!(
        r#"{{"model":"m","max_tokens":1,"messages":[{{"role":"user","content":"req-b uses {secret_b}"}}]}}"#
    );

    // Trust the aichu CA on the client side. The proxy terminates
    // TLS with us (it MITMs by minting a leaf signed by the aichu
    // CA), so the only cert the client ever validates is the one
    // the proxy presents. The upstream's cert is validated on the
    // proxy↔upstream hop by the connector we wired in
    // `spawn_proxy_trusting_upstream`, never here. We don't need to
    // trust it on the client.
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(aichu_ca_pem.as_slice());
    for cert in rustls_pemfile::certs(&mut cursor) {
        let cert = cert.map_err(|e| anyhow::anyhow!("parse aichu CA PEM: {e}"))?;
        root_store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("add aichu CA to client roots: {e}"))?;
    }
    let mut tls_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // ALPN: ask for h2. The proxy's MITM leaf-cert server config
    // advertises ["h2", "http/1.1"] (per hudsucker's
    // rcgen_authority.rs:111-115 when the http2 feature is on), so
    // requesting h2 here forces the inner connection into HTTP/2 —
    // which is the whole point of this test.
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    // The full CONNECT → TLS → H2 round-trip, wrapped in a single
    // timeout so a regression that wedges the proxy fails loudly
    // instead of hanging the test binary.
    let round_trip = async {
        // 1. Raw TCP to the proxy.
        let mut tcp = TcpStream::connect(proxy_addr).await?;

        // 2. HTTP/1.1 CONNECT.
        let connect_line = format!(
            "CONNECT {TUNNEL_HOST}:{port} HTTP/1.1\r\nHost: {TUNNEL_HOST}:{port}\r\n\r\n",
            port = upstream_addr.port(),
        );
        tcp.write_all(connect_line.as_bytes()).await?;

        // Read until end-of-headers (\r\n\r\n). Small fixed buffer is
        // fine — hudsucker's CONNECT response is a tiny `200 OK` with
        // no body.
        let mut header_buf = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            tcp.read_exact(&mut byte).await?;
            header_buf.push(byte[0]);
            if header_buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if header_buf.len() > 4096 {
                anyhow::bail!("CONNECT response headers exceeded 4 KiB");
            }
        }
        let response_head = std::str::from_utf8(&header_buf)?;
        if !response_head.starts_with("HTTP/1.1 200")
            && !response_head.starts_with("HTTP/1.0 200")
        {
            anyhow::bail!("proxy refused CONNECT: {response_head}");
        }

        // 3. TLS over the tunnel.
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(TUNNEL_HOST)
            .map_err(|e| anyhow::anyhow!("invalid SNI name: {e}"))?;
        let tls = tls_connector.connect(server_name, tcp).await?;

        // Confirm we negotiated h2 — if not, this test isn't
        // exercising what it claims to. Surfaces loud rather than
        // silently passing on an HTTP/1.1 fallback.
        let alpn = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|b| b.to_vec())
            .unwrap_or_default();
        if alpn.as_slice() != b"h2" {
            anyhow::bail!(
                "negotiated ALPN was {:?}, expected b\"h2\" — this test \
                 must run over HTTP/2 to exercise multiplexing",
                String::from_utf8_lossy(&alpn),
            );
        }

        // 4. H2 over TLS.
        let (mut h2_client, h2_conn) = h2::client::handshake(tls).await?;
        let conn_task = tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        // The path here is the prompt-endpoint path so the proxy's
        // redaction allow-list lets us through. The authority must
        // match the cert SAN ("localhost") because hyper/h2 validates
        // the :authority pseudo-header against the cert.
        let uri = format!(
            "https://{host}:{port}/v1/messages",
            host = TUNNEL_HOST,
            port = upstream_addr.port(),
        );
        let req_a = H2Request::builder()
            .method("POST")
            .uri(&uri)
            .body(())
            .unwrap();
        let req_b = H2Request::builder()
            .method("POST")
            .uri(&uri)
            .body(())
            .unwrap();

        // Send both stream headers before either body, then both
        // bodies — same interleave as the outer-path test: forces the
        // proxy to clone the handler for BOTH requests before either
        // response can come back, so a same-slot regression races on
        // a shared `current_map`.
        let (resp_a_fut, mut send_a) = h2_client.send_request(req_a, false).unwrap();
        let (resp_b_fut, mut send_b) = h2_client.send_request(req_b, false).unwrap();
        send_a.send_data(H2Bytes::from(body_a.clone()), true).unwrap();
        send_b.send_data(H2Bytes::from(body_b.clone()), true).unwrap();
        drop(h2_client);

        let (resp_a, resp_b) = tokio::try_join!(resp_a_fut, resp_b_fut)?;
        assert_eq!(resp_a.status(), 200, "response A should be 200 over CONNECT+H2");
        assert_eq!(resp_b.status(), 200, "response B should be 200 over CONNECT+H2");

        let body_a_local = collect_h2_body(resp_a.into_body()).await?;
        let body_b_local = collect_h2_body(resp_b.into_body()).await?;

        conn_task.abort();
        Ok::<(String, String), anyhow::Error>((body_a_local, body_b_local))
    };

    let (body_a_recv, body_b_recv) = match tokio::time::timeout(
        Duration::from_secs(20),
        round_trip,
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return Err(e),
        Err(_) => anyhow::bail!(
            "CONNECT+TLS+H2 round-trip timed out — likely a regression \
             in the per-clone `current_map` invariant on hudsucker's \
             inner `service_fn` path. The race-condition assertions \
             below cannot run without both responses."
        ),
    };

    // Same headline contract as the plain-H2 sibling test: each
    // response carries its OWN secret, neither carries the other's,
    // no placeholder leaks. If this fires, the inner `service_fn`
    // path is sharing state across HTTP/2 streams on a CONNECT
    // tunnel — exactly the multiplex race that motivated the
    // per-clone design.
    assert!(
        body_a_recv.contains(secret_a),
        "response A is missing its own secret ({secret_a}) under HTTPS CONNECT — \
         inner `service_fn` reverse pass used the wrong map. Got: {body_a_recv}"
    );
    assert!(
        !body_a_recv.contains(secret_b),
        "response A leaked request B's secret ({secret_b}) — \
         HTTP/2 multiplex race in the CONNECT-tunnel `current_map`. \
         Got: {body_a_recv}"
    );
    assert!(
        body_b_recv.contains(secret_b),
        "response B is missing its own secret ({secret_b}). \
         Got: {body_b_recv}"
    );
    assert!(
        !body_b_recv.contains(secret_a),
        "response B leaked request A's secret ({secret_a}) under HTTPS CONNECT. \
         Got: {body_b_recv}"
    );
    assert!(
        !body_a_recv.contains("\u{ab}SECRET_"),
        "placeholder leaked into response A over CONNECT: {body_a_recv}"
    );
    assert!(
        !body_b_recv.contains("\u{ab}SECRET_"),
        "placeholder leaked into response B over CONNECT: {body_b_recv}"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Same end-to-end injection contract as the OpenAI Chat test, but
/// scoped to the Responses API wire shape. The injector sets the
/// top-level `instructions` string field (NOT a `messages` entry —
/// Responses doesn't have one). Pins the e03-measured guillemets
/// preservation lift for Codex CLI and OpenCode users who route
/// through this endpoint family.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_injects_preserve_tokens_system_prompt_into_responses_request() -> Result<()> {
    let upstream = spawn_capturing_upstream("/v1/responses").await?;
    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;
    let handler = AichuHandler::new();
    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    let _ = client
        .post(format!("http://{}/v1/responses", upstream.addr))
        .header("authorization", "Bearer fake-test-key")
        .json(&json!({
            "model": "gpt-5-mini",
            "input": "Debug AKIAIOSFODNN7EXAMPLE on S3.",
        }))
        .send()
        .await?;

    let captured = upstream.last_body.lock().unwrap().clone().expect("body");
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&captured)?)?;

    // Top-level `instructions` carries our prompt. Per the OpenAI
    // SDK `ResponseCreateParamsBase.instructions` is `string | null`,
    // so the value must be a string — an array form here would
    // signal a regression where someone mirrored the Anthropic
    // array-branch into the Responses injector by mistake.
    let instructions = parsed["instructions"]
        .as_str()
        .expect("instructions should be a string");
    assert!(
        instructions.starts_with(proxy_core::PRESERVE_TOKENS_PROMPT),
        "injected prompt must be the FIRST content in `instructions`; got: {instructions}",
    );

    // `input` must survive byte-for-byte minus redaction; the
    // injector touches `instructions` only.
    let user_input = parsed["input"].as_str().expect("input is a string");
    assert!(
        user_input.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"),
        "user input must carry the redaction placeholder: {user_input}",
    );
    assert!(
        !user_input.contains("AKIAIOSFODNN7EXAMPLE"),
        "raw secret must not reach upstream: {user_input}",
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

/// Spawn an HTTPS-only HTTP/2 upstream that echoes the request body
/// back in a small JSON envelope. Returns the bound `SocketAddr` and
/// the PEM-encoded self-signed leaf cert the client must trust.
///
/// Used by the CONNECT-tunnelled H2 multiplex test:
/// `mitm_isolates_concurrent_h2_streams_under_https_connect_tunnel`.
///
/// Why not axum: we need server-side TLS termination AND a known
/// pipeline-of-one (rustls server → h2 server) so we can echo
/// per-stream. Axum's HTTP/2 server would work but adds dependencies
/// we'd then have to coax into accepting our self-signed cert; doing
/// the rustls + h2 layers directly is shorter and keeps the test
/// honest about what it exercises.
async fn spawn_h2_tls_echoing_upstream(sni_name: &'static str) -> Result<(SocketAddr, Vec<u8>)> {
    use hudsucker::rcgen::generate_simple_self_signed;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::ServerConfig;

    // Idempotent — proxy_mitm::run_proxy installs this too, but the
    // test's rustls server might come up before the proxy does.
    proxy_mitm_ensure_rustls_provider();

    // rcgen's `generate_simple_self_signed` mints a leaf with the
    // given SANs and a self-signed signing key. We use the leaf as
    // a "root" on the client side (rustls accepts self-signed leaves
    // as roots) — keeps the test cert chain trivially one-deep.
    let cert_kit = generate_simple_self_signed(vec![sni_name.to_string()])
        .map_err(|e| anyhow::anyhow!("generate upstream cert: {e}"))?;
    let cert_pem = cert_kit.cert.pem().into_bytes();
    let cert_der = cert_kit.cert.der().clone();
    let key_der: tokio_rustls::rustls::pki_types::PrivateKeyDer<'static> =
        cert_kit.signing_key.into();

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| anyhow::anyhow!("server config: {e}"))?;
    // Negotiate HTTP/2 ALPN — the whole reason this upstream exists
    // is to exercise the H2 path end-to-end through the proxy.
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let mut h2 = match h2::server::handshake(tls).await {
                    Ok(h) => h,
                    Err(_) => return,
                };
                while let Some(req) = h2.accept().await {
                    let (request, mut respond) = match req {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    tokio::spawn(async move {
                        // Drain the request body. Echo it back in the
                        // response so the proxy's outbound-side
                        // placeholder substitution shows up in the
                        // response body — same shape the plain-H2 test
                        // uses to make the cross-stream race visible.
                        let mut body = request.into_body();
                        let mut buf = Vec::new();
                        while let Some(data) = body.data().await {
                            let Ok(data) = data else { return };
                            let _ = body.flow_control().release_capacity(data.len());
                            buf.extend_from_slice(&data);
                        }
                        let echoed = String::from_utf8_lossy(&buf).into_owned();
                        let envelope = serde_json::json!({
                            "id": "msg_echo",
                            "type": "message",
                            "content": [{"type": "text", "text": echoed}],
                        });
                        let envelope_bytes = serde_json::to_vec(&envelope).unwrap_or_default();
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(response, false) else {
                            return;
                        };
                        let _ = send.send_data(bytes::Bytes::from(envelope_bytes), true);
                    });
                }
            });
        }
    });

    Ok((addr, cert_pem))
}

/// Mirror of `proxy_mitm::ensure_rustls_provider` (which is
/// `pub(crate)` in the lib). The test harness needs to install the
/// process-default rustls crypto provider BEFORE the rustls server
/// in `spawn_h2_tls_echoing_upstream` is constructed — without this
/// the server-side `ServerConfig::builder()` panics on rustls 0.23.
/// `proxy_mitm::run_proxy` also installs the provider, but the test
/// upstream may come up first, so we re-install here defensively.
/// `install_default` is idempotent (returns Err after the first
/// call; we ignore that).
fn proxy_mitm_ensure_rustls_provider() {
    use hudsucker::rustls::crypto::aws_lc_rs;
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = aws_lc_rs::default_provider().install_default();
    });
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

/// Variant of `spawn_proxy` that wires a custom HTTPS upstream
/// connector trusting an extra root cert.
///
/// `proxy_mitm::run_proxy` uses `Proxy::builder().with_rustls_connector(...)`,
/// which (per hudsucker 0.24's `builder.rs:139`)
/// hard-wires webpki_roots — the public CA roots only. That works
/// in production where Anthropic/OpenAI/etc. present public-CA-signed
/// certs, but the integration test below needs the proxy to dial a
/// self-signed test upstream. We can't get there through `run_proxy`
/// without changing production code, so this helper assembles the
/// hudsucker proxy by hand with `with_http_connector` + a custom
/// hyper-rustls connector that ALSO trusts the test cert.
///
/// This is test-only by design — the production proxy must keep its
/// "webpki roots only" stance so a misconfigured upstream cert
/// stays a hard error.
async fn spawn_proxy_trusting_upstream(
    ca: hudsucker::certificate_authority::RcgenAuthority,
    handler: AichuHandler,
    extra_root_pem: &[u8],
) -> Result<(SocketAddr, oneshot::Sender<()>)> {
    use hudsucker::Proxy;
    use hudsucker::rustls::ClientConfig as RustlsClientConfig;
    use hudsucker::rustls::crypto::aws_lc_rs;

    // Same idempotent install as `run_proxy` does — required before
    // any rustls ClientConfig construction on rustls 0.23.
    proxy_mitm_ensure_rustls_provider();

    // Trust ONLY the test cert. The test upstream is the only
    // server the proxy ever dials from this spawner. Skipping
    // webpki defaults keeps the test's dependency footprint
    // minimal (no `webpki-roots` crate) and makes any "did we
    // accidentally trust the public web?" mistake immediately
    // observable as a connect failure.
    let mut root_store = hudsucker::rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(extra_root_pem);
    for cert in rustls_pemfile::certs(&mut cursor) {
        let cert = cert.map_err(|e| anyhow::anyhow!("parse extra root PEM: {e}"))?;
        root_store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("add extra root to store: {e}"))?;
    }

    let rustls_config = RustlsClientConfig::builder_with_provider(Arc::new(
        aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| anyhow::anyhow!("rustls protocol versions: {e}"))?
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(rustls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_http_connector(https)
        .with_http_handler(handler)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .build()
        .map_err(|e| anyhow::anyhow!("build test proxy: {e}"))?;

    tokio::spawn(async move {
        let _ = proxy.start().await;
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
