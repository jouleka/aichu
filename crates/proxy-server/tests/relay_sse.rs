//! Integration test: the e02 relay forwards a POST to an Anthropic-shaped
//! `/v1/messages` endpoint and streams the upstream's SSE response back to
//! the client unchanged.
//!
//! This is the RED test that drives the e02 implementation. The contract:
//! upstream receives the body exactly once, the SSE events arrive at the
//! client byte-for-byte intact, and the `text/event-stream` content type is
//! preserved across the relay hop.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::{
    Router,
    extract::State,
    response::sse::{Event, Sse},
    routing::post,
};
use futures_util::{StreamExt, stream};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use proxy_server::{RelayConfig, run_relay};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_streams_anthropic_sse_intact() -> Result<()> {
    let upstream = spawn_test_upstream().await?;

    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(), // unused for this test
        // Pre-existing tests opt out of the preserve-tokens system-
        // prompt injection so their body-content assertions stay
        // focused on the SSE forwarding contract being pinned here.
        // Injection has its own dedicated tests in relay_redacts.rs.
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
            "model": "claude-opus-4-7",
            "messages": [{ "role": "user", "content": "test" }],
            "stream": true,
        }))
        .send()
        .await?;

    assert_eq!(resp.status(), 200, "relay should propagate upstream 200");

    let ct = resp
        .headers()
        .get("content-type")
        .expect("missing content-type")
        .to_str()?;
    assert!(
        ct.starts_with("text/event-stream"),
        "expected SSE content-type from relay, got {ct:?}"
    );

    let text = resp.text().await?;

    // All three SSE events emitted by the upstream must arrive intact. We
    // don't pin byte-for-byte SSE serialization (line endings, keep-alive
    // comments are implementation-defined); we assert each payload is
    // present.
    assert!(text.contains("data: hello"), "missing 'hello' in: {text:?}");
    assert!(text.contains("data: world"), "missing 'world' in: {text:?}");
    assert!(text.contains("data: done"), "missing 'done' in: {text:?}");

    // The upstream must have received exactly one request — proves the
    // relay actually forwarded rather than short-circuiting locally.
    assert_eq!(
        upstream.request_count.load(Ordering::Relaxed),
        1,
        "upstream did not see exactly one forwarded request"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Proves two things this test file's first case cannot:
///
///   1. The `/v1/chat/completions` route is actually wired (e02's OpenAI
///      handler — separate from `/v1/messages`).
///   2. The relay STREAMS the response rather than buffering it. Without
///      this, an implementation that did `upstream.bytes().await` and
///      returned a single chunk would silently pass our other test.
///
/// We make the upstream sleep between SSE events. A streaming relay
/// surfaces those chunks to the client spread over time; a buffering relay
/// would deliver everything in one burst at the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_streams_openai_chat_completions_chunks_over_time() -> Result<()> {
    const GAP: Duration = Duration::from_millis(150);
    // Three events with two 150ms gaps between them → ≥300ms total emission
    // wall-clock. We require the client to observe a span ≥ 200ms between
    // first-byte and last-byte to call this "streaming".
    const STREAMING_SPAN_THRESHOLD: Duration = Duration::from_millis(200);

    let upstream = spawn_test_upstream_with_gap(
        "/v1/chat/completions",
        vec!["hello", "world", "done"],
        GAP,
    )
    .await?;

    let config = RelayConfig {
        anthropic_upstream: "http://127.0.0.1:1".to_string(), // unused
        openai_upstream: format!("http://{}", upstream.addr),
        // See the first test's rationale.
        inject_system_prompt: false,
    };

    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = client
        .post(format!("http://{relay_addr}/v1/chat/completions"))
        .header("authorization", "Bearer fake-test-key")
        .json(&json!({
            "model": "gpt-test",
            "messages": [{ "role": "user", "content": "test" }],
            "stream": true,
        }))
        .send()
        .await?;

    assert_eq!(resp.status(), 200, "relay should propagate upstream 200");
    let ct = resp
        .headers()
        .get("content-type")
        .expect("missing content-type")
        .to_str()?;
    assert!(
        ct.starts_with("text/event-stream"),
        "expected SSE content-type from relay, got {ct:?}"
    );

    // Read the body chunk-by-chunk, tracking when each arrives.
    let mut stream = resp.bytes_stream();
    let start = Instant::now();
    let mut first_at: Option<Duration> = None;
    let mut last_at: Option<Duration> = None;
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let t = start.elapsed();
        if first_at.is_none() {
            first_at = Some(t);
        }
        last_at = Some(t);
        buf.extend_from_slice(&chunk);
    }

    let first = first_at.expect("at least one chunk");
    let last = last_at.expect("at least one chunk");
    let span = last - first;

    let text = std::str::from_utf8(&buf)?;
    assert!(text.contains("data: hello"), "missing 'hello' in: {text:?}");
    assert!(text.contains("data: world"), "missing 'world' in: {text:?}");
    assert!(text.contains("data: done"), "missing 'done' in: {text:?}");

    // The streaming-proof assertion. If the relay buffered the upstream
    // response and emitted all chunks at once, span would be near zero.
    // With ≥300ms of upstream emission, a streaming relay shows the client
    // chunks spread over time.
    assert!(
        span >= STREAMING_SPAN_THRESHOLD,
        "expected response chunks to arrive over time (\u{2265}{STREAMING_SPAN_THRESHOLD:?}); \
         got span {span:?}. This usually means the relay is buffering instead of streaming."
    );

    assert_eq!(
        upstream.request_count.load(Ordering::Relaxed),
        1,
        "upstream did not see exactly one forwarded request"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Phase 2c contract: when the prompt contains a secret, the response
/// STILL streams chunk-by-chunk to the client. The cross-event-split
/// correctness test (`phase_2c_relay_reverses_placeholder_split_across_sse_events`
/// in `relay_redacts.rs`) only proves the bytes come out right; this
/// test proves they come out OVER TIME — i.e., Phase 2c didn't
/// silently fall back to Phase 2b's whole-response buffering.
///
/// Without this, a regression that re-introduced buffering for the
/// with-secrets case would still pass the correctness test (collected
/// bytes reverse to the same final string), but the streaming-UX
/// claim in the README would be a lie.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase_2c_relay_streams_chunks_over_time_with_secrets_present() -> Result<()> {
    const GAP: Duration = Duration::from_millis(150);
    // Three events with two 150ms gaps → ≥300ms upstream emission.
    // Client must observe ≥200ms between first-byte and last-byte to
    // be considered streaming.
    const STREAMING_SPAN_THRESHOLD: Duration = Duration::from_millis(200);

    let upstream = spawn_anthropic_sse_upstream_with_gap(
        "/v1/messages",
        vec![
            // Event 1: bare text, no placeholder. Emits immediately.
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello "}}"#,
            // Event 2: a complete placeholder. The SseReverser sees
            // `«...»` inside one event's text_delta and reverses it.
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"«SECRET_AWS_KEY_001»"}}"#,
            // Event 3: more text. Confirms the stream continues
            // past a reverse.
            r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":" works."}}"#,
        ],
        GAP,
    )
    .await?;

    let config = RelayConfig {
        anthropic_upstream: format!("http://{}", upstream.addr),
        openai_upstream: "http://127.0.0.1:1".to_string(),
        // See the first test's rationale.
        inject_system_prompt: false,
    };
    let (relay_addr, shutdown_tx) = spawn_relay(config).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // The prompt CONTAINS the AWS key, so the proxy mints a
    // placeholder and routes the response through the SseReverser
    // (the with-secrets path). Without the key in the prompt, the
    // empty-map fast-path would short-circuit the streaming wrapper
    // and this test would be trivially streaming (which is what the
    // existing no-secrets test pins).
    let resp = client
        .post(format!("http://{relay_addr}/v1/messages"))
        .header("x-api-key", "fake-test-key")
        .json(&json!({
            "model": "claude-opus-4-5",
            "stream": true,
            "messages": [{
                "role": "user",
                "content": "Debug AKIAIOSFODNN7EXAMPLE on S3.",
            }],
        }))
        .send()
        .await?;

    assert_eq!(resp.status(), 200);

    // Track non-empty chunk arrival times. Empty Bytes from
    // SseReverser (partial-event buffering, partial-placeholder
    // holdback) don't count as streaming progress.
    let mut stream = resp.bytes_stream();
    let start = Instant::now();
    let mut first_at: Option<Duration> = None;
    let mut last_at: Option<Duration> = None;
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let t = start.elapsed();
        if !chunk.is_empty() {
            if first_at.is_none() {
                first_at = Some(t);
            }
            last_at = Some(t);
        }
        buf.extend_from_slice(&chunk);
    }

    let first = first_at.expect("at least one non-empty chunk");
    let last = last_at.expect("at least one non-empty chunk");
    let span = last - first;

    let text = std::str::from_utf8(&buf)?;
    assert!(
        text.contains("AKIAIOSFODNN7EXAMPLE"),
        "Phase 2c must restore the secret; client sees:\n{text}",
    );
    assert!(
        !text.contains("\u{ab}SECRET_"),
        "placeholder leaked to client:\n{text}",
    );

    assert!(
        span >= STREAMING_SPAN_THRESHOLD,
        "expected streaming UX preserved with secrets present (\u{2265}{STREAMING_SPAN_THRESHOLD:?}); \
         got span {span:?}. This means Phase 2c regressed to Phase 2b buffering."
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

/// Variant of `spawn_test_upstream_with_gap` that emits Anthropic-shaped
/// SSE events (with `event: content_block_delta` headers and JSON
/// `data:` payloads) on a configurable path. Used by the Phase 2c
/// streaming test.
async fn spawn_anthropic_sse_upstream_with_gap(
    path: &'static str,
    payloads: Vec<&'static str>,
    gap: Duration,
) -> Result<TestUpstream> {
    let request_count = Arc::new(AtomicU64::new(0));

    #[derive(Clone)]
    struct State {
        request_count: Arc<AtomicU64>,
        payloads: Arc<Vec<&'static str>>,
        gap: Duration,
    }
    let state = State {
        request_count: request_count.clone(),
        payloads: Arc::new(payloads),
        gap,
    };

    async fn handler(
        axum::extract::State(state): axum::extract::State<State>,
        _body: axum::body::Bytes,
    ) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
        state.request_count.fetch_add(1, Ordering::Relaxed);
        let payloads = state.payloads.clone();
        let gap = state.gap;
        let s = stream::unfold(0usize, move |idx| {
            let payloads = payloads.clone();
            async move {
                if idx >= payloads.len() {
                    return None;
                }
                if idx > 0 {
                    tokio::time::sleep(gap).await;
                }
                let event = Event::default()
                    .event("content_block_delta")
                    .data(payloads[idx]);
                Some((Ok::<_, Infallible>(event), idx + 1))
            }
        });
        Sse::new(s)
    }

    let app = Router::new()
        .route(path, post(handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok(TestUpstream {
        addr,
        request_count,
    })
}

#[derive(Clone)]
struct UpstreamState {
    request_count: Arc<AtomicU64>,
}

struct TestUpstream {
    addr: SocketAddr,
    request_count: Arc<AtomicU64>,
}

async fn spawn_test_upstream() -> Result<TestUpstream> {
    let request_count = Arc::new(AtomicU64::new(0));
    let state = UpstreamState {
        request_count: request_count.clone(),
    };

    let app = Router::new()
        .route("/v1/messages", post(upstream_sse_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok(TestUpstream {
        addr,
        request_count,
    })
}

async fn upstream_sse_handler(
    State(state): State<UpstreamState>,
    _body: axum::body::Bytes,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    let events = stream::iter(vec![
        Ok(Event::default().data("hello")),
        Ok(Event::default().data("world")),
        Ok(Event::default().data("done")),
    ]);
    Sse::new(events)
}

/// Variant of `spawn_test_upstream` that emits SSE events on a custom path
/// with a fixed delay between events. Used by the streaming-proof test.
async fn spawn_test_upstream_with_gap(
    path: &'static str,
    payloads: Vec<&'static str>,
    gap: Duration,
) -> Result<TestUpstream> {
    let request_count = Arc::new(AtomicU64::new(0));
    let state = GappedUpstreamState {
        request_count: request_count.clone(),
        payloads: Arc::new(payloads),
        gap,
    };

    let app = Router::new()
        .route(path, post(gapped_upstream_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok(TestUpstream {
        addr,
        request_count,
    })
}

#[derive(Clone)]
struct GappedUpstreamState {
    request_count: Arc<AtomicU64>,
    payloads: Arc<Vec<&'static str>>,
    gap: Duration,
}

async fn gapped_upstream_handler(
    State(state): State<GappedUpstreamState>,
    _body: axum::body::Bytes,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    let payloads = state.payloads.clone();
    let gap = state.gap;
    let stream = stream::unfold(0usize, move |idx| {
        let payloads = payloads.clone();
        async move {
            if idx >= payloads.len() {
                return None;
            }
            if idx > 0 {
                tokio::time::sleep(gap).await;
            }
            let event = Event::default().data(payloads[idx]);
            Some((Ok::<_, Infallible>(event), idx + 1))
        }
    });
    Sse::new(stream)
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
