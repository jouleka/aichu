//! Integration tests for the e03 eval pipeline.
//!
//! Three contracts under test:
//!
//!   1. `evaluate()` reports `preserved=true` when the model echoes the
//!      prompt (placeholder survives) and `false` when it doesn't.
//!
//!   2. `AnthropicProvider` correctly speaks the `/v1/messages` wire shape
//!      against an axum mock server pretending to be Anthropic. Validates
//!      auth headers, request body shape, and response parsing — without
//!      any API budget burn.
//!
//!   3. `OpenAiProvider` correctly speaks the `/v1/chat/completions` wire
//!      shape against an axum mock server pretending to be OpenAI.
//!      Validates `Authorization: Bearer` header, request body shape, and
//!      response parsing (`choices[0].message.content`, `usage.prompt_tokens`
//!      / `usage.completion_tokens`) — without any API budget burn.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::post,
};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};

use e03_placeholder_eval::{
    PlaceholderFormat, evaluate,
    model::{EchoModel, StaticModel},
    providers::{anthropic::AnthropicProvider, openai::OpenAiProvider},
};

#[tokio::test]
async fn echo_model_preserves_every_format() -> Result<()> {
    // If the model returns the prompt verbatim, EVERY placeholder format
    // must be reported as preserved. This pins the substring-detection
    // contract: presence in response → preserved.
    let fixture = "Here's the key: PLAINTEXT_SECRET_VALUE — debug this.";
    let model = EchoModel;

    for fmt in PlaceholderFormat::all() {
        let r = evaluate(
            "echo-fixture",
            fixture,
            "PLAINTEXT_SECRET_VALUE",
            "GENERIC",
            *fmt,
            1,
            &model,
        )
        .await?;
        assert!(
            r.preserved,
            "echo model + format {fmt:?} should yield preserved=true"
        );
        assert_eq!(r.fixture_name, "echo-fixture");
        assert_eq!(r.format, fmt.name());
        // The placeholder field should be the rendered string.
        assert_eq!(r.placeholder, fmt.render("GENERIC", 1));
    }
    Ok(())
}

#[tokio::test]
async fn static_model_response_without_placeholder_yields_not_preserved() -> Result<()> {
    // If the model paraphrases and never emits the placeholder, preserved
    // must be false. This is the failure mode the experiment exists to
    // detect.
    let fixture = "Debug this: my-key-goes-here.";
    let model = StaticModel {
        name: "static-no-placeholder".into(),
        response: "I see a placeholder. Here's a guess at what it was: AKIA1234.".into(),
    };

    let r = evaluate(
        "static-fixture",
        fixture,
        "my-key-goes-here",
        "GENERIC",
        PlaceholderFormat::Guillemets,
        1,
        &model,
    )
    .await?;
    assert!(!r.preserved, "static model response without placeholder should be preserved=false");
    assert!(!r.refused, "static reply does not look like a refusal");
    Ok(())
}

#[tokio::test]
async fn evaluate_errors_when_fixture_does_not_contain_secret_text() -> Result<()> {
    // A silent no-op substitution would invalidate the entire row of
    // results. Fail loud (CLAUDE.md Rule 12).
    let fixture = "no secret here at all";
    let model = EchoModel;

    let err = evaluate(
        "bad-fixture",
        fixture,
        "EXPECTED_SECRET",
        "GENERIC",
        PlaceholderFormat::Guillemets,
        1,
        &model,
    )
    .await
    .expect_err("evaluate must error on no-op substitution");

    assert!(
        err.to_string().contains("does not contain the secret text"),
        "expected substitution-mismatch error, got: {err}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anthropic_provider_speaks_correct_wire_shape_against_mock() -> Result<()> {
    // Verifies: AnthropicProvider sends POST /v1/messages with the right
    // headers, the right JSON body, and parses the response.content[].text
    // back out correctly. No API budget burned — we run against a local
    // axum server pretending to be Anthropic.
    let mock = spawn_anthropic_mock("Hello from the mock model.").await?;

    let provider = AnthropicProvider::new("claude-opus-4-7-test", "sk-ant-mock-key")
        .with_base_url(format!("http://{}", mock.addr));

    let r = evaluate(
        "mock-fixture",
        "Please echo PLACEHOLDER_VALUE back.",
        "PLACEHOLDER_VALUE",
        "GENERIC",
        PlaceholderFormat::Guillemets,
        1,
        &provider,
    )
    .await?;

    assert_eq!(r.model, "anthropic:claude-opus-4-7-test");
    assert_eq!(r.response_excerpt, "Hello from the mock model.");
    assert_eq!(r.input_tokens, Some(11));
    assert_eq!(r.output_tokens, Some(7));
    // Our mock model's response doesn't contain the placeholder.
    assert!(!r.preserved);

    // Mock must have seen exactly one request with auth + version headers.
    let saw = mock.last_seen.lock().unwrap().clone();
    assert_eq!(mock.request_count.load(Ordering::Relaxed), 1);
    let saw = saw.expect("mock should have captured one request");
    assert_eq!(saw.api_key.as_deref(), Some("sk-ant-mock-key"));
    assert_eq!(saw.anthropic_version.as_deref(), Some("2023-06-01"));
    assert_eq!(saw.body["model"], "claude-opus-4-7-test");
    assert_eq!(saw.body["stream"], false);
    let user_content = &saw.body["messages"][0]["content"];
    assert!(
        user_content
            .as_str()
            .unwrap_or("")
            .contains("\u{ab}SECRET_GENERIC_001\u{bb}"),
        "mock should have received the substituted prompt; got {user_content}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openai_provider_speaks_correct_wire_shape_against_mock() -> Result<()> {
    // Verifies: OpenAiProvider sends POST /v1/chat/completions with the
    // right `Authorization: Bearer` header, the right JSON body shape
    // (model + messages array), and parses the response
    // `choices[0].message.content` + `usage.{prompt,completion}_tokens`
    // back out correctly. No API budget burned — we run against a local
    // axum server pretending to be OpenAI.
    //
    // Why this test exists (CLAUDE.md Rule 9): a regression in the auth
    // header (e.g., reverting to `x-api-key`), the endpoint path, the
    // body shape, or the response parser (e.g., reading `output_tokens`
    // instead of `completion_tokens`) would fail this test BEFORE any
    // real API call burns budget.
    let mock = spawn_openai_mock("Hello from the OpenAI mock model.").await?;

    let provider = OpenAiProvider::new("gpt-5-mini-test", "sk-openai-mock-key")
        .with_base_url(format!("http://{}", mock.addr));

    let r = evaluate(
        "mock-fixture",
        "Please echo PLACEHOLDER_VALUE back.",
        "PLACEHOLDER_VALUE",
        "GENERIC",
        PlaceholderFormat::Guillemets,
        1,
        &provider,
    )
    .await?;

    assert_eq!(r.model, "openai:gpt-5-mini-test");
    assert_eq!(r.response_excerpt, "Hello from the OpenAI mock model.");
    assert_eq!(r.input_tokens, Some(13));
    assert_eq!(r.output_tokens, Some(9));
    // Our mock model's response doesn't contain the placeholder.
    assert!(!r.preserved);

    // Mock must have seen exactly one request with the Bearer auth header.
    let saw = mock.last_seen.lock().unwrap().clone();
    assert_eq!(mock.request_count.load(Ordering::Relaxed), 1);
    let saw = saw.expect("mock should have captured one request");
    assert_eq!(
        saw.authorization.as_deref(),
        Some("Bearer sk-openai-mock-key"),
        "OpenAI uses Authorization: Bearer, NOT x-api-key"
    );
    assert_eq!(saw.body["model"], "gpt-5-mini-test");
    let user_content = &saw.body["messages"][0]["content"];
    assert_eq!(saw.body["messages"][0]["role"], "user");
    assert!(
        user_content
            .as_str()
            .unwrap_or("")
            .contains("\u{ab}SECRET_GENERIC_001\u{bb}"),
        "mock should have received the substituted prompt; got {user_content}"
    );
    Ok(())
}

// --- mock server scaffolding ---

#[derive(Clone, Debug)]
struct SeenRequest {
    api_key: Option<String>,
    anthropic_version: Option<String>,
    body: Value,
}

#[derive(Clone, Debug)]
struct SeenOpenAiRequest {
    authorization: Option<String>,
    body: Value,
}

#[derive(Clone)]
struct MockState {
    response_text: String,
    request_count: Arc<AtomicU64>,
    last_seen: Arc<std::sync::Mutex<Option<SeenRequest>>>,
}

struct MockAnthropic {
    addr: SocketAddr,
    request_count: Arc<AtomicU64>,
    last_seen: Arc<std::sync::Mutex<Option<SeenRequest>>>,
}

async fn spawn_anthropic_mock(response_text: &str) -> Result<MockAnthropic> {
    let state = MockState {
        response_text: response_text.to_string(),
        request_count: Arc::new(AtomicU64::new(0)),
        last_seen: Arc::new(std::sync::Mutex::new(None)),
    };
    let request_count = state.request_count.clone();
    let last_seen = state.last_seen.clone();

    let app = Router::new()
        .route("/v1/messages", post(mock_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    wait_for_listener(addr).await?;

    Ok(MockAnthropic {
        addr,
        request_count,
        last_seen,
    })
}

async fn mock_handler(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    state.request_count.fetch_add(1, Ordering::Relaxed);

    let api_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let anthropic_version = headers
        .get("anthropic-version")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    *state.last_seen.lock().unwrap() = Some(SeenRequest {
        api_key,
        anthropic_version,
        body,
    });

    Json(json!({
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-4-7-test",
        "content": [
            {"type": "text", "text": state.response_text},
        ],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 11,
            "output_tokens": 7,
        }
    }))
}

#[derive(Clone)]
struct MockOpenAiState {
    response_text: String,
    request_count: Arc<AtomicU64>,
    last_seen: Arc<std::sync::Mutex<Option<SeenOpenAiRequest>>>,
}

struct MockOpenAi {
    addr: SocketAddr,
    request_count: Arc<AtomicU64>,
    last_seen: Arc<std::sync::Mutex<Option<SeenOpenAiRequest>>>,
}

async fn spawn_openai_mock(response_text: &str) -> Result<MockOpenAi> {
    let state = MockOpenAiState {
        response_text: response_text.to_string(),
        request_count: Arc::new(AtomicU64::new(0)),
        last_seen: Arc::new(std::sync::Mutex::new(None)),
    };
    let request_count = state.request_count.clone();
    let last_seen = state.last_seen.clone();

    let app = Router::new()
        .route("/v1/chat/completions", post(openai_mock_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    wait_for_listener(addr).await?;

    Ok(MockOpenAi {
        addr,
        request_count,
        last_seen,
    })
}

async fn openai_mock_handler(
    State(state): State<MockOpenAiState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    state.request_count.fetch_add(1, Ordering::Relaxed);

    let authorization = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    *state.last_seen.lock().unwrap() = Some(SeenOpenAiRequest {
        authorization,
        body,
    });

    // Canned chat.completion response. Includes `refusal: null` and
    // `finish_reason` to match the real wire shape — the provider must
    // tolerate the extra fields without breaking.
    Json(json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-5-mini-test",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": state.response_text,
                    "refusal": null,
                },
                "logprobs": null,
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 13,
            "completion_tokens": 9,
            "total_tokens": 22,
        }
    }))
}

async fn wait_for_listener(addr: SocketAddr) -> Result<()> {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("mock anthropic never accepted a TCP connection on {addr}")
}
