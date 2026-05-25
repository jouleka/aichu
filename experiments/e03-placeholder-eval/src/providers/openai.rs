// OpenAI /v1/chat/completions provider.
//
// Non-streaming. Reads the API key from the constructor argument (the CLI
// reads it from $OPENAI_API_KEY). The `base_url` field exists so the
// integration test in `tests/` can point at a local mock server.
//
// We deliberately target the Chat Completions endpoint (not the newer
// Responses API): it mirrors the Anthropic provider's shape exactly,
// minimizes new code, and is fully supported on gpt-5-mini.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::{Model, ModelResponse};

const DEFAULT_BASE_URL: &str = "https://api.openai.com";

pub struct OpenAiProvider {
    pub name: String,
    pub model_id: String,
    pub base_url: String,
    pub api_key: String,
    pub max_tokens: u32,
    client: reqwest::Client,
}

impl OpenAiProvider {
    pub fn new(model_id: impl Into<String>, api_key: impl Into<String>) -> Self {
        let model_id = model_id.into();
        Self {
            name: format!("openai:{model_id}"),
            model_id,
            base_url: DEFAULT_BASE_URL.to_string(),
            api_key: api_key.into(),
            // 2048, not 512. gpt-5-mini and other reasoning-capable models
            // count internal reasoning tokens against `max_completion_tokens`.
            // 512 left zero budget for visible output in smoke tests against
            // gpt-5-mini (entire budget spent on reasoning, `content` empty,
            // `preserved=false` for every fixture). Combined with
            // `reasoning_effort: "minimal"` in `complete()`, 2048 leaves a
            // safe headroom for the actual response.
            max_tokens: 2048,
            client: reqwest::Client::new(),
        }
    }

    /// Point at a custom base URL — used by integration tests that target
    /// a local mock server.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }
}

#[async_trait]
impl Model for OpenAiProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn complete(&self, prompt: &str) -> Result<ModelResponse> {
        // `max_completion_tokens` (not `max_tokens`). Per OpenAI docs
        // `max_tokens` is deprecated and "not compatible with o-series
        // models"; gpt-5-mini and other newer reasoning-capable models
        // expect `max_completion_tokens`. Picking the newer name here
        // keeps us forward-compatible without branching per model id.
        //
        // `reasoning_effort: "minimal"` opts out of extended thinking on
        // reasoning-capable models (gpt-5-series, o-series). The
        // placeholder-preservation eval measures whether the model echoes
        // a token verbatim in its output text — a question about text
        // handling, not about reasoning depth. Without this, gpt-5-mini
        // spends its entire token budget on reasoning and emits empty
        // `content`, yielding no usable eval signal. Non-reasoning OpenAI
        // models (gpt-4o, gpt-3.5) may reject or silently ignore the
        // parameter; gate on model id before pointing this provider at
        // them (e.g. `model_id.starts_with("gpt-5") || starts_with("o")`).
        let body = json!({
            "model": self.model_id,
            "max_completion_tokens": self.max_tokens,
            "reasoning_effort": "minimal",
            "messages": [{"role": "user", "content": prompt}],
        });

        let url = format!("{}/v1/chat/completions", self.base_url);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("openai {status}: {body}");
        }

        let parsed: ChatCompletionsResponse =
            resp.json().await.context("parse openai response")?;
        let text = parsed
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content.unwrap_or_default())
            .unwrap_or_default();

        Ok(ModelResponse {
            text,
            input_tokens: parsed.usage.as_ref().map(|u| u.prompt_tokens),
            output_tokens: parsed.usage.as_ref().map(|u| u.completion_tokens),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ChatCompletionsResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Choice {
    message: Message,
}

/// One assistant message from a chat-completion response.
///
/// We only extract `content` for the eval. OpenAI also returns
/// `tool_calls`, `function_call`, `refusal`, and `annotations` on this
/// object depending on the request — none of those carry the regenerated
/// prompt text we need to scan, and `serde` ignores unknown fields by
/// default, which keeps this parser forward-compatible with new fields
/// OpenAI ships.
///
/// `content` is `Option<String>` because OpenAI returns `null` when the
/// model emits a tool call instead of text. We don't request tools here,
/// so in practice this is always `Some(_)`; defaulting to empty string
/// in the caller keeps the eval honest (empty response → preserved=false)
/// rather than panicking.
///
/// **Do not "fix" this by also extracting `refusal` or `tool_calls`
/// without revisiting the eval contract** — those fields would change
/// what `preserved` means.
#[derive(Debug, Deserialize, Serialize)]
struct Message {
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Usage {
    prompt_tokens: u32,
    completion_tokens: u32,
}
