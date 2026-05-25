// Anthropic /v1/messages provider.
//
// Non-streaming. Reads the API key from the constructor argument (the CLI
// reads it from $ANTHROPIC_API_KEY). The `base_url` field exists so the
// integration test in `tests/` can point at a local mock server.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::{Model, ModelResponse};

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";

pub struct AnthropicProvider {
    pub name: String,
    pub model_id: String,
    pub base_url: String,
    pub api_key: String,
    pub max_tokens: u32,
    client: reqwest::Client,
}

impl AnthropicProvider {
    pub fn new(model_id: impl Into<String>, api_key: impl Into<String>) -> Self {
        let model_id = model_id.into();
        Self {
            name: format!("anthropic:{model_id}"),
            model_id,
            base_url: DEFAULT_BASE_URL.to_string(),
            api_key: api_key.into(),
            max_tokens: 512,
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
impl Model for AnthropicProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn complete(&self, system: Option<&str>, prompt: &str) -> Result<ModelResponse> {
        // Anthropic's Messages API puts the system prompt at the TOP LEVEL
        // of the request body, NOT as a `role: "system"` entry inside the
        // `messages` array — the messages array only carries `user` and
        // `assistant` turns. Verified against the Messages API reference
        // (top-level optional `system` parameter alongside `messages`).
        // When `system` is `None` we omit the field so the body is
        // byte-identical to the zero-shot baseline.
        let mut body = json!({
            "model": self.model_id,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "stream": false,
        });
        if let Some(sys) = system {
            body["system"] = json!(sys);
        }

        let url = format!("{}/v1/messages", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("anthropic {status}: {body}");
        }

        let parsed: MessagesResponse = resp.json().await.context("parse anthropic response")?;
        let text = parsed
            .content
            .into_iter()
            .filter_map(|block| match block {
                ContentBlock::Text { text } => Some(text),
                ContentBlock::Other => None,
            })
            .collect::<Vec<_>>()
            .join("");

        Ok(ModelResponse {
            text,
            input_tokens: parsed.usage.as_ref().map(|u| u.input_tokens),
            output_tokens: parsed.usage.as_ref().map(|u| u.output_tokens),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
    #[serde(default)]
    usage: Option<Usage>,
}

/// One block of an Anthropic message response.
///
/// `text` is the only kind we extract for the eval. Anthropic also returns
/// `thinking`, `redacted_thinking`, `tool_use`, and `image` blocks
/// depending on the model and request flags — none of those carry the
/// regenerated prompt text we need to scan, and discarding them keeps
/// this parser forward-compatible with new block types Anthropic ships.
///
/// **Do not "fix" this by adding a `Thinking { thinking: String }` variant
/// without revisiting the eval contract** — thinking blocks contain the
/// model's reasoning, which would change what `preserved` means.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ContentBlock {
    Text { text: String },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize, Serialize)]
struct Usage {
    input_tokens: u32,
    output_tokens: u32,
}
