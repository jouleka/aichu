// Real model-provider implementations. Each impls `crate::model::Model`
// against the provider's wire API. The eval harness treats them uniformly.
//
// Adding a provider is the standard recipe:
//   1. New file under this directory.
//   2. Define a struct holding the reqwest client + auth + base URL.
//   3. Impl `Model`: call the provider's chat-completion endpoint with
//      `stream: false`, parse out the text, return a `ModelResponse`.
//   4. Take `base_url` as a struct field so tests can point at a local
//      mock server (axum) without hitting the real API.

pub mod anthropic;
pub mod openai;
