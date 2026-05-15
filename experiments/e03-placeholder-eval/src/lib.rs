// e03-placeholder-eval — Week 1, Risk 2
//
// Library surface used by both the binary and the integration tests.
// The harness shape is intentionally small: one `evaluate()` function that
// takes a fixture, a placeholder format, and a model, and returns a single
// `EvalResult`. The CLI loops over fixtures × formats × models, but the
// per-cell logic stays in this library so it can be tested without API keys.

pub mod fixtures;
pub mod model;
pub mod placeholder;
pub mod providers;

pub use fixtures::{Fixture, load_fixtures, parse_fixture};

use std::time::Instant;

use anyhow::Result;
use serde::Serialize;

pub use model::{Model, ModelResponse};
pub use placeholder::PlaceholderFormat;

/// Result of evaluating one (fixture, format, model) cell.
#[derive(Debug, Clone, Serialize)]
pub struct EvalResult {
    pub fixture_name: String,
    pub format: String,
    pub model: String,
    pub placeholder: String,
    /// True if the placeholder string was found verbatim in the model's
    /// response. The whole point of the eval.
    ///
    /// **Bias warning for low-information formats.** This is a substring
    /// match. For `redacted` (`[REDACTED]`) and `asterisks` (`***`), the
    /// model can emit the literal string for unrelated reasons (e.g.,
    /// "I'll redact the value as [REDACTED]"). Those rows of the results
    /// JSON are systematically biased toward `preserved=true`. Compare
    /// the typed formats against each other for the real signal; treat
    /// the low-information formats as a negative control / baseline.
    pub preserved: bool,
    /// True if the response looks like a safety refusal. Best-effort
    /// detection — see `model::looks_like_refusal`.
    pub refused: bool,
    pub latency_ms: u64,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    /// First ~200 chars of the response, for debugging. Never the full
    /// response — keeps the results file small and avoids leaking
    /// regenerated secret content.
    pub response_excerpt: String,
}

/// Substitute `secret_text` in `fixture_text` with a placeholder rendered
/// from `format`, send the result to `model`, and report whether the
/// placeholder was preserved verbatim in the response.
///
/// The caller is responsible for picking a sensible `n` (placeholder
/// counter); using `1` is fine for one-shot tests.
///
/// **Duplicate occurrences are collapsed.** If `secret_text` appears N
/// times in `fixture_text`, all N occurrences are replaced with the same
/// rendered placeholder (this is `String::replace`'s default and matches
/// the production proxy's design per build-plan §7). `preserved` is then
/// satisfied if the placeholder appears at least once in the response.
pub async fn evaluate(
    fixture_name: &str,
    fixture_text: &str,
    secret_text: &str,
    secret_type: &str,
    format: PlaceholderFormat,
    n: usize,
    model: &dyn Model,
) -> Result<EvalResult> {
    let placeholder = format.render(secret_type, n);
    if !fixture_text.contains(secret_text) {
        anyhow::bail!(
            "fixture {fixture_name:?} does not contain the secret text {secret_text:?}; \
             the substitution would be a no-op"
        );
    }
    let prompt = fixture_text.replace(secret_text, &placeholder);

    let start = Instant::now();
    let resp = model.complete(&prompt).await?;
    let latency_ms = start.elapsed().as_millis() as u64;

    let preserved = resp.text.contains(&placeholder);
    let refused = model::looks_like_refusal(&resp.text);

    let mut excerpt = resp.text.clone();
    if excerpt.len() > 200 {
        excerpt.truncate(200);
        excerpt.push('\u{2026}');
    }

    Ok(EvalResult {
        fixture_name: fixture_name.to_string(),
        format: format.name().to_string(),
        model: model.name().to_string(),
        placeholder,
        preserved,
        refused,
        latency_ms,
        input_tokens: resp.input_tokens,
        output_tokens: resp.output_tokens,
        response_excerpt: excerpt,
    })
}
