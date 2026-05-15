// The `Model` trait abstracts over real frontier-model providers and
// in-process mocks. The eval harness only needs `complete(prompt) -> text`
// + a name. Streaming is not needed (we want the full response to scan).

use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct ModelResponse {
    pub text: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
}

#[async_trait]
pub trait Model: Send + Sync {
    fn name(&self) -> &str;
    async fn complete(&self, prompt: &str) -> Result<ModelResponse>;
}

/// Best-effort refusal detection. Heuristic only — false positives mean
/// dropping one cell from the preservation stats, which is acceptable in
/// an eval context.
///
/// We require a refusal opening in the first sentence: an optional
/// politeness prefix ("I'm sorry, but"), then a modal ("I can't",
/// "I cannot", "I won't", "I'm unable to", "I'm/I am not able to"),
/// followed by a refusal-context verb (help, assist, provide, generate,
/// share, do, create, write, comply).
///
/// The verb requirement is what stops false positives like "I cannot
/// stress this enough: rotate your keys" — `cannot` alone is not enough,
/// the word after it has to be a refusal verb.
pub fn looks_like_refusal(text: &str) -> bool {
    const POLITE_PREFIXES: &[&str] = &[
        "i'm sorry, but",
        "i'm sorry,",
        "i am sorry, but",
        "i am sorry,",
        "sorry, but",
        "sorry,",
        "apologies, but",
        "apologies,",
        "unfortunately,",
    ];
    const MODALS: &[&str] = &[
        "i can't",
        "i cannot",
        "i won't",
        "i'm unable to",
        "i am unable to",
        "i'm not able to",
        "i am not able to",
    ];
    const VERBS: &[&str] = &[
        "help", "assist", "provide", "generate", "share", "do", "create", "write", "comply",
    ];

    let lower = text.to_lowercase();
    let first_sentence = lower
        .trim_start()
        .split(['.', '\n', '!'])
        .next()
        .unwrap_or("")
        .trim();

    let mut head = first_sentence;
    for prefix in POLITE_PREFIXES {
        if let Some(rest) = head.strip_prefix(prefix) {
            head = rest.trim_start();
            break;
        }
    }

    for modal in MODALS {
        if let Some(rest) = head.strip_prefix(modal) {
            let rest = rest.trim_start();
            for verb in VERBS {
                if rest.starts_with(verb) {
                    return true;
                }
            }
        }
    }
    false
}

// --- Test-only mock models ---
//
// These live in production code (not `#[cfg(test)]`) because integration
// tests in `tests/` are compiled as separate crates and can't see cfg(test)
// items. They're inert in production unless the binary explicitly picks
// `--provider echo` (not a real flag — kept off the CLI surface).

/// A model that returns the prompt verbatim. Useful for testing that
/// `evaluate()` reports `preserved=true` when the placeholder is present
/// in the response.
pub struct EchoModel;

#[async_trait]
impl Model for EchoModel {
    fn name(&self) -> &str {
        "echo"
    }
    async fn complete(&self, prompt: &str) -> Result<ModelResponse> {
        Ok(ModelResponse {
            text: prompt.to_string(),
            input_tokens: Some(prompt.len() as u32 / 4), // rough estimate
            output_tokens: Some(prompt.len() as u32 / 4),
        })
    }
}

/// A model whose response NEVER contains the prompt. Useful for testing
/// that `evaluate()` reports `preserved=false` when the model paraphrases.
pub struct StaticModel {
    pub name: String,
    pub response: String,
}

#[async_trait]
impl Model for StaticModel {
    fn name(&self) -> &str {
        &self.name
    }
    async fn complete(&self, _prompt: &str) -> Result<ModelResponse> {
        Ok(ModelResponse {
            text: self.response.clone(),
            input_tokens: None,
            output_tokens: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_detector_fires_on_canonical_phrases() {
        // The cost of a false negative here is mislabeling a refusal as a
        // preservation failure (we'd see preserved=false + refused=false
        // and think the format is bad, when really the model just refused
        // for content reasons). These phrases are the common openings of
        // Anthropic/OpenAI safety refusals.
        assert!(looks_like_refusal("I can't help with that."));
        assert!(looks_like_refusal("I cannot generate or modify API keys."));
        assert!(looks_like_refusal("I'm sorry, but I can't help."));
        assert!(looks_like_refusal("I won't share secrets."));
        assert!(looks_like_refusal("I am not able to do that."));
        assert!(looks_like_refusal("Sorry, I can't provide that information."));
        assert!(looks_like_refusal("Apologies, I cannot comply with that."));
    }

    #[test]
    fn refusal_detector_does_not_fire_on_normal_responses() {
        // A response that happens to contain "I won't" mid-sentence (e.g.,
        // explaining what the model would do) should not be flagged.
        // We require the phrase to be near the START — production
        // refusals don't bury themselves in paragraph 3.
        let normal = "The function I wrote returns Result. \
            You can check that nothing went wrong by examining the Ok variant. \
            That's the idiomatic Rust pattern; I won't bother with unwrap here.";
        assert!(!looks_like_refusal(normal));
    }

    #[test]
    fn refusal_detector_does_not_fire_on_emphatic_cannot() {
        // "I cannot stress this enough" uses `cannot` for emphasis, not
        // refusal. The modal-plus-verb requirement is precisely to catch
        // this distinction — `stress` isn't a refusal-context verb.
        assert!(!looks_like_refusal(
            "I cannot stress this enough: rotate your keys immediately."
        ));
        assert!(!looks_like_refusal(
            "I cannot believe how often this comes up in code review."
        ));
        // "I can't wait to see this in production" — similar idiom.
        assert!(!looks_like_refusal("I can't wait to see this shipped."));
    }

    #[tokio::test]
    async fn echo_model_returns_prompt_verbatim() {
        let m = EchoModel;
        let r = m.complete("hello \u{ab}SECRET_GENERIC_001\u{bb} world").await.unwrap();
        assert_eq!(r.text, "hello \u{ab}SECRET_GENERIC_001\u{bb} world");
    }

    #[tokio::test]
    async fn static_model_ignores_prompt() {
        let m = StaticModel {
            name: "static".into(),
            response: "fixed".into(),
        };
        let r = m.complete("anything").await.unwrap();
        assert_eq!(r.text, "fixed");
    }
}
