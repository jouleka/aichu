//! End-to-end test for the proxy-core contract: a realistic
//! coding-agent prompt → `redact` → (response with placeholders) →
//! `reverse` → original secrets restored.
//!
//! The "model" is in-memory: we simulate a response that mentions each
//! placeholder once, since that's what we expect the real proxy to see
//! when the redaction + LLM round-trip works.

use proxy_core::{PlaceholderMap, redact, reverse, scan};

#[test]
fn redact_then_reverse_restores_every_secret() {
    let ant_key = format!("sk-ant-api03-{}", "a".repeat(93));
    let prompt = format!(
        "My AWS_ACCESS_KEY_ID is AKIAIOSFODNN7EXAMPLE, \
         and my Anthropic key {ant_key} keeps getting 401. Help me debug."
    );

    // Outbound: detect + substitute
    let mut map = PlaceholderMap::new();
    let redacted = redact(&prompt, &mut map);

    assert_eq!(map.len(), 2, "expected exactly two placeholders minted");
    assert!(
        !redacted.contains("AKIAIOSFODNN7EXAMPLE"),
        "redacted prompt still contains the raw AWS key: {redacted:?}"
    );
    assert!(
        !redacted.contains("sk-ant-api03-"),
        "redacted prompt still contains the raw Anthropic prefix: {redacted:?}"
    );
    assert!(redacted.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"));
    assert!(redacted.contains("\u{ab}SECRET_ANTHROPIC_KEY_001\u{bb}"));

    // Inbound: the model echoes both placeholders in its response (what
    // the e03 eval is supposed to confirm holds in practice).
    let model_response = "\
        Your \u{ab}SECRET_AWS_KEY_001\u{bb} needs s3:GetObject in its policy, \
        and \u{ab}SECRET_ANTHROPIC_KEY_001\u{bb} returns 401 because the org \
        rotated keys yesterday — generate a fresh one at console.anthropic.com.";

    let restored = reverse(model_response, &map);

    assert!(
        restored.contains("AKIAIOSFODNN7EXAMPLE"),
        "reversed response missing AWS key: {restored:?}"
    );
    assert!(
        restored.contains(&ant_key),
        "reversed response missing Anthropic key: {restored:?}"
    );
    assert!(
        !restored.contains("\u{ab}SECRET_"),
        "reversed response still has placeholder syntax: {restored:?}"
    );
}

#[test]
fn redact_preserves_non_secret_content_verbatim() {
    // Anything that isn't a finding must come through untouched —
    // whitespace, punctuation, code blocks, error traces, etc.
    let prompt = "\
The function I wrote returns Result<(), Error>.
Here's the panic:
  thread 'main' panicked at 'no key', src/main.rs:42:9
No keys to redact here.
";
    let mut map = PlaceholderMap::new();
    let redacted = redact(prompt, &mut map);
    assert_eq!(redacted, prompt);
    assert_eq!(map.len(), 0);
}

#[test]
fn duplicate_secret_in_prompt_collapses_to_one_placeholder() {
    // The proxy contract: identical secrets share a placeholder so the
    // model treats them as the same entity (coreference).
    let prompt = "\
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
        # reminder: AKIAIOSFODNN7EXAMPLE is rotated weekly";

    let findings = scan(prompt);
    assert_eq!(findings.len(), 2, "detector returns one finding per match");

    let mut map = PlaceholderMap::new();
    let redacted = redact(prompt, &mut map);
    assert_eq!(map.len(), 1, "but the map collapses to one placeholder");

    // Both occurrences in the redacted text use the same placeholder.
    let n = redacted.matches("\u{ab}SECRET_AWS_KEY_001\u{bb}").count();
    assert_eq!(n, 2);

    // And the reverse correctly restores both.
    let response = "\u{ab}SECRET_AWS_KEY_001\u{bb} rotated yesterday.";
    assert_eq!(
        reverse(response, &map),
        "AKIAIOSFODNN7EXAMPLE rotated yesterday."
    );
}

#[test]
fn reverse_on_a_response_that_drops_the_placeholder_yields_no_restoration() {
    // The failure mode the e03 eval exists to detect: the model
    // paraphrases instead of preserving the placeholder verbatim. The
    // reverse pass has nothing to substitute, so the secret stays
    // hidden behind the (now-missing) placeholder. This is the
    // user-visible "the proxy lost my key in the response" case —
    // we surface the model output unchanged rather than inventing the
    // secret back.
    let prompt = "Why does AKIAIOSFODNN7EXAMPLE fail on S3?";
    let mut map = PlaceholderMap::new();
    let _ = redact(prompt, &mut map);

    let paraphrased_response = "Your AWS access key needs s3:GetObject permission.";
    let restored = reverse(paraphrased_response, &map);
    // No placeholder in the response → nothing to substitute → response
    // surfaces verbatim (key value is NOT injected into a place the
    // model didn't ask for).
    assert_eq!(restored, paraphrased_response);
    assert!(!restored.contains("AKIA"));
}

#[test]
fn redact_handles_byte_offsets_in_utf8_text_correctly() {
    // Mixed-script prompts (em-dash, smart quotes, non-ASCII names)
    // exercise the byte-vs-char distinction in the substitute loop.
    let prompt =
        "В моём .env: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE — пожалуйста, посмотри.";
    let mut map = PlaceholderMap::new();
    let redacted = redact(prompt, &mut map);
    assert!(redacted.starts_with("В моём .env: AWS_ACCESS_KEY_ID="));
    assert!(redacted.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"));
    assert!(redacted.ends_with(" — пожалуйста, посмотри."));
    // Reverse round-trip:
    let response = "\u{ab}SECRET_AWS_KEY_001\u{bb} — это твой ключ.";
    assert_eq!(reverse(response, &map), "AKIAIOSFODNN7EXAMPLE — это твой ключ.");
}
