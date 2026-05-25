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

#[test]
fn round_trip_recovers_gcp_service_account_json_blob() {
    // The whole envelope round-trips intact — header, embedded PEM,
    // and metadata all return verbatim. Pins the WHY of GCP's
    // wins-over-PEM precedence: a single placeholder covers the
    // whole blob, so reverse() restores the entire JSON as the
    // user originally pasted it.
    let blob = r#"{"type":"service_account","project_id":"my-proj","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----\n","client_email":"sa@my-proj.iam.gserviceaccount.com"}"#;
    let prompt = format!("Deploy with this key: {blob}\nThen run.");
    let mut map = PlaceholderMap::new();
    let redacted = redact(&prompt, &mut map);
    assert_eq!(map.len(), 1, "expected one placeholder for the GCP blob, got {}", map.len());
    assert!(
        redacted.contains("\u{ab}SECRET_GCP_SA_JSON_001\u{bb}"),
        "missing GCP placeholder: {redacted:?}",
    );
    // Critical: the redacted text must NOT contain the inner PEM
    // markers either — the GCP envelope swallowed them.
    assert!(
        !redacted.contains("-----BEGIN PRIVATE KEY-----"),
        "inner PEM leaked through GCP envelope redaction: {redacted:?}",
    );

    let response = "Use \u{ab}SECRET_GCP_SA_JSON_001\u{bb} for deploys.";
    let restored = reverse(response, &map);
    assert!(
        restored.contains(blob),
        "round-trip dropped the GCP blob: {restored:?}",
    );
}

#[test]
fn gcp_round_trip_nested_object_form() {
    // The brace-counter pipeline must round-trip a nested-object
    // GCP envelope just as cleanly as the flat-JSON case. Pin the
    // FULL contract: redact returns a single placeholder, reverse
    // restores the entire envelope (nested crypto block + array of
    // delegates + everything else) verbatim.
    let blob = r#"{"type":"service_account","crypto":{"algo":"RS256","keysize":4096},"delegates":[{"id":"a"},{"id":"b"}],"client_email":"sa@my-proj.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"}"#;
    let prompt = format!("Deploy with: {blob}\nThen run.");
    let mut map = PlaceholderMap::new();
    let redacted = redact(&prompt, &mut map);
    assert_eq!(map.len(), 1, "expected one placeholder for the nested GCP blob, got {}", map.len());
    assert!(
        redacted.contains("\u{ab}SECRET_GCP_SA_JSON_001\u{bb}"),
        "missing GCP placeholder: {redacted:?}",
    );
    assert!(
        !redacted.contains("-----BEGIN PRIVATE KEY-----"),
        "inner PEM leaked through nested-form GCP envelope redaction: {redacted:?}",
    );
    assert!(
        !redacted.contains("\"algo\":\"RS256\""),
        "inner crypto block leaked through nested-form GCP envelope redaction: {redacted:?}",
    );

    let response = "Use \u{ab}SECRET_GCP_SA_JSON_001\u{bb} for deploys.";
    let restored = reverse(response, &map);
    assert!(
        restored.contains(blob),
        "round-trip dropped the nested GCP blob: {restored:?}",
    );
}

#[test]
fn round_trip_recovers_twilio_api_key_sid() {
    // Prefix-typed (`SK` + 32 hex) — whole match is the secret.
    // Pins that the TwilioAuthToken kind's two-arm regex restores
    // correctly when the SK branch fires.
    let sid = format!("SK{}", "0123456789abcdef".repeat(2));
    let prompt = format!("My TWILIO_API_KEY_SID={sid} is rejected.");
    let mut map = PlaceholderMap::new();
    let redacted = redact(&prompt, &mut map);
    assert_eq!(map.len(), 1);
    assert!(redacted.contains("\u{ab}SECRET_TWILIO_TOKEN_001\u{bb}"));
    assert!(!redacted.contains(&sid));

    let response = "\u{ab}SECRET_TWILIO_TOKEN_001\u{bb} rotated yesterday.";
    assert_eq!(reverse(response, &map), format!("{sid} rotated yesterday."));
}

#[test]
fn round_trip_recovers_twilio_auth_token_via_identifier() {
    // Identifier-anchored branch — capture group 2 is the secret,
    // identifier prefix stays in the redacted text. Same contract
    // as AWS_SECRET round-trip.
    let token = "1234567890abcdef1234567890abcdef";
    let prompt = format!("TWILIO_AUTH_TOKEN={token}");
    let mut map = PlaceholderMap::new();
    let redacted = redact(&prompt, &mut map);
    assert_eq!(map.len(), 1);
    assert_eq!(
        redacted, "TWILIO_AUTH_TOKEN=\u{ab}SECRET_TWILIO_TOKEN_001\u{bb}",
        "identifier prefix must be preserved verbatim",
    );

    let response = "\u{ab}SECRET_TWILIO_TOKEN_001\u{bb}";
    assert_eq!(reverse(response, &map), token);
}

#[test]
fn round_trip_recovers_cloudflare_api_token() {
    // Identifier-anchored; capture group 1 is the secret. The
    // `CLOUDFLARE_API_TOKEN=` prefix must survive the redact and
    // the original token text must return on reverse.
    let token = "abc123_-XYZ789defghijklmnopqrstuvwxyz0123";
    let prompt = format!("export CLOUDFLARE_API_TOKEN={token}");
    let mut map = PlaceholderMap::new();
    let redacted = redact(&prompt, &mut map);
    assert_eq!(map.len(), 1);
    assert_eq!(
        redacted,
        "export CLOUDFLARE_API_TOKEN=\u{ab}SECRET_CLOUDFLARE_TOKEN_001\u{bb}",
    );

    let response = "Refresh \u{ab}SECRET_CLOUDFLARE_TOKEN_001\u{bb} via the dashboard.";
    assert_eq!(
        reverse(response, &map),
        format!("Refresh {token} via the dashboard."),
    );
}
