// Response-side placeholder reversal.
//
// `reverse(text, map)` walks the response text, finds every
// «SECRET_TYPE_NNN» substring, and replaces it with the original secret
// from `map`. Placeholders not in the map are left alone (the model
// might have invented something that looks like a placeholder, or a
// placeholder from a different session leaked in via a long prompt —
// in either case substituting would inject text we didn't authorize).
//
// **Out of v0 scope**: stream-aware reversal (build-plan §6 gotcha
// #1 — placeholders split across SSE chunks). The reversal here works
// on a complete response string. A streaming layer above can buffer
// until it sees the closing `»` before flushing.

use std::sync::OnceLock;

use regex::Regex;

use crate::placeholder::PlaceholderMap;

/// Matches our placeholder shape: `«SECRET_<TYPE>_<NNN>»`.
/// `<TYPE>` is at least one alphanumeric/underscore character; `<NNN>`
/// is at least one digit. Looser than the renderer's exact 3-digit
/// shape so that future format extensions don't silently fail to
/// reverse.
fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\u{ab}SECRET_[A-Z0-9_]+_[0-9]+\u{bb}").unwrap())
}

/// Replace every placeholder in `text` with its original secret from
/// `map`. Placeholders not in `map` are kept verbatim.
///
/// **Operates on a complete response string.** Streaming callers
/// (Anthropic / OpenAI SSE responses) must buffer chunks until they
/// see the closing `»` before invoking, otherwise a placeholder split
/// across two SSE frames will not match the regex and the secret will
/// not be restored. Build-plan §6 names this as a known gotcha; a
/// stream-aware wrapper is out of v0 scope for this crate.
pub fn reverse(text: &str, map: &PlaceholderMap) -> String {
    if map.is_empty() {
        return text.to_string();
    }
    let re = placeholder_re();
    // regex::replace_all takes a closure; perfect fit for "lookup or
    // leave alone."
    let out = re.replace_all(text, |caps: &regex::Captures<'_>| {
        let m = caps.get(0).unwrap().as_str();
        match map.original_for(m) {
            Some(original) => original.to_string(),
            None => m.to_string(),
        }
    });
    out.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::SecretKind;
    use crate::system_prompt::PRESERVE_TOKENS_PROMPT;

    /// Defensive: the production system prompt the proxy injects on
    /// outbound requests describes the placeholder SHAPE using
    /// `«SECRET_<TYPE>_<NNN>»` (literal `<` and `>`), specifically to
    /// stay OUT of this regex's character class. If anyone ever
    /// relaxes the regex to accept `<` or `>` (or some future
    /// refactor changes the schema text), the prompt's own text
    /// becomes regex-matchable AND will be reverse-substituted with
    /// whatever real secret happens to share its placeholder id —
    /// silently leaking that secret to every echoing assistant
    /// response. Pin the no-match invariant here so the next person
    /// who touches either side is forced to think about it.
    #[test]
    fn placeholder_regex_does_not_match_system_prompt_schema_text() {
        let re = placeholder_re();
        assert!(
            !re.is_match(PRESERVE_TOKENS_PROMPT),
            "production system prompt must NOT contain anything matching \
             the placeholder regex; otherwise the reverse pass will \
             splice user secrets into the model's instruction text"
        );
    }

    fn make_map_with_one_secret(kind: SecretKind, secret: &str) -> PlaceholderMap {
        let mut m = PlaceholderMap::new();
        m.placeholder_for(kind, secret); // mints «SECRET_..._001»
        m
    }

    #[test]
    fn reverses_a_known_placeholder() {
        let map = make_map_with_one_secret(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let response = "Your \u{ab}SECRET_AWS_KEY_001\u{bb} needs s3:GetObject in its policy.";
        let out = reverse(response, &map);
        assert_eq!(
            out,
            "Your AKIAIOSFODNN7EXAMPLE needs s3:GetObject in its policy."
        );
    }

    #[test]
    fn leaves_unknown_placeholders_alone() {
        // The model invents «SECRET_AWS_KEY_999» that the map never
        // minted. We must NOT inject anything for it — that would be
        // putting words in the model's mouth that we don't have the
        // ground truth for. Pass through verbatim instead.
        let map = make_map_with_one_secret(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let response = "I'd recommend rotating \u{ab}SECRET_AWS_KEY_999\u{bb} immediately.";
        let out = reverse(response, &map);
        assert_eq!(out, response);
    }

    #[test]
    fn reverses_multiple_placeholders_in_one_response() {
        let mut map = PlaceholderMap::new();
        map.placeholder_for(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE"); // _001
        map.placeholder_for(SecretKind::AnthropicKey, "sk-ant-api03-fakeOnly"); // _001
        let response =
            "Update \u{ab}SECRET_AWS_KEY_001\u{bb} and rotate \u{ab}SECRET_ANTHROPIC_KEY_001\u{bb}.";
        let out = reverse(response, &map);
        assert_eq!(
            out,
            "Update AKIAIOSFODNN7EXAMPLE and rotate sk-ant-api03-fakeOnly."
        );
    }

    #[test]
    fn reverses_same_placeholder_appearing_multiple_times() {
        // Coreference works on the reverse side too: if the model
        // mentions the placeholder five times, we substitute the
        // original five times.
        let map = make_map_with_one_secret(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let response = "First \u{ab}SECRET_AWS_KEY_001\u{bb}, then \u{ab}SECRET_AWS_KEY_001\u{bb}.";
        let out = reverse(response, &map);
        assert_eq!(out, "First AKIAIOSFODNN7EXAMPLE, then AKIAIOSFODNN7EXAMPLE.");
    }

    #[test]
    fn empty_map_is_a_passthrough() {
        // Fast path: if nothing was redacted on the outbound side,
        // skip the regex walk and return the response unchanged.
        let map = PlaceholderMap::new();
        let response = "Plain text response, no placeholders at all.";
        assert_eq!(reverse(response, &map), response);
    }

    #[test]
    fn handles_response_with_no_placeholders_against_a_populated_map() {
        let map = make_map_with_one_secret(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let response = "No placeholders here, just normal model output.";
        assert_eq!(reverse(response, &map), response);
    }
}
