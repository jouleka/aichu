// PlaceholderMap — the proxy's secret-keeping contract.
//
// Coreference: the same secret text appearing N times in a prompt gets
// ONE placeholder. The counter advances per (SecretKind, secret_text);
// repeat occurrences of the same value reuse the existing placeholder.
//
// Format: «SECRET_<TYPE>_<NNN>» (U+00AB / U+00BB French guillemets).
// Rationale documented in e03 README. This file owns the construction
// of the literal placeholder string; nothing else should hand-write it.

use std::collections::HashMap;

use crate::rules::SecretKind;

/// Placeholder string shape. Public for use in `reverse.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlaceholderFormat;

impl PlaceholderFormat {
    /// Render the placeholder for a secret of `kind` at session-stable
    /// counter `n`. Output looks like `«SECRET_AWS_KEY_001»`.
    pub fn render(kind: SecretKind, n: usize) -> String {
        format!("\u{ab}SECRET_{}_{n:03}\u{bb}", kind.type_slug())
    }
}

/// Per-session bidirectional secret↔placeholder map.
///
/// Use `placeholder_for(kind, secret)` on the outbound (prompt) side and
/// `original_for(placeholder)` on the inbound (response) side.
#[derive(Debug, Default)]
pub struct PlaceholderMap {
    /// Forward: (kind, secret text) → placeholder string. We key by both
    /// kind AND text so the same string matched by two different kinds
    /// (defensive — should not happen with v0's non-overlapping rules)
    /// gets distinct placeholders.
    forward: HashMap<(SecretKind, String), String>,
    /// Reverse: placeholder string → secret text. Single-direction: we
    /// never need kind on the response side, only the original text.
    reverse: HashMap<String, String>,
    /// Per-kind counter. Advances each time a NEW secret of that kind
    /// is seen. Re-occurrences of an already-seen secret reuse the
    /// existing placeholder.
    counters: HashMap<SecretKind, usize>,
}

impl PlaceholderMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the placeholder for `secret`. Mints a new one if this is the
    /// first occurrence of this (kind, secret) pair; returns a clone of
    /// the existing one otherwise.
    ///
    /// Returns `String` (owned) rather than `Cow<str>` because the
    /// borrow checker would otherwise tie the returned reference to
    /// `&mut self`, preventing the caller from looking up another
    /// placeholder until the first one is dropped — which is the
    /// common pattern (collecting all placeholders for a prompt).
    /// We accept one allocation per call to keep the API ergonomic.
    pub fn placeholder_for(&mut self, kind: SecretKind, secret: &str) -> String {
        if let Some(existing) = self.forward.get(&(kind, secret.to_string())) {
            return existing.clone();
        }
        let counter = self.counters.entry(kind).or_insert(0);
        *counter += 1;
        let n = *counter;
        let placeholder = PlaceholderFormat::render(kind, n);
        self.forward
            .insert((kind, secret.to_string()), placeholder.clone());
        self.reverse.insert(placeholder.clone(), secret.to_string());
        placeholder
    }

    /// Look up the original secret for a placeholder string. `None` if
    /// the placeholder wasn't minted by this map (e.g., the model
    /// invented something that looks like a placeholder, or a
    /// placeholder from a different session leaked in).
    pub fn original_for(&self, placeholder: &str) -> Option<&str> {
        self.reverse.get(placeholder).map(String::as_str)
    }

    /// Count of unique placeholders minted. Cheap; used by integration
    /// tests and observability hooks.
    pub fn len(&self) -> usize {
        self.reverse.len()
    }

    pub fn is_empty(&self) -> bool {
        self.reverse.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_uses_french_guillemets_and_three_digit_counter() {
        // The contract production code (e.g., the proxy logs, the
        // user-facing reverse-pass) parses on. A future refactor that
        // changes the shape would silently corrupt the response-side
        // round-trip.
        assert_eq!(
            PlaceholderFormat::render(SecretKind::AwsAccessKey, 1),
            "\u{ab}SECRET_AWS_KEY_001\u{bb}"
        );
        assert_eq!(
            PlaceholderFormat::render(SecretKind::AnthropicKey, 42),
            "\u{ab}SECRET_ANTHROPIC_KEY_042\u{bb}"
        );
        assert_eq!(
            PlaceholderFormat::render(SecretKind::GithubPat, 999),
            "\u{ab}SECRET_GITHUB_PAT_999\u{bb}"
        );
    }

    #[test]
    fn first_call_for_a_secret_mints_a_new_placeholder() {
        let mut map = PlaceholderMap::new();
        let p = map.placeholder_for(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(&*p, "\u{ab}SECRET_AWS_KEY_001\u{bb}");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn repeat_secret_reuses_existing_placeholder() {
        // The whole point of the map: an `.env` paste that contains
        // AWS_ACCESS_KEY_ID twice (e.g., one line for the key, one for
        // a reminder comment) should get the SAME placeholder. Otherwise
        // the model sees two distinct values and won't realize they're
        // the same secret.
        let mut map = PlaceholderMap::new();
        let p1 = map.placeholder_for(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let p2 = map.placeholder_for(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(p1, p2);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn distinct_secrets_of_same_kind_get_distinct_placeholders() {
        let mut map = PlaceholderMap::new();
        let a = map.placeholder_for(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let b = map.placeholder_for(SecretKind::AwsAccessKey, "AKIA00000000000000XX");
        assert_ne!(a, b);
        assert_eq!(a, "\u{ab}SECRET_AWS_KEY_001\u{bb}");
        assert_eq!(b, "\u{ab}SECRET_AWS_KEY_002\u{bb}");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn counters_are_per_kind_not_global() {
        // If counters were global, an AWS key followed by an Anthropic
        // key would render as «SECRET_AWS_KEY_001» / «SECRET_ANTHROPIC_KEY_002»
        // which is confusing. Per-kind counters keep the numbering
        // independent so you read «AWS_KEY_001» and «ANTHROPIC_KEY_001»
        // for the first of each type.
        let mut map = PlaceholderMap::new();
        let aws = map.placeholder_for(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let ant = map.placeholder_for(SecretKind::AnthropicKey, "sk-ant-api03-xxx");
        assert_eq!(aws, "\u{ab}SECRET_AWS_KEY_001\u{bb}");
        assert_eq!(ant, "\u{ab}SECRET_ANTHROPIC_KEY_001\u{bb}");
    }

    #[test]
    fn original_for_returns_the_secret_text() {
        let mut map = PlaceholderMap::new();
        let p = map.placeholder_for(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(map.original_for(&p), Some("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn original_for_unknown_placeholder_returns_none() {
        // If the model invents a placeholder we never minted (or hands
        // back one from a different session), reverse() must NOT
        // substitute — it'd be inventing text. Returning None is the
        // signal for "leave it alone."
        let map = PlaceholderMap::new();
        assert_eq!(map.original_for("\u{ab}SECRET_AWS_KEY_999\u{bb}"), None);
        assert_eq!(map.original_for("[REDACTED]"), None);
    }
}
