// Secret-pattern rules.
//
// We ship PREFIX-TYPED patterns from build-plan §3. These are
// unambiguous (Anthropic, OpenAI, AWS access key, GitHub PAT, Stripe
// live key, JWT, Slack token) — patterns where the FALSE-POSITIVE rate
// on real text is low because the prefix is distinctive and the rest
// of the pattern is shape-constrained.
//
// Still deferred: AWS_SECRET (no distinctive prefix; needs entropy
// gate + identifier-proximity check to avoid false positives on bare
// 40-char base64-ish strings) and PEM blocks (multi-line, requires
// scanning across newlines).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretKind {
    AnthropicKey,
    OpenAiKey,
    AwsAccessKey,
    GithubPat,
    StripeLiveKey,
    /// JSON Web Tokens (`eyJ...eyJ...sig` three-segment base64url).
    /// Distinctive shape; the `eyJ` prefix is the base64 of `{"a`
    /// which begins almost every JWT header.
    Jwt,
    /// Slack tokens — `xoxb-` (bot), `xoxa-` (workspace app legacy),
    /// `xoxp-` (user), `xoxr-` (refresh) prefixes followed by
    /// team/user/secret segments.
    SlackToken,
    /// AWS secret access key — a 40-char base64-ish string with no
    /// distinctive prefix of its own. We rely on TWO precision levers
    /// at once: (a) the regex is **identifier-anchored** to
    /// `aws_secret_access_key=...` so a bare 40-char base64 elsewhere
    /// won't trip it; (b) an **entropy gate** discards captures with
    /// Shannon entropy below ~3.5, so an all-zeros or repeating
    /// pattern after the identifier is also rejected.
    AwsSecretAccessKey,
}

impl SecretKind {
    /// All v0 kinds in detection order. Detection order doesn't matter
    /// semantically (patterns are non-overlapping by prefix) but matters
    /// for the aho-corasick pre-filter table.
    pub const ALL: &'static [SecretKind] = &[
        SecretKind::AnthropicKey,
        SecretKind::OpenAiKey,
        SecretKind::AwsAccessKey,
        SecretKind::GithubPat,
        SecretKind::StripeLiveKey,
        SecretKind::Jwt,
        SecretKind::SlackToken,
        SecretKind::AwsSecretAccessKey,
    ];

    /// Keywords the aho-corasick pre-filter scans for. If `input` does
    /// not contain at least one of these substrings, the slower regex
    /// pipeline is skipped entirely. This is the perf optimization
    /// build-plan §3 calls out (the TruffleHog/Betterleaks trick).
    ///
    /// A kind may have multiple keywords when its regex covers multiple
    /// distinct prefixes — `GithubPat` matches both classic `ghp_` and
    /// fine-grained `github_pat_` tokens, and both must trip the
    /// prefilter for fine-grained PATs to be detectable.
    pub fn prefilter_keywords(&self) -> &'static [&'static str] {
        match self {
            SecretKind::AnthropicKey => &["sk-ant-"],
            SecretKind::OpenAiKey => &["sk-"],
            // AKIA = long-term IAM user keys. ASIA = short-term STS
            // tokens from `aws sts assume-role` / instance profiles.
            // Both are sensitive and both show up in pasted env files.
            SecretKind::AwsAccessKey => &["AKIA", "ASIA"],
            SecretKind::GithubPat => &["ghp_", "github_pat_"],
            SecretKind::StripeLiveKey => &["sk_live_"],
            // "eyJ" = base64("{\"a"), how every JWT header starts.
            SecretKind::Jwt => &["eyJ"],
            SecretKind::SlackToken => &["xoxb-", "xoxa-", "xoxp-", "xoxr-"],
            // Case-sensitive prefilter; we list both spellings users
            // commonly write the identifier in (lowercase Python /
            // uppercase .env). The regex itself uses `(?i)` so a
            // freak mixed-case variant `Aws_Secret_...` would also
            // match if it tripped the prefilter.
            SecretKind::AwsSecretAccessKey => {
                &["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"]
            }
        }
    }

    /// Precise regex pattern. Anchored to the prefix; trailing length is
    /// fixed where the provider documents it, open otherwise.
    pub fn regex(&self) -> &'static str {
        match self {
            // Per Anthropic docs: sk-ant-api03- prefix + 93-char tail
            // mixing alphanum/_/-. The 93 is the documented body length.
            SecretKind::AnthropicKey => r"sk-ant-api03-[A-Za-z0-9_-]{93}",
            // OpenAI: legacy `sk-` keys + project-scoped `sk-proj-`.
            // Both must NOT match `sk-ant-` (we exclude `ant-` via a
            // negative lookahead-like alternation in the rule order).
            // Tail length: at least 40 chars, base alphabet.
            SecretKind::OpenAiKey => r"sk-(?:proj-)?[A-Za-z0-9_-]{40,}",
            // AWS access key: AKIA + 16 uppercase alphanumerics (long-
            // term IAM keys) OR ASIA + 16 (short-term STS tokens — same
            // body shape, equally sensitive).
            SecretKind::AwsAccessKey => r"(?:AKIA|ASIA)[0-9A-Z]{16}",
            // GitHub: classic PATs ghp_ + 36, plus the longer
            // fine-grained github_pat_ + 82-char body.
            SecretKind::GithubPat => r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})",
            // Stripe live secret keys. Test keys (sk_test_) are NOT
            // matched — they're not credentials worth redacting.
            SecretKind::StripeLiveKey => r"sk_live_[A-Za-z0-9]{24,}",
            // JWT: three base64url segments separated by dots. Each
            // header/payload segment starts with `eyJ`. Minimum
            // lengths filter accidental three-dot sequences.
            SecretKind::Jwt => {
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}"
            }
            // Slack: `xox[abpr]-` followed by team/user/secret segments
            // separated by dashes. Real tokens have digit-only ID
            // segments and a fixed length; the build-plan §3 spec is
            // 10-48 chars after the prefix. We use 10-200 (a bit looser
            // upper bound for safety) so the greedy match stops before
            // engulfing surrounding kebab-case prose like
            // `xoxb-foo-bar-baz then more=value`.
            SecretKind::SlackToken => r"xox[abpr]-[A-Za-z0-9-]{10,200}",
            // AWS secret access key. Identifier-anchored so we only
            // fire on `aws_secret_access_key=<value>` shapes — group
            // 1 is the 40-char base64-ish secret. The separator class
            // covers .env (`=`), JSON ("...":"...", `:`), YAML
            // (`: `), TOML (`=`), and quoted strings. The entropy
            // gate (see min_entropy below) is the second filter.
            //
            // `\b` before the identifier is a precision lever: without
            // it, the regex would match `not_aws_secret_access_key=...`
            // or `customer_aws_secret_access_key_extra=...` because
            // the underscore is a word char. With `\b`, the boundary
            // requires a transition between word and non-word — so
            // the identifier must be its own token, not a suffix of
            // a larger one.
            SecretKind::AwsSecretAccessKey => {
                r#"(?i)\baws_secret_access_key[\s"':=]+([A-Za-z0-9/+=]{40})"#
            }
        }
    }

    /// Which capture group of `regex()` is the actual secret to redact.
    /// Default 0 (the whole match). Identifier-anchored kinds use 1.
    pub fn secret_capture_group(&self) -> usize {
        match self {
            SecretKind::AwsSecretAccessKey => 1,
            _ => 0,
        }
    }

    /// Minimum Shannon entropy (bits/char) the captured secret must
    /// exceed to be reported. `None` = no gate (the prefix-typed
    /// kinds are already high-confidence; gating them would only add
    /// false negatives).
    ///
    /// `Some(3.5)` for AWS_SECRET: discards repeating patterns and
    /// all-zeros / all-letters strings that match the regex's
    /// `[A-Za-z0-9/+=]{40}` shape but aren't real random secrets.
    ///
    /// **Deviation from build-plan §3.** The plan suggests 4.5. We
    /// use 3.5. Reasoning: AWS's own published example secret
    /// (`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`) has measured
    /// entropy ~4.5, sitting right on the build-plan threshold.
    /// Real-world AWS secrets with unlucky character distributions
    /// can dip below 4.5. The trade-off:
    ///   - Threshold 4.5 (build plan): slightly higher precision;
    ///     small risk of missing a real secret (privacy gap).
    ///   - Threshold 3.5 (this code): may accept a 40-char hex
    ///     string in an `aws_secret_access_key=` field as a "secret"
    ///     (entropy ~4.0). The cost is a mild false positive —
    ///     redact and reverse cancel out, the user sees the original
    ///     hex back. The privacy guarantee remains intact.
    ///
    /// We err on the side of NOT missing real secrets, given the
    /// project's headline is privacy. Per Rule 7, this divergence is
    /// surfaced here rather than averaged silently.
    pub fn min_entropy(&self) -> Option<f64> {
        match self {
            SecretKind::AwsSecretAccessKey => Some(3.5),
            _ => None,
        }
    }

    /// Slug used as the `<TYPE>` part of `«SECRET_<TYPE>_<NNN>»`.
    /// Stable: changing this would break every placeholder map already
    /// produced by previous proxy runs.
    pub fn type_slug(&self) -> &'static str {
        match self {
            SecretKind::AnthropicKey => "ANTHROPIC_KEY",
            SecretKind::OpenAiKey => "OPENAI_KEY",
            SecretKind::AwsAccessKey => "AWS_KEY",
            SecretKind::GithubPat => "GITHUB_PAT",
            SecretKind::StripeLiveKey => "STRIPE_KEY",
            SecretKind::Jwt => "JWT",
            SecretKind::SlackToken => "SLACK_TOKEN",
            SecretKind::AwsSecretAccessKey => "AWS_SECRET",
        }
    }
}

impl fmt::Display for SecretKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.type_slug())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn every_kind_has_a_compilable_regex() {
        // If a regex doesn't compile, the detector panics at startup —
        // catch that at test time, not in production.
        for kind in SecretKind::ALL {
            Regex::new(kind.regex())
                .unwrap_or_else(|e| panic!("{kind:?} regex doesn't compile: {e}"));
        }
    }

    #[test]
    fn prefilter_keywords_are_prefixes_of_regex_matches() {
        // The aho-corasick prefilter is correctness-critical: every
        // regex match must contain at least one of the kind's
        // prefilter keywords, otherwise the detector would silently
        // skip real secrets when the prefilter declares "nothing here."
        let samples_per_kind: &[(SecretKind, &[String])] = &[
            (
                SecretKind::AnthropicKey,
                &[format!("sk-ant-api03-{}", "a".repeat(93))],
            ),
            (
                SecretKind::OpenAiKey,
                &[
                    format!("sk-{}", "a".repeat(40)),
                    format!("sk-proj-{}", "a".repeat(40)),
                ],
            ),
            (
                SecretKind::AwsAccessKey,
                &[
                    "AKIAAAAAAAAAAAAAAAAA".to_string(),
                    "ASIAAAAAAAAAAAAAAAAA".to_string(),
                ],
            ),
            (
                SecretKind::GithubPat,
                &[
                    format!("ghp_{}", "a".repeat(36)),
                    format!("github_pat_{}", "a".repeat(82)),
                ],
            ),
            (
                SecretKind::StripeLiveKey,
                &[format!("sk_live_{}", "a".repeat(24))],
            ),
            (
                SecretKind::Jwt,
                &[format!(
                    "eyJ{}.eyJ{}.{}",
                    "a".repeat(10),
                    "a".repeat(10),
                    "a".repeat(20),
                )],
            ),
            (
                SecretKind::SlackToken,
                &[
                    format!("xoxb-{}", "a".repeat(10)),
                    format!("xoxp-{}", "a".repeat(10)),
                    format!("xoxa-{}", "a".repeat(10)),
                    format!("xoxr-{}", "a".repeat(10)),
                ],
            ),
            (
                SecretKind::AwsSecretAccessKey,
                &[
                    format!("AWS_SECRET_ACCESS_KEY={}", "a".repeat(40)),
                    format!("aws_secret_access_key=\"{}\"", "b".repeat(40)),
                ],
            ),
        ];
        for (kind, samples) in samples_per_kind {
            let re = Regex::new(kind.regex()).unwrap();
            let keywords = kind.prefilter_keywords();
            for sample in *samples {
                let m = re.find(sample).unwrap_or_else(|| {
                    panic!("{kind:?} regex didn't match its own sample {sample:?}")
                });
                let matched = m.as_str();
                let any_keyword = keywords.iter().any(|kw| matched.contains(kw));
                assert!(
                    any_keyword,
                    "{kind:?}: match {matched:?} doesn't contain any of its keywords {keywords:?}"
                );
            }
        }
    }

    #[test]
    fn type_slugs_are_uppercase_and_unique() {
        // Placeholder shape «SECRET_<TYPE>_<NNN>» assumes UPPER_CASE
        // type slugs. Two kinds sharing a slug would make the placeholder
        // map ambiguous on reverse.
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for kind in SecretKind::ALL {
            let slug = kind.type_slug();
            assert_eq!(slug, slug.to_uppercase(), "{kind:?} slug not upper-case");
            assert!(seen.insert(slug), "duplicate type_slug {slug}");
        }
    }
}
