// Detector pipeline: aho-corasick keyword pre-filter → regex per kind →
// entropy gate (per kind, optional) → collect non-overlapping
// Findings sorted by start.
//
// The pre-filter is a perf optimization, not correctness: we run regex
// only for kinds whose keyword is present in the input. Removing the
// pre-filter would still produce correct results (just slower). The
// pre-filter test in `rules.rs` pins the invariant that every regex
// match contains the kind's keyword.
//
// The entropy gate is a precision filter for kinds with no distinctive
// prefix (AWS_SECRET). For prefix-typed kinds the gate is `None` and
// every regex match becomes a Finding.

use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::{Finding, rules::SecretKind};

struct Compiled {
    prefilter: AhoCorasick,
    /// Parallel to `prefilter` pattern index: regex per kind, ordered the
    /// same way as `SecretKind::ALL`.
    regexes: Vec<(SecretKind, Regex)>,
}

fn compiled() -> &'static Compiled {
    static C: OnceLock<Compiled> = OnceLock::new();
    C.get_or_init(|| {
        let mut keywords: Vec<&str> = Vec::new();
        for k in SecretKind::ALL {
            keywords.extend_from_slice(k.prefilter_keywords());
        }
        let prefilter = AhoCorasick::new(&keywords).expect("aho-corasick build failed");
        let regexes = SecretKind::ALL
            .iter()
            .map(|k| {
                let re = Regex::new(k.regex())
                    .unwrap_or_else(|e| panic!("{k:?} regex build failed: {e}"));
                (*k, re)
            })
            .collect();
        Compiled { prefilter, regexes }
    })
}

/// Scan `input` for secret-shaped substrings. Returns findings in
/// ascending `start` order, with no overlaps.
///
/// Overlap resolution: when two kinds match the same byte range or
/// nest, the LONGER match wins. For different ranges, both are kept
/// if they don't actually overlap. This matters in practice for
/// `sk-ant-...` vs `sk-...` — both prefilter keywords fire on an
/// Anthropic key, both regexes would match, but the Anthropic match
/// is longer and ends later, so we keep it and drop the OpenAI match
/// that overlaps with it.
pub fn scan(input: &str) -> Vec<Finding> {
    let c = compiled();
    if !c.prefilter.is_match(input) {
        return Vec::new();
    }

    let mut findings: Vec<Finding> = Vec::new();
    for (kind, re) in &c.regexes {
        let group_idx = kind.secret_capture_group();
        let threshold = kind.min_entropy();
        for caps in re.captures_iter(input) {
            // `secret_capture_group` returns 0 for the whole match
            // (prefix-typed kinds) or a higher index for identifier-
            // anchored kinds where the captured secret excludes the
            // identifier prefix.
            let Some(m) = caps.get(group_idx) else {
                continue;
            };
            // Apply the entropy gate, if any. For kinds without a
            // distinctive prefix (AWS_SECRET), this is what stops
            // all-zeros / repeating-pattern strings from being
            // classified as secrets.
            if let Some(min) = threshold {
                if shannon_entropy(m.as_str()) < min {
                    continue;
                }
            }
            findings.push(Finding {
                kind: *kind,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_string(),
            });
        }
    }

    if findings.is_empty() {
        return findings;
    }

    // Deduplicate overlaps: keep the longest, prefer earlier ties.
    findings.sort_by(|a, b| {
        a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)) // longer (later end) first on tie
    });

    let mut out: Vec<Finding> = Vec::with_capacity(findings.len());
    for f in findings {
        match out.last() {
            None => out.push(f),
            Some(prev) => {
                if f.start >= prev.end {
                    // Disjoint.
                    out.push(f);
                } else if f.end > prev.end {
                    // Overlap, but new finding extends past prev — replace.
                    out.pop();
                    out.push(f);
                }
                // else: fully contained within prev — drop.
            }
        }
    }
    out
}

/// Shannon entropy of a byte sequence, in bits per character.
///
/// Random base64 strings score ~5.0; hex digits ~4.0; long repeating
/// patterns approach 0. Used as a precision filter on kinds with no
/// distinctive prefix — see `SecretKind::min_entropy`.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0;
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        let p = *c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(findings: &[Finding]) -> Vec<SecretKind> {
        findings.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn empty_input_returns_no_findings() {
        assert!(scan("").is_empty());
    }

    #[test]
    fn plain_prose_returns_no_findings() {
        let s = "The quick brown fox jumps over the lazy dog. No secrets here.";
        assert!(scan(s).is_empty());
    }

    #[test]
    fn detects_anthropic_key_in_typical_prompt() {
        // Use programmatic length so we can't miscount: 93 chars after
        // the `sk-ant-api03-` prefix, matching the regex's exact width.
        let key = format!("sk-ant-api03-{}", "x".repeat(93));
        let s = format!("My key is {key} — why is it 401?");
        let f = scan(&s);
        assert_eq!(kinds(&f), vec![SecretKind::AnthropicKey]);
        assert_eq!(f[0].text, key);
    }

    #[test]
    fn detects_aws_access_key_published_example() {
        // AWS's own published example value. Real long-term IAM keys
        // are AKIA + 16 uppercase alphanumerics.
        let s = "set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in your env";
        let f = scan(s);
        assert_eq!(kinds(&f), vec![SecretKind::AwsAccessKey]);
        assert_eq!(f[0].text, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn detects_aws_sts_short_term_keys() {
        // STS-issued temporary credentials (e.g. from `aws sts assume-
        // role` or an instance profile) begin with ASIA + 16. Same
        // sensitivity as long-term keys — they grant whatever the
        // assumed role can do.
        let key = format!("ASIA{}", "X".repeat(16));
        let s = format!("AWS_ACCESS_KEY_ID={key} (short-term)");
        let f = scan(&s);
        assert_eq!(kinds(&f), vec![SecretKind::AwsAccessKey]);
        assert_eq!(f[0].text, key);
    }

    #[test]
    fn detects_github_pat_classic_and_fine_grained() {
        let classic = format!("GITHUB_TOKEN=ghp_{}", "a".repeat(36));
        let f = scan(&classic);
        assert_eq!(kinds(&f), vec![SecretKind::GithubPat]);
        assert!(f[0].text.starts_with("ghp_"));

        let fine = format!("GITHUB_TOKEN=github_pat_{}", "a".repeat(82));
        let f = scan(&fine);
        assert_eq!(kinds(&f), vec![SecretKind::GithubPat]);
        assert!(f[0].text.starts_with("github_pat_"));
    }

    #[test]
    fn detects_stripe_live_but_not_test_keys() {
        // Stripe live keys are real credentials. Test-mode keys are
        // per-account playground tokens; we deliberately do not classify
        // them as StripeLiveKey in v0.
        let live = format!("STRIPE_SECRET_KEY=sk_live_{}", "a".repeat(24));
        assert_eq!(kinds(&scan(&live)), vec![SecretKind::StripeLiveKey]);

        let test = format!("STRIPE_TEST_KEY=sk_test_{}", "a".repeat(24));
        // sk_test_ matches the broader OpenAI rule (sk- prefix +
        // alphanumerics). That's a known caveat documented on the
        // OpenAiKey rule. The IMPORTANT thing for the v0 contract is:
        // it does NOT get classified as StripeLiveKey. We test that
        // here.
        let f = scan(&test);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::StripeLiveKey),
            "test-mode Stripe key should not be classified as StripeLiveKey: {f:?}"
        );
    }

    #[test]
    fn anthropic_key_wins_over_openai_when_overlapping() {
        // An Anthropic key begins with `sk-` (OpenAI prefilter) AND
        // `sk-ant-` (Anthropic prefilter). Both regexes match the same
        // byte range. The dedup must keep AnthropicKey (more specific)
        // and drop OpenAiKey (less specific) so the placeholder map
        // doesn't end up with two entries for the same secret.
        let key = format!("sk-ant-api03-{}", "a".repeat(93));
        let s = format!("auth: {key}");
        let f = scan(&s);
        assert_eq!(kinds(&f), vec![SecretKind::AnthropicKey]);
    }

    #[test]
    fn multiple_disjoint_findings_are_returned_in_input_order() {
        let ghp = format!("ghp_{}", "a".repeat(36));
        let s = format!("aws=AKIAIOSFODNN7EXAMPLE then gh={ghp}");
        let f = scan(&s);
        assert_eq!(kinds(&f), vec![SecretKind::AwsAccessKey, SecretKind::GithubPat]);
        // Verify byte offsets are correct and in order.
        assert!(f[0].start < f[1].start);
        assert_eq!(&s[f[0].start..f[0].end], "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(f[1].text, ghp);
    }

    #[test]
    fn detects_jwt_three_segment_token() {
        // jwt.io's canonical example. Three base64url segments
        // separated by dots, each starting with "eyJ" for the first
        // two (header + payload).
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
                   SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let s = format!("Authorization: Bearer {jwt}");
        let f = scan(&s);
        assert_eq!(kinds(&f), vec![SecretKind::Jwt]);
        assert_eq!(f[0].text, jwt);
    }

    #[test]
    fn detects_slack_bot_token() {
        // Test fixtures use kebab-case fake values, not the
        // `xox[bpar]-DIGITS-DIGITS-CHARS` real-token shape, because
        // GitHub's push-protection scanner flags any commit
        // containing a real-shaped Slack token even in test
        // fixtures (we hit this on the e03 corpus). The regex still
        // matches because `xox[abpr]-[A-Za-z0-9-]{10,200}` accepts
        // any 10-200 char alphanumeric-dash sequence after the
        // prefix.
        let s = "SLACK_BOT_TOKEN=xoxb-FAKE-EXAMPLE-DO-NOT-USE-token-for-eval in env";
        let f = scan(s);
        assert_eq!(kinds(&f), vec![SecretKind::SlackToken]);
        assert!(f[0].text.starts_with("xoxb-"));
    }

    #[test]
    fn shannon_entropy_zero_on_constant_string() {
        // Repeating one character has zero entropy by definition.
        assert_eq!(super::shannon_entropy("aaaaaaaaaa"), 0.0);
        assert_eq!(super::shannon_entropy(""), 0.0);
    }

    #[test]
    fn shannon_entropy_high_on_random_base64() {
        // AWS's published example secret. Real AWS secrets are
        // generated random, ~5.0 bits/char.
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let h = super::shannon_entropy(secret);
        assert!(
            h > 4.0,
            "expected entropy > 4.0 for random base64; got {h}",
        );
    }

    #[test]
    fn shannon_entropy_low_on_repeating_short_alphabet() {
        // 40 zeros → entropy 0.0.
        assert_eq!(super::shannon_entropy(&"0".repeat(40)), 0.0);
        // 40 hex digits cycling 0123456789abcdef0123... → uniform over 16 chars → 4.0 exactly.
        let hex = "0123456789abcdef".repeat(3) + &"0123456789ab"[..8];
        let h = super::shannon_entropy(&hex);
        // Allow a small tolerance — exact 4.0 is sensitive to the
        // last partial cycle.
        assert!(
            (h - 4.0).abs() < 0.2,
            "expected entropy ~4.0 for hex cycle; got {h}",
        );
    }

    #[test]
    fn detects_aws_secret_access_key_with_identifier() {
        // AWS's own published example pair. The detector must find
        // both the access key (AKIA...) AND the secret access key.
        // The secret has no distinctive prefix, so it's anchored to
        // the `aws_secret_access_key=` identifier.
        let s = "\
            AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n\
            AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n\
            AWS_REGION=us-east-1";
        let f = scan(s);
        let kinds_set: std::collections::HashSet<_> = f.iter().map(|x| x.kind).collect();
        assert!(
            kinds_set.contains(&SecretKind::AwsAccessKey),
            "missing AwsAccessKey in {f:?}",
        );
        assert!(
            kinds_set.contains(&SecretKind::AwsSecretAccessKey),
            "missing AwsSecretAccessKey in {f:?}",
        );
        let secret_finding = f
            .iter()
            .find(|x| x.kind == SecretKind::AwsSecretAccessKey)
            .unwrap();
        // The captured text must be just the 40-char secret, not the
        // identifier prefix or trailing newline.
        assert_eq!(secret_finding.text, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    }

    #[test]
    fn does_not_flag_aws_secret_with_low_entropy() {
        // A 40-character all-zeros string after the identifier looks
        // like our regex pattern but obviously isn't a real secret.
        // The entropy gate must drop it.
        let s = "AWS_SECRET_ACCESS_KEY=0000000000000000000000000000000000000000";
        let f = scan(s);
        let secret_kinds: Vec<_> = f
            .iter()
            .filter(|x| x.kind == SecretKind::AwsSecretAccessKey)
            .collect();
        assert!(
            secret_kinds.is_empty(),
            "all-zeros should be entropy-filtered; got {secret_kinds:?}",
        );
    }

    #[test]
    fn does_not_flag_aws_secret_when_identifier_is_a_word_suffix() {
        // `\b` before the identifier prevents the regex from matching
        // when `aws_secret_access_key` is a suffix of a larger token
        // like `not_aws_secret_access_key` or
        // `customer_aws_secret_access_key_hint`. Otherwise a
        // misnamed config key could trip an unintended redaction.
        let s = "not_aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let f = scan(s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::AwsSecretAccessKey),
            "suffix-of-larger-identifier must not be flagged: {f:?}",
        );

        let s2 = "customer_aws_secret_access_key_extra=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let f2 = scan(s2);
        assert!(
            !f2.iter().any(|x| x.kind == SecretKind::AwsSecretAccessKey),
            "embedded-within-larger-identifier must not be flagged: {f2:?}",
        );
    }

    #[test]
    fn does_not_flag_floating_base64_without_identifier() {
        // A bare 40-char base64-ish string with no `aws_secret_*`
        // identifier nearby is NOT classified as an AWS secret. This
        // is what keeps the false-positive rate low: identifier
        // anchoring is the primary precision lever.
        let s = "Random data: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY (a hash maybe)";
        let f = scan(s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::AwsSecretAccessKey),
            "bare base64 without identifier must not be flagged: {f:?}",
        );
    }

    #[test]
    fn detects_slack_user_token_variant() {
        // xoxp-, xoxa-, xoxr- are valid Slack prefixes too.
        let s = "user token: xoxp-FAKE-EXAMPLE-DO-NOT-USE-user-token-for-eval";
        let f = scan(s);
        assert_eq!(kinds(&f), vec![SecretKind::SlackToken]);
        assert!(f[0].text.starts_with("xoxp-"));
    }

    #[test]
    fn duplicate_secrets_yield_two_findings() {
        // The detector itself doesn't dedupe by text — that's the
        // PlaceholderMap's job (collapsing duplicates to the same
        // placeholder). The detector returns one Finding per match.
        let s = "key1=AKIAIOSFODNN7EXAMPLE and again key2=AKIAIOSFODNN7EXAMPLE";
        let f = scan(s);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].text, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(f[1].text, "AKIAIOSFODNN7EXAMPLE");
    }
}
