// Detector pipeline: aho-corasick keyword pre-filter → regex per kind →
// collect non-overlapping Findings sorted by start.
//
// The pre-filter is a perf optimization, not correctness: we run regex
// only for kinds whose keyword is present in the input. Removing the
// pre-filter would still produce correct results (just slower). The
// pre-filter test in `rules.rs` pins the invariant that every regex
// match contains the kind's keyword.

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
        for m in re.find_iter(input) {
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
