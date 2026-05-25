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
//
// Exception: `GcpServiceAccountJson` does NOT go through the
// regex-captures path. Its registered regex (still compiled, still
// pinned by the prefilter invariant test for documentation) only
// matches FLAT JSON. Nested-object derivatives (workload-identity
// JSON with `"crypto": {...}`, federated configs with `"delegates":
// [{...}]`) ship in the wild. To cover them without depending on
// regex recursion (the `regex` crate has none), we marker-locate
// `"type":"service_account"` and brace-walk outward to find the
// enclosing envelope. See `gcp_service_account_envelopes`.

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
        // GCP runs through the brace-counter pipeline rather than the
        // regex `captures_iter`. The regex stays compiled (and pinned
        // by the prefilter invariant test) but its `[^{}]*?` body
        // can't match nested-object envelopes, so we ignore it here.
        if *kind == SecretKind::GcpServiceAccountJson {
            for (start, end) in gcp_service_account_envelopes(input) {
                findings.push(Finding {
                    kind: *kind,
                    start,
                    end,
                    text: input[start..end].to_string(),
                });
            }
            continue;
        }
        let group_indices = kind.secret_capture_groups();
        let threshold = kind.min_entropy();
        for caps in re.captures_iter(input) {
            // `secret_capture_groups` returns `&[0]` for the whole
            // match (prefix-typed kinds), `&[1]` for identifier-
            // anchored kinds where the captured secret excludes the
            // identifier prefix, or a longer slice when the regex
            // has multiple alternation arms each with their own
            // capture group (e.g., Twilio's SK-vs-auth-token
            // alternation). The detector picks the FIRST group in
            // the list that actually participated in the match.
            let Some(m) = group_indices.iter().find_map(|&g| caps.get(g)) else {
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

/// Maximum brace nesting depth the GCP envelope walker will track.
/// Beyond this the walker bails (returning whatever envelopes have
/// already been closed) rather than allocating unboundedly or
/// looping on pathological input. Real service-account JSON nests
/// at most one or two levels (`crypto`, `delegates`); 32 is several
/// orders of magnitude past anything we expect from real tooling.
const GCP_MAX_BRACE_DEPTH: usize = 32;
/// `(start, end)` byte spans for every GCP service-account envelope
/// in `input`. `end` is exclusive (slice with `input[start..end]`).
///
/// The walker is the production replacement for the legacy flat
/// regex `\{[^{}]*?"type":"service_account"[^{}]*?\}`. It:
///
///   1. Locates each `"type":"service_account"` discriminator (with
///      JSON-flexible whitespace around the colon) via a small
///      marker regex.
///   2. Runs a single forward pass over the input, tracking:
///        - JSON string state (we ignore braces inside `"..."`,
///          honoring `\"` escapes so an embedded literal quote
///          doesn't prematurely close the string)
///        - a stack of open `{` byte positions
///        - per stack frame, whether a marker has been seen inside
///          that scope yet
///   3. When a `}` pops a frame whose marker-seen flag is set,
///      records the `(open_pos, close_pos + 1)` envelope.
///
/// Returns envelopes in input order. Multiple non-overlapping
/// envelopes can appear in one input (concatenated pasted records).
///
/// Adversarial-input policy:
///   - Marker inside a string literal: ignored. WHY: a quoted
///     mention of `"type":"service_account"` in documentation or
///     error text isn't a real credential.
///   - Unbalanced braces (open without matching close): no envelope
///     emitted. WHY: fail-loud — we don't grab arbitrary text after
///     an unclosed `{` and call it a secret.
///   - Depth > `GCP_MAX_BRACE_DEPTH`: walker bails (warn + return
///     what's already closed). WHY: protects against pathological
///     adversarial input designed to exhaust memory.
fn gcp_service_account_envelopes(input: &str) -> Vec<(usize, usize)> {
    // Marker = the discriminator the legacy regex anchored on.
    // Whitespace around the colon is tolerated (jq pretty-printers
    // insert one space). The opening `"` of `"type"` is the
    // marker's `start()` byte; checking string-state at that byte
    // tells us whether the marker is a real top-level key or just
    // a quoted mention.
    static MARKER: OnceLock<Regex> = OnceLock::new();
    let marker = MARKER.get_or_init(|| {
        Regex::new(r#""type"\s*:\s*"service_account""#)
            .expect("gcp marker regex builds")
    });

    let marker_starts: Vec<usize> = marker.find_iter(input).map(|m| m.start()).collect();
    if marker_starts.is_empty() {
        return Vec::new();
    }
    let marker_set: std::collections::HashSet<usize> = marker_starts.iter().copied().collect();

    let bytes = input.as_bytes();
    let mut stack: Vec<usize> = Vec::new();
    let mut pending: Vec<bool> = Vec::new(); // parallel to stack: "marker seen in this scope?"
    let mut envelopes: Vec<(usize, usize)> = Vec::new();
    let mut in_string = false;
    let mut escape_next = false;

    for (i, &b) in bytes.iter().enumerate() {
        // Record marker-presence BEFORE state transitions. At byte
        // `i = marker.start()` we have not yet entered the
        // following `"type"` string, so `in_string` reflects whether
        // the marker as a whole sits inside an enclosing string.
        if marker_set.contains(&i) && !in_string && !stack.is_empty() {
            if let Some(last) = pending.last_mut() {
                *last = true;
            }
        }

        if in_string {
            // Inside a JSON string. Honor backslash escapes so
            // `\"` doesn't terminate the string and `\\` doesn't
            // leave the next `"` as an escaped quote.
            if escape_next {
                escape_next = false;
            } else if b == b'\\' {
                escape_next = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }

        match b {
            b'"' => in_string = true,
            b'{' => {
                if stack.len() >= GCP_MAX_BRACE_DEPTH {
                    // Bail. Already-emitted envelopes stay; pending
                    // ones get dropped on the floor. The user sees
                    // a Rule-12 warn rather than a silent hang.
                    tracing::warn!(
                        depth = stack.len(),
                        "gcp envelope walker hit max brace depth; bailing",
                    );
                    return envelopes;
                }
                stack.push(i);
                pending.push(false);
            }
            b'}' => {
                if let Some(open) = stack.pop() {
                    let had_marker = pending.pop().unwrap_or(false);
                    if had_marker {
                        envelopes.push((open, i + 1));
                    }
                }
                // Unbalanced `}` (no matching `{`): ignored. Not
                // our problem to validate JSON, only to avoid
                // panicking.
            }
            _ => {}
        }
    }
    // If the input ended mid-string or with unclosed braces, any
    // markers in unclosed scopes are intentionally dropped: see the
    // `gcp_does_not_match_unbalanced_braces` test for the WHY.
    envelopes
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

    // ---- PEM private-key block detection -----------------------------------

    #[test]
    fn detects_rsa_private_key_pem_block() {
        // RSA PKCS#1 format — the most common SSH/TLS key shape. The
        // whole multi-line block (header + base64 body + footer) is the
        // matched secret.
        let pem = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
-----END RSA PRIVATE KEY-----";
        let prompt = format!("Here is my key:\n{pem}\nPlease deploy.");
        let f = scan(&prompt);
        assert_eq!(kinds(&f), vec![SecretKind::PemPrivateKey]);
        assert_eq!(f[0].text, pem, "the whole PEM block should be the secret");
    }

    #[test]
    fn detects_generic_pkcs8_private_key_pem_block() {
        // No type qualifier — `BEGIN PRIVATE KEY` (PKCS#8 generic) is
        // what most modern tooling emits. The regex's optional
        // `(?:[A-Z][A-Z0-9 ]*? )?` clause covers this.
        let pem = "\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDxxxxxxxxxxxxxx
-----END PRIVATE KEY-----";
        let f = scan(pem);
        assert_eq!(kinds(&f), vec![SecretKind::PemPrivateKey]);
    }

    #[test]
    fn detects_openssh_private_key_pem_block() {
        // OpenSSH's custom envelope format — `ssh-keygen` default since
        // OpenSSH 7.8. Common enough to need its own coverage check.
        let pem = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABxxxxxxxxxxxxx
-----END OPENSSH PRIVATE KEY-----";
        let f = scan(pem);
        assert_eq!(kinds(&f), vec![SecretKind::PemPrivateKey]);
    }

    #[test]
    fn does_not_flag_certificate_pem_block() {
        // Certificates are public; flagging them as secrets would be a
        // privacy false-positive that adds friction without privacy
        // benefit. The regex's `PRIVATE KEY` suffix is the
        // discriminator.
        //
        // Asserting `f.is_empty()` (not just "no PEM finding") guards
        // against a future fixture swap where a longer realistic
        // base64 body happens to contain e.g. `AKIA[0-9A-Z]{16}` and
        // trips `AwsAccessKey` silently — the test would still pass
        // the loose check but the real expectation is "this block is
        // not a secret of any kind."
        let pem = "\
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUWAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END CERTIFICATE-----";
        let f = scan(pem);
        assert!(f.is_empty(), "CERTIFICATE block must produce no findings: {f:?}");
    }

    #[test]
    fn does_not_flag_public_key_pem_block() {
        // Same rationale as certificates — public keys are designed to
        // be shared. Tight assertion matches the CERTIFICATE test's.
        let pem = "\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxxxxxxxxxxxxxxxxxxxx
-----END PUBLIC KEY-----";
        let f = scan(pem);
        assert!(f.is_empty(), "PUBLIC KEY block must produce no findings: {f:?}");
    }

    #[test]
    fn two_pem_keys_in_one_input_yield_two_findings() {
        // The detector returns one Finding per non-overlapping match;
        // PlaceholderMap's dedup is a separate concern. Two distinct
        // keys (different bodies) → two findings.
        let input = "\
First key:
-----BEGIN RSA PRIVATE KEY-----
AAAAA
-----END RSA PRIVATE KEY-----
Second key (different body):
-----BEGIN EC PRIVATE KEY-----
BBBBB
-----END EC PRIVATE KEY-----";
        let f = scan(input);
        let pem_findings: Vec<_> = f
            .iter()
            .filter(|x| x.kind == SecretKind::PemPrivateKey)
            .collect();
        assert_eq!(pem_findings.len(), 2, "expected two PEM findings, got {f:?}");
        assert!(pem_findings[0].text.contains("AAAAA"));
        assert!(pem_findings[1].text.contains("BBBBB"));
    }

    // ---- GCP service-account JSON detection --------------------------------

    #[test]
    fn detects_gcp_service_account_json_blob() {
        // Realistic flat shape that Google's `gcloud iam
        // service-accounts keys create` emits (whitespace-free JSON
        // — that's what our discriminator anchors on). The PEM is
        // embedded inside the JSON string with `\n` escapes, NOT
        // literal newlines, because that's the on-disk shape.
        let blob = r#"{"type":"service_account","project_id":"my-proj-123","private_key_id":"abc123","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\n","client_email":"sa@my-proj.iam.gserviceaccount.com","client_id":"123456789"}"#;
        let prompt = format!("Here's my key:\n{blob}\nUpload it please.");
        let f = scan(&prompt);
        assert_eq!(
            kinds(&f),
            vec![SecretKind::GcpServiceAccountJson],
            "expected exactly one GCP finding, got {f:?}",
        );
        assert_eq!(f[0].text, blob, "the whole JSON envelope should be the secret");
    }

    #[test]
    fn gcp_service_account_wins_over_inner_pem_match() {
        // Precedence pin: a GCP service-account JSON blob CAN also
        // contain a literal-newline PEM private key in its body
        // (some tooling pretty-prints the value). The detector's
        // overlap resolver keeps the LONGER match, so the GCP
        // envelope wins and the inner PEM does NOT produce a
        // separate `PemPrivateKey` finding.
        //
        // Why this matters (Rule 9 — test the WHY): the JSON
        // envelope itself leaks identifying metadata
        // (`client_email`, `project_id`, `private_key_id`), so a
        // PEM-only redaction would leave the project's identity
        // exposed. One placeholder over the whole blob is the
        // correct unit of redaction.
        let blob = "{\"type\":\"service_account\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\",\"client_email\":\"sa@proj.iam.gserviceaccount.com\"}";
        let f = scan(blob);
        assert_eq!(
            kinds(&f),
            vec![SecretKind::GcpServiceAccountJson],
            "GCP must win over nested PEM; got {f:?}",
        );
    }

    #[test]
    fn does_not_flag_non_service_account_json() {
        // A JSON object that LOOKS like a config blob but lacks the
        // `"type":"service_account"` discriminator must not be
        // flagged. Otherwise users' general `.json` configs would
        // get redacted as if they were credentials.
        let s = r#"{"type":"oauth_client","client_id":"abc","client_secret":"xyz"}"#;
        let f = scan(s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::GcpServiceAccountJson),
            "non-service-account JSON must not be flagged as GCP: {f:?}",
        );
    }

    #[test]
    fn gcp_detects_pretty_printed_service_account() {
        // `jq` and most JSON pretty-printers emit
        // `"type": "service_account"` with ONE space after the
        // colon. Users routinely `cat key.json | jq` before
        // pasting; if the regex required the canonical no-space
        // form we'd silently miss real keys. The discriminator
        // tolerates `\s*` around the colon — pin that here.
        let blob = r#"{"type": "service_account","project_id":"my-proj","client_email":"sa@my-proj.iam.gserviceaccount.com"}"#;
        let f = scan(blob);
        assert_eq!(
            kinds(&f),
            vec![SecretKind::GcpServiceAccountJson],
            "pretty-printed (`jq`-style) GCP JSON must match: {f:?}",
        );
        assert_eq!(f[0].text, blob, "envelope must round-trip verbatim");
    }

    #[test]
    fn gcp_detects_multi_line_indented_service_account() {
        // The fully indented form `jq .` emits — newlines between
        // every key, two-space indentation. `(?s)` is what makes
        // this work; without dotall, `[^{}]*?` would refuse to
        // cross newlines. We also need the `\s*`-around-`:`
        // tolerance because indented form has the same space.
        let blob = "{\n  \"type\": \"service_account\",\n  \"project_id\": \"my-proj\",\n  \"client_email\": \"sa@my-proj.iam.gserviceaccount.com\"\n}";
        let f = scan(blob);
        assert_eq!(
            kinds(&f),
            vec![SecretKind::GcpServiceAccountJson],
            "multi-line indented GCP JSON must match: {f:?}",
        );
        assert_eq!(f[0].text, blob);
    }

    #[test]
    fn gcp_detects_service_account_with_nested_crypto_block() {
        // Realistic extended-format JSON: a nested `"crypto"` object
        // alongside the standard top-level keys. The flat regex
        // `\{[^{}]*?...\}` would refuse to cross the inner `{`/`}`
        // and miss this case entirely. WHY this matters: workload-
        // identity / federated-credential JSONs ship with nested
        // crypto blocks in the wild; we must redact the WHOLE
        // envelope so identifying metadata (client_email,
        // project_id) doesn't leak with the inner blocks unredacted.
        let blob = r#"{"type":"service_account","crypto":{"algo":"RS256","keysize":4096},"client_email":"sa@my-proj.iam.gserviceaccount.com","project_id":"my-proj"}"#;
        let f = scan(blob);
        assert_eq!(
            kinds(&f),
            vec![SecretKind::GcpServiceAccountJson],
            "nested crypto block must not defeat detection; got {f:?}",
        );
        assert_eq!(
            f[0].text, blob,
            "the WHOLE envelope (including nested crypto object) is the secret",
        );
    }

    #[test]
    fn gcp_detects_service_account_with_nested_delegates_array_of_objects() {
        // The other common nested shape: `"delegates"` array of
        // objects. Same redaction-unit argument as the crypto-block
        // test — the flat regex would stop at the first inner `}`
        // and miss the envelope, so we'd silently leak the
        // surrounding metadata.
        let blob = r#"{"type":"service_account","delegates":[{"id":"a"},{"id":"b"}],"client_email":"sa@my-proj.iam.gserviceaccount.com"}"#;
        let f = scan(blob);
        assert_eq!(
            kinds(&f),
            vec![SecretKind::GcpServiceAccountJson],
            "nested array-of-objects must not defeat detection; got {f:?}",
        );
        assert_eq!(f[0].text, blob);
    }

    #[test]
    fn gcp_does_not_match_unbalanced_braces() {
        // Adversarial input: a marker inside a `{` with no matching
        // `}` to close it. The brace walker MUST return without
        // matching (and must not hang, but a hang would manifest as
        // a test timeout, not a wrong assertion). WHY: fail-loud on
        // malformed JSON — emitting a finding that runs from the `{`
        // to the end of the input would over-redact arbitrary text
        // following a stray marker.
        let s = r#"{"type":"service_account","project_id":"oops-no-close-brace"#;
        let f = scan(s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::GcpServiceAccountJson),
            "unbalanced JSON must produce no GCP finding; got {f:?}",
        );
    }

    #[test]
    fn gcp_does_not_match_marker_inside_string_literal() {
        // The marker character sequence (`"type":"service_account"`)
        // appears INSIDE a quoted string value, escaped with `\"`.
        // The actual JSON object has `"type":"other"`. A naive
        // brace-walker that ignores string-quoting would see the
        // marker, grab the surrounding `{...}`, and false-positive.
        // WHY this matters: documentation, code snippets, and error
        // messages routinely quote credential field names; treating
        // a string mention of the marker as a real key would over-
        // redact unrelated content.
        let s = r#"{"description":"Use \"type\":\"service_account\" as the discriminator","type":"other"}"#;
        let f = scan(s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::GcpServiceAccountJson),
            "marker inside string literal must not match; got {f:?}",
        );
    }

    #[test]
    fn gcp_detects_two_concatenated_service_accounts() {
        // Two GCP blobs back-to-back in one input — exactly what a
        // user pastes when dumping multiple `.env` records. Both
        // must produce distinct findings (each will mint its own
        // placeholder via PlaceholderMap dedup-by-text). WHY: the
        // legacy flat regex DID handle this case (each blob is
        // flat), and the brace-counter must remain a superset.
        let blob_a = r#"{"type":"service_account","project_id":"proj-a","client_email":"a@a.iam"}"#;
        let blob_b = r#"{"type":"service_account","project_id":"proj-b","client_email":"b@b.iam"}"#;
        let s = format!("{blob_a}\n{blob_b}");
        let f = scan(&s);
        let gcp_findings: Vec<_> = f
            .iter()
            .filter(|x| x.kind == SecretKind::GcpServiceAccountJson)
            .collect();
        assert_eq!(
            gcp_findings.len(),
            2,
            "two concatenated blobs must produce two findings; got {f:?}",
        );
        assert_eq!(gcp_findings[0].text, blob_a);
        assert_eq!(gcp_findings[1].text, blob_b);
    }

    // ---- Twilio detection --------------------------------------------------

    #[test]
    fn detects_twilio_api_key_sid() {
        // SK + 32 hex chars (34 total). The whole SID is the
        // captured secret — it's a credential half, half-paired
        // with a separately-issued secret.
        let sid = format!("SK{}", "0123456789abcdef".repeat(2));
        assert_eq!(sid.len(), 34);
        let s = format!("TWILIO_API_KEY_SID={sid}");
        let f = scan(&s);
        assert_eq!(
            kinds(&f),
            vec![SecretKind::TwilioAuthToken],
            "expected one Twilio finding, got {f:?}",
        );
        assert_eq!(f[0].text, sid);
    }

    #[test]
    fn twilio_account_sid_is_not_a_secret() {
        // Twilio's Account SID (`AC` + 32 hex) has the same byte
        // shape as the API-key SID but is intentionally NOT a
        // secret: Twilio docs explicitly describe it as the Basic-
        // auth USERNAME, paired with the auth token as the
        // password. Flagging it would over-redact non-sensitive
        // tenant identifiers and hide context the model needs
        // (e.g., it's fine for an Account SID to appear in a stack
        // trace the user is debugging).
        let account_sid = format!("AC{}", "0123456789abcdef".repeat(2));
        let s = format!("TWILIO_ACCOUNT_SID={account_sid}");
        let f = scan(&s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::TwilioAuthToken),
            "Account SID must not be flagged as a Twilio secret: {f:?}",
        );
    }

    #[test]
    fn detects_twilio_auth_token_identifier_anchored() {
        // The auth token is 32 hex chars with no provider prefix,
        // so identifier anchoring on `twilio_auth_token=` is the
        // precision lever. The captured text must exclude the
        // identifier, same contract as AWS_SECRET.
        let token = "1234567890abcdef1234567890abcdef";
        let s = format!("TWILIO_AUTH_TOKEN={token}");
        let f = scan(&s);
        assert_eq!(
            kinds(&f),
            vec![SecretKind::TwilioAuthToken],
            "expected auth-token finding, got {f:?}",
        );
        assert_eq!(
            f[0].text, token,
            "capture group must exclude the identifier prefix",
        );
    }

    #[test]
    fn does_not_flag_twilio_auth_token_when_identifier_is_word_suffix() {
        // Same `\b` precision lever as AWS_SECRET — a `\b` before
        // the identifier prevents `not_twilio_auth_token=...` from
        // matching, which would otherwise over-redact misnamed
        // config keys.
        let s = "not_twilio_auth_token=1234567890abcdef1234567890abcdef";
        let f = scan(s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::TwilioAuthToken),
            "suffix-of-larger-identifier must not be flagged: {f:?}",
        );
    }

    #[test]
    fn does_not_flag_bare_32_hex_without_twilio_identifier() {
        // A bare 32-hex string with no `twilio_auth_token`
        // identifier looks exactly like an MD5 hash, a Git commit
        // SHA prefix, an etag, or a request ID. Identifier
        // anchoring is what makes the difference between "secret"
        // and "any other 32-hex value" — without it the false-
        // positive rate would tank the user experience.
        let s = "etag: 9e107d9d372bb6826bd81d3542a419d6, commit b7c5a3";
        let f = scan(s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::TwilioAuthToken),
            "bare 32-hex without identifier must not be flagged: {f:?}",
        );
    }

    #[test]
    fn twilio_sk_prefix_must_be_uppercase() {
        // Twilio documents API-key SIDs as `SK` (UPPERCASE) followed
        // by 32 lowercase hex chars. Matching `sk` + 32 hex would
        // be a precision bug for two reasons:
        //
        // (1) `sk` is the prefix of OpenAI legacy keys (`sk-...`)
        //     and a common substring in unrelated text; treating it
        //     as a Twilio SID would over-redact.
        //
        // (2) The global aho-corasick prefilter combines every
        //     kind's keywords into ONE table; an input containing
        //     ANY kind's keyword (e.g., `AKIA` from AWS) passes the
        //     gate for every kind, including Twilio. If the Twilio
        //     regex used `(?i)` on the SK arm, a random 34-char
        //     lowercase-hex token in a doc that ALSO mentions an
        //     AWS key would false-positive as Twilio.
        //
        // The fixture: an AWS access key (trips the prefilter) plus
        // a separate 34-char lowercase-hex token shaped like `sk` +
        // 32 hex. Only the AWS finding should appear.
        let lowercase_sk = format!("sk{}", "0123456789abcdef".repeat(2));
        assert_eq!(lowercase_sk.len(), 34);
        let s = format!("AKIAIOSFODNN7EXAMPLE log line: {lowercase_sk}");
        let f = scan(&s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::TwilioAuthToken),
            "lowercase `sk` + 32 hex must NOT be flagged as Twilio: {f:?}",
        );
    }

    // ---- Cloudflare API token detection ------------------------------------

    #[test]
    fn detects_cloudflare_api_token_identifier_anchored() {
        // Cloudflare tokens have no provider prefix — identifier
        // anchoring on `cloudflare_api_token=` (and the shorter
        // `cf_api_token=` / `cf_token=` aliases) is the lever.
        // High-entropy URL-safe random body, ~40 chars. Asserting
        // the length is within the regex's documented {30,80}
        // range so a future format-bump test won't pass with a
        // sample that falls outside the accepted window.
        let token = "abc123_-XYZ789defghijklmnopqrstuvwxyz0123";
        assert!(
            (30..=80).contains(&token.len()),
            "test fixture must fit the documented Cloudflare token length range",
        );
        let s = format!("CLOUDFLARE_API_TOKEN={token}");
        let f = scan(&s);
        assert_eq!(
            kinds(&f),
            vec![SecretKind::CloudflareApiToken],
            "expected one Cloudflare finding, got {f:?}",
        );
        assert_eq!(
            f[0].text, token,
            "capture group must exclude the identifier prefix",
        );
    }

    #[test]
    fn detects_cloudflare_api_token_via_cf_aliases() {
        // The shorter `CF_API_TOKEN` and `CF_TOKEN` env-var names
        // are common in Cloudflare's own CLI tools (e.g., wrangler).
        // Both must match the same kind so the placeholder map
        // collapses them consistently.
        let token = "abc123_-XYZ789defghijklmnopqrstuvwxyz0123";
        for ident in &["CF_API_TOKEN", "cf_token"] {
            let s = format!("{ident}={token}");
            let f = scan(&s);
            assert_eq!(
                kinds(&f),
                vec![SecretKind::CloudflareApiToken],
                "alias {ident} should match Cloudflare: {f:?}",
            );
        }
    }

    #[test]
    fn does_not_flag_cloudflare_token_with_low_entropy() {
        // Same gate as AWS_SECRET. A 40-char all-zeros string after
        // the identifier matches the regex shape but obviously
        // isn't a real token. Entropy gate drops it.
        let s = "CLOUDFLARE_API_TOKEN=0000000000000000000000000000000000000000";
        let f = scan(s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::CloudflareApiToken),
            "all-zeros must be entropy-filtered: {f:?}",
        );
    }

    #[test]
    fn does_not_flag_cloudflare_token_when_identifier_is_word_suffix() {
        // `\b` precision lever — `not_cloudflare_api_token=...`
        // must not match. Same rationale as AWS_SECRET and Twilio.
        let s = "not_cloudflare_api_token=abc123_-XYZ789defghijklmnopqrstuvwxyz0123";
        let f = scan(s);
        assert!(
            !f.iter().any(|x| x.kind == SecretKind::CloudflareApiToken),
            "suffix-of-larger-identifier must not be flagged: {f:?}",
        );
    }
}
