//! Integration test: every fixture in `prompts/` parses correctly and
//! contains its declared `SECRET_TEXT` verbatim.
//!
//! This is the safety net for the fixture corpus: if someone adds a new
//! fixture and forgets to put the secret in the body, or typos a header,
//! CI catches it before the eval is ever run.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;
use e03_placeholder_eval::load_fixtures;

fn prompts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("prompts")
}

#[test]
fn corpus_loads_at_least_fifty_fixtures() -> Result<()> {
    let fixtures = load_fixtures(&prompts_dir())?;
    assert!(
        fixtures.len() >= 50,
        "expected >=50 fixtures in prompts/, got {}",
        fixtures.len()
    );
    Ok(())
}

#[test]
fn every_fixture_contains_its_secret_text_verbatim() -> Result<()> {
    // load_fixtures already enforces this on load, so this test is more
    // of a documented contract than a separate check. Still useful: if a
    // future refactor weakens parse_fixture's validation, this catches it.
    let fixtures = load_fixtures(&prompts_dir())?;
    for f in &fixtures {
        assert!(
            f.text.contains(&f.secret_text),
            "fixture {:?}: body does not contain SECRET_TEXT={:?}",
            f.name,
            f.secret_text
        );
    }
    Ok(())
}

#[test]
fn corpus_covers_all_planned_secret_types() -> Result<()> {
    // The build-plan §3 ruleset targets these secret families. If the
    // corpus drops a type, the eval's per-type signal disappears.
    const REQUIRED: &[&str] = &[
        "AWS_KEY",
        "AWS_SECRET",
        "OPENAI_KEY",
        "ANTHROPIC_KEY",
        "GITHUB_PAT",
        "STRIPE_KEY",
        "SLACK_TOKEN",
        "JWT",
        "PEM_KEY",
        "GCP_SA_JSON",
        "DATABASE_URL",
        "GENERIC",
    ];

    let fixtures = load_fixtures(&prompts_dir())?;
    let mut by_type: BTreeMap<&str, usize> = BTreeMap::new();
    for f in &fixtures {
        *by_type.entry(f.secret_type.as_str()).or_insert(0) += 1;
    }

    for required in REQUIRED {
        assert!(
            by_type.contains_key(required),
            "corpus is missing required SECRET_TYPE={required}; have only {:?}",
            by_type.keys().collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
fn fixture_names_are_unique() -> Result<()> {
    // load_fixtures dedupes nothing; if two .txt files have the same
    // stem (which they shouldn't), the eval would produce confusing
    // duplicate rows.
    let fixtures = load_fixtures(&prompts_dir())?;
    let mut seen = std::collections::HashSet::new();
    for f in &fixtures {
        assert!(
            seen.insert(f.name.clone()),
            "duplicate fixture name: {:?}",
            f.name
        );
    }
    Ok(())
}

#[test]
fn no_obviously_real_secrets_in_corpus() -> Result<()> {
    // The corpus is for redaction-eval, NOT a secrets dump. Every value
    // must be a vendor-published example, a clearly-fake pattern, or
    // self-document as test/example. This test fires if someone pastes
    // a real-looking credential.
    let fixtures = load_fixtures(&prompts_dir())?;

    for f in &fixtures {
        let secret = &f.secret_text;
        // Heuristic: real AWS keys look like AKIA + 16 random alphanum.
        // We accept AKIAIOSFODNN7EXAMPLE (AWS's published example) and
        // anything containing TEST/FAKE/EXAMPLE/INVALID. Reject the rest.
        if secret.starts_with("AKIA") && secret.len() == 20 {
            assert!(
                secret == "AKIAIOSFODNN7EXAMPLE",
                "fixture {:?}: AWS key {secret:?} is not the published AWS example. Use AKIAIOSFODNN7EXAMPLE.",
                f.name
            );
        }
        // The canonical jwt.io example token. Accepted ONLY at exact
        // equality — a prefix match would let a tampered signature pass.
        const CANONICAL_JWT: &str =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        // Generic test for real-looking long random tokens. Allowed
        // markers: vendor "example" patterns, or self-documenting
        // fake/test substrings. Nothing else: a future contributor who
        // pastes a real-looking high-entropy token will trip this.
        let looks_real = secret.len() > 30
            && !secret.contains("fake")
            && !secret.contains("Fake")
            && !secret.contains("FAKE")
            && !secret.contains("test")
            && !secret.contains("Test")
            && !secret.contains("TEST")
            && !secret.contains("example")
            && !secret.contains("Example")
            && !secret.contains("EXAMPLE")
            && !secret.contains("invalid")
            && !secret.contains("Invalid")
            && secret != CANONICAL_JWT;
        assert!(
            !looks_real,
            "fixture {:?}: SECRET_TEXT={secret:?} looks like it could be a real credential. \
             Use a vendor-published example or a clearly-fake value containing 'test', 'fake', or 'example'.",
            f.name
        );
    }
    Ok(())
}
