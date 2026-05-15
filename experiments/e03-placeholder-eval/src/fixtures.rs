// Fixture loader.
//
// Each fixture is one `.txt` file with header lines and a body:
//
//   SECRET_TEXT=<literal text to substitute>
//   SECRET_TYPE=<type slug, e.g. AWS_KEY>
//                                     <- blank line ends headers
//   <prompt body — must contain SECRET_TEXT verbatim>
//
// The blank-line separator is optional: header lines may also appear at
// the top of the body. The loader stops looking for headers as soon as it
// hits a non-header non-blank line.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

#[derive(Debug, Clone)]
pub struct Fixture {
    pub name: String,
    pub secret_text: String,
    pub secret_type: String,
    pub text: String,
}

/// Load every `.txt` fixture under `dir`. Files are returned sorted by
/// name so the eval has deterministic iteration order.
pub fn load_fixtures(dir: &Path) -> Result<Vec<Fixture>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("non-utf8 fixture name: {}", path.display()))?
            .to_string();
        let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let fixture = parse_fixture(&name, &raw)
            .with_context(|| format!("parse fixture {}", path.display()))?;
        out.push(fixture);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Parse one fixture from its raw `.txt` content.
pub fn parse_fixture(name: &str, raw: &str) -> Result<Fixture> {
    let mut secret_text: Option<String> = None;
    let mut secret_type: Option<String> = None;
    let mut body_lines: Vec<&str> = Vec::new();
    let mut in_body = false;

    for line in raw.lines() {
        if !in_body {
            if let Some(rest) = line.strip_prefix("SECRET_TEXT=") {
                secret_text = Some(rest.to_string());
                continue;
            }
            if let Some(rest) = line.strip_prefix("SECRET_TYPE=") {
                secret_type = Some(rest.to_string());
                continue;
            }
            if line.trim().is_empty() {
                in_body = true;
                continue;
            }
            // A non-blank, non-header line marks the body's start.
            in_body = true;
        }
        body_lines.push(line);
    }

    let secret_text = secret_text.ok_or_else(|| anyhow!("missing SECRET_TEXT= header"))?;
    let secret_type = secret_type.ok_or_else(|| anyhow!("missing SECRET_TYPE= header"))?;
    let text = body_lines.join("\n");

    if !text.contains(&secret_text) {
        anyhow::bail!(
            "fixture body does not contain SECRET_TEXT={secret_text:?}; \
             the substitution would be a no-op"
        );
    }

    Ok(Fixture {
        name: name.to_string(),
        secret_text,
        secret_type,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parses_well_formed_fixture() {
        let raw = "SECRET_TEXT=AKIATESTKEY\nSECRET_TYPE=AWS_KEY\n\nMy key is AKIATESTKEY — what's wrong?\n";
        let f = parse_fixture("test", raw).unwrap();
        assert_eq!(f.name, "test");
        assert_eq!(f.secret_text, "AKIATESTKEY");
        assert_eq!(f.secret_type, "AWS_KEY");
        assert!(f.text.contains("AKIATESTKEY"));
    }

    #[test]
    fn rejects_fixture_with_missing_secret_text_header() {
        let raw = "SECRET_TYPE=AWS_KEY\n\nbody\n";
        let err = parse_fixture("test", raw).unwrap_err();
        assert!(err.to_string().contains("SECRET_TEXT"));
    }

    #[test]
    fn rejects_fixture_with_missing_secret_type_header() {
        let raw = "SECRET_TEXT=foo\n\nfoo bar\n";
        let err = parse_fixture("test", raw).unwrap_err();
        assert!(err.to_string().contains("SECRET_TYPE"));
    }

    #[test]
    fn rejects_fixture_where_body_does_not_contain_secret_text() {
        // The "no-op substitution" trap: if the body doesn't contain the
        // literal SECRET_TEXT, .replace() would silently do nothing and
        // we'd compute preservation against an unmodified prompt — exactly
        // the case that invalidates a whole row of results. Fail loud.
        let raw = "SECRET_TEXT=NOT_IN_BODY\nSECRET_TYPE=AWS_KEY\n\nThis text does not contain the literal string.\n";
        let err = parse_fixture("test", raw).unwrap_err();
        assert!(err.to_string().contains("no-op"));
    }

    #[test]
    fn load_fixtures_returns_empty_on_empty_dir() {
        let dir = TempDir::new().unwrap();
        let v = load_fixtures(dir.path()).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn load_fixtures_sorts_by_filename() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        // Write two fixtures in reverse-alphabetical order.
        fs::write(
            p.join("zeta.txt"),
            "SECRET_TEXT=foo\nSECRET_TYPE=GENERIC\n\nfoo here",
        )
        .unwrap();
        fs::write(
            p.join("alpha.txt"),
            "SECRET_TEXT=foo\nSECRET_TYPE=GENERIC\n\nfoo here",
        )
        .unwrap();
        let v = load_fixtures(p).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "alpha");
        assert_eq!(v[1].name, "zeta");
    }

    #[test]
    fn load_fixtures_ignores_non_txt_files() {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::write(
            p.join("a.txt"),
            "SECRET_TEXT=foo\nSECRET_TYPE=GENERIC\n\nfoo here",
        )
        .unwrap();
        fs::write(p.join("README.md"), "# notes\nignore me").unwrap();
        let v = load_fixtures(p).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "a");
    }
}
