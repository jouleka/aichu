// `aichu scan` — offline dry run.
//
// Reads a file (or stdin) and reports which detectors `proxy_core::scan`
// would fire on it, then exits. It is the threat model's "would this
// actually catch my secret?" question made executable: a user can verify
// detection on a real file WITHOUT routing live agent traffic through the
// proxy, and a CI job or pre-commit hook can gate on the exit code.
//
// Three invariants this module upholds:
//
//   - **No network, no disk writes.** Detection runs entirely on-host
//     (`proxy_core::scan`); this module only reads its input and writes a
//     report to stdout. Nothing is forwarded anywhere. This is the same
//     on-host guarantee the README's "what stays local" table makes for
//     the proxy, now reachable without starting the proxy at all.
//
//   - **No secret bytes in the output.** The report names the detector,
//     the location, the length, and the placeholder the value WOULD map
//     to — never the secret itself. `report_lines_never_contain_the_secret_bytes`
//     pins this. Printing the secret would defeat the whole point of a
//     tool that exists to keep secrets off the wire (and out of your
//     scrollback and CI logs).
//
//   - **Exit code carries the verdict.** `0` = clean, `EXIT_SECRETS_FOUND`
//     (2) = at least one detector fired, `1` = an I/O / usage error
//     (produced by main's `to_exit_code` when `read_scan_input` bails).
//     The 2-vs-1 split lets CI tell "a leak was detected" (scrub the file)
//     apart from "the scan could not run" (fix the invocation) — Rule 12,
//     fail loud, rather than collapsing both into a single nonzero code.

use std::io::Read;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Args;
use proxy_core::{PlaceholderMap, SecretKind, scan};

/// Process exit code when `aichu scan` finds at least one secret.
///
/// Deliberately NOT 1: main's `to_exit_code` already uses 1 for an
/// errored run (unreadable file, non-UTF-8 input), and CI needs to
/// distinguish "a leak was detected" from "the scanner itself could not
/// run". Pinned by `exit_code_is_two_when_secrets_found`.
pub const EXIT_SECRETS_FOUND: u8 = 2;

/// Arguments to `aichu scan`.
#[derive(Args, Debug, Clone)]
pub struct ScanArgs {
    /// File to scan. Omit, or pass `-`, to read from stdin
    /// (e.g. `cat secrets.env | aichu scan`).
    pub file: Option<String>,
}

/// A rendered scan report: one display line per detector hit, plus the
/// counts the summary line and the exit code are derived from.
///
/// Lines are pre-formatted (masked) strings rather than structured hits
/// because every consumer — stdout, and the tests — wants the same safe
/// rendering; keeping the secret out of this struct entirely means there
/// is no path by which a caller could accidentally surface it.
struct ScanReport {
    lines: Vec<String>,
    /// Total detector hits (occurrences). A value seen twice counts twice
    /// here, but shares one placeholder — see
    /// `repeated_secret_shares_one_placeholder_across_occurrences`.
    match_count: usize,
    /// Distinct `SecretKind`s that fired.
    kind_count: usize,
}

impl ScanReport {
    fn found(&self) -> bool {
        self.match_count > 0
    }
}

/// Entry point for `aichu scan`. Reads the input, builds the report,
/// prints it, and returns the verdict exit code. Returns its OWN
/// `ExitCode` (rather than `Result<()>` like the other handlers) so it
/// can signal "secrets found" as code 2 — see `EXIT_SECRETS_FOUND`.
pub fn handle_scan(args: ScanArgs) -> ExitCode {
    let input = match read_scan_input(args.file.as_deref()) {
        Ok(text) => text,
        Err(e) => {
            // Fail loud: surface the read error and exit 1 (via FAILURE).
            // A silent empty-scan here would falsely report "clean".
            eprintln!("Error: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    let report = build_scan_report(&input);
    print_report(&report, args.file.as_deref());
    ExitCode::from(exit_code_byte(report.found()))
}

/// Where `aichu scan` reads from. `None` and `"-"` both mean stdin; any
/// other value is a file path. Factored out so the routing (and the
/// matching "stdin" label in `print_report`) is pinned by a pure test
/// instead of only being exercised through real stdin/file IO — and so
/// the two call sites can't drift on what counts as stdin.
enum ScanSource<'a> {
    Stdin,
    File(&'a str),
}

fn resolve_source(file: Option<&str>) -> ScanSource<'_> {
    match file {
        None | Some("-") => ScanSource::Stdin,
        Some(path) => ScanSource::File(path),
    }
}

/// Read the scan input from a named file, or from stdin when `file` is
/// `None` or `"-"`. A missing / unreadable / non-UTF-8 file is an `Err`
/// (main maps it to exit 1) — not a silently-empty scan.
fn read_scan_input(file: Option<&str>) -> Result<String> {
    match resolve_source(file) {
        ScanSource::Stdin => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading scan input from stdin")?;
            Ok(buf)
        }
        ScanSource::File(path) => {
            std::fs::read_to_string(path).with_context(|| format!("reading scan input file {path}"))
        }
    }
}

/// Run detection over `input` and render each hit into a masked display
/// line. Mirrors `proxy_core::redact`'s coreference (identical secret →
/// identical placeholder) by driving the same `PlaceholderMap`, so the
/// placeholder a hit reports is exactly the one the proxy would mint.
fn build_scan_report(input: &str) -> ScanReport {
    let findings = scan(input);
    let mut map = PlaceholderMap::new();
    let mut lines = Vec::with_capacity(findings.len());
    let mut kinds: std::collections::HashSet<SecretKind> = std::collections::HashSet::new();
    for f in &findings {
        // `placeholder_for` drives the same coreference the proxy uses, so
        // a repeated value reports the same `«SECRET_..._NNN»` it would be
        // redacted to. The secret text goes IN here but never comes back
        // out into `lines` — only the placeholder does.
        let placeholder = map.placeholder_for(f.kind, &f.text);
        let (line, col) = line_col(input, f.start);
        let len = f.text.chars().count();
        lines.push(format_finding(&f.kind.to_string(), line, col, len, &placeholder));
        kinds.insert(f.kind);
    }
    ScanReport {
        lines,
        match_count: findings.len(),
        kind_count: kinds.len(),
    }
}

/// Format a single detector hit for display. Receives ONLY non-secret
/// metadata (kind slug, 1-based line/column, character length, and the
/// placeholder) — the secret text never reaches this function, which is
/// how the no-leak invariant is upheld structurally rather than by
/// careful escaping.
fn format_finding(kind: &str, line: usize, col: usize, len: usize, placeholder: &str) -> String {
    format!("  {kind:<16} line {line}:{col}  ({len} chars)  → {placeholder}")
}

/// 1-based (line, column) of `byte_offset` within `input`. Column is
/// counted in characters from the start of the line so multi-byte UTF-8
/// before the secret doesn't throw the number off for a human reading
/// the file in an editor.
fn line_col(input: &str, byte_offset: usize) -> (usize, usize) {
    // `byte_offset` is a `Finding.start`, which the regex engine
    // guarantees lands on a char boundary; `.min(len)` defends the slice
    // against a degenerate caller rather than against real scan output.
    let off = byte_offset.min(input.len());
    let prefix = &input[..off];
    let line = prefix.matches('\n').count() + 1;
    let line_start = prefix.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let col = prefix[line_start..].chars().count() + 1;
    (line, col)
}

/// Map the found/clean verdict to a process exit-code byte. Split out as
/// a pure function so the 0/2 contract is unit-testable without spawning
/// the binary.
fn exit_code_byte(found: bool) -> u8 {
    if found {
        EXIT_SECRETS_FOUND
    } else {
        0
    }
}

/// Write the report to stdout. Thin IO over `ScanReport`; the header
/// names the source so piped and file scans are distinguishable, and the
/// closing line re-states that nothing left the machine.
fn print_report(report: &ScanReport, source: Option<&str>) {
    let src = match resolve_source(source) {
        ScanSource::Stdin => "stdin",
        ScanSource::File(path) => path,
    };
    println!("aichu scan — {src}\n");
    if !report.found() {
        println!("No secrets detected. (local dry run — nothing was sent anywhere.)");
        return;
    }
    for line in &report.lines {
        println!("{line}");
    }
    println!();
    println!(
        "{} match(es) across {} detector(s). Nothing was sent anywhere — local dry run.",
        report.match_count, report.kind_count,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- line_col ---------------------------------------------------------

    #[test]
    fn line_col_is_one_based_at_start() {
        assert_eq!(line_col("anything", 0), (1, 1));
    }

    #[test]
    fn line_col_tracks_column_within_the_first_line() {
        assert_eq!(line_col("abcXYZ", 3), (1, 4));
    }

    #[test]
    fn line_col_tracks_newlines() {
        // "ab\ncd": 'c' is byte 3 → line 2, col 1; 'd' is byte 4 → line 2, col 2.
        assert_eq!(line_col("ab\ncd", 3), (2, 1));
        assert_eq!(line_col("ab\ncd", 4), (2, 2));
    }

    #[test]
    fn line_col_handles_consecutive_newlines() {
        // "x\n\ny": 'y' is byte 3 and sits on line 3, col 1 (the blank
        // line 2 still advances the line counter).
        assert_eq!(line_col("x\n\ny", 3), (3, 1));
    }

    // ---- format_finding ---------------------------------------------------

    #[test]
    fn format_finding_includes_kind_location_length_and_placeholder() {
        let s = format_finding("AWS_KEY", 4, 18, 20, "\u{ab}SECRET_AWS_KEY_001\u{bb}");
        assert!(s.contains("AWS_KEY"), "{s}");
        assert!(s.contains("4:18"), "{s}");
        assert!(s.contains("20 chars"), "{s}");
        assert!(s.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"), "{s}");
    }

    // ---- exit_code_byte ---------------------------------------------------

    #[test]
    fn exit_code_is_two_when_secrets_found() {
        assert_eq!(exit_code_byte(true), EXIT_SECRETS_FOUND);
        assert_eq!(exit_code_byte(true), 2);
    }

    #[test]
    fn exit_code_is_zero_when_clean() {
        assert_eq!(exit_code_byte(false), 0);
    }

    // ---- build_scan_report ------------------------------------------------

    // AWS's own published example access key — matches `AKIA` + 16.
    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    #[test]
    fn clean_input_yields_no_matches() {
        let report = build_scan_report("just some ordinary text\nwith no secrets at all\n");
        assert!(!report.found());
        assert_eq!(report.match_count, 0);
        assert_eq!(report.kind_count, 0);
        assert!(report.lines.is_empty());
    }

    #[test]
    fn single_secret_is_reported_with_kind_location_and_placeholder() {
        let input = format!("key = {AWS_KEY}\n");
        let report = build_scan_report(&input);
        assert!(report.found());
        assert_eq!(report.match_count, 1);
        assert_eq!(report.kind_count, 1);
        let line = &report.lines[0];
        assert!(line.contains("AWS_KEY"), "{line}");
        assert!(line.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"), "{line}");
        assert!(line.contains("line 1:"), "{line}");
    }

    #[test]
    fn report_lines_never_contain_the_secret_bytes() {
        // THE load-bearing invariant. A secret-redaction tool must not
        // print the secret it found — not to the terminal, not into a CI
        // log. The report carries the placeholder and metadata only.
        let input = format!("AWS_ACCESS_KEY_ID={AWS_KEY}\n");
        let report = build_scan_report(&input);
        assert!(report.found());
        for line in &report.lines {
            assert!(
                !line.contains(AWS_KEY),
                "report leaked the secret value: {line}"
            );
        }
    }

    #[test]
    fn repeated_secret_shares_one_placeholder_across_occurrences() {
        // Coreference: the same value seen twice gets ONE placeholder, but
        // each occurrence is still reported at its own location so the
        // user can find every copy.
        let input = format!("first {AWS_KEY}\nsecond {AWS_KEY}\n");
        let report = build_scan_report(&input);
        assert_eq!(report.match_count, 2, "both occurrences reported");
        assert_eq!(report.kind_count, 1);
        assert!(report.lines[0].contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"));
        assert!(report.lines[1].contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"));
        assert!(report.lines[0].contains("line 1:"));
        assert!(report.lines[1].contains("line 2:"));
    }

    #[test]
    fn distinct_kinds_each_get_their_own_placeholder() {
        let gh = format!("ghp_{}", "a".repeat(36));
        let input = format!("aws={AWS_KEY}\ngh={gh}\n");
        let report = build_scan_report(&input);
        assert_eq!(report.kind_count, 2);
        assert_eq!(report.match_count, 2);
        let joined = report.lines.join("\n");
        assert!(joined.contains("AWS_KEY"), "{joined}");
        assert!(joined.contains("GITHUB_PAT"), "{joined}");
        assert!(joined.contains("\u{ab}SECRET_AWS_KEY_001\u{bb}"), "{joined}");
        assert!(joined.contains("\u{ab}SECRET_GITHUB_PAT_001\u{bb}"), "{joined}");
    }

    // ---- read_scan_input --------------------------------------------------

    #[test]
    fn read_scan_input_reads_a_named_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("input.txt");
        std::fs::write(&path, "hello secrets").unwrap();
        let got = read_scan_input(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(got, "hello secrets");
    }

    #[test]
    fn read_scan_input_errors_on_missing_file() {
        // Fail loud (Rule 12): a path that doesn't exist is a usage error
        // surfaced to the user (main maps it to exit 1), not a silent
        // "clean scan" that would falsely reassure.
        let dir = tempfile::TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist.txt");
        assert!(read_scan_input(Some(missing.to_str().unwrap())).is_err());
    }

    #[test]
    fn read_scan_input_errors_on_non_utf8_file() {
        // `scan` deliberately REJECTS non-UTF-8 input, whereas the proxy
        // handler FORWARDS non-UTF-8 bodies unchanged. Pin that divergence
        // so a future "be lenient" change to `read_scan_input` is a
        // conscious one, not an accident — and so the "non-UTF-8 file is an
        // Err" promise in this module's doc stays true.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("binary.bin");
        std::fs::write(&path, [0xFF, 0xFE, 0x00, 0x9F]).unwrap();
        assert!(read_scan_input(Some(path.to_str().unwrap())).is_err());
    }

    // ---- resolve_source ---------------------------------------------------

    #[test]
    fn resolve_source_routes_none_and_dash_to_stdin() {
        // Both bare `aichu scan` (None) and `aichu scan -` must read stdin.
        // A regression dropping the `"-"` arm would route `-` to
        // `fs::read_to_string("-")` (a file error) instead — this pins it
        // without needing to drive real stdin.
        assert!(matches!(resolve_source(None), ScanSource::Stdin));
        assert!(matches!(resolve_source(Some("-")), ScanSource::Stdin));
    }

    #[test]
    fn resolve_source_routes_a_path_to_file() {
        match resolve_source(Some("secrets.env")) {
            ScanSource::File(p) => assert_eq!(p, "secrets.env"),
            ScanSource::Stdin => panic!("a real path must route to File, not stdin"),
        }
    }
}
