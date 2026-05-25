// proxy-core — the redaction pipeline used by the aichu proxy modes.
//
// Public surface:
//
//   scan(input)               → Vec<Finding>           detect secret-shaped
//                                                       substrings
//
//   redact(input, &mut map)   → String                  substitute secrets
//                                                       with typed placeholders
//                                                       and record the
//                                                       reverse mapping
//
//   reverse(response, &map)   → String                  swap placeholders
//                                                       in a model response
//                                                       back to the original
//                                                       secret text
//
// Design choices (locked in v0):
//
//   - Coreference: identical secret text → identical placeholder. The same
//     AKIA-key appearing twice in the prompt gets ONE placeholder; the
//     response only needs to mention it once for `preserved` to hold.
//
//   - Placeholder format: «SECRET_<TYPE>_<NNN>» (French guillemets, typed,
//     three-digit counter). See `placeholder.rs` and the e03 research
//     writeup for why this shape.
//
//   - The reverse map is the proxy's secret-keeping contract. It lives
//     in process memory only; nothing in this crate persists it to disk.

pub mod detector;
pub mod placeholder;
pub mod reverse;
pub mod rules;
pub mod sse;
pub mod system_prompt;

pub use detector::scan;
pub use placeholder::{PlaceholderFormat, PlaceholderMap};
pub use reverse::reverse;
pub use rules::SecretKind;
pub use sse::SseReverser;
pub use system_prompt::{
    InjectionShape, PRESERVE_TOKENS_PROMPT, inject_anthropic, inject_openai, inject_responses,
};

/// One detected secret. Byte offsets are into the original `&str` passed
/// to `scan`; substring slicing via `&input[finding.start..finding.end]`
/// yields the matched text without re-allocating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: SecretKind,
    pub start: usize,
    pub end: usize,
    pub text: String,
}

/// Redact every finding in `input` by substituting it with a placeholder
/// from `map`. Returns the redacted string. The `map` is updated in place
/// to record both directions (secret↔placeholder); use `reverse(...)` on
/// the model's response to swap placeholders back to the original
/// secrets.
///
/// If `input` has no findings, the returned string is a clone of the input.
pub fn redact(input: &str, map: &mut PlaceholderMap) -> String {
    let findings = scan(input);
    if findings.is_empty() {
        return input.to_string();
    }
    substitute(input, &findings, map)
}

/// Inner substitution loop. Walks `input` left-to-right, copying spans
/// verbatim, replacing each finding with `map.placeholder_for(kind, text)`.
///
/// Assumes `findings` are non-overlapping and in ascending start order
/// (which is what `scan` guarantees).
pub(crate) fn substitute(input: &str, findings: &[Finding], map: &mut PlaceholderMap) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    for f in findings {
        if f.start > cursor {
            out.push_str(&input[cursor..f.start]);
        }
        let placeholder = map.placeholder_for(f.kind, &f.text);
        out.push_str(&placeholder);
        cursor = f.end;
    }
    if cursor < input.len() {
        out.push_str(&input[cursor..]);
    }
    out
}
