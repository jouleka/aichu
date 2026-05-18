// Streaming SSE-aware placeholder reverser (Phase 2c).
//
// Phase 2b buffers the entire upstream response when secrets were
// minted on the outbound side, then runs `proxy_core::reverse` against
// the bytes. That works for placeholders that land WHOLLY inside one
// `content_block_delta` event's `text_delta` payload, but it FAILS
// when the model fragments a placeholder across two events: the bytes
// between the fragments include JSON/SSE framing (`"}}\n\nevent: ...,
// "text":"`), and the reverse regex's `[A-Z0-9_]+_[0-9]+` character
// class cannot match across those bytes.
//
// Phase 2c (this module) parses the SSE stream event-by-event,
// extracts the `delta.text` payload, accumulates it into a per-stream
// buffer, and applies `reverse` to the buffer's "safe" prefix —
// emitting reversed text downstream while holding back the tail that
// COULD be the prefix of an incomplete placeholder.
//
// Holdback heuristic: scan for the rightmost `«` in the pending
// buffer. If found AND its tail (no `»`) is consistent with the
// shape `«SECRET_<TYPE>_<NNN>` (i.e., `«`, then a prefix of
// `SECRET_`, then `[A-Z0-9_]*`), hold back from that position.
// Otherwise, the whole buffer is safe to emit. The two emit-everything
// cases are: (1) no `«` at all, (2) the rightmost `«` has a matching
// `»` later in the buffer (so any placeholder there is structurally
// complete, and `reverse` can match it). On stream end, `flush`
// emits any remaining held-back text — uncompleted placeholders pass
// through unreversed, which is a UX cost but never a privacy leak
// (the bytes are the placeholder we minted, not the original secret).
//
// **Why per-stream, not per-block:** The SseReverser uses one
// pending buffer for the whole stream, not one per content_block
// index. A model response that splits a placeholder across
// content_block boundaries would visually shift the secret to a
// different block under this design — but that's a hypothetical
// concern (Anthropic emits one text block per turn for a normal
// completion; placeholders never legitimately cross a tool-use
// boundary). Per-block tracking can be added if a real failure
// mode surfaces it.

use bytes::Bytes;
use serde_json::Value;

use crate::placeholder::PlaceholderMap;
use crate::reverse::reverse;

/// Stateful SSE-aware reverser. One instance per upstream response.
///
/// Feed incoming bytes via `push_bytes` (production: handles chunk
/// boundaries that fall mid-UTF-8-character) or `push` (test
/// convenience: pre-validated `&str`). Call `flush` once when the
/// upstream stream ends to drain any held-back text and partial
/// events.
#[derive(Debug, Default)]
pub struct SseReverser {
    /// Raw bytes from upstream that did not yet form a valid UTF-8
    /// suffix — populated only when a chunk boundary lands inside a
    /// multi-byte character. Drained as soon as the next chunk
    /// completes the character.
    byte_buf: Vec<u8>,
    /// Bytes received from upstream that form an incomplete SSE event
    /// (no terminator seen yet). When we observe `\n\n` (or
    /// `\r\n\r\n`), the prefix is parsed and removed from this buffer.
    parse_buf: String,
    /// Accumulated `text_delta` payload that hasn't been emitted yet
    /// because its tail could still be the prefix of an incomplete
    /// placeholder. See module-level holdback heuristic.
    pending_text: String,
}

impl SseReverser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed `chunk` raw bytes from an upstream byte stream. Handles
    /// chunk boundaries that fall inside multi-byte UTF-8 characters
    /// — the invalid tail is buffered until the next push completes
    /// it.
    ///
    /// Returns the SSE bytes ready to forward to the client. Empty
    /// when everything in the chunk was held back (partial event,
    /// partial UTF-8, or partial placeholder).
    pub fn push_bytes(&mut self, chunk: &[u8], map: &PlaceholderMap) -> Bytes {
        self.byte_buf.extend_from_slice(chunk);

        // Find the longest valid UTF-8 prefix of the accumulated
        // byte buffer. Anything past that point is either an
        // incomplete multi-byte character (next chunk will complete
        // it) or a hard decode error (rare; we leave it in byte_buf
        // and let `flush` decide what to do).
        let valid_len = match std::str::from_utf8(&self.byte_buf) {
            Ok(_) => self.byte_buf.len(),
            Err(e) => e.valid_up_to(),
        };

        if valid_len == 0 {
            return Bytes::new();
        }

        // Drain the valid prefix, route through the str-typed
        // pipeline. The drained portion is owned (Vec<u8>) which we
        // then convert to &str — this is a single allocation per
        // chunk, dominated by the actual SSE parsing cost below.
        let drained: Vec<u8> = self.byte_buf.drain(..valid_len).collect();
        let chunk_str = std::str::from_utf8(&drained)
            .expect("valid_len bytes are valid UTF-8 by construction");
        Bytes::from(self.push(chunk_str, map))
    }

    /// Feed `chunk` bytes-as-utf8 from upstream. Returns the SSE
    /// bytes ready to forward to the client.
    ///
    /// `map` is borrowed for the duration of the call only; callers
    /// that want the same map for every push can keep it on the
    /// stack and pass `&map` each time.
    ///
    /// Prefer `push_bytes` for production streaming — it handles
    /// UTF-8 chunk boundaries. This entry point is kept for tests
    /// and for callers who already have a `&str` in hand.
    pub fn push(&mut self, chunk: &str, map: &PlaceholderMap) -> String {
        self.parse_buf.push_str(chunk);

        let mut out = String::new();
        while let Some((event_text, rest_start)) = split_first_event(&self.parse_buf) {
            let emitted = self.process_event(&event_text, map);
            out.push_str(&emitted);
            self.parse_buf.drain(..rest_start);
        }
        out
    }

    /// Byte-typed counterpart to `flush`. Returns the same final
    /// bytes the `String`-typed `flush` would, wrapped in `Bytes`
    /// for cheap forwarding into a `Body::from_stream`.
    ///
    /// Any bytes left in `byte_buf` (truncated UTF-8 at end of
    /// stream) are dropped with a warn-level log: they cannot be
    /// safely interpreted as part of any SSE event, and they
    /// cannot be part of a placeholder either (`«` and `»` are
    /// 2-byte sequences; a truncated trailing byte is too short
    /// to be either). The privacy round-trip is intact; only the
    /// UX of the tail char is degraded.
    pub fn flush_bytes(&mut self, map: &PlaceholderMap) -> Bytes {
        if !self.byte_buf.is_empty() {
            tracing::warn!(
                bytes = self.byte_buf.len(),
                "dropping trailing invalid UTF-8 from SSE stream on flush",
            );
            self.byte_buf.clear();
        }
        Bytes::from(self.flush(map))
    }

    /// Called when the upstream stream ends. Returns the final SSE
    /// bytes to forward, including any held-back text emitted as a
    /// synthetic `content_block_delta` event.
    ///
    /// The held-back text — if any — passes through `reverse` one
    /// last time before being emitted. A placeholder that never
    /// closed (`«SECRET_AWS_` with no `»`) does NOT match the
    /// reverse regex and is emitted as-is. That is a UX cost (user
    /// sees a partial placeholder), never a privacy leak (the bytes
    /// are the placeholder we minted, not the original secret).
    pub fn flush(&mut self, map: &PlaceholderMap) -> String {
        let mut out = String::new();

        // Drain any partial event still in parse_buf. SSE streams
        // typically end with `\n\n`, but a truncated upstream might
        // leave a partial event behind — pass it through after
        // attempting normal processing.
        if !self.parse_buf.is_empty() {
            let event_text = std::mem::take(&mut self.parse_buf);
            out.push_str(&self.process_event(&event_text, map));
        }

        // Emit any held-back text as a synthetic content_block_delta.
        // This is the "stream ended mid-placeholder" path: an unclosed
        // `«SECRET_...` stays in pending_text until flush, then goes
        // out as-is (no » means reverse() won't match — see flush()
        // doc for the privacy invariant).
        if !self.pending_text.is_empty() {
            let remaining = std::mem::take(&mut self.pending_text);
            let reversed = reverse(&remaining, map);
            out.push_str(&format_synthetic_text_delta(&reversed));
        }

        out
    }

    fn process_event(&mut self, event_text: &str, map: &PlaceholderMap) -> String {
        let parsed = parse_sse_event(event_text);

        // Only content_block_delta with a text_delta payload needs
        // placeholder-aware re-serialization. Everything else
        // (message_start, content_block_start/stop, message_delta,
        // message_stop, ping, input_json_delta, etc.) flows through
        // unchanged. Critically, content_block_stop also gets a
        // pre-flush of pending_text so a placeholder that was held
        // back at end-of-block goes out before the stop event.
        match parsed.event_type.as_deref() {
            Some("content_block_delta") => {
                if let Some(out) = self.try_process_text_delta(&parsed, map) {
                    return out;
                }
                // Not a text_delta (e.g., input_json_delta): pass through.
                ensure_event_terminator(event_text)
            }
            Some("content_block_stop") | Some("message_delta") | Some("message_stop") => {
                let mut out = String::new();
                if !self.pending_text.is_empty() {
                    let remaining = std::mem::take(&mut self.pending_text);
                    let reversed = reverse(&remaining, map);
                    out.push_str(&format_synthetic_text_delta(&reversed));
                }
                out.push_str(&ensure_event_terminator(event_text));
                out
            }
            _ => ensure_event_terminator(event_text),
        }
    }

    /// Try to rewrite a `content_block_delta` event whose JSON has a
    /// `delta.type == "text_delta"`. Returns `None` if the event
    /// isn't a text_delta (so the caller falls back to passthrough).
    fn try_process_text_delta(
        &mut self,
        parsed: &SseEvent,
        map: &PlaceholderMap,
    ) -> Option<String> {
        let data = parsed.data.as_deref()?;
        let mut json: Value = serde_json::from_str(data).ok()?;
        let delta = json.get("delta")?;
        let delta_type = delta.get("type").and_then(Value::as_str)?;
        if delta_type != "text_delta" {
            return None;
        }
        let text = delta.get("text").and_then(Value::as_str)?.to_string();

        // Accumulate text, compute safe-to-emit prefix, drain it.
        self.pending_text.push_str(&text);
        let safe_end = safe_emit_position(&self.pending_text);
        let safe_text: String = self.pending_text.drain(..safe_end).collect();

        // Everything in the chunk got held back (e.g., the entire
        // text was `«SECRET_AWS_`). Skip emitting an empty
        // content_block_delta — it would be valid but visible UX
        // noise for clients that key off `text.length > 0`.
        if safe_text.is_empty() {
            return Some(String::new());
        }

        // Apply reverse to the safe portion. Placeholders that fully
        // close before this position will be substituted; everything
        // else passes through unchanged.
        let reversed = reverse(&safe_text, map);

        // Re-serialize the event with the reversed text.
        // Preserves the rest of the JSON (index, etc.) so downstream
        // clients that key off block index still see the right value.
        if let Some(delta_obj) = json.get_mut("delta").and_then(Value::as_object_mut) {
            delta_obj.insert("text".to_string(), Value::String(reversed));
        }

        let event_type = parsed.event_type.as_deref().unwrap_or("message");
        Some(format!(
            "event: {event_type}\ndata: {}\n\n",
            serde_json::to_string(&json).ok()?
        ))
    }
}

/// Parsed SSE event view. Holds borrowed data slots; the actual
/// bytes live on `parse_buf` until we drain them.
#[derive(Debug, Default)]
struct SseEvent {
    event_type: Option<String>,
    data: Option<String>,
}

/// Parse a single SSE event's text into its `event:` type and joined
/// `data:` payload. Lines without recognized field names (or comments
/// starting with `:`) are ignored, matching the SSE spec.
fn parse_sse_event(text: &str) -> SseEvent {
    let mut event_type = None;
    let mut data_lines: Vec<String> = Vec::new();

    for line in text.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event_type = Some(value.trim_start().to_string());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(value.trim_start().to_string());
        }
        // Other field lines (id:, retry:) and comments (:...) are
        // ignored — they don't affect the placeholder round-trip.
    }

    SseEvent {
        event_type,
        data: if data_lines.is_empty() {
            None
        } else {
            Some(data_lines.join("\n"))
        },
    }
}

/// Find the byte offset where the first complete SSE event ends in
/// `buf`. Returns `(event_text, rest_offset)` where `event_text` is
/// the event payload (without the terminator) and `rest_offset` is
/// the byte index in `buf` where remaining unparsed bytes begin.
///
/// Handles both `\n\n` and `\r\n\r\n` event terminators per the SSE
/// spec.
fn split_first_event(buf: &str) -> Option<(String, usize)> {
    if let Some(idx) = buf.find("\r\n\r\n") {
        return Some((buf[..idx].to_string(), idx + 4));
    }
    if let Some(idx) = buf.find("\n\n") {
        return Some((buf[..idx].to_string(), idx + 2));
    }
    None
}

/// Ensure an event text ends with `\n\n` so concatenation yields a
/// well-formed SSE stream. Pass-through events from `process_event`
/// have their terminator stripped by `split_first_event`; this
/// re-attaches it.
fn ensure_event_terminator(event_text: &str) -> String {
    if event_text.ends_with("\n\n") || event_text.ends_with("\r\n\r\n") {
        event_text.to_string()
    } else {
        format!("{event_text}\n\n")
    }
}

/// Build a synthetic `content_block_delta` event carrying `text` as
/// its `text_delta.text`. Used to emit held-back text on flush or on
/// content_block_stop.
fn format_synthetic_text_delta(text: &str) -> String {
    // serde_json::to_string is the only way to guarantee correct
    // string escaping (newlines, quotes, etc.). Build the object
    // first, then format the SSE wrapper.
    let json = serde_json::json!({
        "type": "content_block_delta",
        "delta": {"type": "text_delta", "text": text},
    });
    format!(
        "event: content_block_delta\ndata: {}\n\n",
        serde_json::to_string(&json).expect("serde_json never fails on this shape"),
    )
}

/// Byte offset in `buf` where the safe-to-emit prefix ends.
///
/// Returns `buf.len()` (emit everything) when:
///   - there is no `«` in `buf`, OR
///   - the rightmost `«` has a matching `»` later in `buf` (any
///     placeholder there is structurally complete and `reverse` can
///     match it).
///
/// Returns the byte index of the rightmost `«` when its tail could
/// be the prefix of an incomplete placeholder — i.e., the tail
/// matches the shape `«` + prefix-of-`SECRET_` + `[A-Z0-9_]*`. The
/// caller holds back from that index and re-evaluates after the
/// next push.
pub fn safe_emit_position(buf: &str) -> usize {
    let Some(idx) = buf.rfind('\u{ab}') else {
        return buf.len();
    };
    let tail = &buf[idx..];
    if tail.contains('\u{bb}') {
        return buf.len();
    }
    if is_partial_placeholder_prefix(tail) {
        return idx;
    }
    buf.len()
}

/// True if `tail` (which must start with `«` and contain no `»`)
/// could be the prefix of `«SECRET_<TYPE>_<NNN>».
///
/// Valid prefixes:
///   - any prefix of `«SECRET_` (e.g., `«`, `«S`, `«SECRET`,
///     `«SECRET_`)
///   - `«SECRET_` followed by zero or more characters from
///     `[A-Z0-9_]` (the TYPE and counter chars)
///
/// Anything else (lowercase, punctuation, whitespace after the
/// `SECRET_` boundary) means the tail cannot extend into a
/// well-formed placeholder, so it's safe to emit.
pub fn is_partial_placeholder_prefix(tail: &str) -> bool {
    let Some(after_open) = tail.strip_prefix('\u{ab}') else {
        return false;
    };
    const SECRET_PREFIX: &str = "SECRET_";
    if SECRET_PREFIX.starts_with(after_open) {
        return true;
    }
    let Some(after_secret) = after_open.strip_prefix(SECRET_PREFIX) else {
        return false;
    };
    after_secret
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::SecretKind;

    fn map_with(kind: SecretKind, secret: &str) -> PlaceholderMap {
        let mut m = PlaceholderMap::new();
        m.placeholder_for(kind, secret);
        m
    }

    // ---- safe_emit_position ----

    #[test]
    fn safe_emit_empty_buffer_returns_zero() {
        // Boundary: empty input should return 0 (which is also the length).
        // Without this, a buffered chunk that's empty would underflow.
        assert_eq!(safe_emit_position(""), 0);
    }

    #[test]
    fn safe_emit_no_guillemet_emits_everything() {
        // No `«` means no placeholder can be in flight; the whole buffer
        // is safe to emit. This is the fast path for normal text.
        let buf = "Hello there, how are you?";
        assert_eq!(safe_emit_position(buf), buf.len());
    }

    #[test]
    fn safe_emit_complete_placeholder_emits_everything() {
        // A closed `«...»` is structurally complete; reverse() can match
        // it. No holdback needed.
        let buf = "Your \u{ab}SECRET_AWS_KEY_001\u{bb} is leaked.";
        assert_eq!(safe_emit_position(buf), buf.len());
    }

    #[test]
    fn safe_emit_partial_placeholder_holds_back_at_guillemet() {
        // The critical case this module exists for: `«SECRET_AWS_` with
        // no closing `»` is a partial placeholder. We must NOT emit the
        // `«` and partial tail downstream — that's what made the
        // cross-event-split case leak in Phase 2b.
        let buf = "Your \u{ab}SECRET_AWS_";
        // "Your " is 5 ASCII bytes; the `«` starts at byte 5.
        assert_eq!(safe_emit_position(buf), 5);
    }

    #[test]
    fn safe_emit_just_guillemet_holds_back() {
        // Even `«` alone — the model has only emitted the opening
        // guillemet — must hold back, in case the next chunk completes
        // a placeholder.
        let buf = "Prefix \u{ab}";
        assert_eq!(safe_emit_position(buf), "Prefix ".len());
    }

    #[test]
    fn safe_emit_guillemet_followed_by_non_secret_text_emits() {
        // A `«` that's followed by a lowercase word can't be the start
        // of a placeholder (our format is `«SECRET_...`). Holding back
        // here would unnecessarily stall a stream that contains
        // legitimate French punctuation.
        let buf = "Bonjour \u{ab}monde";
        assert_eq!(safe_emit_position(buf), buf.len());
    }

    #[test]
    fn safe_emit_secret_underscore_then_invalid_char_emits() {
        // `«SECRET_ ` (space) breaks the placeholder shape. The TYPE_NNN
        // portion only allows `[A-Z0-9_]`. Holding back would stall the
        // stream on text that can never extend into a valid placeholder.
        let buf = "Look \u{ab}SECRET_ ahem";
        assert_eq!(safe_emit_position(buf), buf.len());
    }

    #[test]
    fn safe_emit_multiple_guillemets_uses_rightmost() {
        // First placeholder complete, second still partial: hold back
        // ONLY from the second `«`. The first one's full placeholder
        // gets emitted (and reverse()d by the caller). Using the
        // leftmost `«` would emit the partial too and re-introduce
        // the cross-event leak.
        let buf = "\u{ab}SECRET_AWS_KEY_001\u{bb} and \u{ab}SECRET_AWS_";
        let expected = buf.rfind('\u{ab}').unwrap();
        assert_eq!(safe_emit_position(buf), expected);
    }

    // ---- is_partial_placeholder_prefix ----

    #[test]
    fn partial_prefix_just_opening_guillemet_is_prefix() {
        assert!(is_partial_placeholder_prefix("\u{ab}"));
    }

    #[test]
    fn partial_prefix_building_secret_word() {
        // Each successive char of "SECRET_" is a valid prefix.
        for n in 0..=7 {
            let tail = format!("\u{ab}{}", &"SECRET_"[..n]);
            assert!(
                is_partial_placeholder_prefix(&tail),
                "expected {tail:?} to be a valid prefix",
            );
        }
    }

    #[test]
    fn partial_prefix_past_secret_underscore() {
        // After `SECRET_`, allowed chars are `[A-Z0-9_]`. These should
        // be valid prefixes since they could extend into the TYPE_NNN
        // portion of a placeholder.
        assert!(is_partial_placeholder_prefix("\u{ab}SECRET_A"));
        assert!(is_partial_placeholder_prefix("\u{ab}SECRET_AWS"));
        assert!(is_partial_placeholder_prefix("\u{ab}SECRET_AWS_KEY"));
        assert!(is_partial_placeholder_prefix("\u{ab}SECRET_AWS_KEY_001"));
        assert!(is_partial_placeholder_prefix("\u{ab}SECRET_ANTHROPIC_KEY_042"));
    }

    #[test]
    fn partial_prefix_rejects_lowercase_after_secret() {
        // `«SECRET_aws` cannot extend into a well-formed placeholder
        // (our TYPE_NNN regex is uppercase only). Holding back would
        // stall on text that's safe to emit.
        assert!(!is_partial_placeholder_prefix("\u{ab}SECRET_aws"));
    }

    #[test]
    fn partial_prefix_rejects_punctuation_after_secret() {
        assert!(!is_partial_placeholder_prefix("\u{ab}SECRET_!"));
        assert!(!is_partial_placeholder_prefix("\u{ab}SECRET_ X"));
    }

    #[test]
    fn partial_prefix_rejects_word_that_diverges_from_secret() {
        // `«SECRETLY` shares the first six letters of `SECRET_` but
        // then has `LY` instead of `_`. Not a valid prefix.
        assert!(!is_partial_placeholder_prefix("\u{ab}SECRETLY"));
    }

    #[test]
    fn partial_prefix_rejects_input_without_opening_guillemet() {
        // Defensive: callers pass tails starting at the rightmost
        // `«`; if the contract is violated, return false rather than
        // pretend it's a partial.
        assert!(!is_partial_placeholder_prefix("SECRET_"));
    }

    // ---- parse_sse_event ----

    #[test]
    fn parse_event_with_event_and_data_lines() {
        let event = "event: content_block_delta\ndata: {\"hello\":\"world\"}";
        let parsed = parse_sse_event(event);
        assert_eq!(parsed.event_type.as_deref(), Some("content_block_delta"));
        assert_eq!(parsed.data.as_deref(), Some("{\"hello\":\"world\"}"));
    }

    #[test]
    fn parse_event_with_only_data_line() {
        // Default event type per SSE spec is "message"; we don't
        // synthesize that — the caller defaults if it cares.
        let event = "data: payload";
        let parsed = parse_sse_event(event);
        assert!(parsed.event_type.is_none());
        assert_eq!(parsed.data.as_deref(), Some("payload"));
    }

    #[test]
    fn parse_event_with_multiple_data_lines_joins_with_newline() {
        // SSE spec: multi-line data joins with `\n`.
        let event = "event: foo\ndata: line1\ndata: line2";
        let parsed = parse_sse_event(event);
        assert_eq!(parsed.data.as_deref(), Some("line1\nline2"));
    }

    #[test]
    fn parse_event_ignores_comments_and_unknown_fields() {
        // SSE comments start with `:` and are ignored.
        // `id:` and `retry:` are valid but not relevant here.
        let event = ": this is a comment\nid: 5\nretry: 1000\nevent: x\ndata: y";
        let parsed = parse_sse_event(event);
        assert_eq!(parsed.event_type.as_deref(), Some("x"));
        assert_eq!(parsed.data.as_deref(), Some("y"));
    }

    // ---- split_first_event ----

    #[test]
    fn split_returns_first_event_and_offset() {
        let buf = "event: foo\ndata: 1\n\nevent: bar\ndata: 2\n\n";
        let (first, rest_offset) = split_first_event(buf).unwrap();
        assert_eq!(first, "event: foo\ndata: 1");
        assert_eq!(&buf[rest_offset..], "event: bar\ndata: 2\n\n");
    }

    #[test]
    fn split_handles_crlf_terminator() {
        // SSE spec allows `\r\n\r\n` as well as `\n\n`. Real-world
        // upstreams (especially proxies in front of Anthropic) may
        // emit either; we must not deadlock on the form we don't
        // expect.
        let buf = "event: foo\r\ndata: 1\r\n\r\nevent: bar";
        let (first, rest_offset) = split_first_event(buf).unwrap();
        assert_eq!(first, "event: foo\r\ndata: 1");
        assert_eq!(&buf[rest_offset..], "event: bar");
    }

    #[test]
    fn split_returns_none_when_no_terminator() {
        // A partial chunk arrives mid-event; we cannot process it yet.
        // The push() loop relies on this returning None to stop.
        let buf = "event: foo\ndata: 1";
        assert!(split_first_event(buf).is_none());
    }

    // ---- SseReverser end-to-end ----

    /// Build an event with a single text_delta payload — the shape
    /// the test fixture in `proxy-server/tests/relay_redacts.rs`
    /// generates.
    fn text_delta_event(text: &str) -> String {
        format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":{}}}}}\n\n",
            serde_json::to_string(text).unwrap(),
        )
    }

    #[test]
    fn sse_reverser_reverses_placeholder_inside_single_event() {
        // Baseline: when a complete placeholder lands inside one event,
        // the reverser must substitute it back. This is the Phase 2b
        // case that was already working — the test exists to pin that
        // Phase 2c doesn't regress it.
        let map = map_with(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let mut r = SseReverser::new();
        let event = text_delta_event("Your \u{ab}SECRET_AWS_KEY_001\u{bb} works.");
        let out = r.push(&event, &map);
        // The map has nothing pending after a complete placeholder.
        let flushed = r.flush(&map);
        let combined = format!("{out}{flushed}");
        assert!(
            combined.contains("AKIAIOSFODNN7EXAMPLE"),
            "expected secret restored, got {combined:?}",
        );
        assert!(
            !combined.contains("\u{ab}SECRET_"),
            "placeholder leaked: {combined:?}",
        );
    }

    #[test]
    fn sse_reverser_reverses_placeholder_split_across_three_events() {
        // The Phase 2c module needs to accumulate placeholder
        // fragments across more than two events too. Three-way split
        // exercises the case where the second push neither completes
        // the placeholder nor adds a break char — pending must keep
        // accumulating, not get prematurely flushed. Without this
        // test, a future refactor that "clears pending on every
        // event" would still pass the two-event case but silently
        // fail here, leaking the fragments.
        let map = map_with(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let mut r = SseReverser::new();
        let event1 = text_delta_event("\u{ab}SECRET_");
        let event2 = text_delta_event("AWS_KEY_");
        let event3 = text_delta_event("001\u{bb} ok.");
        let out1 = r.push(&event1, &map);
        let out2 = r.push(&event2, &map);
        let out3 = r.push(&event3, &map);
        let flushed = r.flush(&map);
        let combined = format!("{out1}{out2}{out3}{flushed}");
        assert!(
            combined.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret not restored across 3-way split: {combined:?}",
        );
        assert!(
            !combined.contains("\u{ab}SECRET_"),
            "placeholder leaked: {combined:?}",
        );
        assert!(combined.contains("ok."));
    }

    #[test]
    fn sse_reverser_holds_back_across_unrelated_event_then_reverses() {
        // A `ping` (or any non-text-delta event) arriving between
        // two text_delta chunks of a fragmented placeholder must not
        // disturb the held-back state. Without this guarantee,
        // anything Anthropic sends between event-stream keepalives
        // and content_block_deltas would silently leak placeholder
        // fragments.
        let map = map_with(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let mut r = SseReverser::new();
        let head = text_delta_event("Your \u{ab}SECRET_AWS_");
        let ping = "event: ping\ndata: {\"type\":\"ping\"}\n\n";
        let tail = text_delta_event("KEY_001\u{bb} works.");
        let out_a = r.push(&head, &map);
        let out_b = r.push(ping, &map);
        let out_c = r.push(&tail, &map);
        let flushed = r.flush(&map);
        let combined = format!("{out_a}{out_b}{out_c}{flushed}");
        assert!(
            combined.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret not restored when an unrelated event was interleaved: {combined:?}",
        );
        assert!(
            !combined.contains("\u{ab}SECRET_"),
            "placeholder leaked across interleaved event: {combined:?}",
        );
        // The interleaved ping must still reach the client — silently
        // dropping it would break keepalive semantics for clients
        // that watch for it.
        assert!(
            combined.contains("event: ping"),
            "interleaved event was dropped: {combined:?}",
        );
    }

    #[test]
    fn sse_reverser_reverses_placeholder_split_across_two_events() {
        // The Phase 2c headline case: event 1 ends with `«SECRET_AWS_`
        // and event 2 starts with `KEY_001»`. Phase 2b's whole-buffer
        // reverse() couldn't match across the intervening SSE/JSON
        // framing bytes; the streaming reverser must.
        let map = map_with(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let mut r = SseReverser::new();
        let event1 = text_delta_event("Your \u{ab}SECRET_AWS_");
        let event2 = text_delta_event("KEY_001\u{bb} needs s3:GetObject.");
        let out1 = r.push(&event1, &map);
        let out2 = r.push(&event2, &map);
        let flushed = r.flush(&map);
        let combined = format!("{out1}{out2}{flushed}");
        assert!(
            combined.contains("AKIAIOSFODNN7EXAMPLE"),
            "expected secret restored, got {combined:?}",
        );
        assert!(
            !combined.contains("\u{ab}SECRET_"),
            "placeholder leaked: {combined:?}",
        );
        assert!(combined.contains("needs s3:GetObject"));
    }

    #[test]
    fn sse_reverser_holds_back_partial_then_flush_emits_unreversed() {
        // Privacy invariant: if the stream ENDS while a partial
        // placeholder is held back (model crashed mid-emission,
        // network truncation), flush emits the held-back bytes as a
        // synthetic content_block_delta. The user sees the unreversed
        // placeholder fragment — never the original secret, since the
        // placeholder never closed and reverse() cannot match.
        let map = map_with(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let mut r = SseReverser::new();
        let event = text_delta_event("prefix \u{ab}SECRET_AWS_");
        let out = r.push(&event, &map);
        let flushed = r.flush(&map);
        let combined = format!("{out}{flushed}");
        // "prefix " was safe to emit; the placeholder fragment goes
        // out only on flush.
        assert!(combined.contains("prefix "));
        // The original secret MUST NOT appear — there was never a
        // complete placeholder to reverse.
        assert!(
            !combined.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret leaked from incomplete placeholder: {combined:?}",
        );
        // The placeholder fragment passes through unreversed on flush.
        assert!(
            combined.contains("\u{ab}SECRET_AWS_"),
            "expected partial placeholder to be flushed, got {combined:?}",
        );
    }

    #[test]
    fn sse_reverser_passes_through_non_text_events_unchanged() {
        // message_start has no delta.text to process; it must not get
        // mangled by the reverser. Without this, the SSE stream's
        // event ordering would corrupt.
        let map = map_with(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let mut r = SseReverser::new();
        let event = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
        let out = r.push(event, &map);
        assert_eq!(out, event);
    }

    #[test]
    fn sse_reverser_flushes_pending_before_content_block_stop() {
        // When content_block_stop arrives with pending held-back
        // text, the reverser must emit a final synthetic
        // content_block_delta BEFORE the stop event — otherwise the
        // client receives the stop, treats the block as complete,
        // and then a stale delta arrives out of order.
        let map = map_with(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let mut r = SseReverser::new();
        let delta_event = text_delta_event("prefix \u{ab}SECRET_AWS_");
        let stop_event = "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n";

        let mut out = String::new();
        out.push_str(&r.push(&delta_event, &map));
        out.push_str(&r.push(stop_event, &map));

        // The flushed delta must come BEFORE the content_block_stop
        // event. Find the byte offsets and compare.
        let stop_idx = out.find("content_block_stop").expect("stop event present");
        let pending_idx = out
            .find("\u{ab}SECRET_AWS_")
            .expect("flushed pending text present");
        assert!(
            pending_idx < stop_idx,
            "flushed delta must precede stop event in output; got {out:?}",
        );
    }

    #[test]
    fn sse_reverser_push_bytes_handles_mid_utf8_chunk_boundary() {
        // The byte-typed push must tolerate a chunk boundary that
        // splits a multi-byte UTF-8 character. `«` is two bytes
        // (0xC2 0xAB); if reqwest's bytes_stream delivers chunks
        // that split there, naive `from_utf8` would error and we'd
        // either lose bytes or panic. The byte_buf carries the
        // dangling first byte across pushes.
        let map = map_with(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let mut r = SseReverser::new();
        let full = text_delta_event("\u{ab}SECRET_AWS_KEY_001\u{bb} fixed");
        let bytes = full.as_bytes();
        // Find the byte position of the opening `«` (0xC2 0xAB) and
        // split the chunk BETWEEN those two bytes — the worst case
        // for the boundary handler.
        let guillemet_pos = bytes.iter().position(|&b| b == 0xC2).unwrap();
        let (part_a, part_b) = bytes.split_at(guillemet_pos + 1);

        let out_a = r.push_bytes(part_a, &map);
        let out_b = r.push_bytes(part_b, &map);
        let flushed = r.flush_bytes(&map);

        let combined: Vec<u8> = out_a.iter().chain(out_b.iter()).chain(flushed.iter()).copied().collect();
        let combined_str = std::str::from_utf8(&combined).expect("output must be valid UTF-8");
        assert!(
            combined_str.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret not restored after mid-UTF8 chunk split: {combined_str:?}",
        );
        assert!(
            !combined_str.contains("\u{ab}SECRET_"),
            "placeholder leaked: {combined_str:?}",
        );
    }

    #[test]
    fn sse_reverser_handles_chunked_event_arrival() {
        // The bytes_stream from reqwest delivers chunks at arbitrary
        // boundaries. The reverser must tolerate an event arriving
        // across multiple push() calls — the parse_buf must hold the
        // partial event until the terminator shows up.
        let map = map_with(SecretKind::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE");
        let mut r = SseReverser::new();
        let full = text_delta_event("Hello \u{ab}SECRET_AWS_KEY_001\u{bb} world.");
        // Split right before the `«` (a char boundary) so the chunk
        // boundary lands mid-event but at valid UTF-8. The "find" is
        // also semantically meaningful: this is the failure point
        // upstream byte streams routinely produce — they split inside
        // an SSE event but at character boundaries (TCP doesn't honor
        // SSE structure).
        let split = full.find('\u{ab}').unwrap();
        let (part_a, part_b) = full.split_at(split);

        let out_a = r.push(part_a, &map);
        let out_b = r.push(part_b, &map);
        let combined = format!("{out_a}{out_b}");
        assert!(combined.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!combined.contains("\u{ab}SECRET_"));
    }
}
