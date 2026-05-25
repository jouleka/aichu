// system_prompt — preserve-tokens system prompt injection helpers.
//
// The proxy redacts secret-shaped substrings from the user's prompt
// before forwarding to a model provider, leaving `«SECRET_TYPE_NNN»`
// placeholders in their place. Some models paraphrase or omit those
// placeholders when generating their response, which silently breaks
// the round-trip reverse pass (the user sees a response that doesn't
// mention the secret they typed).
//
// The fix: prepend a small system prompt that tells the model these
// placeholders are first-class strings to be echoed verbatim. The
// experimental e03 eval measured this lifts guillemets preservation
// from 12% to 96% on gpt-5-mini — strong enough that this module
// makes the prompt injection default-on in the proxy handlers.
//
// Public surface:
//
//   PRESERVE_TOKENS_PROMPT    inline `const &str`, baked into the
//                             binary via `include_str!`. No file I/O.
//
//   inject_anthropic(body)    prepend to `system` in an Anthropic
//                             /v1/messages JSON body. Handles the
//                             `Union[str, Iterable[TextBlockParam]]`
//                             system-field shape documented in the
//                             Anthropic Python SDK (verified via
//                             context7 — see crate doc comments).
//
//   inject_openai(body)       prepend to `messages` in an OpenAI
//                             /v1/chat/completions JSON body. If the
//                             first message is already `role: "system"`,
//                             merge into its content; otherwise
//                             insert a new system message at index 0.
//
//   inject_responses(body)    prepend to the top-level `instructions`
//                             field in an OpenAI Responses-API JSON
//                             body (`/v1/responses`, Codex CLI's
//                             `/backend-api/codex/responses`, and
//                             OpenCode's `/zen/v1/responses`). The
//                             field is documented as `string | null`
//                             in the OpenAI TypeScript SDK
//                             (`ResponseCreateParamsBase.instructions`),
//                             which the comment describes as "a system
//                             (or developer) message inserted into the
//                             model's context" — semantically equivalent
//                             to Anthropic's top-level `system` field.
//
//   InjectionShape            enum factored out of proxy-mitm and
//                             proxy-server: each handler crate maps
//                             its known prompt endpoints onto one of
//                             these variants and calls `.inject(body)`
//                             instead of branching on the variant
//                             itself. Adding a new wire shape only
//                             requires editing this crate plus the
//                             handler-crate path mappings.
//
// Design choices locked in v0:
//
//   - PREPEND, never replace. Client-supplied system prompts always
//     survive — the preserve-tokens text goes FIRST so the model sees
//     it before any client-supplied instructions, but the client's
//     own prompt is untouched after it.
//
//   - SEPARATOR: two newlines (`\n\n`). Distinct from the placeholder
//     prose and matches the convention used by most existing
//     prompt-stacking code.
//
//   - FAIL LOUD (per CLAUDE.md Rule 12). Both inject_ functions
//     mutate in place; if the body shape doesn't match what we
//     expect (e.g. `messages` is not an array on OpenAI, or `system`
//     is some unexpected non-string non-array on Anthropic), we log
//     at warn level and leave the body unchanged — never silently
//     replace a value with a different shape.

use serde_json::{Value, json};

/// The preserve-tokens system prompt the proxy injects into
/// forwarded requests. Inline const (no file I/O) — bakes into the
/// binary at compile time via `include_str!`, so the production
/// binary is fully self-contained and does not depend on the
/// experimental e03 text file shipping alongside it.
///
/// Kept under 200 words and focused on the production placeholder
/// format only (guillemets `«…»`). The e03 eval used a longer prompt
/// that named all six experimental formats; production only emits
/// guillemets (see `placeholder::PlaceholderFormat`), so the prompt
/// can be shorter without losing fidelity.
pub const PRESERVE_TOKENS_PROMPT: &str = include_str!("preserve_tokens.txt");

/// Separator between the preserve-tokens prompt and any existing
/// client-supplied system prompt. Two newlines — distinct enough
/// from in-prose paragraph breaks that the model sees a clear
/// boundary, conventional for stacked-prompt assembly.
const SEPARATOR: &str = "\n\n";

/// Prepend `PRESERVE_TOKENS_PROMPT` to the `system` field of an
/// Anthropic `/v1/messages` request body.
///
/// Anthropic's `system` field is `Union[str, Iterable[TextBlockParam]]`
/// per the Python SDK's `MessageCreateParamsBase` (verified via
/// context7 against `/anthropics/anthropic-sdk-python` —
/// `src/anthropic/types/message_create_params.py`).
///
/// Behavior:
///   - `system` absent → set to `PRESERVE_TOKENS_PROMPT` (string).
///   - `system` is a string → set to `PRESERVE + "\n\n" + existing`.
///   - `system` is an array → insert `{"type":"text","text":PRESERVE}`
///     at index 0; original blocks shift down.
///   - `system` is anything else → log warn, leave body unchanged.
///     (We never replace an unexpected shape with a different shape;
///     fail loud.)
///
/// Mutates `body` in place. No-op if `body` is not a JSON object.
pub fn inject_anthropic(body: &mut Value) {
    let Some(obj) = body.as_object_mut() else {
        tracing::warn!("inject_anthropic: body is not a JSON object, leaving unchanged");
        return;
    };

    match obj.get_mut("system") {
        None => {
            obj.insert("system".to_string(), Value::String(PRESERVE_TOKENS_PROMPT.to_string()));
        }
        Some(Value::String(existing)) => {
            let combined = format!("{PRESERVE_TOKENS_PROMPT}{SEPARATOR}{existing}");
            *existing = combined;
        }
        Some(Value::Array(arr)) => {
            // Prepend a text block. Preserves any per-block
            // `cache_control` markers the caller may have set on
            // existing blocks — we only touch index 0.
            arr.insert(0, json!({"type": "text", "text": PRESERVE_TOKENS_PROMPT}));
        }
        Some(other) => {
            tracing::warn!(
                "inject_anthropic: `system` field is neither string nor array (got {:?}), leaving unchanged",
                other,
            );
        }
    }
}

/// Prepend `PRESERVE_TOKENS_PROMPT` to the `messages` array of an
/// OpenAI `/v1/chat/completions` request body.
///
/// Behavior:
///   - `messages` absent or not an array → log warn, leave body unchanged
///     (fail loud — the caller's body is malformed, don't paper over it).
///   - `messages[0].role == "system"` (with string `content`) → set
///     content to `PRESERVE + "\n\n" + existing`. Length unchanged.
///   - `messages[0].role == "system"` (with non-string `content`) →
///     insert a new system message at index 0 (defensive — OpenAI's
///     newer schemas allow array content, but the safe operation is
///     to add our own system message rather than splice into an
///     unknown shape).
///   - anything else (no system message, or first message is not
///     system) → insert `{"role":"system","content":PRESERVE}` at
///     index 0. We do NOT insert past index 0 — OpenAI's behavior
///     with multiple system messages is provider-dependent and we
///     shouldn't rely on it.
///
/// Mutates `body` in place. No-op if `body` is not a JSON object.
pub fn inject_openai(body: &mut Value) {
    let Some(obj) = body.as_object_mut() else {
        tracing::warn!("inject_openai: body is not a JSON object, leaving unchanged");
        return;
    };

    let Some(messages) = obj.get_mut("messages").and_then(|v| v.as_array_mut()) else {
        tracing::warn!(
            "inject_openai: `messages` is missing or not an array, leaving body unchanged",
        );
        return;
    };

    let first_is_system = messages
        .first()
        .and_then(|m| m.get("role"))
        .and_then(|r| r.as_str())
        == Some("system");

    if first_is_system {
        // Try to merge into the existing string content.
        if let Some(content) = messages[0].get_mut("content") {
            if let Some(s) = content.as_str() {
                let combined = format!("{PRESERVE_TOKENS_PROMPT}{SEPARATOR}{s}");
                *content = Value::String(combined);
                return;
            }
        }
        // Non-string content (or no content at all): fall through
        // to inserting our own system message at index 0. The
        // user's original system message stays at index 1; OpenAI
        // accepts multi-system layouts, and the alternative
        // (splicing into an array-shaped content) requires knowing
        // OpenAI's block schema variants.
        tracing::debug!(
            "inject_openai: first message is system but content is not a string; \
             inserting separate system message at index 0",
        );
    }

    messages.insert(
        0,
        json!({"role": "system", "content": PRESERVE_TOKENS_PROMPT}),
    );
}

/// Prepend `PRESERVE_TOKENS_PROMPT` to the top-level `instructions`
/// field of an OpenAI Responses-API request body (`/v1/responses`,
/// Codex CLI's `/backend-api/codex/responses`, and OpenCode's
/// `/zen/v1/responses`).
///
/// Wire-shape decision (verified via context7 against
/// `/openai/openai-node` —
/// `openai-node/src/resources/responses/responses.ts::ResponseCreateParamsBase`):
///
///   /// A system (or developer) message inserted into the model's context.
///   instructions?: string | null;
///
/// `instructions` is a top-level string-typed field, semantically
/// equivalent to Anthropic's top-level `system` (a system-level
/// directive that prepends to whatever conversational `input` the
/// caller passed). Unlike the Chat Completions wire shape, the
/// Responses API does NOT take a `messages` array — `input` is
/// either a `string` or an `InputItem[]` carrying user/assistant
/// content. We deliberately do NOT prepend a `role: "system"` item
/// to `input`: while the Realtime variant accepts that shape, the
/// stateless Responses API treats `instructions` as the canonical
/// slot for system-level guidance, and using it keeps our injection
/// site analogous to `inject_anthropic` (one top-level field).
///
/// Behavior:
///   - `instructions` absent OR null → set to `PRESERVE_TOKENS_PROMPT`
///     (string). Treating `null` the same as absent matches the
///     `string | null` schema: `null` is documented as "no system
///     message," same intent as omitting the field.
///   - `instructions` is a string → set to `PRESERVE + "\n\n" + existing`.
///     Client-supplied instructions survive verbatim at the end.
///   - `instructions` is anything else (non-string non-null) → log
///     warn, leave body unchanged. Fail loud (CLAUDE.md Rule 12):
///     we never replace an unexpected shape with a different shape.
///     The OpenAI schema does not currently allow an array for
///     `instructions`, but a future API extension might; sending
///     our string into an array slot would either error upstream
///     or silently drop part of the caller's payload.
///
/// Mutates `body` in place. No-op if `body` is not a JSON object.
pub fn inject_responses(body: &mut Value) {
    let Some(obj) = body.as_object_mut() else {
        tracing::warn!("inject_responses: body is not a JSON object, leaving unchanged");
        return;
    };

    match obj.get_mut("instructions") {
        None | Some(Value::Null) => {
            obj.insert(
                "instructions".to_string(),
                Value::String(PRESERVE_TOKENS_PROMPT.to_string()),
            );
        }
        Some(Value::String(existing)) => {
            let combined = format!("{PRESERVE_TOKENS_PROMPT}{SEPARATOR}{existing}");
            *existing = combined;
        }
        Some(other) => {
            tracing::warn!(
                "inject_responses: `instructions` field is not a string (got {:?}), leaving unchanged",
                other,
            );
        }
    }
}

/// Wire shape the system-prompt injector can safely mutate for a
/// given path. Each handler crate maps its known prompt endpoints
/// onto one of these variants and calls `.inject(body)`, so adding a
/// new wire shape requires changes only in this crate plus the
/// handler-crate path mappings.
///
/// Why not also factor out the path → shape mapping itself: the two
/// handler crates already filter prompt endpoints via different
/// mechanisms (proxy-mitm's `is_prompt_endpoint`, proxy-server's
/// axum routes) and the path sets they recognize are not symmetric
/// — proxy-mitm intercepts Codex CLI's `/backend-api/codex/responses`
/// and OpenCode's `/zen/v1/responses`, while proxy-server's router
/// currently only carries the canonical OpenAI/Anthropic paths.
/// Centralizing the path-to-shape mapping would require one of the
/// crates to carry routes it doesn't actually serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionShape {
    /// Anthropic `/v1/messages` — `system` is a top-level body field.
    Anthropic,
    /// OpenAI `/v1/chat/completions` (and the OpenCode zen alias) —
    /// system goes as the first element of `messages` with
    /// `role: "system"`.
    OpenAiChat,
    /// OpenAI Responses API (`/v1/responses`, `/backend-api/codex/responses`,
    /// `/zen/v1/responses`) — system goes in the top-level
    /// `instructions` field (string-typed).
    OpenAiResponses,
}

impl InjectionShape {
    /// Dispatch to the underlying `inject_*` function for this shape.
    /// Mutates `body` in place. Each variant's behavior matches the
    /// dedicated `inject_*` function it dispatches to; see those for
    /// the absent / present / unexpected-shape branches.
    ///
    /// MUST be called AFTER redaction; both handler crates document
    /// the ordering rationale at their call sites (the preserve-tokens
    /// prompt contains `«SECRET_<TYPE>_<NNN>»` schema text that would
    /// otherwise get caught by the redaction detector).
    pub fn inject(self, body: &mut Value) {
        match self {
            Self::Anthropic => inject_anthropic(body),
            Self::OpenAiChat => inject_openai(body),
            Self::OpenAiResponses => inject_responses(body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- inject_anthropic --------------------------------------------------

    #[test]
    fn inject_anthropic_when_system_absent_sets_string() {
        // Why this pins behavior: when no system prompt is set, the
        // proxy must add ours as a plain string. A regression that
        // instead inserted an array form would still "work" against
        // Anthropic (both shapes are accepted) but would surprise
        // downstream tooling that inspects the request before/after
        // injection. The string-equals-prompt assertion locks the
        // simplest possible shape.
        let mut body = json!({
            "model": "claude-opus-4-5",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "hello"}],
        });
        inject_anthropic(&mut body);
        assert_eq!(
            body["system"].as_str().unwrap(),
            PRESERVE_TOKENS_PROMPT,
            "absent system field should be set to the plain prompt string"
        );
    }

    #[test]
    fn inject_anthropic_when_system_is_string_prepends() {
        // Why this matters: a client that already sets `system`
        // (e.g. claude CLI's "You are Claude Code, ...") must NOT
        // have it dropped. Our prompt goes FIRST, separator, then
        // the original. The `starts_with` + `ends_with` assertions
        // pin both halves without coupling to the exact byte
        // representation of the separator.
        let original = "You are a helpful assistant.";
        let mut body = json!({
            "model": "claude-opus-4-5",
            "max_tokens": 100,
            "system": original,
            "messages": [{"role": "user", "content": "hi"}],
        });
        inject_anthropic(&mut body);
        let combined = body["system"].as_str().unwrap();
        assert!(
            combined.starts_with(PRESERVE_TOKENS_PROMPT),
            "preserve-tokens prompt must come FIRST; got: {combined}"
        );
        assert!(
            combined.ends_with(original),
            "original client prompt must survive verbatim at the end; got: {combined}"
        );
        assert!(
            combined.contains(SEPARATOR),
            "separator must appear between our prompt and the client's; got: {combined}"
        );
    }

    #[test]
    fn inject_anthropic_when_system_is_array_prepends_text_block() {
        // Why an array: Anthropic's `system` accepts an array of
        // TextBlockParam, which is how clients enable per-block
        // `cache_control` markers. If we replaced the array with a
        // string here, we'd silently drop the caller's caching
        // configuration — a real (and silent) performance regression.
        // The test pins that: (1) our block goes at index 0,
        // (2) the caller's blocks survive unmodified at indices 1..,
        // (3) cache_control markers on caller blocks are preserved.
        let cached_block = json!({
            "type": "text",
            "text": "Big context block",
            "cache_control": {"type": "ephemeral"},
        });
        let mut body = json!({
            "model": "claude-opus-4-5",
            "max_tokens": 100,
            "system": [cached_block.clone()],
            "messages": [{"role": "user", "content": "hi"}],
        });
        inject_anthropic(&mut body);
        let arr = body["system"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "expected one inserted block + original block");
        assert_eq!(arr[0]["type"], "text");
        assert_eq!(arr[0]["text"], PRESERVE_TOKENS_PROMPT);
        assert_eq!(arr[1], cached_block, "original cache_control block must survive unchanged");
    }

    #[test]
    fn inject_anthropic_when_system_is_unexpected_type_leaves_unchanged() {
        // Fail-loud branch (CLAUDE.md Rule 12): if `system` is some
        // shape we don't recognize (the API tightened, or the caller
        // sent garbage), we must NOT replace it with a different
        // shape. The body returns unchanged; tracing emits a warn
        // (not asserted here — `tracing` events are captured by
        // subscriber, not by serde_json::Value).
        let mut body = json!({
            "system": 42,
            "messages": [{"role": "user", "content": "hi"}],
        });
        let original = body.clone();
        inject_anthropic(&mut body);
        assert_eq!(body, original, "unexpected system shape must be left untouched");
    }

    // ---- inject_openai -----------------------------------------------------

    #[test]
    fn inject_openai_when_no_system_message_inserts_at_index_zero() {
        // Why this pins behavior: a fresh chat with no system
        // message should get ours prepended, NOT appended. OpenAI
        // honors the first system message; putting ours after the
        // user turn would push it past the prompt the model
        // attends to first.
        let mut body = json!({
            "model": "gpt-5-mini",
            "messages": [{"role": "user", "content": "hello"}],
        });
        inject_openai(&mut body);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], PRESERVE_TOKENS_PROMPT);
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "hello");
    }

    #[test]
    fn inject_openai_when_first_message_is_system_merges_content() {
        // Why merge instead of inserting a second system message:
        // OpenAI's documented behavior for multiple system messages
        // is "the model may give precedence to the first" — and
        // historically this has not been guaranteed across model
        // versions. Merging into ONE system message means our
        // preserve-tokens directive lands in the slot the model
        // definitely reads. The client's original system content
        // must still survive at the end.
        let original = "You are helpful.";
        let mut body = json!({
            "model": "gpt-5-mini",
            "messages": [
                {"role": "system", "content": original},
                {"role": "user", "content": "hi"},
            ],
        });
        inject_openai(&mut body);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(
            messages.len(),
            2,
            "merging into existing system message must NOT add a new entry"
        );
        let combined = messages[0]["content"].as_str().unwrap();
        assert!(combined.starts_with(PRESERVE_TOKENS_PROMPT));
        assert!(combined.ends_with(original));
        assert!(combined.contains(SEPARATOR));
        assert_eq!(messages[1]["role"], "user");
    }

    #[test]
    fn inject_openai_when_system_message_is_not_first_inserts_new_at_index_zero() {
        // Defensive branch: the user might have shuffled message
        // order (an assistant or user message before a system
        // message). Treat that as the no-system-prompt case — our
        // system message goes at index 0, the original messages
        // are pushed down. The "no merge with a non-first system
        // message" choice avoids the model seeing two distinct
        // system messages with overlapping intent.
        let mut body = json!({
            "model": "gpt-5-mini",
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "system", "content": "ignored"},
            ],
        });
        inject_openai(&mut body);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], PRESERVE_TOKENS_PROMPT);
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[2]["role"], "system");
        assert_eq!(messages[2]["content"], "ignored");
    }

    #[test]
    fn inject_openai_when_messages_is_missing_leaves_body_unchanged() {
        // Fail-loud branch: a `messages`-less body is not a valid
        // chat-completions request. Mutating it (e.g. by creating
        // a `messages` array containing only our system message)
        // would silently change the request semantics. Leave it
        // alone and let the upstream reject the malformed request
        // with its own error.
        let mut body = json!({"model": "gpt-5-mini"});
        let original = body.clone();
        inject_openai(&mut body);
        assert_eq!(body, original);
    }

    #[test]
    fn inject_openai_when_messages_is_not_an_array_leaves_body_unchanged() {
        // Same fail-loud rationale as the missing-messages case.
        let mut body = json!({"model": "gpt-5-mini", "messages": "not an array"});
        let original = body.clone();
        inject_openai(&mut body);
        assert_eq!(body, original);
    }

    // ---- inject_responses --------------------------------------------------

    #[test]
    fn inject_responses_when_instructions_absent_sets_string() {
        // Why this pins behavior: a default Responses request from
        // Codex CLI or OpenCode rarely sets `instructions` — we must
        // add ours as a plain string. The string-equals-prompt
        // assertion locks the simplest possible shape and catches
        // any regression that switched to e.g. wrapping in an object.
        let mut body = json!({
            "model": "gpt-5-mini",
            "input": "How do I check if a Python object is an instance of a class?",
        });
        inject_responses(&mut body);
        assert_eq!(
            body["instructions"].as_str().unwrap(),
            PRESERVE_TOKENS_PROMPT,
            "absent instructions field should be set to the plain prompt string",
        );
    }

    #[test]
    fn inject_responses_when_instructions_is_null_sets_string() {
        // Why null gets the same treatment as absent: the OpenAI
        // SDK types `instructions` as `string | null`, and `null`
        // is documented as "no system message" — same intent as
        // omitting the field. If we left `null` in place we'd
        // silently drop the preserve-tokens injection for any
        // client that explicitly set the field to null (some SDK
        // wrappers do this on default-only construction).
        let mut body = json!({
            "model": "gpt-5-mini",
            "input": "hello",
            "instructions": null,
        });
        inject_responses(&mut body);
        assert_eq!(
            body["instructions"].as_str().unwrap(),
            PRESERVE_TOKENS_PROMPT,
        );
    }

    #[test]
    fn inject_responses_when_instructions_is_string_prepends() {
        // Why this matters: a client that already sets
        // `instructions` (e.g. Codex CLI's "You are a coding
        // assistant...") must NOT have it dropped. Our prompt goes
        // FIRST, separator, then the original. The `starts_with` +
        // `ends_with` assertions pin both halves without coupling
        // to the exact byte representation of the separator —
        // mirrors the Anthropic test for consistency.
        let original = "You are a coding assistant that talks like a pirate.";
        let mut body = json!({
            "model": "gpt-5-mini",
            "instructions": original,
            "input": "Are semicolons optional in JavaScript?",
        });
        inject_responses(&mut body);
        let combined = body["instructions"].as_str().unwrap();
        assert!(
            combined.starts_with(PRESERVE_TOKENS_PROMPT),
            "preserve-tokens prompt must come FIRST; got: {combined}",
        );
        assert!(
            combined.ends_with(original),
            "original client instructions must survive verbatim at the end; got: {combined}",
        );
        assert!(
            combined.contains(SEPARATOR),
            "separator must appear between our prompt and the client's; got: {combined}",
        );
    }

    #[test]
    fn inject_responses_when_instructions_is_unexpected_type_leaves_unchanged() {
        // Fail-loud branch (CLAUDE.md Rule 12): the OpenAI schema
        // documents `instructions` as `string | null` only. If a
        // future client (or a future API extension) sends an array
        // or an object, replacing it with our string would either
        // error upstream or silently drop part of the caller's
        // payload. Leaving the body untouched lets the upstream
        // surface its own error — same policy as the Anthropic
        // and OpenAI Chat unexpected-shape branches.
        let mut body = json!({
            "model": "gpt-5-mini",
            "input": "hello",
            "instructions": ["array", "form"],
        });
        let original = body.clone();
        inject_responses(&mut body);
        assert_eq!(body, original, "unexpected instructions shape must be left untouched");
    }

    #[test]
    fn inject_responses_preserves_input_array_untouched() {
        // Why this pins behavior: the Responses API's `input` can
        // be an array of items (e.g. multimodal vision requests).
        // The injector touches only `instructions`; any change to
        // `input` would corrupt multimodal payloads. This test
        // catches a regression where someone added a "splice into
        // input" path by mistake.
        let input_array = json!([
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "What is in this image?"},
                    {"type": "input_image", "image_url": "https://example.com/x.jpg"},
                ],
            }
        ]);
        let mut body = json!({
            "model": "gpt-5.2",
            "input": input_array.clone(),
        });
        inject_responses(&mut body);
        assert_eq!(
            body["input"], input_array,
            "input array must survive injection byte-for-byte",
        );
        assert_eq!(body["instructions"].as_str().unwrap(), PRESERVE_TOKENS_PROMPT);
    }

    // ---- InjectionShape::inject dispatch ---------------------------------

    #[test]
    fn injection_shape_inject_dispatches_to_underlying_helper() {
        // Why this exists: the factored enum is the new single
        // entry point for both handler crates. A regression where
        // someone renamed a variant but forgot to update the match
        // arm — or added a new variant without wiring its dispatch
        // — would silently no-op for that wire shape. Each branch
        // checks the post-condition specific to that injector
        // (Anthropic: top-level `system` string; OpenAI Chat:
        // first message becomes system at index 0; Responses:
        // top-level `instructions` string). If the dispatch ever
        // calls the wrong helper, the assertion for the wrong
        // shape fires with a clear failure pointing at which arm
        // is broken.
        // Anthropic.
        let mut anth = json!({
            "model": "claude-opus-4-5",
            "messages": [{"role": "user", "content": "hi"}],
        });
        InjectionShape::Anthropic.inject(&mut anth);
        assert_eq!(
            anth["system"].as_str().unwrap(),
            PRESERVE_TOKENS_PROMPT,
            "Anthropic arm must set top-level `system`",
        );

        // OpenAI Chat.
        let mut chat = json!({
            "model": "gpt-5-mini",
            "messages": [{"role": "user", "content": "hi"}],
        });
        InjectionShape::OpenAiChat.inject(&mut chat);
        let messages = chat["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(
            messages[0]["content"], PRESERVE_TOKENS_PROMPT,
            "OpenAI Chat arm must insert a system message at index 0",
        );

        // OpenAI Responses.
        let mut resp = json!({
            "model": "gpt-5-mini",
            "input": "hi",
        });
        InjectionShape::OpenAiResponses.inject(&mut resp);
        assert_eq!(
            resp["instructions"].as_str().unwrap(),
            PRESERVE_TOKENS_PROMPT,
            "OpenAI Responses arm must set top-level `instructions`",
        );
    }
}
