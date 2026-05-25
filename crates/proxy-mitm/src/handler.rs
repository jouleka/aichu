// AichuHandler — the Hudsucker handler that observes and mutates every
// intercepted request and response.
//
// Request side (Phase 1 of the proxy-core wiring):
//   - read inbound body
//   - run `proxy_core::redact` over the body bytes; secrets are replaced
//     with typed placeholders before the body leaves this process
//   - forward the redacted body upstream
//
// Response side (Phase 2a + Phase 2c):
//   - if the outbound pass minted no placeholders → response passes
//     through unchanged (streaming preserved)
//   - if the outbound pass DID mint placeholders AND the response is
//     `text/event-stream` → stream-process via
//     `proxy_core::SseReverser` (Phase 2c). Streaming UX preserved
//     AND cross-event placeholder splits get reversed correctly.
//   - otherwise (placeholders minted, non-streaming response) →
//     buffer the response, run `proxy_core::reverse` once, emit
//     non-streaming (Phase 2a).
//
// State threading: per-request, on the handler instance itself.
//
// Hudsucker's outer dispatcher clones the handler exactly once per
// request before invoking `handle_request`, and the same clone is
// later given to `handle_response` for that same request — see
// `hudsucker::proxy::internal::InternalProxy::proxy`, which threads
// `&mut self.http_handler` through both calls inside one async task.
// HTTP/2 multiplexing therefore produces N concurrent CLONES of this
// handler on a single TLS connection (one per in-flight stream),
// each with its own `current_map`. There is no shared map slot to
// collide on, so two overlapping HTTP/2 streams cannot leak each
// other's secrets — pinned by
// `mitm_isolates_concurrent_h2_streams_on_one_connection`.
//
// History: an earlier revision stored maps in
// `Arc<Mutex<HashMap<SocketAddr, ...>>>` keyed by
// `HttpContext.client_addr`. That was a real privacy bug under H2
// multiplexing because every stream on one connection shares one
// `client_addr` and would race on the same key. Per-clone state
// removes both the race AND the orphan-entry leak that motivated
// the previous TTL sweep (a dropped clone naturally drops its
// `current_map`).
//
// `request_count` remains `Arc<AtomicU64>` because it is intentionally
// shared across every clone — integration tests assert on the total
// request count across the whole proxy.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use futures_util::stream::{self, Stream, StreamExt};
use http_body_util::{BodyDataStream, BodyExt};
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{
        Request, Response,
        header::{ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
    },
};
use proxy_core::{InjectionShape, PlaceholderMap, SseReverser};

#[derive(Clone)]
pub struct AichuHandler {
    request_count: Arc<AtomicU64>,
    /// The `PlaceholderMap` minted for THIS request by
    /// `handle_request`, retrieved by `handle_response` on the same
    /// handler clone. `None` after creation, after the response has
    /// consumed it, or when nothing on the outbound side matched any
    /// detector. Each in-flight request owns its own clone of
    /// `AichuHandler` (see module-level State threading note) so this
    /// field never has to mediate between concurrent streams.
    current_map: Option<PlaceholderMap>,
    /// Whether to inject `proxy_core::PRESERVE_TOKENS_PROMPT` into
    /// forwarded prompt-endpoint request bodies. Default ON — the
    /// e03 eval measured this lifts guillemets preservation from
    /// 12% to 96% on gpt-5-mini. The CLI's `--no-system-prompt`
    /// flag toggles this off; see `crates/cli/src/main.rs`.
    inject_system_prompt: bool,
}

impl Default for AichuHandler {
    fn default() -> Self {
        Self {
            request_count: Arc::new(AtomicU64::new(0)),
            current_map: None,
            // Default ON — see the field doc comment for the rationale
            // (and crates/cli/src/main.rs::Run for the flag wiring).
            inject_system_prompt: true,
        }
    }
}

impl AichuHandler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Toggle preserve-tokens system-prompt injection on or off.
    /// Defaults to ON via `AichuHandler::new`; the CLI's
    /// `--no-system-prompt` flag flips this off when set.
    ///
    /// Returns `self` so callers can chain in builder style next to
    /// `AichuHandler::new()`.
    pub fn with_inject_system_prompt(mut self, on: bool) -> Self {
        self.inject_system_prompt = on;
        self
    }

    /// Returns a handle to the request counter. Cheap to clone; intended for
    /// integration tests that need to assert request observation.
    pub fn request_count(&self) -> Arc<AtomicU64> {
        self.request_count.clone()
    }
}

/// Path-scoped allow-list for redaction.
///
/// Only bodies posted to KNOWN prompt-carrying endpoints are redacted.
/// Auth flows, model metadata, telemetry, and anything else flows
/// through unchanged regardless of whether it contains secret-shaped
/// substrings. Add new endpoints here as we extend agent coverage.
fn is_prompt_endpoint(path: &str) -> bool {
    matches!(
        path,
        // Anthropic Messages API
        "/v1/messages"
            // OpenAI Chat Completions and Responses APIs
            | "/v1/chat/completions"
            | "/v1/responses"
            // Codex CLI's ChatGPT-backend path (per our e03 smoke-test findings)
            | "/backend-api/codex/responses"
            // OpenCode's zen routing endpoints
            | "/zen/v1/responses"
            | "/zen/v1/chat/completions"
    )
}

/// Map a prompt-endpoint path to the wire-shape variant of
/// `proxy_core::InjectionShape` that can safely mutate it. Distinct
/// from the redaction allow-list above — both the Chat-Completions
/// and Responses families of endpoints are recognized here so the
/// injector can prepend `PRESERVE_TOKENS_PROMPT` to whichever
/// system-level field the wire shape exposes (`messages[0]` for
/// Chat, top-level `instructions` for Responses, top-level `system`
/// for Anthropic).
///
/// `None` is reserved for paths that pass redaction's allow-list
/// but have no known injection shape — there are none today, but
/// keeping the `Option` return shape avoids forcing every new prompt
/// endpoint to have an injection variant on day one. (If a future
/// endpoint joins `is_prompt_endpoint` without a matching shape,
/// the injector short-circuits at the `None` arm in
/// `inject_after_redact` and the redact-then-forward path still
/// runs.)
fn injection_shape_for(path: &str) -> Option<InjectionShape> {
    match path {
        "/v1/messages" => Some(InjectionShape::Anthropic),
        "/v1/chat/completions" | "/zen/v1/chat/completions" => Some(InjectionShape::OpenAiChat),
        "/v1/responses" | "/backend-api/codex/responses" | "/zen/v1/responses" => {
            Some(InjectionShape::OpenAiResponses)
        }
        _ => None,
    }
}

/// Parse `body_str` as JSON, dispatch to the shape-matching
/// `proxy_core::InjectionShape::inject`, and re-serialize. Returns
/// the original `body_str` unchanged when:
///   - `shape` is `None` (path has no known injection shape — see
///     `injection_shape_for`), or
///   - the body is not valid JSON (we fail loud: log at warn and
///     forward unmodified rather than rewriting a body we can't
///     parse — per CLAUDE.md Rule 12).
///
/// MUST be called AFTER redaction; see the call site for the
/// ordering rationale (the prompt itself contains `«SECRET_*»`
/// example strings that would otherwise get caught by the
/// detector).
fn inject_after_redact(body_str: &str, shape: Option<InjectionShape>) -> String {
    let Some(shape) = shape else {
        return body_str.to_string();
    };
    let mut value: serde_json::Value = match serde_json::from_str(body_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "request body is not valid JSON on a known prompt endpoint; \
                 skipping system-prompt injection and forwarding unchanged",
            );
            return body_str.to_string();
        }
    };
    shape.inject(&mut value);
    // serde_json::to_string emits compact JSON. The wire never
    // requires the upstream to see pretty-printed bytes, and compact
    // serialization keeps the redacted size invariant we relied on
    // when stripping content-length above.
    match serde_json::to_string(&value) {
        Ok(s) => s,
        Err(e) => {
            // serde_json::to_string only fails on serializer errors
            // (e.g. Map key that isn't a string) — practically
            // unreachable for a Value we just parsed. Surface at
            // warn and forward the redacted body unmodified so the
            // request still goes through.
            tracing::warn!(
                error = %e,
                "failed to re-serialize JSON after system-prompt injection; \
                 forwarding redacted body without injection",
            );
            body_str.to_string()
        }
    }
}

impl HttpHandler for AichuHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        tracing::info!(method = %req.method(), uri = %req.uri(), "request");

        // Path-scoped allow list. Only redact bodies on known prompt
        // endpoints. Anything else (OAuth refresh, MCP registry, model
        // metadata) gets forwarded unchanged.
        //
        // The bug this guard fixes: claude CLI's OAuth refresh request
        // body contains a `sk-`-shaped refresh token that matches the
        // OpenAiKey regex. Redacting it replaces the token with a
        // placeholder Anthropic's OAuth endpoint cannot parse → 400 →
        // claude can't refresh → 401 on every downstream request. The
        // smoke test against real claude surfaced this; the test
        // `mitm_does_not_redact_non_prompt_paths` pins the fix.
        if !is_prompt_endpoint(req.uri().path()) {
            return RequestOrResponse::Request(req);
        }

        let (mut parts, body) = req.into_parts();

        let body_bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                tracing::warn!(error = %e, "failed to collect request body, forwarding empty");
                return RequestOrResponse::Request(Request::from_parts(parts, Body::empty()));
            }
        };

        // Redact: bytes → str → redact → bytes. Same UTF-8 round-trip
        // pattern e02 uses. Non-UTF-8 bodies forward unchanged.
        //
        // The system-prompt injection runs AFTER redaction, BEFORE
        // forwarding (the order is load-bearing: if injection ran
        // first, the preserve-tokens prompt's own example strings
        // like `«SECRET_AWS_KEY_001»` would be picked up by the
        // detector and reverse-substituted back into actual secret
        // text on the response side — corrupting the prompt that
        // makes the proxy work).
        let mut map = PlaceholderMap::new();
        let inject_shape = injection_shape_for(parts.uri.path());
        let new_body = match std::str::from_utf8(&body_bytes) {
            Ok(s) => {
                let redacted = proxy_core::redact(s, &mut map);
                if !map.is_empty() {
                    tracing::info!(
                        placeholders = map.len(),
                        "redacted outbound body before forwarding upstream",
                    );
                }
                let final_body = if self.inject_system_prompt {
                    inject_after_redact(&redacted, inject_shape)
                } else {
                    redacted
                };
                Body::from(Bytes::from(final_body))
            }
            Err(_) => {
                tracing::debug!("non-utf8 inbound body, forwarding without redaction");
                Body::from(body_bytes)
            }
        };

        // Hand the map off to handle_response via the per-clone field.
        // Only stash if non-empty — keeps the response-side check a
        // single Option match. Each in-flight request runs on its own
        // clone (see module-level State threading note), so there is
        // no concurrent writer to coordinate with and no orphan to
        // sweep: the field is dropped with the clone if the response
        // path never runs.
        if !map.is_empty() {
            self.current_map = Some(map);
        }

        // The body length probably changed after redaction; strip the
        // stale `content-length` header so hyper computes a new one
        // from the actual body length. Without this, upstream rejects
        // the request with a framing error.
        parts.headers.remove(CONTENT_LENGTH);

        // Strip Accept-Encoding so upstream returns the response body
        // uncompressed. Without this, Anthropic gzips its responses,
        // our UTF-8 check fails on the compressed bytes, and the
        // reverse pass silently falls through to "passthrough with
        // placeholders intact." The smoke test against real claude
        // caught this — `text/event-stream; charset=utf-8` is the
        // declared content-type but with Content-Encoding: gzip the
        // body bytes aren't UTF-8 until decompressed. Phase 2c could
        // add decompress-modify-recompress; for v0 we just ask
        // upstream not to compress.
        parts.headers.remove(ACCEPT_ENCODING);

        RequestOrResponse::Request(Request::from_parts(parts, new_body))
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        // Owned String so we can use `ct` after `res` is moved via
        // `into_parts()` below. The HeaderValue's lifetime is tied to
        // `res`, so a `&str` borrow would dangle after the move.
        let ct = res
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        tracing::info!(status = %res.status(), content_type = %ct, "response");

        // Take the per-request map off this handler clone. Absent →
        // nothing was redacted on the outbound side → pass response
        // through unchanged. Streaming UX preserved for the no-secret
        // case. `take()` empties the slot so a clone reuse (which
        // hudsucker does not currently do, but could) cannot leak the
        // map into a later unrelated request.
        let map = match self.current_map.take() {
            Some(m) => m,
            None => return res,
        };

        let (mut parts, body) = res.into_parts();

        let new_body = if ct.starts_with("text/event-stream") {
            // Phase 2c: stream-process the SSE response. The
            // SseReverser parses events as they arrive, holds back
            // partial-placeholder tails across events, and emits
            // reversed text downstream event-by-event. Streaming UX
            // preserved AND cross-event placeholder splits get
            // reversed correctly. See
            // `crates/proxy-server/tests/relay_redacts.rs::phase_2c_*`
            // for the spec test.
            tracing::info!(
                placeholders = map.len(),
                content_type = %ct,
                "phase-2c streaming SSE reverse",
            );
            Body::from_stream(reverse_sse_stream(BodyDataStream::new(body), map))
        } else {
            // Phase 2a: non-streaming path. Buffer the response, run
            // reverse once, emit as a non-streaming Body. A
            // non-streaming endpoint can't lose streaming UX it didn't
            // have. Same UTF-8 round-trip and "JSON delimiters don't
            // appear inside placeholders" invariant we relied on for
            // the outbound redaction.
            let body_bytes = match body.collect().await {
                Ok(c) => c.to_bytes(),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to collect response body, returning empty");
                    return Response::from_parts(parts, Body::empty());
                }
            };

            match std::str::from_utf8(&body_bytes) {
                Ok(s) => {
                    let restored = proxy_core::reverse(s, &map);
                    tracing::info!(
                        placeholders = map.len(),
                        content_type = %ct,
                        "buffered + reverse-applied response",
                    );
                    Body::from(Bytes::from(restored))
                }
                Err(_) => {
                    // Surface at warn level: this is almost always a sign
                    // the response is compressed (gzip / br / zstd) and
                    // we forgot to strip Accept-Encoding on the request
                    // side. Reverse pass cannot run on compressed bytes,
                    // so the user will see placeholders.
                    tracing::warn!(
                        "response body is not valid UTF-8 (likely compressed); \
                         reverse pass skipped, placeholders may reach client",
                    );
                    Body::from(body_bytes)
                }
            }
        };

        // Same content-length concern as on the request side: the
        // reversed body's length differs from the original, so strip
        // the stale header and let hyper compute a fresh one.
        parts.headers.remove(CONTENT_LENGTH);

        Response::from_parts(parts, new_body)
    }
}

/// Wrap a byte-frame stream from the upstream response body with an
/// `SseReverser`, returning a new stream that emits reversed SSE
/// bytes downstream. Mirrors `proxy_server::handler::reverse_sse_stream`
/// — the two implementations differ only in their error type
/// (hudsucker::Error vs io::Error) because the upstream Body types
/// differ (hudsucker::Body via http_body_util vs reqwest::Response).
fn reverse_sse_stream<S, E>(
    upstream: S,
    map: PlaceholderMap,
) -> impl Stream<Item = Result<Bytes, hudsucker::Error>> + Send
where
    S: Stream<Item = Result<Bytes, E>> + Send + Unpin + 'static,
    E: Into<hudsucker::Error> + Send + 'static,
{
    // The size difference between Streaming and Flushed is fine: we
    // allocate this enum once per upstream response and toggle between
    // the two variants in-place. Boxing the inner struct would add a
    // heap allocation per request without observable benefit.
    #[allow(clippy::large_enum_variant)]
    enum State<S> {
        Streaming {
            upstream: S,
            reverser: SseReverser,
            map: PlaceholderMap,
        },
        Flushed,
    }

    stream::unfold(
        State::Streaming {
            upstream,
            reverser: SseReverser::new(),
            map,
        },
        |state| async move {
            let State::Streaming {
                mut upstream,
                mut reverser,
                map,
            } = state
            else {
                return None;
            };

            match upstream.next().await {
                Some(Ok(bytes)) => {
                    let out = reverser.push_bytes(&bytes, &map);
                    Some((
                        Ok(out),
                        State::Streaming {
                            upstream,
                            reverser,
                            map,
                        },
                    ))
                }
                Some(Err(e)) => {
                    // Propagate the upstream error. We do NOT flush —
                    // the partially-processed state is not safe to
                    // emit after a stream-level error.
                    Some((Err(e.into()), State::Flushed))
                }
                None => {
                    // Clean upstream EOF: emit the final flush bytes
                    // and terminate on the next poll.
                    let final_bytes = reverser.flush_bytes(&map);
                    Some((Ok(final_bytes), State::Flushed))
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_shape_for_recognizes_every_known_prompt_endpoint() {
        // Why this exists: the path → shape mapping lives in this
        // crate (not proxy-core) and is the only place that
        // decides whether Codex CLI's `/backend-api/codex/responses`
        // and OpenCode's `/zen/v1/responses` get preserve-tokens
        // injection. A regression where someone removed one of
        // those arms — or added a new prompt endpoint to
        // `is_prompt_endpoint` without wiring its shape here —
        // would silently degrade those tools' placeholder
        // preservation from the e03-measured 96% back to 12%
        // without any test failure on the headline Anthropic /
        // OpenAI Chat paths.
        assert_eq!(
            injection_shape_for("/v1/messages"),
            Some(InjectionShape::Anthropic),
        );
        assert_eq!(
            injection_shape_for("/v1/chat/completions"),
            Some(InjectionShape::OpenAiChat),
        );
        assert_eq!(
            injection_shape_for("/zen/v1/chat/completions"),
            Some(InjectionShape::OpenAiChat),
        );
        assert_eq!(
            injection_shape_for("/v1/responses"),
            Some(InjectionShape::OpenAiResponses),
            "Responses-API path must inject — Codex CLI users depend on this",
        );
        assert_eq!(
            injection_shape_for("/backend-api/codex/responses"),
            Some(InjectionShape::OpenAiResponses),
            "Codex CLI's ChatGPT-backend path must inject",
        );
        assert_eq!(
            injection_shape_for("/zen/v1/responses"),
            Some(InjectionShape::OpenAiResponses),
            "OpenCode's zen Responses path must inject",
        );
    }

    #[test]
    fn injection_shape_for_returns_none_on_non_prompt_paths() {
        // Symmetric guard: paths outside the prompt-endpoint set
        // (OAuth token endpoints, model metadata, anything else)
        // must NOT match a shape. A regression where someone added
        // a catch-all arm would graft a `system` field onto every
        // outbound body — breaking OAuth flows in exactly the way
        // `mitm_does_not_inject_on_non_prompt_endpoints` is meant
        // to catch end-to-end. This test catches it at the unit
        // level so the failure points directly at the mapping.
        assert_eq!(injection_shape_for("/v1/oauth/token"), None);
        assert_eq!(injection_shape_for("/v1/models"), None);
        assert_eq!(injection_shape_for("/"), None);
    }
}
