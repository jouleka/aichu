// AichuHandler — the Hudsucker handler that observes and mutates every
// intercepted request and response.
//
// Request side (Phase 1 of the proxy-core wiring):
//   - read inbound body
//   - run `proxy_core::redact` over the body bytes; secrets are replaced
//     with typed placeholders before the body leaves this process
//   - forward the redacted body upstream
//
// Response side (Phase 2):
//   - if the outbound pass minted no placeholders → response passes
//     through unchanged (streaming preserved)
//   - if the outbound pass DID mint placeholders → buffer the response,
//     run `proxy_core::reverse`, emit non-streaming. Same trade-off
//     documented in e02's Phase 2b: privacy wins over streaming UX for
//     prompts that contain secrets; Phase 2c-style per-event SSE
//     reversal is future work.
//
// State threading: keyed by client_addr, not stored on the handler.
//
// Hudsucker's published trait docs say "each request/response pair is
// passed to the same instance." Empirically (live smoke test against
// real claude CLI through MITM), this is NOT true under HTTPS CONNECT
// MITM: hudsucker spawns separate handler clones for handle_request
// vs handle_response, and a per-clone field like `current_map` is
// empty when handle_response sees it. State must therefore live in
// shared storage that survives the clone boundary.
//
// We use `Arc<Mutex<HashMap<SocketAddr, PlaceholderMap>>>` keyed by
// `HttpContext.client_addr`. The same address is observed in both
// handle_request and handle_response for a given request, so the
// response side can look up what the request side recorded.
//
// Known limitation (v0): HTTP/2 multiplexing — one client_addr can
// carry several concurrent requests on a single TLS stream. Two
// overlapping requests would race on the same map slot. v0 ships
// this as an accepted limitation; a follow-up can key on something
// finer-grained (e.g., a stream id) when we have an integration test
// that catches a collision.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{
        Request, Response,
        header::{ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
    },
};
use proxy_core::PlaceholderMap;

#[derive(Clone, Default)]
pub struct AichuHandler {
    request_count: Arc<AtomicU64>,
    /// Per-request PlaceholderMaps keyed by `HttpContext.client_addr`.
    /// Populated in `handle_request` (if anything was redacted) and
    /// consumed (removed) in `handle_response`.
    ///
    /// `Arc<Mutex<...>>` so the state survives the handler clones
    /// hudsucker creates per request/response under MITM.
    maps: Arc<Mutex<HashMap<SocketAddr, PlaceholderMap>>>,
}

impl AichuHandler {
    pub fn new() -> Self {
        Self::default()
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

impl HttpHandler for AichuHandler {
    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
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
        let mut map = PlaceholderMap::new();
        let new_body = match std::str::from_utf8(&body_bytes) {
            Ok(s) => {
                let redacted = proxy_core::redact(s, &mut map);
                if !map.is_empty() {
                    tracing::info!(
                        placeholders = map.len(),
                        "redacted outbound body before forwarding upstream",
                    );
                }
                Body::from(Bytes::from(redacted))
            }
            Err(_) => {
                tracing::debug!("non-utf8 inbound body, forwarding without redaction");
                Body::from(body_bytes)
            }
        };

        // Store the map so handle_response (likely a separate clone)
        // can retrieve it. Only insert if non-empty — saves us a
        // lookup on the response side when nothing was redacted.
        if !map.is_empty() {
            self.maps.lock().unwrap().insert(ctx.client_addr, map);
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
        ctx: &HttpContext,
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

        // Retrieve (and remove) the per-request map. Absent → nothing
        // was redacted on the outbound side → pass response through
        // unchanged. Streaming UX preserved for the no-secret case.
        let map = match self.maps.lock().unwrap().remove(&ctx.client_addr) {
            Some(m) => m,
            None => return res,
        };

        let (mut parts, body) = res.into_parts();

        let body_bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                tracing::warn!(error = %e, "failed to collect response body, returning empty");
                return Response::from_parts(parts, Body::empty());
            }
        };

        let new_body = match std::str::from_utf8(&body_bytes) {
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
        };

        // Same content-length concern as on the request side: the
        // reversed body's length differs from the original, so strip
        // the stale header and let hyper compute a fresh one.
        parts.headers.remove(CONTENT_LENGTH);

        Response::from_parts(parts, new_body)
    }
}
