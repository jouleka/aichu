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
// Hudsucker calls `handle_request` and `handle_response` on the SAME
// handler instance for a matching pair (per the trait docs), which lets
// us thread the PlaceholderMap as a struct field between the two
// methods.
//
// **Concurrency assumption.** This design depends on hudsucker cloning
// the handler PER REQUEST/RESPONSE PAIR, so each pair gets its own
// `current_map`. The trait doc ("each request/response pair is passed
// to the same instance") is consistent with that interpretation but
// does not explicitly rule out one clone serving multiple concurrent
// requests on a single HTTP/2 stream-multiplexed connection. If
// hudsucker ever does the latter, two simultaneous redactions on one
// handler instance would race on `current_map`. The defensive
// `self.current_map = PlaceholderMap::new()` at the top of
// `handle_request` and the final clear in `handle_response` protect
// *sequential* reuse on one clone (every request observes a fresh
// map at entry), but they do NOT protect truly concurrent calls.
//
// How to detect a violation: integration test that fires two
// overlapping requests through the proxy with different secrets and
// asserts each reverses correctly. If a future test of that shape
// flakes, suspect this assumption first and move `current_map` to a
// `tokio::sync::Mutex<HashMap<RequestId, PlaceholderMap>>` keyed off
// some per-request identifier.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{
        Request, Response,
        header::{CONTENT_LENGTH, CONTENT_TYPE},
    },
};
use proxy_core::PlaceholderMap;

#[derive(Clone, Default)]
pub struct AichuHandler {
    request_count: Arc<AtomicU64>,
    /// PlaceholderMap for the current request/response pair. Lives on
    /// the handler instance; hudsucker reuses the same instance across
    /// the matching pair, so we can populate it in `handle_request`
    /// and read it in `handle_response`.
    current_map: PlaceholderMap,
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

impl HttpHandler for AichuHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        tracing::info!(method = %req.method(), uri = %req.uri(), "request");

        // Reset the per-pair map. Defensive against handler reuse.
        self.current_map = PlaceholderMap::new();

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
        let new_body = match std::str::from_utf8(&body_bytes) {
            Ok(s) => {
                let redacted = proxy_core::redact(s, &mut self.current_map);
                if !self.current_map.is_empty() {
                    tracing::info!(
                        placeholders = self.current_map.len(),
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

        // The body length probably changed after redaction; strip the
        // stale `content-length` header so hyper computes a new one
        // from the actual body length. Without this, upstream rejects
        // the request with a framing error.
        parts.headers.remove(CONTENT_LENGTH);

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

        if self.current_map.is_empty() {
            // No redaction happened → nothing to reverse → pass through
            // unchanged. Streaming UX preserved for the no-secret case.
            return res;
        }

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
                let restored = proxy_core::reverse(s, &self.current_map);
                tracing::info!(
                    placeholders = self.current_map.len(),
                    content_type = %ct,
                    "buffered + reverse-applied response",
                );
                Body::from(Bytes::from(restored))
            }
            Err(_) => {
                tracing::debug!("non-utf8 response body, returning unchanged");
                Body::from(body_bytes)
            }
        };

        // Same content-length concern as on the request side: the
        // reversed body's length differs from the original, so strip
        // the stale header and let hyper compute a fresh one.
        parts.headers.remove(CONTENT_LENGTH);

        // Clear the map after handling so a reused handler instance
        // doesn't carry state across requests.
        self.current_map = PlaceholderMap::new();

        Response::from_parts(parts, new_body)
    }
}
