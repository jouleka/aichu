// AichuHandler — observes every intercepted request and response.
//
// For Week 1 we are validating the MITM wire. The handler therefore:
//   - logs the request line (method, uri) via tracing
//   - logs the response status + content-type
//   - never mutates the body, never changes headers
//   - exposes a counter that integration tests can read to assert
//     "the handler actually saw the request"
//
// SSE per-frame logging is out of scope for the GREEN pass; the response
// body is forwarded byte-for-byte without inspection.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{Request, Response, header::CONTENT_TYPE},
};

#[derive(Clone, Default)]
pub struct AichuHandler {
    request_count: Arc<AtomicU64>,
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
        tracing::info!(
            method = %req.method(),
            uri = %req.uri(),
            "request"
        );
        RequestOrResponse::Request(req)
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        let ct = res
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        tracing::info!(
            status = %res.status(),
            content_type = %ct,
            "response"
        );
        res
    }
}
