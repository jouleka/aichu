// Phase-1 relay handlers with outbound redaction.
//
// Request side (Phase 1, this commit):
//   - read inbound body
//   - run `proxy_core::redact` over the body bytes; secrets are replaced
//     with typed placeholders before the body leaves this process
//   - forward the redacted body upstream
//
// Response side (Phase 2, follow-up): currently a pass-through. The
// placeholders the model sees in its prompt will appear verbatim in
// its response if it preserves them (which is what e03 is supposed to
// measure). A future commit will add `proxy_core::reverse` on the
// response stream so the user gets the original secrets back.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Response, StatusCode},
    routing::post,
};
use bytes::Bytes;
use proxy_core::PlaceholderMap;
use reqwest::Client;

use crate::RelayConfig;

#[derive(Clone)]
struct AppState {
    http: Client,
    config: Arc<RelayConfig>,
}

pub fn router(config: RelayConfig) -> Router {
    let state = AppState {
        http: Client::builder()
            .build()
            .expect("build reqwest client"),
        config: Arc::new(config),
    };
    Router::new()
        .route("/v1/messages", post(handle_anthropic_messages))
        .route("/v1/chat/completions", post(handle_openai_chat))
        .with_state(state)
}

async fn handle_anthropic_messages(
    State(state): State<AppState>,
    req: Request,
) -> Response<Body> {
    let url = format!("{}/v1/messages", state.config.anthropic_upstream);
    forward(state.http, url, req).await
}

async fn handle_openai_chat(
    State(state): State<AppState>,
    req: Request,
) -> Response<Body> {
    let url = format!("{}/v1/chat/completions", state.config.openai_upstream);
    forward(state.http, url, req).await
}

/// Forward `req` to `url` over reqwest and stream the upstream response back
/// to the client. Hop-by-hop headers are stripped on both legs. The request
/// body is redacted via `proxy_core::redact` before forwarding.
async fn forward(client: Client, url: String, req: Request) -> Response<Body> {
    let (parts, body) = req.into_parts();

    // Read the inbound body. LLM request bodies are small (JSON prompts +
    // config), so buffering is fine for v0.
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("read inbound body: {e}"),
            );
        }
    };

    // Phase-1 redaction: run the body bytes through proxy-core. Secrets
    // are substituted with typed placeholders before the body leaves
    // this process.
    //
    // We operate on the raw bytes-as-UTF-8 rather than parsing the JSON
    // first: secret patterns (sk-ant-..., AKIA..., etc.) don't contain
    // JSON delimiters, so they're wholly inside string values and the
    // structural JSON survives the substitution.
    //
    // The PlaceholderMap is per-request and dropped at function return.
    // Counters reset per request; cross-request coreference (the same
    // secret keeping `_001` across multiple turns of a conversation) is
    // out of scope for Phase 1. Phase 2 will thread the map through to
    // the response-side reversal pass, at which point we can also
    // consider session-scoped maps.
    let body_bytes = match std::str::from_utf8(&body_bytes) {
        Ok(s) => {
            let mut map = PlaceholderMap::new();
            let redacted = proxy_core::redact(s, &mut map);
            if !map.is_empty() {
                tracing::info!(
                    placeholders = map.len(),
                    "redacted outbound body before forwarding to {url}",
                );
            }
            Bytes::from(redacted)
        }
        Err(_) => {
            // Non-UTF-8 body (binary?). Pass through unchanged; the
            // body is unlikely to carry a secret-shaped substring we
            // could match anyway.
            tracing::debug!("non-utf8 inbound body, forwarding without redaction");
            body_bytes
        }
    };

    // Forward inbound headers minus hop-by-hop + host/content-length.
    let mut out_headers = HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        out_headers.insert(name.clone(), value.clone());
    }

    let upstream_resp = match client
        .post(&url)
        .headers(out_headers)
        .body(body_bytes)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return error_response(StatusCode::BAD_GATEWAY, format!("upstream {url}: {e}"));
        }
    };

    let status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();

    // Stream the response body straight through. Body::from_stream accepts
    // any Stream<Result<Bytes, E>> where E: Into<BoxError>; reqwest::Error
    // satisfies that.
    let resp_body = Body::from_stream(upstream_resp.bytes_stream());

    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }

    match builder.body(resp_body) {
        Ok(r) => r,
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("build relay response: {e}"),
        ),
    }
}

fn error_response(status: StatusCode, msg: String) -> Response<Body> {
    tracing::warn!(%status, "{}", msg);
    Response::builder()
        .status(status)
        .body(Body::from(msg))
        .expect("build error response")
}

/// Hop-by-hop headers per RFC 7230 §6.1, plus `host` and `content-length`
/// which reqwest sets itself based on the outbound URL and body, and
/// `transfer-encoding` which would conflict with our streaming response
/// body construction.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_recognizes_rfc_7230_set() {
        // If a future refactor changes how we strip headers, this test
        // catches accidental forwarding of a header that would corrupt the
        // outbound or relayed request.
        for name in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "host",
            "content-length",
        ] {
            assert!(is_hop_by_hop(name), "expected {name} to be stripped");
        }
    }

    #[test]
    fn hop_by_hop_allows_auth_and_content_type() {
        // The client's bearer/api-key auth must reach upstream, and content-
        // type must survive (it determines whether reqwest serializes the
        // body as JSON or otherwise).
        assert!(!is_hop_by_hop("authorization"));
        assert!(!is_hop_by_hop("x-api-key"));
        assert!(!is_hop_by_hop("anthropic-version"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("accept"));
    }
}
