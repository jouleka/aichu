// Phase-2a relay handlers with outbound redaction + non-streaming
// response-side reversal.
//
// Request side (Phase 1, landed earlier):
//   - read inbound body
//   - run `proxy_core::redact` over the body bytes; secrets are replaced
//     with typed placeholders before the body leaves this process
//   - forward the redacted body upstream
//
// Response side (Phase 2a, this commit):
//   - if the upstream response is `application/json` (i.e., the request
//     was `stream: false`), buffer the body, run `proxy_core::reverse`
//     against the PlaceholderMap from the outbound pass, and emit the
//     reversed body to the client.
//   - if the upstream response is `text/event-stream` (streaming), pass
//     through unchanged. SSE-aware reversal (build-plan §6 gotcha:
//     placeholders split across chunks) is Phase 2b.

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

/// Forward `req` to `url` over reqwest. Hop-by-hop headers are stripped
/// on both legs. The request body is redacted via `proxy_core::redact`
/// before forwarding.
///
/// Response handling branches on upstream content-type:
///   - `application/json` (non-streaming, request was `stream: false`)
///     and the request had at least one placeholder substituted →
///     buffer the response, run `proxy_core::reverse` to restore the
///     original secret in the response text, emit non-streaming.
///   - Anything else (notably `text/event-stream` for `stream: true`)
///     → stream the body through unchanged; SSE-aware reversal is
///     out of scope for Phase 2a.
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
    // The PlaceholderMap is per-request. Phase 2a threads it through to
    // the response-side reversal pass below. Cross-request coreference
    // (same secret keeping `_001` across conversation turns) is still
    // out of scope; that would require a session-keyed map.
    let mut placeholder_map = PlaceholderMap::new();
    let body_bytes = match std::str::from_utf8(&body_bytes) {
        Ok(s) => {
            let redacted = proxy_core::redact(s, &mut placeholder_map);
            if !placeholder_map.is_empty() {
                tracing::info!(
                    placeholders = placeholder_map.len(),
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

    // Decide whether we can apply the reverse pass now (Phase 2a:
    // non-streaming JSON) or have to pass through unchanged (Phase 2b
    // territory: SSE and friends).
    let content_type = upstream_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // `starts_with` covers `application/json; charset=utf-8` which
    // some providers emit. Anthropic and OpenAI both return plain
    // `application/json` on non-streaming endpoints.
    let is_json = content_type.starts_with("application/json");

    let resp_body = if is_json && !placeholder_map.is_empty() {
        // Buffer the full body, run the reverse pass, hand back as a
        // non-streaming Body. Same UTF-8 round-trip and same "JSON
        // delimiters don't appear inside placeholders" invariant we
        // relied on for the outbound redaction.
        match upstream_resp.bytes().await {
            Ok(bytes) => match std::str::from_utf8(&bytes) {
                Ok(s) => {
                    let restored = proxy_core::reverse(s, &placeholder_map);
                    tracing::info!(
                        placeholders = placeholder_map.len(),
                        "applied reverse pass to non-streaming JSON response from {url}",
                    );
                    Body::from(Bytes::from(restored))
                }
                Err(_) => {
                    tracing::debug!(
                        "non-utf8 JSON response from {url}, returning unchanged",
                    );
                    Body::from(bytes)
                }
            },
            Err(e) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    format!("upstream body: {e}"),
                );
            }
        }
    } else {
        // Streaming or non-JSON: pass through unchanged. The user will
        // see placeholders in their response if the model preserved
        // them; Phase 2b will buffer SSE chunks and reverse them.
        Body::from_stream(upstream_resp.bytes_stream())
    };

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
