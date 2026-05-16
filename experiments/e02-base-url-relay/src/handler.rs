// Phase-2b relay handlers with outbound redaction + full response-side
// reversal (non-streaming JSON + buffered SSE).
//
// Request side (Phase 1):
//   - read inbound body
//   - run `proxy_core::redact` over the body bytes; secrets are replaced
//     with typed placeholders before the body leaves this process
//   - forward the redacted body upstream
//
// Response side (Phase 2a + Phase 2b):
//
//   When the outbound pass minted no placeholders (no secrets in the
//   prompt), the response always streams through unchanged regardless
//   of content-type — streaming UX preserved for non-secret traffic.
//
//   When the outbound pass DID mint placeholders, the response is
//   buffered, run through `proxy_core::reverse`, and emitted as a
//   non-streaming body. This applies uniformly to application/json
//   (Phase 2a) and text/event-stream (Phase 2b).
//
//   Trade-off (Phase 2b): when secrets are in the prompt and the
//   response is SSE, the user loses streaming UX — the proxy holds
//   the entire response until it's complete, then delivers it as one
//   chunk.
//
//   Known limitation (Phase 2b → Phase 2c): the whole-response
//   buffering only reverses placeholders that land WHOLLY inside a
//   single SSE event's `text_delta` payload. If the model fragments a
//   placeholder across two `content_block_delta` events (e.g. event 1
//   ends with `«SECRET_AWS_` and event 2 begins with `KEY_001»`), the
//   bytes between them include JSON/SSE framing (`"}}\n\nevent: ...`)
//   which breaks the reverse regex's `[A-Z0-9_]+_[0-9]+` character
//   class. The placeholder stays unreversed and the user sees the
//   fragments. Phase 2c's per-event SSE-aware reversal fixes both
//   issues (streaming UX + cross-event split).

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
/// Response handling branches on whether the outbound pass redacted
/// anything:
///   - **No placeholders minted** (no secrets in the prompt) → response
///     streams through unchanged regardless of content-type.
///     Streaming UX preserved.
///   - **Placeholders minted** → response is buffered to bytes, run
///     through `proxy_core::reverse` against the PlaceholderMap, and
///     emitted as a non-streaming Body. Applies to both
///     `application/json` and `text/event-stream`. SSE streaming UX
///     is lost in this case; Phase 2c will restore it via per-event
///     reversal that doesn't require buffering the whole response.
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

    let resp_body = if placeholder_map.is_empty() {
        // No redaction happened on the outbound side → nothing to
        // reverse on the inbound side. Stream through unchanged.
        // Preserves streaming UX for the common no-secret case.
        Body::from_stream(upstream_resp.bytes_stream())
    } else {
        // The outbound pass minted at least one placeholder. Buffer
        // the full response, run the reverse pass, hand back as a
        // non-streaming Body. Same UTF-8 round-trip and "JSON
        // delimiters don't appear inside placeholders" invariant we
        // relied on for the outbound redaction.
        //
        // For SSE responses this means losing streaming for the
        // with-secrets case — see the file header for the Phase 2b
        // trade-off note.
        let content_type = upstream_headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        match upstream_resp.bytes().await {
            Ok(bytes) => match std::str::from_utf8(&bytes) {
                Ok(s) => {
                    let restored = proxy_core::reverse(s, &placeholder_map);
                    tracing::info!(
                        placeholders = placeholder_map.len(),
                        content_type = %content_type,
                        "buffered + reverse-applied response from {url}",
                    );
                    Body::from(Bytes::from(restored))
                }
                Err(_) => {
                    tracing::debug!(
                        "non-utf8 response from {url}, returning unchanged",
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
