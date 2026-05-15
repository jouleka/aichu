// Pass-through relay handlers.
//
// For Week 1 we forward bytes in both directions without parsing. The job
// is to prove streaming survives the relay; redaction lands in proxy-core,
// not here.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Response, StatusCode},
    routing::post,
};
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
/// to the client. Hop-by-hop headers are stripped on both legs.
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
