// Phase-2c relay handlers with outbound redaction + full response-side
// reversal (non-streaming JSON + streaming SSE).
//
// Request side (Phase 1):
//   - read inbound body
//   - run `proxy_core::redact` over the body bytes; secrets are replaced
//     with typed placeholders before the body leaves this process
//   - forward the redacted body upstream
//
// Response side (Phase 2a + Phase 2c):
//
//   When the outbound pass minted no placeholders (no secrets in the
//   prompt), the response always streams through unchanged regardless
//   of content-type — streaming UX preserved for non-secret traffic.
//
//   When the outbound pass DID mint placeholders, the response handling
//   branches on content type:
//
//   - `text/event-stream` (streaming SSE, Phase 2c): the upstream byte
//     stream is wrapped with `proxy_core::SseReverser`, which parses
//     events as they arrive, accumulates `text_delta` payloads, holds
//     back any tail that could be the prefix of an incomplete
//     placeholder, and emits reversed text downstream event-by-event.
//     Streaming UX preserved AND cross-event placeholder splits get
//     reversed correctly.
//
//   - `application/json` and everything else (Phase 2a): the response
//     is buffered, run through `proxy_core::reverse`, and emitted as a
//     non-streaming body. A non-streaming endpoint can't lose
//     streaming UX anyway.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, Response, StatusCode},
    routing::post,
};
use bytes::Bytes;
use futures_util::stream::{self, Stream, StreamExt};
use proxy_core::{InjectionShape, PlaceholderMap, SseReverser};
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
        // Responses-API endpoint (forwarded to the OpenAI upstream).
        // Codex CLI and OpenCode both speak this shape; without a
        // route here, Mode A users on those tools would silently get
        // no preserve-tokens injection. The wire shape is
        // documented in `proxy_core::system_prompt::inject_responses`.
        .route("/v1/responses", post(handle_openai_responses))
        .with_state(state)
}

async fn handle_anthropic_messages(
    State(state): State<AppState>,
    req: Request,
) -> Response<Body> {
    let url = format!("{}/v1/messages", state.config.anthropic_upstream);
    let inject = state
        .config
        .inject_system_prompt
        .then_some(InjectionShape::Anthropic);
    forward(state.http, url, req, inject).await
}

async fn handle_openai_chat(
    State(state): State<AppState>,
    req: Request,
) -> Response<Body> {
    let url = format!("{}/v1/chat/completions", state.config.openai_upstream);
    let inject = state
        .config
        .inject_system_prompt
        .then_some(InjectionShape::OpenAiChat);
    forward(state.http, url, req, inject).await
}

async fn handle_openai_responses(
    State(state): State<AppState>,
    req: Request,
) -> Response<Body> {
    let url = format!("{}/v1/responses", state.config.openai_upstream);
    let inject = state
        .config
        .inject_system_prompt
        .then_some(InjectionShape::OpenAiResponses);
    forward(state.http, url, req, inject).await
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
///   - **Placeholders minted + `text/event-stream`** → response is
///     wrapped with `proxy_core::SseReverser` and streamed. Cross-event
///     placeholder splits get reversed; streaming UX preserved.
///   - **Placeholders minted, other content types** → response is
///     buffered to bytes and run through `proxy_core::reverse` once,
///     then emitted as a non-streaming Body. Applies to
///     `application/json` and anything else (non-streaming endpoints
///     can't lose streaming they didn't have).
async fn forward(
    client: Client,
    url: String,
    req: Request,
    inject_shape: Option<InjectionShape>,
) -> Response<Body> {
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
            // System-prompt injection runs AFTER redaction (the
            // same ordering proxy-mitm uses). If injection ran
            // before redaction, the preserve-tokens prompt's own
            // schema text (`«SECRET_<TYPE>_<NNN>»`) is harmless to
            // the detector (no `[0-9]+`), but a future drift to a
            // literal-counter example would silently get redacted
            // and shrink the prompt. Keep the ordering invariant
            // explicit at the call site.
            let final_body = inject_after_redact(&redacted, inject_shape);
            Bytes::from(final_body)
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
        let content_type = upstream_headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if content_type.starts_with("text/event-stream") {
            // Phase 2c: stream-process the SSE response. The
            // SseReverser parses events as they arrive, accumulates
            // `text_delta` payloads, holds back partial-placeholder
            // tails across events, and emits reversed text
            // downstream. Streaming UX preserved AND cross-event
            // placeholder splits get reversed correctly.
            tracing::info!(
                placeholders = placeholder_map.len(),
                content_type = %content_type,
                "phase-2c streaming SSE reverse from {url}",
            );
            Body::from_stream(reverse_sse_stream(
                upstream_resp.bytes_stream(),
                placeholder_map,
            ))
        } else {
            // Non-streaming path (application/json and anything else):
            // buffer the full response, run reverse once, emit as a
            // non-streaming Body. A non-streaming endpoint can't
            // lose streaming it didn't have.
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

/// Wrap an upstream byte stream with an `SseReverser`, returning a
/// new stream that emits reversed SSE bytes downstream.
///
/// The state machine has three resting states:
///   - `Streaming`: pumping bytes from upstream through `push_bytes`
///   - `Flushed`: upstream EOF reached; emit the final `flush_bytes`
///     output (which carries any held-back text + the synthetic
///     terminator events) and finish
///   - terminated by returning `None` from the unfold
///
/// Errors from the upstream stream are forwarded as-is and end the
/// stream (no more pushes after an error). `Body::from_stream` is
/// happy with `Stream<Item = io::Result<Bytes>>`; we map reqwest's
/// error into an `io::Error` for that boundary.
fn reverse_sse_stream<S>(
    upstream: S,
    map: PlaceholderMap,
) -> impl Stream<Item = std::io::Result<Bytes>> + Send
where
    S: Stream<Item = reqwest::Result<Bytes>> + Send + Unpin + 'static,
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
                    // Surface the upstream error as an io::Error so
                    // Body::from_stream propagates it. We do NOT
                    // attempt to flush — the half-processed state is
                    // not safe to emit after a stream-level error.
                    let io_err = std::io::Error::other(e);
                    Some((Err(io_err), State::Flushed))
                }
                None => {
                    // Clean upstream EOF: emit the final flush bytes
                    // (held-back text + content_block_stop / message_stop
                    // events already passed through), then terminate
                    // on the next poll.
                    let final_bytes = reverser.flush_bytes(&map);
                    Some((Ok(final_bytes), State::Flushed))
                }
            }
        },
    )
}

/// Parse `body_str` as JSON, dispatch to the shape-matching
/// `proxy_core::system_prompt` injector, and re-serialize. Returns
/// the original `body_str` unchanged when:
///   - `shape` is `None` (injection disabled by config or not a
///     known shape), or
///   - the body is not valid JSON (we fail loud: log at warn and
///     forward unmodified rather than rewriting a body we can't
///     parse — per CLAUDE.md Rule 12).
///
/// MUST be called AFTER redaction; the call site enforces the
/// ordering invariant and documents the reason.
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
    // Compact serialization — the wire does not require pretty-
    // printed bytes, and keeping output compact matches the
    // pre-injection size profile (we only added one field/element).
    match serde_json::to_string(&value) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to re-serialize JSON after system-prompt injection; \
                 forwarding redacted body without injection",
            );
            body_str.to_string()
        }
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
