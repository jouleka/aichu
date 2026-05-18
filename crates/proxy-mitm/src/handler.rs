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
//
// Orphaned-entry cleanup: entries are tagged with an `Instant` on
// insert, and every prompt-endpoint request opportunistically sweeps
// the map for anything older than `ENTRY_TTL` (15 minutes). This
// bounds the memory footprint when `handle_response` never runs (TLS
// error after request forwarded, client cancellation, upstream
// timeout). No background task — the sweep runs on the request path
// so there's no extra synchronization beyond the existing Mutex.
//
// What the TTL actually needs to cover: the gap between a request
// being forwarded and `handle_response` firing for its INITIAL
// HEADERS, not the full streaming duration. Healthy upstreams
// (Anthropic, OpenAI, OpenCode) send response headers within seconds
// even for long streaming generations; the body can take minutes
// without keeping the map entry alive (the entry is removed the
// moment `handle_response` runs). 15 minutes is a generous margin
// over that seconds-scale reality — raising it for "Anthropic
// streams can run 10 minutes" would be a misread.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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
use proxy_core::{PlaceholderMap, SseReverser};

/// How long a placeholder-map entry may live before the opportunistic
/// sweep evicts it. 15 minutes is comfortably longer than any
/// legitimate request→initial-response gap (Anthropic and OpenAI send
/// response headers within seconds, even for long streaming
/// generations) while still bounding orphaned-entry memory.
const ENTRY_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Default)]
pub struct AichuHandler {
    request_count: Arc<AtomicU64>,
    /// Per-request PlaceholderMaps keyed by `HttpContext.client_addr`,
    /// each tagged with its insertion `Instant`. Populated in
    /// `handle_request` (if anything was redacted) and consumed
    /// (removed) in `handle_response`. The timestamp drives the
    /// opportunistic TTL sweep — see `sweep_stale` and the
    /// module-level cleanup note above.
    ///
    /// `Arc<Mutex<...>>` so the state survives the handler clones
    /// hudsucker creates per request/response under MITM.
    maps: Arc<Mutex<HashMap<SocketAddr, (Instant, PlaceholderMap)>>>,
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
        //
        // Sweep stale entries on the SAME lock acquisition whether
        // or not we're about to insert: this is the cheapest place
        // to do TTL cleanup (we already hold the mutex on every
        // prompt-endpoint request, regardless of secret presence).
        // If sweep only ran when inserting, a stream of non-secret
        // prompt requests would let prior orphans linger past their
        // TTL until the next secret-bearing request arrived.
        let now = Instant::now();
        {
            let mut maps = self.maps.lock().unwrap();
            sweep_stale(&mut maps, now, ENTRY_TTL);
            if !map.is_empty() {
                maps.insert(ctx.client_addr, (now, map));
            }
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
        // Discard the insertion timestamp — it only mattered for the
        // TTL sweep on the insert path.
        let map = match self.maps.lock().unwrap().remove(&ctx.client_addr) {
            Some((_inserted_at, m)) => m,
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

/// Remove entries whose insertion time is older than `now - ttl`.
/// Pure (the timestamp is injected, not read from the clock) so unit
/// tests can drive both branches deterministically without sleeping.
fn sweep_stale(
    maps: &mut HashMap<SocketAddr, (Instant, PlaceholderMap)>,
    now: Instant,
    ttl: Duration,
) {
    maps.retain(|_, (inserted_at, _)| now.duration_since(*inserted_at) < ttl);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(last_octet: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(127, 0, 0, last_octet), 0))
    }

    #[test]
    fn sweep_stale_removes_entries_older_than_ttl() {
        // An entry inserted 30 minutes ago should be evicted when TTL
        // is 15 minutes. The privacy guarantee is unchanged (an
        // orphaned entry can never reverse a response that's never
        // coming), but bounded memory is the contract this test
        // pins.
        let now = Instant::now();
        let ttl = Duration::from_secs(15 * 60);
        let mut maps = HashMap::new();
        maps.insert(
            addr(1),
            (now - Duration::from_secs(30 * 60), PlaceholderMap::new()),
        );
        sweep_stale(&mut maps, now, ttl);
        assert!(maps.is_empty(), "expected stale entry to be removed");
    }

    #[test]
    fn sweep_stale_keeps_fresh_entries() {
        // An entry inserted 1 minute ago must NOT be evicted under a
        // 15-minute TTL — that would break the response-side reverse
        // pass on a still-in-flight request.
        let now = Instant::now();
        let ttl = Duration::from_secs(15 * 60);
        let mut maps = HashMap::new();
        maps.insert(
            addr(1),
            (now - Duration::from_secs(60), PlaceholderMap::new()),
        );
        sweep_stale(&mut maps, now, ttl);
        assert_eq!(maps.len(), 1, "fresh entry should remain");
    }

    #[test]
    fn sweep_stale_partitions_mixed_entries() {
        // Mixed fresh + stale: only the stale ones drop. Exercises
        // the partition behavior of `HashMap::retain` on this map
        // shape, including the timestamp-comparison direction (older
        // than TTL = evict).
        let now = Instant::now();
        let ttl = Duration::from_secs(15 * 60);
        let mut maps = HashMap::new();
        let fresh = addr(1);
        let stale_a = addr(2);
        let stale_b = addr(3);
        let recent = addr(4);
        maps.insert(fresh, (now - Duration::from_secs(60), PlaceholderMap::new()));
        maps.insert(
            stale_a,
            (now - Duration::from_secs(30 * 60), PlaceholderMap::new()),
        );
        maps.insert(
            stale_b,
            (now - Duration::from_secs(20 * 60), PlaceholderMap::new()),
        );
        maps.insert(
            recent,
            (now - Duration::from_secs(5 * 60), PlaceholderMap::new()),
        );
        sweep_stale(&mut maps, now, ttl);
        assert!(maps.contains_key(&fresh));
        assert!(maps.contains_key(&recent));
        assert!(!maps.contains_key(&stale_a));
        assert!(!maps.contains_key(&stale_b));
    }

    #[test]
    fn sweep_stale_on_empty_map_is_a_noop() {
        // Defensive: the function must not panic on an empty map.
        // Calling sweep on every insert means empty-map cases happen
        // on the first request after startup.
        let mut maps: HashMap<SocketAddr, (Instant, PlaceholderMap)> = HashMap::new();
        sweep_stale(&mut maps, Instant::now(), Duration::from_secs(15 * 60));
        assert!(maps.is_empty());
    }

    #[test]
    fn sweep_stale_boundary_at_exactly_ttl_evicts() {
        // The comparison is `now - inserted < ttl`, so an entry at
        // EXACTLY ttl is evicted (`duration_since == ttl` is NOT
        // less than `ttl`). Pin this boundary so a future refactor
        // that flips to `<=` would surface here.
        let now = Instant::now();
        let ttl = Duration::from_secs(15 * 60);
        let mut maps = HashMap::new();
        maps.insert(addr(1), (now - ttl, PlaceholderMap::new()));
        sweep_stale(&mut maps, now, ttl);
        assert!(maps.is_empty(), "entry at exactly TTL should be evicted");
    }
}
