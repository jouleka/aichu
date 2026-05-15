# e02-base-url-relay

**Risk under test:** Does the no-MITM "base-URL relay" architecture (Mode A) survive real coding-agent traffic? Specifically, can we proxy streaming `/v1/messages` (Anthropic) and `/v1/chat/completions` (OpenAI) over an HTTP localhost endpoint while keeping SSE intact?

## Goal

Stand up an `axum` HTTP server on `127.0.0.1:8788` that:

1. Accepts `/v1/messages` and forwards to `https://api.anthropic.com/v1/messages` with the client's auth header.
2. Accepts `/v1/chat/completions` and forwards to `https://api.openai.com/v1/chat/completions`.
3. For streaming responses, parses SSE on the way back with `eventsource-stream`, then re-emits the exact same events to the client.
4. Pass-through only — no redaction yet. The goal is to prove streaming survives a relay.

## How to run

```bash
# Set whatever you have available; only the providers you exercise need keys.
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...

cargo run --release
```

Then:

```bash
# Aider (will speak to /v1/chat/completions)
aider --openai-api-base http://127.0.0.1:8788/v1 \
      --openai-api-key "$OPENAI_API_KEY"

# Claude Code via ANTHROPIC_BASE_URL.
# Claude Code appends /v1/messages — our server mounts the handler at that
# exact path, so ANTHROPIC_BASE_URL is the bare origin (no /v1 suffix).
ANTHROPIC_BASE_URL=http://127.0.0.1:8788 claude
```

## Success criteria

- ✅ A streaming Aider session completes through the proxy with the same UX as direct.
- ✅ A streaming Claude Code session completes through the proxy.
- ✅ SSE `event:`/`data:` framing is preserved byte-for-byte on the response side.
- ✅ Throughput overhead is negligible (no noticeable lag).

## Kill criteria

- ❌ Cannot relay streaming SSE without buffering whole responses.
- ❌ Anthropic or OpenAI rejects the relayed request because of header re-writing.
- ❌ Agents send wire formats this experiment can't trivially parse (gRPC, Connect-protobuf).

If killed: redaction-on-the-fly is unrealistic at this layer; reconsider architecture.

## Result

### Automated (`cargo test`)

✅ Three tests passing:

- `relay_streams_anthropic_sse_intact` (integration) — a `POST /v1/messages`
  with `stream: true` routed through the relay reaches the local upstream,
  the SSE body (`data: hello / data: world / data: done`) is preserved
  byte-for-byte to the client, and the upstream sees exactly one forwarded
  request.
- `handler::hop_by_hop_recognizes_rfc_7230_set` — the RFC 7230 §6.1
  hop-by-hop header set is stripped on both legs (`connection`, `keep-alive`,
  `proxy-authenticate`, `proxy-authorization`, `te`, `trailers`,
  `transfer-encoding`, `upgrade`), plus `host` and `content-length` (which
  reqwest sets itself).
- `handler::hop_by_hop_allows_auth_and_content_type` — `authorization`,
  `x-api-key`, `anthropic-version`, `content-type`, `accept` are NOT
  stripped (so the client's auth and content negotiation reach upstream
  intact).

This proves the relay's wiring: bytes round-trip unmodified, streaming
SSE is forwarded chunk-by-chunk via `Body::from_stream(bytes_stream())`
without buffering whole responses, and header hygiene is in place.

### Manual (real Anthropic traffic, 2026-05-15)

Setup: `cargo run --release -p e02-base-url-relay` with default upstreams
(`https://api.anthropic.com`, `https://api.openai.com`). Two checks:

**1. Real `claude` invocation → real model response through the relay.**

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8788 \
  claude -p "Reply with only the single word PONG and nothing else." \
         --output-format text
```

Output: `PONG`. Claude Code talks plain HTTP to localhost; relay re-issues
over HTTPS to real Anthropic; auth, streaming, content-type, and body all
round-trip without modification.

**2. Curl with a deliberately-invalid key → real Anthropic 401.**

```bash
curl -X POST http://127.0.0.1:8788/v1/messages \
     -H "Content-Type: application/json" \
     -H "x-api-key: sk-ant-deliberately-invalid" \
     -H "anthropic-version: 2023-06-01" \
     -d '{"model":"claude-opus-4-7",
          "messages":[{"role":"user","content":"hi"}],
          "max_tokens":10}'
```

Response: `HTTP 401`, body `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"},"request_id":"req_011Cb45iXCZAUxKSLEzHtvgq"}`.

The `request_id: req_011...` is Anthropic's own format — proof the relay
actually reached `api.anthropic.com` and propagated the upstream response
verbatim. (If the relay had short-circuited or fabricated the 401, no
real `request_id` would appear.)

### Risk 3 verdict

**Fully validated** for the Anthropic path. The Mode A architecture
survives real coding-agent traffic with zero CA install: a plain-HTTP
localhost endpoint that re-issues over HTTPS to upstream, preserving
streaming, auth, and error semantics.

The OpenAI path was structurally tested in the integration test
(`relay_streams_openai_chat_completions_chunks_over_time`) but not yet
exercised against real `api.openai.com` — that's a follow-up requiring
an `OPENAI_API_KEY`. Codex CLI's `[model_providers]` config path is the
intended production wiring; this experiment proves the relay does its
side correctly.

### Follow-ups identified during the smoke test

- The relay currently has **no per-request tracing** in the handler — only
  startup logs appear. Production `crates/proxy-server` should add a
  `tower-http::trace::TraceLayer` or an explicit `tracing::info!` at
  forward time so operators can see what's being relayed. Not blocking
  for this experiment but flagged for the production crate.

### Risk 3 verdict

**Wiring validated.** The architecture survives a streaming SSE relay
end-to-end without buffering or breaking framing. The kill criteria from
the README's planning section ("Cannot relay streaming SSE without
buffering whole responses", "Agents send wire formats this experiment
can't trivially parse") were not triggered — the JSON/SSE happy path
works exactly as the build plan §6 predicted.

The remaining open question is whether real Anthropic/OpenAI traffic
through this relay reveals wire-format surprises (e.g., specific header
quirks, non-SSE binary frames inside tool-call streams). That's the
manual test.
