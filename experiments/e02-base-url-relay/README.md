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

> Not yet run.
