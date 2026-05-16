# e01-hudsucker-mitm

> **Experiment graduated.** This risk was validated for the CLI scope.
> Production code now lives in [`crates/proxy-mitm`](../../crates/proxy-mitm/).
> This README is preserved as the historical record of the risk evaluation
> (goal, kill criteria, smoke-test results, v0 scope decision, and the three
> bugs surfaced by the end-to-end test against real Anthropic).

**Risk under test:** Can a Hudsucker-based MITM proxy (HTTP/2 + rustls + on-the-fly rcgen CA) successfully intercept streaming `/v1/messages` traffic from Claude Code CLI? Same question for Codex CLI's `/v1/responses`.

## Goal

Stand up the smallest possible Hudsucker proxy that:

1. Generates a CA on first run, writes the public cert to `./ca/aichu-ca.pem`.
2. Listens on `127.0.0.1:8788`.
3. Logs every intercepted request line (method, host, path).
4. Logs every SSE `data:` frame from the response side, without modifying the stream.
5. Survives a complete streaming `claude` CLI conversation end-to-end.

## How to run

```bash
# 1. Build and start the proxy
cargo run --release

# 2. In another shell, trust the generated CA (one-time, manual)
#    macOS:
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    ./ca/aichu-ca.pem

# 3. Point Claude Code at the proxy
export HTTPS_PROXY=http://127.0.0.1:8788
export NODE_EXTRA_CA_CERTS=$PWD/ca/aichu-ca.pem
claude  # interact normally

# 4. To clean up after testing.
#    Note: -c matches by common name. The actual CN is set by rcgen at proxy
#    startup and logged at INFO level on first run. Use that exact CN here,
#    or use -Z <SHA1> after `security find-certificate -a -c <prefix> -Z`.
sudo security delete-certificate -c "<CA-COMMON-NAME-FROM-STARTUP-LOG>" /Library/Keychains/System.keychain
rm -rf ./ca
```

## Success criteria

- ✅ Claude Code completes a multi-turn streaming conversation through the proxy with no errors.
- ✅ Proxy logs show the request body and at least one full SSE response.
- ✅ HTTP/2 ALPN negotiates without falling back to HTTP/1.1 (check tracing output).

## Kill criteria

- ❌ Cannot MITM Claude Code CLI end-to-end within 2 days of focused work.
- ❌ HTTP/2 GOAWAY errors mid-stream that cannot be resolved by feature flags or hudsucker config.
- ❌ Claude Code rejects the CA even after `NODE_EXTRA_CA_CERTS` is set correctly.

If killed: pivot architecture to Mode A only (no MITM, base-URL relay). See `e02-base-url-relay`.

## Result

### Automated (`cargo test`)

✅ Five tests passing as of the initial implementation:

- `proxy_relays_sse_stream_and_logs_request` (integration) — a plain-HTTP
  `GET /sse` routed through aichu reaches the upstream, the SSE body
  round-trips intact, and `AichuHandler::handle_request` runs exactly once.
- `ca::first_call_writes_cert_and_key_files` — first call persists the CA.
- `ca::cert_file_is_a_pem_certificate` — cert is PEM-formatted on disk.
- `ca::second_call_reuses_existing_ca_without_regenerating` — subsequent
  calls do **not** mint a new CA (critical: regenerating would invalidate
  the user's system-store trust install).
- `ca::key_file_has_owner_only_permissions` (Unix) — key file is mode 0o600.

This proves the **wiring** survives: hudsucker `HttpHandler` runs, the
proxy relays bodies unmodified, the CA persistence story is correct.

### Manual smoke test (2026-05-15)

Six real-world coding-agent surfaces exercised against the running proxy.
Setup: proxy on `127.0.0.1:8788`, fresh-generated CA at
`/tmp/aichu-smoke/ca/aichu-ca.pem`. Each agent invoked with
`HTTPS_PROXY=http://127.0.0.1:8788`,
`NODE_EXTRA_CA_CERTS=/tmp/aichu-smoke/ca/aichu-ca.pem`, and
`SSL_CERT_FILE=/tmp/aichu-smoke/ca/aichu-ca.pem`.

| Tool | Version | Verdict | Evidence |
|---|---|---|---|
| **Claude Code CLI** | 2.1.90 | ✅ Full | `PONG`; decrypted `POST api.anthropic.com/v1/messages?beta=true` |
| **Codex CLI** | 0.130.0 | ✅ Full | `PONG`; routes via `chatgpt.com/backend-api/codex/responses` (not `api.openai.com`) |
| **OpenCode** (Bun) | 1.1.47 | ✅ Full | `PONG`; routes via `opencode.ai/zen/v1/responses` + `/zen/v1/chat/completions` |
| **Cursor CLI** | 2026.01.23 | 🟡 Transport only | Decrypted `POST api2.cursor.sh/aiserver.v1.DashboardService/GetMe`; chat path not exercised — `cursor-agent` was unauthenticated locally |
| **Cursor IDE** | 2.4.31 | ❌ Not viable | A separate Cursor process exited via direct TCP connections to Cloudflare + AWS us-east-1, bypassing the proxy entirely. We did not confirm the process role — likely Chromium's network-service utility, which is consistent with Chromium's macOS proxy handling. Admin/settings paths on `api2.cursor.sh` *are* MITM-able; chat is not. `api3.cursor.sh` + `metrics.cursor.sh` additionally cert-pin |
| **Claude Desktop** | 1.7196.0 | ❌ Not viable | Chat traffic flows through Chromium's network service (the Electron `Claude Helper` utility process, sub-type `network.mojom.NetworkService`). On macOS this component reads OS system-proxy settings, not `HTTPS_PROXY` env vars. Only Cowork agentic-VM worker registration (`POST /v1/code/sessions/<id>/worker/register`) crossed the proxy — that path appears to use a Node-land HTTP client that does honor env vars |

**Why the Electron desktop apps escape env-var MITM**

On macOS (the platform tested), Chromium's network stack reads (a) OS
system-wide proxy settings, (b) command-line flags like
`--proxy-server=...`, (c) PAC scripts, and (d) programmatic
`session.setProxy()` config. It does **not** read `HTTPS_PROXY` env
vars on macOS or Windows. (On Linux it falls back to env vars only
when no GNOME/KDE proxy config is detected.) Electron apps that put
their chat path in the renderer therefore route chat through
Chromium's network service, which bypasses any env-var-based proxy.
CLI tools, by contrast, use HTTP libraries (Rust `reqwest`, Node
`https-proxy-agent`, libcurl) that read `HTTPS_PROXY` cleanly — which
is why they all worked.

**Side findings worth recording for the threat model**

- Codex CLI 0.130.0 with ChatGPT-account auth routes through
  `chatgpt.com/backend-api/codex/responses`, not `api.openai.com`.
  API-key auth, or a custom `model_provider` in `~/.codex/config.toml`,
  would route elsewhere. Our redaction rules need to recognize both
  wire shapes (ChatGPT-backend and OpenAI Responses API).
- OpenCode routes through `opencode.ai/zen/...`, their own
  billing-aware proxy that re-fans to Anthropic/OpenAI. aichu would
  redact prompts heading to opencode.ai, not directly to the model
  provider — privacy-equivalent but worth flagging.
- Claude Code CLI's MCP child processes (`mcp-proxy.anthropic.com`,
  npm registry) inherited the parent's `HTTPS_PROXY` and routed
  through the proxy successfully.

### v0 scope decision

aichu v0 ships for **CLI surfaces only**: Claude Code, Codex CLI,
OpenCode, and (with one `cursor-agent login`) Cursor CLI. Electron
desktop apps (Cursor IDE, Claude Desktop) are deferred to **Mode C /
transparent capture** (eBPF on Linux, Network Extension on macOS) per
`docs/build-plan.md` §4 tier 3, because their chat path is by design
unreachable from an env-var-based MITM.

### Risk 1 verdict

**Validated for the CLI scope.** The result matches the build plan's
prediction for non-CLI surfaces. The mechanism is clearer than the
original framing: not just cert pinning, but Chromium's network
service routing chat traffic in a way that doesn't consult
`HTTPS_PROXY` on macOS. Cert pinning on `api3.cursor.sh` is a
secondary defense; the primary block is the renderer + network-service
architecture.

### End-to-end Mode B smoke test (2026-05-16, post-redaction-wiring)

With `proxy-core` wired into `AichuHandler`, verified the full
redact + reverse round-trip works against real Anthropic through the
MITM path. Prompt: `Echo this string back to me verbatim and add
nothing else: AKIAIOSFODNN7EXAMPLE`. Claude received the prompt with
`«SECRET_AWS_KEY_001»` in place of the key; Anthropic preserved the
placeholder; the relay reversed it; client saw `AKIAIOSFODNN7EXAMPLE`
in the response.

The test surfaced **three real bugs** that the integration test suite
did not catch (all fixed in the same commit cycle as the wiring):

1. **OAuth refresh redaction.** Claude Code's `POST
   platform.claude.com/v1/oauth/token` carries a `sk-`-shaped refresh
   token. Our `OpenAiKey` regex matched it; the redacted body was
   rejected (400) by Anthropic's OAuth endpoint; claude couldn't
   refresh; every downstream call 401'd. Fix: path-scoped allow-list
   in `handle_request` — only redact known prompt endpoints
   (`/v1/messages`, `/v1/chat/completions`, `/v1/responses`,
   `/backend-api/codex/responses`, `/zen/v1/responses`,
   `/zen/v1/chat/completions`). Regression test:
   `mitm_does_not_redact_non_prompt_paths`.

2. **Per-pair state didn't survive across hudsucker handler clones.**
   Trait docs say "each request/response pair is passed to the same
   instance"; empirically, hudsucker spawns a fresh handler clone per
   sub-request under MITM, so a `current_map` field set in
   `handle_request` is empty in `handle_response`. Fix: move state to
   `Arc<Mutex<HashMap<SocketAddr, PlaceholderMap>>>` keyed by
   `HttpContext.client_addr` — survives the clone boundary because the
   Arc is shared. Known limitation: HTTP/2 multiplexing on one
   connection could collide; v0 accepts the risk, deferring a finer
   key (e.g., stream id) to follow-up.

3. **gzipped responses break the UTF-8 reverse path.** Anthropic
   gzips its `text/event-stream` responses by default. We collect the
   body bytes and run `std::str::from_utf8` before
   `proxy_core::reverse`; gzipped bytes aren't valid UTF-8, so the
   reverse fell through to the "pass through unchanged" branch and the
   user saw placeholders. Fix: strip `Accept-Encoding` from the
   outbound request headers — upstream then returns the body
   uncompressed. The non-UTF-8 fallback was also promoted from `debug`
   to `warn` so this class of bug surfaces in production logs.
   Regression test:
   `mitm_strips_accept_encoding_so_responses_are_uncompressed`.

All three bugs are documented in `src/handler.rs` with pointers to
the regression tests that pin the fixes.

**Known v0 limitations recorded for follow-up:**

- **Map leak on dropped connections.** If `handle_response` is never
  called (TLS error after request forwarded, client cancellation,
  upstream timeout), the `HashMap` entry for that `client_addr` is
  never removed. Long-running proxy sessions could accumulate orphan
  entries. v0 ships without mitigation; follow-up options are a size
  cap, a TTL sweep, or a `Drop`-guard wrapper around the inserted map.
- **Accept-Encoding test scope.** The regression test
  `mitm_strips_accept_encoding_so_responses_are_uncompressed` asserts
  redaction still works alongside the strip, not that the header was
  actually removed from the outbound request. A tighter test needs a
  mock that captures request headers, not just bodies. Acceptable for
  v0 — the manual smoke test against real Anthropic confirms the
  end-to-end behavior.
- **Cursor CLI chat path TBD.** The allow-list does not yet include a
  path for `cursor-agent` chat. The smoke test above only reached
  `api2.cursor.sh/aiserver.v1.DashboardService/GetMe` (an admin/auth
  path) because `cursor-agent` was unauthenticated locally. The actual
  chat path will be identified when someone runs the smoke test with
  a logged-in `cursor-agent` session; the allow-list will be extended
  at that point.
