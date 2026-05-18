# aichu

Local Rust proxy that redacts secrets from prompts sent to AI coding agents (Claude Code, Codex, OpenCode, Cursor CLI), then restores them in responses.

> **Status:** Week 1 risks validated. Production code shipped: `crates/proxy-core` (redaction), `crates/proxy-mitm` (Mode B), `crates/proxy-server` (Mode A), `crates/cli` (the `aichu` binary). End-to-end redaction round-trip works against real Anthropic traffic through both proxy modes. See [Threat model](#threat-model) for guarantees + known limitations.

## Why this exists

AI coding agents have access to your entire workspace, including files containing API keys, tokens, and credentials. When you ask an agent a question, those secrets can be sent verbatim to the model provider. This proxy sits between the agent and the model provider, detects secrets in outbound prompts, replaces them with reversible placeholders, and restores them in the streamed response.

See [`docs/build-plan.md`](docs/build-plan.md) for the full architectural plan, prior art, and competitive landscape.

## Week 1 goals (validate before building)

The build plan identifies three risks that must be validated before committing to an architecture. Each gets its own experiment crate:

| Experiment | Risk | Kill criteria |
|---|---|---|
| [`e01-hudsucker-mitm`](experiments/e01-hudsucker-mitm) | Can we MITM real coding agents (cert pinning, HTTP/2, SSE)? | Cannot MITM Claude Code CLI streaming end-to-end in 2 days → pivot to Mode A only |
| [`e02-base-url-relay`](experiments/e02-base-url-relay) | Does the no-MITM base-URL approach work for Aider / OpenCode / Codex / Claude Code? | Cannot relay streaming `/v1/messages` with intact SSE → architecture is broken |
| [`e03-placeholder-eval`](experiments/e03-placeholder-eval) | Do LLMs preserve placeholder tokens verbatim across families? | No format > 95% verbatim preservation on prefix-typed secrets → reversible-redaction concept is fragile |

Each experiment's README records its goal, run instructions, and result (✅/❌ with notes) as it completes.

## Running aichu

```bash
# Build + install the binary.
cargo install --path crates/cli

# One-time: install the local CA into the OS trust store.
# (sudo prompts for your login password; macOS + Debian-family Linux in v0.)
aichu trust

# Run the proxy. Listens on 127.0.0.1:8788; Ctrl-C to stop.
aichu          # equivalent to `aichu run`

# In another shell, point a coding agent at the proxy.
export HTTPS_PROXY=http://127.0.0.1:8788
export NODE_EXTRA_CA_CERTS=$HOME/.aichu/ca/aichu-ca.pem
claude         # or codex, opencode, cursor-agent, etc.

# Troubleshooting:
aichu doctor   # diagnoses CA, trust-store install, HTTPS_PROXY, and proxy-port issues

# To clean up:
aichu untrust  # remove CA from the OS trust store
rm -rf ~/.aichu  # remove cert + key files
```

## Running an experiment

Only `e03-placeholder-eval` remains in `experiments/` — `e01` and `e02`
have graduated to `crates/proxy-mitm/` and `crates/proxy-server/`
respectively. To run the placeholder-preservation harness:

```bash
cd experiments/e03-placeholder-eval
cargo run --release
```

Workspace-level `cargo build` builds everything.

## Project structure

```
aichu/
├── Cargo.toml              # workspace root
├── rust-toolchain.toml     # pinned stable toolchain
├── CLAUDE.md               # 12-rule project guidelines
├── docs/
│   └── build-plan.md       # full architectural plan
├── crates/
│   ├── proxy-core/         # detection + redaction + reverse (used by both modes)
│   ├── proxy-mitm/         # Mode B: HTTPS MITM with on-the-fly rcgen CA (graduated from e01)
│   ├── proxy-server/       # Mode A: localhost HTTP server, base-URL relay (graduated from e02)
│   └── cli/                # the `aichu` binary
└── experiments/            # week-1 risk-validation crates
    ├── e01-hudsucker-mitm/ # historical record only (code graduated to crates/proxy-mitm)
    ├── e02-base-url-relay/ # historical record only (code graduated to crates/proxy-server)
    └── e03-placeholder-eval/  # harness for measuring placeholder preservation
```

## Eventual production layout (in progress)

- `crates/proxy-core/`   — redaction pipeline, placeholder map (shared) ✅ shipped
- `crates/proxy-mitm/`   — Mode B: Hudsucker MITM ✅ shipped
- `crates/proxy-server/` — Mode A: localhost HTTP server, base-URL relay ✅ shipped
- `crates/cli/`          — `aichu run | trust | untrust | doctor` ✅ shipped (macOS + Debian-family Linux; RHEL/Arch/Windows v1+)

## v0 scope: CLI tools only

Validated empirically against six real coding-agent surfaces (see
[e01 README → Manual smoke test](experiments/e01-hudsucker-mitm/README.md#manual-smoke-test-2026-05-15)),
aichu v0 ships for:

- **Claude Code CLI** — `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS`
- **Codex CLI** — same env vars, or `[model_providers]` in `~/.codex/config.toml`
- **OpenCode** (Bun) — same env vars
- **Cursor CLI** (`cursor-agent`) — same env vars (requires `cursor-agent login`)

**Out of scope for v0:** Cursor IDE and Claude Desktop. Both put their chat
path in Chromium's network service, which on macOS doesn't read `HTTPS_PROXY`
and routes chat traffic via a separate process holding direct TCP
connections. Reaching them requires Mode C / transparent capture (eBPF on
Linux, macOS Network Extension) — a future investment, not a v0 feature.

## Threat model

### What aichu protects against

A specific, narrow class of accidental leakage: **secret-shaped substrings in
prompts you send to AI coding agents**. Concretely: you paste an `.env` file,
a stack trace, or a code snippet into Claude Code; without aichu, the bytes
(including any embedded API key, OAuth token, AWS credential, JWT, Slack
token, etc.) flow verbatim to Anthropic / OpenAI / etc. With aichu running,
those substrings are replaced with typed placeholders like
`«SECRET_AWS_KEY_001»` before the request leaves your machine, and restored
on the way back so the model's response still references the original
secret to you locally.

This is **leakage hygiene**, not security. The threat is human carelessness,
not adversarial.

### What aichu does NOT protect against

- **A compromised or malicious coding agent.** The agent already has access
  to your filesystem; if it wants your `.env`, it can `cat` it directly
  rather than embed it in a prompt. aichu sits in the network path, not the
  filesystem path.
- **Secrets in formats we don't detect.** v0 covers 9 patterns:
  Anthropic, OpenAI, AWS access key, GitHub PAT, Stripe live key, JWT,
  Slack token, AWS secret access key (identifier-anchored + entropy
  gate), PEM private-key blocks (multi-line, RSA/EC/PKCS#8/OpenSSH/DSA).
  Custom tokens with no distinctive prefix and no surrounding identifier
  are NOT redacted. See "Known limitations" below.
- **Model paraphrase / drop of placeholders.** When the model preserves
  `«SECRET_AWS_KEY_001»` verbatim in its response, we reverse it back to
  the original secret. When the model paraphrases ("your AWS key"), there
  is nothing to substitute and the user sees the placeholder gone from the
  response. Build-plan §7 and the prior-art writeup in
  [`experiments/e03-placeholder-eval/README.md`](experiments/e03-placeholder-eval/README.md)
  argue qualitatively that rare-Unicode-bracket placeholders preserve well
  (the academic state-of-the-art —
  [LLM-Redactor, arxiv 2604.12064](https://arxiv.org/abs/2604.12064) —
  converged on the same design principle). The full
  per-format-per-model preservation matrix has NOT been measured: the
  e03 harness is wired and tested against an axum mock, but the real-API
  run is deferred until Anthropic Console credits are available.
  Manually we have observed the round-trip working on a handful of prompts
  against real Anthropic through both modes; that is empirical existence
  proof, not a statistical preservation rate.
- **Traffic outside the proxy.** DNS lookups, ICMP, anything not routed
  through `HTTPS_PROXY` / base URL config. The proxy only sees what the
  agent CHOOSES to route through it.
- **Side channels.** Response latency, byte counts, timing correlations.
  Not an active concern for a hygiene tool.
- **Local compromise.** If an attacker has local code execution on your
  machine, they read your `.env` directly. aichu is not a defense against
  that.
- **Chromium-based desktop apps' chat traffic.** Cursor IDE and Claude
  Desktop route chat through Chromium's network service, which on macOS
  doesn't honor `HTTPS_PROXY` env vars. aichu cannot see that traffic in
  v0. See [v0 scope](#v0-scope-cli-tools-only).

### What runs locally vs. what leaves the machine

| Thing | Stays local | Leaves machine |
|---|---|---|
| Secret detection (`proxy-core::scan`) | ✅ 100% on-host | — |
| Placeholder map (in-memory `HashMap<SocketAddr, PlaceholderMap>` for Mode B; per-request scope for Mode A) | ✅ never persisted | — |
| CA private key (Mode B only) | ✅ `./ca/aichu-ca.key`, mode `0o600` on Unix | — |
| Redacted prompt body | — | ✅ over HTTPS to the model provider you configured |
| Original secret text | ✅ stays in the proxy process | ❌ never leaves |
| Telemetry | local stderr logs via `tracing` only; zero remote sinks, no analytics SDK, no auto-update beacon | — |

### Trust assumptions

You are trusting:

1. **The OS** to enforce file permissions on the CA key and to provide
   process isolation between aichu and other local processes.
2. **The Rust crates in the dependency tree** (`hyper`, `rustls`,
   `hudsucker`, `axum`, `reqwest`, and `proxy-core` itself) to do what
   they say.
3. **Your model provider** with the redacted prompt — the placeholder
   round-trip protects only the secret substring, not the surrounding
   prompt structure (file paths, error message text, code that
   references the secret by variable name, etc).

You are NOT trusting:

- A system-wide CA install. Mode B mints a per-machine CA and asks the
  user to install it into the system trust store via an explicit
  `aichu trust` command (macOS + Debian-family Linux shipped; RHEL/Arch/Windows v1+). For Mode A, no
  CA is installed at all.
- Any third-party server. The proxy contacts your configured model
  provider only.

One trust boundary that's easy to miss: **the Mode B CA private key
persists between runs.** It lives at `./ca/aichu-ca.key` (or wherever
the binary's `cwd` is at first run) with permissions `0o600`. Anyone
who copies that file can sign certs for any host on a machine that
trusts your CA. Treat it like an SSH private key — don't commit the
`ca/` directory to git, don't include it in machine images or
container layers, and rotate (`rm -rf ./ca/` then re-run) if you
suspect exposure.

### Known limitations (v0)

- **HTTP/2 multiplexing.** Mode B keys the per-request PlaceholderMap
  by `client_addr`. HTTP/2 multiplexed streams share a TCP connection
  (and thus a `client_addr`), so two truly concurrent requests on one
  connection could race. Not observed in practice; documented in
  `crates/proxy-mitm/src/handler.rs`.
- **Orphaned-entry cleanup is sweep-based, not push-based.** If
  `handle_response` never runs (TLS error, client cancellation,
  upstream timeout), the HashMap entry for that `client_addr` would
  otherwise linger forever. v0 evicts entries older than 15 minutes
  via an opportunistic sweep on every prompt-endpoint request
  (`crates/proxy-mitm/src/handler.rs::sweep_stale`). Worst-case
  memory: roughly `request_rate × orphan_rate × 15 min` entries at a
  few KB each. For a localhost single-user proxy that's typically
  zero; under sustained pathological churn it could reach the low
  thousands transiently before the next sweep — single-digit MB at
  most.
- **Pattern coverage growing.** The 9 v0 patterns cover the most
  common secret shapes that appear in pasted `.env` files and code
  snippets, but the universe of secrets is broader — custom HMAC
  signatures, GCP service-account JSONs, Twilio auth tokens,
  Cloudflare API tokens, etc. are not yet covered. The architecture
  scales (one new variant + regex + dedicated detection tests per
  pattern); coverage expansion is a future-work axis, not a v0
  ship-blocker.
- **Manual eval not yet run.** The e03 harness can measure placeholder
  preservation rates across model families. The real-API run is gated
  on Anthropic Console credits and remains a deferred work item.

### Audit-friendly invariants

The proxy is structured so a reader can verify each invariant from the
code:

- **No disk writes** for the placeholder map or any intercepted body.
  Search for `std::fs::write` / `OpenOptions::write` in the workspace —
  only the CA key write path appears.
- **No outbound network calls** from the proxy other than the
  reqwest/hudsucker forward to the upstream URL the agent specified.
  No analytics, no telemetry, no auto-updates.
- **Allow-list on redaction targets** (Mode B): only requests to known
  prompt endpoints (`/v1/messages`, `/v1/chat/completions`, etc.)
  trigger redaction. OAuth refresh, model metadata, and unrelated
  traffic flow through unchanged. See
  `is_prompt_endpoint(path)` in `crates/proxy-mitm/src/handler.rs`.
- **Bidirectional map is per-session, in-memory only.** See `PlaceholderMap`
  in `crates/proxy-core/src/placeholder.rs` — backed by `HashMap`s, no
  serialization, no Drop side-effect.
- **Fail-closed on proxy crash.** If the proxy process panics or exits
  between redact and reverse, the in-memory PlaceholderMap dies with
  it. The agent sees a connection error; the user sees nothing leaked.
  The crash is a denial-of-service event, not a privacy event.
- **Upstream 5xx leaves the map unused.** If upstream returns an error
  response with no body (or a JSON error body that contains no
  placeholder), the reverse pass runs but substitutes nothing. The
  user sees the upstream error verbatim; no original secret is
  injected into a place the model didn't reference.

## License

Dual-licensed under MIT or Apache 2.0, at your option.
