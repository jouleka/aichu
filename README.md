# aichu

**Keep credentials out of AI coding-agent traffic without breaking the conversation.**

`aichu` is a local Rust proxy and offline scanner. It detects secret-shaped
values in outbound prompt traffic, swaps them for typed placeholders, and
restores those values locally when the model echoes the placeholders back.
The provider receives the useful context—not the credential itself.

> **Current status:** working v0 CLI for macOS, Linux, and Windows. The MITM
> proxy, base-URL relay, redaction core, offline scanner, trust management,
> and diagnostics are implemented and tested. Install from source; the crate
> is not published to crates.io yet.

## The product in one request

```text
coding agent             aichu on localhost                model provider
────────────             ──────────────────                ──────────────
"debug sk-live-…"  ───▶  detect + replace            ───▶  "debug «SECRET_…»"
"check sk-live-…"  ◀───  restore preserved token     ◀───  "check «SECRET_…»"
```

The placeholder map stays in memory. Original secret bytes are not written to
disk, logged, or sent upstream. Detection covers the complete request body on
known prompt endpoints, including pasted files and tool output returned to the
model—not only text typed directly by the user.

## Quick start

```bash
git clone https://github.com/jouleka/aichu.git
cd aichu
cargo install --path crates/cli

# One-time: generate and trust a local CA for the HTTPS proxy.
aichu trust

# Start the proxy on 127.0.0.1:8788.
aichu run --report
```

Point a CLI agent at the proxy from another shell:

```bash
export HTTPS_PROXY=http://127.0.0.1:8788
export NODE_EXTRA_CA_CERTS="$HOME/.aichu/ca/aichu-ca.pem"

claude # or codex, opencode, cursor-agent
```

`aichu doctor` checks the CA, trust-store installation, proxy environment,
and listening port. When you are finished, `aichu untrust` removes the CA
from the OS trust store.

## Scan before anything leaves the machine

The scanner uses the same detection core without opening a socket:

```bash
aichu scan .env
cat config.yaml | aichu scan
```

It reports detector names, locations, and generated placeholders—never the
secret bytes. Exit codes make it usable in CI and pre-commit hooks:

| Exit | Meaning |
|---:|---|
| `0` | No detector fired |
| `1` | Input could not be read |
| `2` | At least one secret-shaped value was detected |

## Supported surfaces

| Surface | v0 route | Status |
|---|---|---|
| Claude Code CLI | `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS` | Validated |
| Codex CLI | Proxy variables or a custom model provider | Validated |
| OpenCode | Proxy variables / base URL | Validated |
| Cursor CLI (`cursor-agent`) | Proxy variables after login | Validated |

Cursor IDE and Claude Desktop are intentionally out of scope for v0. Their
Chromium network paths do not reliably honor the CLI proxy configuration on
macOS; supporting them requires transparent capture rather than pretending the
current proxy can see traffic that bypasses it.

## Architecture

| Component | Responsibility |
|---|---|
| `proxy-core` | Secret detection, typed placeholders, and in-memory reversal |
| `proxy-mitm` | HTTPS proxy with a locally generated CA and streaming support |
| `proxy-server` | Base-URL relay for clients that can target a local endpoint |
| `cli` | `run`, `scan`, `trust`, `untrust`, and `doctor` |

The v0 CLI starts the MITM route. The base-URL relay is implemented as a
separate crate for integrations that do not need a trusted local CA.

```text
crates/
├── cli/          # user-facing binary
├── proxy-core/   # shared detection and reversal pipeline
├── proxy-mitm/   # HTTPS interception mode
└── proxy-server/ # base-URL relay mode
```

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The repository began with three explicit risk experiments. Their READMEs keep
the original hypotheses and results:

- [`e01-hudsucker-mitm`](experiments/e01-hudsucker-mitm) — real-agent MITM,
  HTTP/2, and SSE feasibility
- [`e02-base-url-relay`](experiments/e02-base-url-relay) — no-MITM relay and
  streaming integrity
- [`e03-placeholder-eval`](experiments/e03-placeholder-eval) — how reliably
  model families preserve reversible placeholder tokens

See [`docs/build-plan.md`](docs/build-plan.md) for the original architecture,
prior-art review, and validation plan.

## Threat model

### What aichu protects against

A specific, narrow class of accidental leakage: **secret-shaped substrings in
the prompt traffic your AI coding agent sends upstream**. This is broader than
just what you type: aichu redacts the *entire* outbound request body on known
prompt endpoints, so a secret is caught whether it rides in a prompt you typed,
a pasted `.env` file, a stack trace, a code snippet, **or a tool result the
agent fed back to the model** (command output, a file it read into context).
Without aichu, the bytes
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
- **Secrets in formats we don't detect.** v0 covers 12 patterns:
  Anthropic, OpenAI, AWS access key, GitHub PAT, Stripe live key, JWT,
  Slack token, AWS secret access key (identifier-anchored + entropy
  gate), PEM private-key blocks (multi-line, RSA/EC/PKCS#8/OpenSSH/DSA),
  GCP service-account JSON, Twilio API-key SID + auth token,
  Cloudflare API token (identifier-anchored). Custom tokens with no
  distinctive prefix and no surrounding identifier are NOT redacted.
  See "Known limitations" below.
- **Model paraphrase / drop of placeholders.** When the model preserves
  `«SECRET_AWS_KEY_001»` verbatim in its response, we reverse it back to
  the original secret. When the model paraphrases ("your AWS key"), there
  is nothing to substitute and the user sees the placeholder gone from
  the response. **Measured on openai:gpt-5-mini, 50 fixtures × 6 formats
  = 300 calls per condition, 2026-05-25:**

  | Format | Zero-shot | Instructed | Δ |
  |---|---|---|---|
  | `«SECRET_TYPE_NNN»` (guillemets — production) | 12% | **96%** | +84 pp |
  | `__SECRET_TYPE_NNN__` (underscore_type) | 24% | 94% | +70 pp |
  | `<SECRET_N>` (angle_num) | 20% | 90% | +70 pp |
  | `{{VAR}}` (mustache) | 40% | 90% | +50 pp |
  | `***` / `[REDACTED]` (substring-biased controls) | 20% / 12% | 88% / 82% | +68 / +70 pp |

  Refusals: 0 / 300 in both conditions. Raw results at
  [`experiments/e03-placeholder-eval/results/gpt-5-mini-2026-05-25.json`](experiments/e03-placeholder-eval/results/gpt-5-mini-2026-05-25.json)
  (zero-shot) and
  [`gpt-5-mini-instructed-2026-05-25.json`](experiments/e03-placeholder-eval/results/gpt-5-mini-instructed-2026-05-25.json)
  (with system prompt at
  [`instructions/preserve-tokens.txt`](experiments/e03-placeholder-eval/instructions/preserve-tokens.txt)).

  **Reading these numbers:**

  - **Security property holds in both conditions.** The proxy strips
    the secret BEFORE the request leaves the machine; the original
    secret never reaches the model. Preservation rate measures
    response-side UX, NOT whether secrets leak.
  - **Zero-shot UX is degraded.** Without a system prompt,
    gpt-5-mini paraphrases ("your AWS key is the problem...")
    instead of echoing the placeholder. The user still gets a useful
    answer, just with no original secret restored where they'd
    expect it.
  - **With a short system prompt, UX is restored.** Guillemets
    clears build-plan §9's 95% threshold (96%). The system prompt
    file is the recommended template for any production deployment
    that wants the response-side reversal to work.

  Cross-family measurement (Anthropic Opus/Sonnet, Google Gemini)
  remains deferred — same harness, one CLI flag away once budget
  exists.
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
  `aichu trust` command (macOS + Linux (Debian, Red Hat, and Arch families) + Windows shipped). For Mode A, no
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

- **Pattern coverage growing.** The 12 v0 patterns cover the most
  common secret shapes in pasted `.env` files and code snippets, but
  the universe of secrets is broader — custom HMAC signatures,
  database connection strings with embedded credentials, generic
  bearer tokens with no surrounding identifier, etc. are not yet
  covered. The architecture scales (one new variant + regex +
  dedicated detection tests per pattern); coverage expansion is a
  future-work axis, not a v0 ship-blocker.
- **OpenCode `/zen/v1/responses` body shape unvalidated.** The proxy
  treats this path as the canonical OpenAI Responses-API shape and
  injects the preserve-tokens prompt into a top-level `instructions`
  field. If OpenCode's zen layer wraps or transforms the body before
  it reaches the OpenAI upstream, our injection may land in a slot
  zen doesn't pass through. The injector is fail-loud (warn + forward
  unchanged on shape mismatch), so the worst case is degraded UX
  (no preservation lift) rather than a corrupted body. A smoke-test
  against a real OpenCode capture would close the loop.
- **Cross-family eval still partial.** First measured run lives at
  [`experiments/e03-placeholder-eval/results/gpt-5-mini-2026-05-25.json`](experiments/e03-placeholder-eval/results/gpt-5-mini-2026-05-25.json)
  (300 calls × gpt-5-mini, summarized under "Model paraphrase" above).
  Anthropic / Google preservation rates and a system-prompt-instructed
  variant remain deferred — each is one cargo invocation away once
  budget exists.

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
