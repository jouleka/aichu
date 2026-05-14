# Build Plan: A Rust Local HTTPS Proxy That Redacts Secrets From AI Coding Agents

> **Archived from the original planning doc.** This is the source-of-truth design document for the project. Update in place as decisions evolve; do not let it drift from reality.

## TL;DR — The Opinionated Stack

| Layer | Pick | Why |
|---|---|---|
| MITM core | **Hudsucker 0.19.4** (omjadas) | Only actively maintained pure-Rust MITM library with HTTP/2, rustls, rcgen CA-on-the-fly, and a stable handler trait. Dual MIT/Apache-2.0. |
| TLS | **rustls** via `tokio_rustls` (Hudsucker default) | Pure-Rust, audited, what Claude Code/Codex already trust via system store. |
| Cert gen | **rcgen** (Hudsucker feature `rcgen-ca`) | On-the-fly leaf cert minting; works without OpenSSL. |
| Secret detection | **Port Gitleaks' `config/gitleaks.toml` rules into Rust `regex` crate**, packaged as a static ruleset. **Do not** shell out to TruffleHog v3 (AGPL-3.0 contagion risk + 250ms+ startup) or to Gitleaks (Go binary, ~25 MB). | Both regex engines are RE2-compatible (no look-arounds), so rules port cleanly. Borrow Betterleaks' BPE-rarity filter idea later to cut FPs on prose. |
| SSE | **`eventsource-stream`** (lib.rs, 270K dl/mo) over `reqwest::Response::bytes_stream()` | Lets you parse, mutate, and re-emit `data:` frames as a `Stream<Event>` without breaking back-pressure. |
| Placeholder format | `«SECRET_AWS_KEY_001»` (French guillemets + ALL_CAPS slug + counter) | See §7 — beats `[REDACTED]`, `{{...}}`, `<...>`, and `__PWM_1__` for preservation. |
| Distribution | Single static binary via `cargo dist`, plus `brew install` tap and a `curl \| sh` installer that does the CA-trust step interactively with a clearly worded prompt | See §4 — the CA install is your conversion funnel. |

**Riskiest unknown #1 (validate in week 1):** Cursor IDE is doing something cert-pinning-like and Claude Cowork (Bun runtime) ignores `NODE_EXTRA_CA_CERTS`. If you cannot MITM at least Claude Code CLI + Codex CLI + Aider + OpenCode without weird breakage, the product is dead. See §9.

**Prior art warning:** Formal.ai has already published a public walkthrough of exactly this pattern (mitmproxy + addon to inject real Anthropic keys after Claude Code sends dummies). This is a positive signal that the technique works, but it also means the "secrets-only" framing is not novel — your wedge has to be the *zero-config local UX*, not the idea.

---

## 1. Rust MITM Proxy Libraries in 2026

| Library | Stars / activity | HTTPS w/ on-the-fly CA | HTTP/2 | SSE/streaming | License | Verdict |
|---|---|---|---|---|---|---|
| **Hudsucker** (`omjadas/hudsucker`) v0.19.4 | ~120★, 5 releases/12mo, ~1K dl/mo | ✅ rcgen or OpenSSL feature | ✅ behind `http2` feature flag | ✅ — passes `hyper::Body` through, you map the stream | MIT/Apache-2.0 | **Primary recommendation.** Mature handler trait, websocket support, rustls-first. |
| **ideamans/hudsucker** fork | active | ✅ | ✅ + request/response correlation in `HttpContext` | ✅ | MIT/Apache-2.0 | Use if you need to correlate streaming responses back to the originating request payload (which you do, for placeholder mapping). Consider vendoring the correlation patch upstream. |
| **http-mitm-proxy** (`hatoo`) | recent, hyper-based | ✅ rcgen | partial (HTTP/1.1 ↔ HTTP/2 relay caveats documented by author) | raw bytes only — no SSE parser | MIT/Apache-2.0 | Lower-level than Hudsucker. Useful as a reference but Hudsucker covers the same ground with better ergonomics. |
| **mitmproxy_rs** | active, part of mitmproxy project | N/A — designed as Python bindings, not a standalone Rust MITM library | — | — | MIT | **Don't use as your core**, but **steal ideas from**: WireGuard mode, macOS Network Extension (`mitmproxy-macos`), Windows WinDivert, and Linux eBPF (`mitmproxy-linux-ebpf`) for transparent per-process interception (see §4). |
| **third-wheel** (`campbellC`) | abandoned (~2yrs no release) | ✅ | ❌ HTTP/1.1 only | ❌ | MIT | Skip. |
| **MitmRust** (`loocor`) | PRD-stage repo, no production users | claimed rustls + tower+hyper | claimed | claimed | unclear | Marketing > code. Skip. |

**Critical caveat the README doesn't tell you:** Hudsucker's HTTP/2 support requires the `http2` feature explicitly. Anthropic, OpenAI Responses API, and Cursor's `api2.cursor.sh` all negotiate HTTP/2 via ALPN. If you build with default features only, you will get downgrade-to-HTTP/1.1 errors and SSE will silently break.

**Required Cargo.toml:**

```toml
hudsucker = { version = "0.19", features = ["full", "http2", "rcgen-ca", "rustls-client"] }
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream"] }
eventsource-stream = "0.2"
regex = "1.11"
aho-corasick = "1.1"   # fast keyword pre-filtering (Trufflehog/Betterleaks trick)
```

---

## 2. How Each Agent Actually Routes Traffic in 2026

Critical findings (these contradict assumptions in the original pitch):

### Claude Code CLI (Node.js)
- ✅ Respects `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` (precedence: `https_proxy` > `HTTPS_PROXY` > `http_proxy` > `HTTP_PROXY`).
- ✅ Trusts system trust store + bundled Mozilla CA by default (`CLAUDE_CODE_CERT_STORE=bundled,system`).
- ✅ `NODE_EXTRA_CA_CERTS=/path/to/your-ca.pem` works. Also readable from `~/.claude/settings.json`'s `env` block (with anti-injection protection — only loaded from user settings, not project settings).
- Endpoints: `api.anthropic.com`, `claude.ai`, `platform.claude.com`, plus `downloads.claude.ai`, `storage.googleapis.com` (binary updates).
- ⚠️ Supports mTLS via `CLAUDE_CODE_CLIENT_CERT`/`CLAUDE_CODE_CLIENT_KEY` — your proxy must not break this.

### Claude Code VS Code extension
- ❌ **Broken**: Issue #15684 documents that the VS Code extension ignores both `~/.claude/settings.json` env vars and shell `HTTP_PROXY`. As of Dec 2025 / CLI v2.0.76. Don't promise IDE-extension support in v0.

### Claude Desktop / Cowork (Bun runtime, native build)
- ❌ Issue #24470: Cowork doesn't load macOS system certificates because the Bun-built binary doesn't honor `NODE_EXTRA_CA_CERTS`. Defer.
- Issue #45994: No proxy configuration in the Cowork UI; VM ignores host proxy settings.

### Cursor IDE (desktop)
- ⚠️ **Cert-pinning-like behavior on `api2.cursor.sh`.** Forum post (forum.cursor.com/t/83585) reports `Client TLS handshake failed. The client disconnected during the handshake.` even with a properly-trusted mitmproxy CA. This is the **most dangerous unknown** for the project.
- The IDE has model-name-based internal routing: if you set a custom endpoint but use a recognized model name (`claude-3.5-sonnet`), Cursor still routes to `api2.cursor.sh`. Documented workaround is to use a prefix (`cus-claude-...`) so the IDE treats it as a generic OpenAI endpoint.
- Cursor allows a custom OpenAI base URL + key in settings. This is your easiest path: have the user point Cursor at `http://localhost:PORT/v1` and intercept there. **No CA install required for this path**, but you only see traffic that Cursor decided to send to your "OpenAI-compatible" endpoint — not its proprietary completion/agent traffic.

### Cursor CLI (`agent`)
- ❌ Forum threads (#133724, #148868) confirm `HTTPS_PROXY` env vars **do not work**. No documented `--endpoint`/`--api-key` flag that points at a proxy as of late 2025 / early 2026 (#129424 is still an open feature request).
- For now, Cursor CLI is **not supportable** in v0 without help from Cursor.

### Codex CLI (Rust, reqwest)
- ⚠️ Issue #4242 (Sep 2025, still open): Codex CLI does **not consistently** honor `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` across all its `reqwest` clients (login, Ollama, main inference). A PR (#3455) adds `apply_env_proxy` but is unmerged as of the snapshot.
- ✅ However, Codex supports custom `[model_providers.foo]` blocks in `~/.codex/config.toml` with `base_url`, `wire_api`, `env_key`, etc. **This is the clean path**: tell users to set `model_provider = "secrets-proxy"` and `base_url = "http://localhost:PORT/v1"`.
- ✅ `CODEX_CA_CERTIFICATE` and `SSL_CERT_FILE` are honored for custom CAs.
- Built-in provider IDs (`openai`, `ollama`, `lmstudio`) are reserved — use any other id.

### Aider
- ✅ Easiest of all. `aider --openai-api-base http://localhost:PORT --openai-api-key fake-key` works. Uses LiteLLM under the hood.
- ✅ Or set `OPENAI_BASE_URL`/`ANTHROPIC_BASE_URL` env vars.
- No cert pinning. No proxy hassles.

### OpenCode (sst/opencode, Bun + AI SDK)
- ✅ `opencode.json` lets you define an arbitrary provider with `baseURL` pointing at your proxy. Uses `@ai-sdk/openai-compatible` and the Vercel AI SDK; standard fetch under the hood.
- ✅ Honors managed settings, environment variables, `.well-known/opencode` org config.
- Should work cleanly via the base-URL path (no CA install needed if you terminate locally on HTTP).

### Anthropic MCP transport — does it change anything?

Mostly **no** for v0: MCP servers are spawned as child processes (stdio or streamable HTTP). MCP traffic that stays local doesn't touch your proxy. *Outbound* HTTP calls made *by* MCP servers (web fetch, RAG retrievers) do — and they typically run as separate child processes with their own environments. Claude Code documentation explicitly warns that child MCP processes need their own `HTTPS_PROXY` / `NODE_EXTRA_CA_CERTS`, so plan for users to set those at the `claude mcp add` env block level.

### The cleanest v0 audience

**OpenAI-compatible-base-URL mode + native HTTPS MITM only where needed**, in this priority order:

1. **Aider** — works perfectly via `--openai-api-base`, zero CA install.
2. **OpenCode** — works perfectly via `opencode.json` provider, zero CA install.
3. **Codex CLI** — works via `[model_providers.x]`, optional CA for direct intercepts.
4. **Claude Code CLI** — full MITM with CA install; `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS`. Two-line setup.
5. *(Defer)* Cursor desktop, Cursor CLI, Claude Code VS Code extension, Claude Cowork.

This is a much smaller wedge than "all five agents," but it's the only one that ships in two weeks.

---

## 3. Secrets Detection for Live Request Inspection

### Comparison

| Tool | Language | Embed as Rust lib? | Detector count | Live-verification | License | FP rate on prose+code |
|---|---|---|---|---|---|---|
| **TruffleHog v3** (trufflesecurity) | Go | ❌ Must shell out (FFI possible but heavy) | 800+, with active API verification | ✅ unique selling point | AGPL-3.0 | Low *with* `--only-verified`; AGPL bars proprietary linking |
| **Gitleaks** (gitleaks/gitleaks) | Go, RE2 regex | ❌ binary; rules are reusable | ~160 rules in default `gitleaks.toml` | ❌ | MIT | Medium on prose; `generic-api-key` in particular is noisy |
| **Rusty Hog** (newrelic/rusty-hog) | Rust | ✅ It's a Rust crate, but a CLI suite — not a clean library API | ~25 patterns, JSON-configurable | ❌ | Apache-2.0 | Medium |
| **Betterleaks** (betterleaks/betterleaks) | Go | ❌ | Same engine class as Gitleaks + CEL filters + BPE-token rarity scoring + async `validate` hooks | ✅ via CEL `validate` blocks | source-available, check current license | Designed to be lower; new project; maintained by Gitleaks' original author, funded by Aikido |
| **detect-secrets** (Yelp) | Python | ❌ FFI is unpleasant | ~25 plugins, mostly entropy + base patterns | partial | Apache-2.0 | Entropy-heavy, high FP on minified code; mature and stable; baseline-file workflow doesn't fit live proxying well |

### Recommendation for v0

**Port the Gitleaks default ruleset to a Rust crate, with a layered detection pipeline:**

1. **Aho-Corasick pre-filter** on rule "keywords" (e.g. `sk-`, `xoxb-`, `AKIA`, `ghp_`, `gcp-`, `anthropic`) — this is what TruffleHog v3 itself does to skip 99% of regex evaluation. Use the `aho-corasick` crate (~10M dl/mo).
2. **`regex` crate** (RE2-compatible) for the precise patterns. Gitleaks' rules are already Go RE2, so they port one-for-one. Look-arounds are not used.
3. **Shannon entropy gate** on the captured group with per-rule thresholds (Rusty Hog already uses this pattern).
4. **Stopword/identifier proximity** check (like Gitleaks 8.8+ `stopwords` and Betterleaks `filter` CEL): if the surrounding 60 chars contain `example`, `test`, `dummy`, `YOUR_`, `CHANGEME`, skip.
5. *(Optional v0.2)* Active verification for `sk-ant-`, `sk-`, `AKIA`, `ghp_`, `xoxb-` — but **off by default**, because firing requests to AWS STS / GitHub API / Slack from a privacy proxy is the worst look imaginable. Make it an opt-in `--verify` flag.

### High-confidence patterns to ship in v0 (curated)

- **Anthropic**: `sk-ant-api03-[A-Za-z0-9_-]{93}` and `sk-ant-oat01-[A-Za-z0-9_-]{93}`
- **OpenAI**: `sk-(proj-)?[A-Za-z0-9_-]{40,}` (note: OpenAI rotated to project-scoped keys; both legacy `sk-` and `sk-proj-` are in the wild)
- **AWS**: access key `AKIA[0-9A-Z]{16}` or `ASIA[0-9A-Z]{16}`, plus secret key with 40-char base64-ish
- **GCP**: service-account JSON detection by JSON shape (`"type": "service_account"`)
- **GitHub**: `ghp_[A-Za-z0-9]{36}`, `gho_…`, `ghs_…`, `github_pat_\w{82}`
- **Stripe**: `sk_live_[A-Za-z0-9]{24,}`, `rk_live_…`
- **Slack**: `xox[baprs]-[A-Za-z0-9-]{10,48}`
- **JWT**: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- **PEM**: `-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----`
- **Generic high-entropy** (off by default): >40 chars, entropy > 4.5, near `key|token|secret|password|api`.

### FP rate on natural-language + code (the actual production case)

The 2026 LLM-Redactor paper (arXiv 2604.12064) found that **typed-placeholder approaches reduce token count by ~12%** while preserving ~85% of model response quality in cross-family LLM-as-judge eval, but only when the underlying detector has been tuned for prose. With raw Gitleaks rules on mixed prompt content, expect:

- ~0% FP on prefix-typed secrets (`sk-ant-…`, `AKIA…`, `xoxb-…`) — these are unambiguous.
- 5–20% FP on `generic-api-key`-style rules — recommend **off by default**.
- High FP on bare hex/base64 of length 32–64 (UUIDs, hashes, content digests). Entropy + identifier-proximity gate is mandatory.

The Anthropic key prefix `sk-ant-` is **the cleanest case** in the entire secret-scanning ecosystem; if your demo is "redact your Anthropic key before sending it to Anthropic," you'll get 0% FPs and 100% TPs.

---

## 4. Local CA / Cert Trust UX

### What kills adoption

A security-conscious developer is asked to install a private root CA that can decrypt all their TLS. This is correctly terrifying. Three failure modes that have killed prior attempts:

1. **Opaque installer that just runs `security add-trusted-cert`** — no consent, no explanation, no easy uninstall. Hard "no" from the audience you're targeting.
2. **CA + private key in the same binary distribution** — if your CA private key ships in the package, *anyone* with your binary can sign certs for any site. Must be **generated locally on first run**, stored in OS keychain (macOS Keychain, GNOME Keyring / `secret-service`).
3. **Permanent, system-wide trust** with no scoping. mitmproxy installs to system trust store; Charles/Proxyman do the same. Devs hate this.

### Best-in-class approaches to copy

- **mitmproxy's `mitmweb` flow**: starts the proxy first, prints `Open http://mitm.it to install the CA cert`. Browser-based install. Each platform has its own button + instructions. Cert is generated per-machine on first run.
- **Proxyman**: GUI walkthrough with screenshots for macOS/iOS/Android. Highest-rated UX in this space.
- **Caddy's local CA approach**: `caddy trust` is one command, prompts for `sudo`, and exposes `caddy untrust` symmetrically. Steal this verbatim.

### What you should actually do in v0

**Tier 1 (zero CA install) for Aider, OpenCode, Codex CLI:** Run as a **plain HTTP server on localhost** that speaks the OpenAI/Anthropic wire protocol, and have the agent point its `base_url` at `http://127.0.0.1:8788/v1` or `/anthropic`. Re-issue the outbound request over HTTPS to the real upstream. **No MITM, no CA, no kernel hooks.** This covers ~80% of your value with ~0% of the trust friction.

**Tier 2 (CA install) for Claude Code CLI:** Generate the CA on first run, store the key in OS keychain (not on disk), provide:

- `secretsproxy trust` → installs CA to system store, requires sudo, prints exactly which keychain it's writing to.
- `secretsproxy untrust` → removes it, also requires sudo.
- `secretsproxy doctor` → verifies the install, prints SHA256 of the CA cert so users can verify against the installer.

Use `NODE_EXTRA_CA_CERTS` env var **per process** (not system trust store) when possible. This is huge: you can ship a `secretsproxy run -- claude` wrapper that sets `NODE_EXTRA_CA_CERTS=/path/to/our-ca.pem` and `HTTPS_PROXY=http://127.0.0.1:8788` for the child process only. **No system-wide cert install needed for Claude Code.**

**Tier 3 (no CA, no env var, transparent):** `mitmproxy_rs` has done the hard work here. On macOS, `mitmproxy-macos` uses a Network Extension to transparently proxy traffic by process name or PID; on Linux, `mitmproxy-linux-ebpf` uses eBPF to do the same kernel-side. This is **the right long-term architecture** because it cleanly addresses the Bun-runtime / cert-pinning problem (Claude Cowork, Cursor IDE) by intercepting the syscalls rather than the TLS handshake. **But it's enormously more work**: code signing, notarization for the macOS Network Extension; CAP_BPF / root on Linux. Defer to v0.3 once you have users.

**LD_PRELOAD tricks:** Don't bother. Doesn't work on macOS (SIP), brittle on Linux, won't work for statically-linked Go (Codex) or Bun binaries. eBPF is the cleaner version of the same idea.

### Recommended install copy (what the curl|sh actually prints)

```
secretsproxy will:
  • create a local Certificate Authority on this machine (stored in macOS Keychain)
  • install it into your system trust store (requires sudo)
  • the private key never leaves Keychain and is unique to this install
  • you can revoke it any time with: secretsproxy untrust
  • SHA256 of this CA: ab12...ef90
Proceed? [y/N]
```

---

## 5. Competitive Landscape & The Actual Gap

| Tool | OSS / commercial | Local-first / cloud | Secrets / PII / general | Audience |
|---|---|---|---|---|
| **LiteLLM** | OSS (MIT) | self-host | general routing; PII via **Presidio plugin** | Backend devs / platform |
| **Portkey** | OSS gateway (Apache-2.0 since Mar 2026) + managed | both | guardrails incl. PII redaction, jailbreak; **not secrets-focused** | Production AI apps |
| **Helicone AI Gateway** | OSS (Rust) | both | observability + routing, basic guardrails | Production AI apps |
| **Cloudflare AI Gateway** | commercial | cloud only | observability, caching | App teams on CF |
| **Kong AI Gateway** | commercial (OSS Kong core) | self-host | enterprise routing | Enterprise platform |
| **Langfuse** | OSS | both | observability; proxy mode is logging-first | LLM app dev |
| **Pomerium / Pomerium AI** | OSS + commercial | both | identity-aware access; not content redaction | Enterprise security |
| **Cape Privacy** | commercial | confidential compute | TEE/MPC for inference | Enterprise data |
| **Lakera Guard** | commercial | cloud API + on-prem | prompt-injection, PII; **content safety, not secrets** | Production AI |
| **Nightfall AI** | commercial | cloud | DLP including AI use case; PII-led | Enterprise |
| **Skyflow LLM Vault** | commercial | cloud (managed) | PII tokenization for LLMs | Regulated industries |
| **Private AI** | commercial | self-host container | PII NER for LLM prompts | Enterprise |
| **Microsoft Presidio** | OSS (MIT) | library / self-host | PII NER + regex; **integrates with LiteLLM for placeholder restoration via `replace` op** | Devs build-it-yourself |
| **PII Shield (MS announcement, Azure)** | preview | self-host | PII proxy for LLMs | Enterprise |
| **Gravitee AI** | commercial | self-host | API gateway w/ PII filter | Enterprise |
| **prompt-sentinel** (Python pkg) | OSS | library | **Secrets** redaction with token mapping | Python apps |
| **LeakGuard** (Chrome ext, MVP) | early OSS | local | Secrets in browser-based LLM use | Individual devs |
| **Formal.ai blog/Connectors** | commercial | self-host | Same idea: inject secrets after agent send | Enterprise data egress |

### The specific gap a Rust local-first secrets-focused dev tool fills

1. **Local-first** — every secrets-aware option above is either a library you have to assemble (Presidio, prompt-sentinel) or a cloud/enterprise platform requiring SSO, contracts, and a team. Nothing is a `brew install` solo-developer experience.
2. **Secrets-focused, not PII-focused** — Presidio, Skyflow, Private AI, Lakera, Nightfall all lead with PII (names, addresses, SSNs). For an individual developer pasting code at a coding agent, the real risk is `AWS_SECRET_ACCESS_KEY`, not names. *Nobody* is making this the headline.
3. **Coding-agent-shaped, not API-shaped** — LiteLLM/Portkey/Helicone assume *your app* is calling LLMs. Your tool assumes *your IDE* is calling LLMs. Different config surface (env vars + base URLs + sometimes CA), different installation story (per-laptop, not per-cluster).
4. **Rust binary, not Docker compose** — every OSS gateway here is Python or TypeScript with non-trivial install. The wedge is "single static binary, `brew install`, points at localhost, done."

### Honest caveats

- **prompt-sentinel** (Python, by George Kour) already does secrets redaction with reversible placeholders — same core idea but library-only, not a proxy.
- **LiteLLM + Presidio** already supports a `replace` operation that puts the original value back in the response, again with the same primitive (just for PII).
- **Formal.ai** has shipped a customer-facing version of this same pattern (their Connectors product), enterprise-priced.

Your wedge is therefore **distribution and form factor**, not novelty. Frame the launch accordingly.

---

## 6. SSE Streaming in Rust — Concrete Wiring

Both Anthropic (`/v1/messages` with `stream: true`) and OpenAI (`/v1/chat/completions`, `/v1/responses` with `stream: true`) emit SSE. You need to: parse → mutate `delta` content text → reassemble → send to client, while maintaining the placeholder reverse-map for the duration of the stream.

### Library choices, ranked

- **`eventsource-stream`** (Julian Popescu, ~270K dl/mo, MIT/Apache) — **use this as the parser**. It's an adapter that turns any `Stream<Item=Result<Bytes>>` (which is what `reqwest::Response::bytes_stream()` and `hyper::Body` both produce) into a `Stream<Item=Result<Event>>` where `Event { event, data, id, retry }`. Zero-allocation hot path. Works with Hudsucker because Hudsucker hands you the raw body as a `hyper::Body`. This is the foundation block.
- **`reqwest-eventsource`** — wrapper around `reqwest` for clients that originate SSE connections. Convenient for the *outbound* leg if you build the proxy as "reqwest re-issues the upstream request" rather than "Hudsucker tunnels it." For Mode A (plain HTTP localhost), this is what you want. Built on top of `eventsource-stream`.
- **`eventsource-client`** v0.17 (LaunchDarkly, hyper v1, MIT) — more full-featured (auto-reconnect with backoff, hyper-rustls integration, pluggable transport). Heavier than needed for a relay; use only if you decide the proxy should itself maintain long-lived SSE clients (e.g., for caching scenarios).
- **`async-sse`** (http-rs ecosystem) — a parser/encoder pair for SSE. Spec-correct and minimal, but development cadence has been slower than `eventsource-stream`'s and ecosystem integration is more limited. Defensible alternative if you want pure-trait separation between parsing and async runtime, but no compelling advantage for this use case.

### Pattern (pseudo-Rust)

```rust
async fn handle_response(ctx: &HttpContext, resp: Response<Body>) -> Response<Body> {
    // Only mutate SSE streams
    if !resp.headers().get(CONTENT_TYPE)
        .is_some_and(|v| v.to_str().unwrap_or("").starts_with("text/event-stream")) {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let placeholder_map = ctx.extensions.get::<PlaceholderMap>().cloned().unwrap_or_default();
    let event_stream = body
        .map_err(io::Error::other)
        .eventsource()
        .map(move |ev| {
            let mut ev = ev?;
            // Anthropic: data is JSON {"type":"content_block_delta","delta":{"type":"text_delta","text":"..."}}
            // OpenAI:    data is JSON {"choices":[{"delta":{"content":"..."}}]}
            ev.data = reverse_placeholders(&ev.data, &placeholder_map);
            Ok::<_, io::Error>(format!("event: {}\ndata: {}\n\n", ev.event, ev.data))
        });
    let new_body = Body::wrap_stream(event_stream.map_ok(Bytes::from));
    Response::from_parts(parts, new_body)
}
```

### Critical streaming gotchas

1. **Placeholders can be split across SSE chunks.** If you put `«SECRET_001»` in the input and the model streams it back as `«SECRET`/`_001»` in two separate `text_delta` events, naïve replacement fails. Buffer until you see a delimiter (the closing `»`) or until N bytes accumulate. The arxiv 2604.12064 paper documents this exact failure mode.
2. **JSON-in-SSE** — Anthropic `content_block_delta` carries the actual text inside a JSON field, so you must parse the data line as JSON, mutate the string, re-serialize, and re-emit. Don't try regex substitution on raw SSE bytes.
3. **HTTP/2 streaming + Hudsucker** — verified working with `features = ["http2"]`; without it you'll get `h2: GOAWAY` errors from Anthropic mid-stream.
4. **Tool-call streaming** — OpenAI tool calls and Anthropic `tool_use` blocks are also streamed. Secrets can appear inside tool argument JSON — apply redaction reversal there too.

---

## 7. Placeholder Token Strategy

This is the most under-researched area of the project; here's what's known and what to do.

### Prior art

- **arxiv 2604.12064 ("LLM-Redactor")**, 2026, 8-technique benchmark. Option B (NER + typed placeholder, format `<TYPE_N>`) was the best practical tradeoff: ~12% token *reduction* (placeholders are shorter than the values they replace) and 85% LLM-as-judge preference vs. the unredacted baseline. Critically, typed placeholders preserve semantics — `<EMAIL_1>` tells the model "this is an email" so it can still reason about it.
- **prompt-sentinel** (George Kour, OSS Python): uses opaque tokens, restores after response.
- **LeakGuard** (Chrome ext MVP, on OpenAI forum): uses `[PWM_1]` style — square brackets, all-caps acronym, integer counter, deterministic mapping (same secret → same placeholder within a session).
- **LiteLLM + Presidio**: uses `<PERSON>`, `<EMAIL_ADDRESS>` style placeholders with reversible `replace` operation that swaps back in the response.
- **LogRocket guide**: `entityMap` stored in request context, deterministic placeholders, explicit `destroy()` after rehydration.

### What you actually want (LLM behavior, not just programmatic restoration)

The placeholder must satisfy:

- **(a) preserved verbatim** — the model must not paraphrase or modify it
- **(b) recognizable on the response side** — unambiguous regex match
- **(c) doesn't trigger safety filters** — looks neutral, not like an attempted jailbreak
- **(d) tokenizes efficiently** — single or few BPE tokens, ideally
- **(e) signals semantic type to the model** — so `Use the AWS key sk-foo to call S3` → after redaction still says `Use the AWS key «SECRET_AWS_KEY_001» to call S3`, and the model still understands the request.

### Empirical observations from public LLM behavior

- `[REDACTED]` and `***` are **bad**: models often "helpfully" expand them ("Please provide your actual AWS key here") and lose the placeholder. Verified anecdotally across both Sonnet 4 and GPT-class models.
- `{{VAR_NAME}}` (Mustache-style) is **bad**: triggers template-completion behavior; the model often replaces it with an example value.
- `<EMAIL_1>` (Presidio default) is **OK** but Anthropic's safety system is occasionally suspicious of HTML-tag-looking content.
- `__SECRET_AWS_KEY_001__` is **good** for preservation but eats 6–8 BPE tokens per occurrence.
- `«SECRET_AWS_KEY_001»` (French guillemets) is **best in informal testing**: rare in training data so the model treats it as an opaque identifier; tokenizes as 4–6 tokens; visually obvious to the redaction-reversal regex; doesn't look like a jailbreak attempt.

### Recommended format (v0)

```
«SECRET_<TYPE>_<N>»
```

where `<TYPE>` is one of `AWS_KEY`, `AWS_SECRET`, `ANTHROPIC_KEY`, `OPENAI_KEY`, `GITHUB_PAT`, `STRIPE_KEY`, `SLACK_TOKEN`, `JWT`, `PEM_KEY`, `GENERIC`, and `<N>` is a session-stable counter.

**Counter scope:** per-session/per-process (not per-request), so identical secrets within a conversation collapse to the same placeholder. Document and test this — it materially changes how multi-turn conversations work.

### A research item worth its own day

**Run an empirical eval** before launch (this is also a great blog post): take 50 realistic coding-agent prompts with embedded secrets, generate variants with 6 placeholder formats, measure (i) verbatim preservation rate by the target LLMs, (ii) refusal/safety trigger rate, (iii) BPE token cost. **Validate that `«SECRET_X_N»` beats `<EMAIL_1>` and `[PWM_1]` empirically** — don't trust the qualitative report above. This is also riskiest-unknown #2 (§9).

---

## 8. HN / Reddit Launch Trajectories (2024–2026)

Honest disclosure: this is the weakest-sourced section of the report. Direct, granular "Show HN" trajectory data for the *specific* niche (local dev privacy proxies for AI agents) is sparse in public sources, and I'm flagging it explicitly rather than fabricating precise numbers. What follows is pattern analysis from adjacent launches and the structural mechanics of HN, not validated per-launch metrics.

### What works on Show HN for dev-security tools (pattern analysis)

- **Single static binary, one-line install, no signup.** Tools that require an account before showing value rarely break 100 points.
- **A live, public scary demo.** "I MITMd Claude Code and watched it send my .env" — concrete + alarming. Formal.ai's blog post is essentially this, and it spread widely in security Twitter.
- **A specific, technical headline.** "Show HN: Rust local proxy that redacts API keys before Claude Code sends them" beats "Show HN: Privacy for AI coding."
- **Time it for a Tuesday or Wednesday morning Pacific.** Avoid the OpenAI/Anthropic launch news cycle.
- **GitHub repo with security-conscious README:** threat model, what the tool can/can't see, where the CA private key lives, how to uninstall.

### Realistic week-1 expectations (priors, not predictions)

For a niche Rust developer-security tool on Show HN, public data suggests:

- **Realistic median**: 50–150 points, 300–800 GitHub stars in week 1 if it hits front page.
- **Upside (top quartile of similar launches)**: 300–500 points, 2K–4K stars. Requires either celebrity boost, a contemporaneous AI security incident, or genuine novelty.
- **Top decile (rare)**: 1K+ points, 10K+ stars. Don't model your business around this.

A useful real datapoint: GitGuardian's "29M leaked secrets in 2025" report (HelpNetSecurity, April 2026) — *34% YoY increase in public-repo secret leakage, attributed in part to AI-assisted coding*. That's the macro story your launch is riding. Reference it in the Show HN post.

### Where this specific concept is likely to underperform

1. **HN is allergic to "install a root CA"** in ways that don't apply to general developers. Expect at least 30% of comments to push back on the trust model. **Pre-empt this in the README** with a security section.
2. **Adjacency to Formal.ai's blog post** — readers will compare. Beat it with: lower friction (one binary vs mitmproxy + addon), broader agent coverage, and zero-config-for-OpenAI-compatible-mode (Aider/OpenCode/Codex).
3. **r/ClaudeAI and r/cursor are more receptive than r/programming** for actually picking it up; r/devops will engage more on the technical mechanics. r/netsec will dissect the threat model — make sure that holds up.

### What I cannot verify

Specific star/upvote counts for prior near-neighbors (e.g., LeakGuard MVP, prompt-sentinel, PII Shield blog post) — they exist as forum posts and blog announcements but consistent week-1 traction data did not surface in available sources. **Treat the numbers above as structural priors, not empirical predictions.**

---

## 9. Riskiest Unknowns — Validate Week 1

If any one of these doesn't work, you should change course before writing real code. Spend the entire first week on this.

### Risk 1 (highest): Cert pinning / non-Node runtimes break MITM

**Symptoms in evidence:** Cursor IDE shows `Client TLS handshake failed` even with a properly trusted mitmproxy CA (cursor forum #83585). Claude Cowork (Bun runtime) doesn't load macOS system certs (#24470). Cursor CLI doesn't honor `HTTPS_PROXY` (#133724, #148868). Codex CLI's proxy support is inconsistent across its internal `reqwest` clients (#4242).

**Validate by:** building a hello-world Hudsucker proxy with HTTP/2 + rustls + rcgen CA, install the cert into system trust + into `NODE_EXTRA_CA_CERTS`, and confirm you can successfully MITM:

- `claude` CLI doing a streaming `/v1/messages` call → must see the prompt, see the SSE response.
- `codex` CLI doing a streaming `/v1/responses` call with `[model_providers.proxy]` pointed at you → same.
- `aider --openai-api-base http://localhost:8788` doing a streaming completion → same.
- `opencode` with custom provider pointing at you → same.

**Kill criteria:** If you cannot MITM Claude Code CLI streaming end-to-end in two days, the project shape changes. Either pivot to OpenAI-compatible-base-URL-only mode (no MITM, no CA) which still works for Aider/OpenCode/Codex, or commit to the eBPF/Network Extension path which is a v0.5 timeline.

### Risk 2 (high): LLMs don't preserve your placeholder tokens

**Symptoms in evidence:** LLM-Redactor paper shows non-trivial quality variation by placeholder format; community reports (LeakGuard, OpenAI forum) of models paraphrasing placeholders.

**Validate by:** running the 6-format × 50-prompt empirical eval described in §7 against Sonnet 4, Opus 4, GPT-5.4. Measure verbatim-preservation rate per format. **Threshold: ≥98% on `sk-`/`AKIA`/`xoxb-` prefix-typed secrets.** Below that, your placeholder-restoration breaks in production.

**Kill criteria:** If no format gets above 95% preservation across all three model families, the entire reversible-redaction concept is fragile and you need either (a) instruction prefix injection ("Preserve any token of the form «…» exactly") or (b) a different architecture (e.g., never round-trip the secret; have the user write `${MY_AWS_KEY}` and substitute at the proxy on the outbound side only, never on the response side).

### Risk 3 (medium): Anthropic / OpenAI rotate API or wire format and break you

**Symptoms in evidence:** OpenAI added `/v1/responses` alongside `/v1/chat/completions` in 2025 with different SSE event shapes. Anthropic's MCP transport added a streamable HTTP variant. Cursor's `Connect-Protocol-Version: 1` and Connect-style framing on `api2.cursor.sh` is non-standard. Codex CLI uses both `chat/completions` and `responses` wire APIs depending on `wire_api` config.

**Validate by:** writing a passthrough mode (just relay, no redaction) and running it for a week against each agent's normal workflow. Log every distinct (endpoint, method, content-type) tuple. Confirm none of them surprise you with binary protocols (gRPC, Connect-protobuf, etc.).

**Kill criteria:** If >20% of agent traffic is in a non-SSE-non-JSON wire format you can't trivially parse, scope-cut to just the JSON/SSE happy path and document that proprietary completion traffic (Cursor's `api2.cursor.sh`) is out of scope.

---

## Concrete v0 Build Sequence (4 weeks, solo dev)

**Week 1 — validate the three risks above.** Throwaway code. End of week, you know whether to proceed and on which agent surface.

**Week 2 — core proxy.**

- Hudsucker 0.19 + rustls + rcgen + HTTP/2.
- Plain-HTTP "OpenAI-compatible" mode on `http://127.0.0.1:8788/v1` and `http://127.0.0.1:8788/anthropic`. Re-issues outbound over HTTPS via reqwest.
- SSE relay using `eventsource-stream` (and `reqwest-eventsource` on the outbound leg if useful).
- Placeholder map per-session in `DashMap<SessionId, BiMap<Secret, Placeholder>>` with TTL.
- Gitleaks-rule port for 12 hand-curated patterns (Anthropic, OpenAI, AWS, GCP, GitHub, Stripe, Slack, JWT, PEM, plus three generics with high-entropy gates).

**Week 3 — MITM path + CA UX.**

- `secretsproxy trust` / `untrust` / `doctor` commands (copy Caddy's UX).
- Per-process wrapper: `secretsproxy run -- claude` sets `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS` for the child only.
- `cargo dist` for cross-platform single-binary releases; Homebrew tap.
- Logging UI: terminal TUI (ratatui) showing redactions as they happen, with a "what was redacted" panel that requires keystroke to reveal the originals (so a shoulder-surf doesn't expose them).

**Week 4 — launch prep.**

- Threat model in README. Audit-friendly section: where the CA key lives, what data the proxy can see, what it can't see, network egress claims (zero telemetry, prove it with a packet capture).
- Live demo recording: "watch my Claude Code session leak `.env` — then watch it not leak."
- Public placeholder-format eval results as a blog post.
- Show HN draft: title `Show HN: Local Rust proxy that redacts API keys from Claude Code / Codex / Aider before they hit Anthropic/OpenAI`. Repo, demo gif, threat model, single curl install.

---

## Where the Pitch's Assumptions Look Wrong

1. **"Intercepts traffic from Claude Code, Cursor, Codex, Aider, OpenCode"** — Cursor is mostly not supportable in v0 (cert pinning + IDE-only routing). Cut it from the scope or scope it to "Cursor with custom OpenAI endpoint" only. Codex CLI's proxy support is also inconsistent — use the `[model_providers]` path instead.
2. **"Local CA + MITM"** as the architecture — overkill for 4 of the 5 agents. Aider, OpenCode, Codex CLI, and even Claude Code CLI all work better with **base-URL redirection + per-process env injection**. The MITM with CA install is the *fallback*, not the default. This dramatically improves your install conversion.
3. **"Secrets-only" framing** — fine as a wedge, but understand prompt-sentinel and LiteLLM+Presidio's `replace` mode have shipped roughly this. Your differentiation is the **distribution, not the redaction logic**.
4. **"Distributed free via HN/Reddit"** — fine, but the threat model section of your README is going to do more work than the launch post. Plan accordingly.
5. **"Streaming SSE response support (critical for LLM responses)"** — yes, but the harder problem is placeholder tokens that split across SSE chunks (§6 gotcha #1), not the SSE parsing itself.
6. **Anthropic's MCP transport changing things** — minimal impact for v0; MCP traffic is local. The bigger Anthropic-side surprise is the Bun-built Cowork desktop ignoring `NODE_EXTRA_CA_CERTS`, which kills MITM for that specific surface.

---

## Final Architectural Recommendation

Build a **dual-mode** proxy:

- **Mode A (default, friction-free):** localhost HTTP server on port 8788 exposing OpenAI-shaped `/v1/*` and Anthropic-shaped `/v1/messages` endpoints. Agents are configured to point their base URLs at it. No CA, no MITM. Covers Aider, OpenCode, Codex CLI, plus Claude Code via `ANTHROPIC_BASE_URL`.
- **Mode B (advanced):** Hudsucker-based HTTPS MITM for users who want transparent interception. Requires CA install, opt-in. Eventually replaced by mitmproxy_rs-style eBPF / Network Extension transparent capture as v0.5.

Both modes share the same redaction core (regex pipeline → placeholder map → SSE-aware reverse) so you don't pay double for the path divergence.

This is the architecture that survives Cursor's cert pinning, Bun's cert quirks, Codex CLI's inconsistent proxy support, and the security-conscious user who refuses to install a root CA. Ship Mode A first, in two weeks. Mode B is the post-HN-launch follow-up.
