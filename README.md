# aichu

Local Rust proxy that redacts secrets from prompts sent to AI coding agents (Claude Code, Codex, Aider, OpenCode), then restores them in responses.

> **Status:** Week 1 — risk validation. Everything in `experiments/` is **throwaway code**. Production crates do not exist yet and won't until the three Week 1 risks have been validated or killed.

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

## Running an experiment

```bash
cd experiments/e01-hudsucker-mitm
cargo run --release
```

Each experiment is its own binary crate. Workspace-level `cargo build` builds everything.

> **Note on duplicate hyper versions in `Cargo.lock`.** Hudsucker 0.19 (used by `e01`) is built on hyper 0.14, while axum 0.7 (used by `e02`) is built on hyper 1.x. They never share types — each experiment is a separate binary — so the duplicate is intentional. It will collapse when the production layout consolidates around a single stack.

## Project structure

```
aichu/
├── Cargo.toml              # workspace root
├── rust-toolchain.toml     # pinned stable toolchain
├── CLAUDE.md               # 12-rule project guidelines
├── docs/
│   └── build-plan.md       # full architectural plan
└── experiments/            # week-1 throwaway validation crates
    ├── e01-hudsucker-mitm/
    ├── e02-base-url-relay/
    └── e03-placeholder-eval/
```

## After Week 1

Once risks are validated (or killed), the production layout will look roughly like:

- `crates/proxy-core/`   — redaction pipeline, placeholder map (shared)
- `crates/proxy-server/` — Mode A: localhost HTTP server, base-URL relay
- `crates/proxy-mitm/`   — Mode B: Hudsucker MITM (if Risk 1 passes)
- `crates/cli/`          — `aichu run | trust | untrust | doctor`

Any experiment whose risk was killed disappears from the architecture.

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

## License

Dual-licensed under MIT or Apache 2.0, at your option.
