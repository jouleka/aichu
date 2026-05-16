# Experiments

Throwaway validation crates for the three Week 1 risks identified in [`../docs/build-plan.md`](../docs/build-plan.md) §9.

**Rule:** code in here is allowed to be ugly. It is not the production codebase. When an experiment delivers its verdict, update its README with the result and move on. Production code lands in `crates/` (which does not exist yet — by design).

## Experiments

| Crate | Risk under test | Status |
|---|---|---|
| [`e01-hudsucker-mitm`](e01-hudsucker-mitm) | Can we MITM real coding agents? | ✅ validated for CLI scope — graduated to [`crates/proxy-mitm`](../crates/proxy-mitm) |
| [`e02-base-url-relay`](e02-base-url-relay) | Does no-MITM base-URL relay work? | not started |
| [`e03-placeholder-eval`](e03-placeholder-eval) | Do LLMs preserve placeholder tokens? | not started |

## Conventions

- Each experiment is a separate binary crate, member of the workspace at the repo root.
- Each has its own README declaring: **goal**, **kill criteria**, **how to run**, and (once done) **result**.
- Real API keys for upstream services are read from `.env` (gitignored) or shell env. **Never** commit credentials, even for testing.
- Log output goes to stdout via `tracing-subscriber`. No log files.
- When an experiment is complete, do not delete it — it documents the validation work for future contributors.
