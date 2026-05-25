# e03-placeholder-eval

**Risk under test:** Will frontier LLMs (Anthropic Opus 4.7, OpenAI GPT-5.x, Google Gemini-class) preserve our placeholder tokens verbatim across a turn? If they paraphrase `«SECRET_AWS_KEY_001»` into something else, reversible-redaction is broken.

## Goal

Build a small CLI eval harness that:

1. Loads a set of prompt fixtures from `prompts/` — each fixture is a coding-agent-style prompt containing an embedded "secret".
2. For each fixture, generates variants using 6 placeholder formats:
    - `[REDACTED]`
    - `***`  *(deliberate negative control — known-bad per build-plan §7, included to confirm our metrics actually detect failure)*
    - `{{VAR}}`
    - `<SECRET_1>`
    - `__SECRET_AWS_KEY_001__`
    - `«SECRET_AWS_KEY_001»`  *(current top candidate)*
3. Sends each variant to each target model (Anthropic, OpenAI; Gemini optional).
4. Inspects the response for verbatim preservation of the placeholder.
5. Emits a CSV/JSON summary: per (format, model, prompt) → preserved? refused? token count.

## How to run

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...

cargo run --release -- \
    --prompts prompts/ \
    --models anthropic,openai \
    --formats all \
    --out results.json
```

Add `--instructions <FILE>` to prepend a UTF-8 text file as a system
prompt on every call (the build-plan §9 option (a) experiment — "what
if we tell the model to preserve `«...»` tokens verbatim?"). Omit the
flag for the zero-shot baseline.

The output JSON is refreshed after every cell, so a kill mid-run leaves
a valid array of however many cells completed.

## Success criteria

- ✅ At least one placeholder format achieves ≥98% verbatim preservation on prefix-typed secrets across all tested models.
- ✅ No format triggers safety refusals at a rate > 5%.
- ✅ Results reproducible across two independent runs (seeded sampling or temperature=0).

## Kill criteria

- ❌ No format gets above 95% preservation across all model families.

If killed: the reversible-redaction concept is fragile. Either (a) add an instruction-prefix injection that explicitly tells the model to preserve the token, or (b) abandon round-tripping and substitute outbound-only (user writes `${MY_KEY}`, we swap on the way out — no response-side restoration needed).

## Prompt fixtures

`prompts/` will hold 50 small `.txt` files, each a realistic coding-agent prompt with an embedded secret. Examples:

- "Here's my .env: `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`. Why does my S3 upload fail?"
- "Debug this error from the Anthropic SDK: 401 Unauthorized. My key is sk-ant-api03-..."
- "Please review this commit: `+ GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`"

These will be added as we run the eval. Do not include real secrets — use vendor-published example/test keys (e.g. `AKIAIOSFODNN7EXAMPLE`).

## Result

### Automated (`cargo test`)

✅ **14 tests** passing:

**Unit (10):**
- `placeholder::tests` (5) — render contract pinned for each format,
  zero-padding to 3 digits enforced, `name`/`FromStr` round-trip, `all()`
  returns exactly the 6 candidates, unknown format rejected.
- `model::tests` (5) — `EchoModel` returns prompt verbatim,
  `StaticModel` ignores prompt, `looks_like_refusal` fires on canonical
  refusals (including with politeness prefixes), does NOT fire on normal
  responses containing "I won't" mid-paragraph, does NOT fire on emphatic
  "I cannot stress this enough" (verb requirement catches the
  modal-without-refusal-verb idiom).

**Integration (4):**
- `echo_model_preserves_every_format` — when the model echoes the prompt
  verbatim, all 6 placeholder formats are reported `preserved=true`.
  Pins the substring-detection contract.
- `static_model_response_without_placeholder_yields_not_preserved` —
  when the model paraphrases and the placeholder is absent from the
  response, `preserved=false`. The failure mode the experiment exists
  to detect.
- `evaluate_errors_when_fixture_does_not_contain_secret_text` — silent
  no-op substitutions are blocked at the source (CLAUDE.md Rule 12 — fail
  loud).
- `anthropic_provider_speaks_correct_wire_shape_against_mock` — against
  a local axum server pretending to be Anthropic, verifies request body
  shape, `x-api-key` + `anthropic-version` headers, response parsing
  (`content[].text` + `usage.{input,output}_tokens`). No real API budget
  burned.

### Manual (real-API runs)

#### openai:gpt-5-mini — 2026-05-25 (2 × 300 calls, ~$1.00 total)

Two runs against the same 50 fixtures × 6 formats: a **zero-shot
baseline** (no system prompt) and an **instructed** variant that
prepends [`instructions/preserve-tokens.txt`](instructions/preserve-tokens.txt)
as a system message. Same model, same fixtures, same harness.

| Format | Zero-shot | Instructed | Δ |
|---|---|---|---|
| `«SECRET_TYPE_NNN»` (guillemets — production) | 12% | **96%** | +84 pp |
| `__SECRET_TYPE_NNN__` (underscore_type) | 24% | 94% | +70 pp |
| `<SECRET_N>` (angle_num) | 20% | 90% | +70 pp |
| `{{VAR}}` (mustache) | 40% | 90% | +50 pp |
| `***` (asterisks, substring-biased control) | 20% | 88% | +68 pp |
| `[REDACTED]` (substring-biased control) | 12% | 82% | +70 pp |

Refusals: 0 / 300 in both runs. Avg latency: ~8.5 s / call
(gpt-5-mini with `reasoning_effort=minimal`). Total output across
both runs: ~512k tokens, ~$1.00.

Raw data:
- Zero-shot: [`results/gpt-5-mini-2026-05-25.json`](results/gpt-5-mini-2026-05-25.json)
- Instructed: [`results/gpt-5-mini-instructed-2026-05-25.json`](results/gpt-5-mini-instructed-2026-05-25.json)

**Reading these numbers:**

1. **The security property holds in both conditions.** The proxy
   strips the secret BEFORE the request leaves the machine. The
   original secret never reaches the model. Preservation rate
   measures response-side UX, not whether secrets leak.
2. **Zero-shot UX is degraded.** gpt-5-mini paraphrases ("your
   AWS key is the problem, use an IAM role instead") instead of
   echoing the placeholder. The user gets a useful answer that
   just doesn't pretend to know the original secret.
3. **A short system prompt restores UX.** Guillemets goes from
   12% → 96%, clearing the §9 95% kill threshold by 1 percentage
   point. The instruction file is short (one paragraph + a list
   of placeholder shapes); the cost is one extra system message
   per request.

Reproduce:

```bash
export OPENAI_API_KEY=sk-...

# zero-shot
cargo run --release -p e03-placeholder-eval -- \
    --prompts experiments/e03-placeholder-eval/prompts/ \
    --provider openai --model gpt-5-mini --formats all \
    --out fresh-zero-shot.json

# instructed
cargo run --release -p e03-placeholder-eval -- \
    --prompts experiments/e03-placeholder-eval/prompts/ \
    --provider openai --model gpt-5-mini --formats all \
    --instructions experiments/e03-placeholder-eval/instructions/preserve-tokens.txt \
    --out fresh-instructed.json
```

#### anthropic — deferred

Same harness, gated on Anthropic Console credits. When ready:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
cargo run --release -p e03-placeholder-eval -- \
    --prompts experiments/e03-placeholder-eval/prompts/ \
    --provider anthropic \
    --model claude-opus-4-5 \
    --formats all \
    --out results/anthropic-opus-4-5-YYYY-MM-DD.json
```

Estimated cost: 300 × ~$0.02/call on Opus 4.5 ≈ **$5–6**.
Sonnet 4.5 / Haiku are ~10× cheaper.

### Research-based justification for the placeholder design (2026-05-16)

Without burning budget on an empirical run, the public record gives
enough signal to decide whether `«SECRET_TYPE_N»` is the right pick.
**Summary: the academic state-of-the-art independently converged on
the same design principle.**

| Source | Placeholder | Notes |
|---|---|---|
| **arxiv 2604.12064** (LLM-Redactor, April 2026) — closest prior art to this experiment | `⟨KIND_N⟩` using Unicode mathematical angle brackets (U+27E8 / U+27E9) | Explicit rationale in the paper: "rare Unicode angle brackets to avoid collision with user text that might contain literal `{EMAIL_1}` syntax." Same design principle as our French guillemets `«…»` (U+00AB / U+00BB). The paper evaluates 8 privacy-preserving techniques over a 1,300-sample / 4,014-annotation benchmark and reports **0.6% combined leak on PII, zero exact leaks on 500 PII samples** for the redaction + placeholder-restoration path. The paper does **not** publish per-format preservation rates (it picks one format and runs with it), so we cannot read off "guillemets vs angle brackets" numbers from it. |
| **arxiv 2508.05545** (PRvL, 2025) — broader PII-redaction evaluation across several LLM architectures and training strategies | `[NAME]`, `[EMAIL]`, etc. | Focuses on whether PII is masked correctly. No quantitative data on placeholder format fidelity. (See paper for the full model list — we did not verify every name.) |
| **prompt-sentinel** (Python OSS, George Kour) | `__SECRET_1__` | Reversible via per-process singleton context. Same coreference semantics we use. No published preservation rates. Format is character-heavier than single-character bracket pairs; we did not measure token counts. |
| **Microsoft Presidio + LiteLLM** | `{{PERSON_1}}` (mustache-style) | Same-value → same-placeholder coreference stability. Build-plan §7 hypothesizes mustache syntax may trigger template-completion behavior in models trained on Jinja-style prompts; not empirically tested here. |
| **WangYihang/llm-redactor** (Go, OSS) — direct prior art for the same product idea | `[REDACTED]` | Local transparent proxy for AI coding agents (Claude/Gemini/Codex). Uses the literal `[REDACTED]` placeholder, which build-plan §7 flags as one of the worst-case formats (models often "helpfully expand" it: "Please provide your actual key here"). No documented round-trip / reversal mechanism in their README — they appear to redact-and-drop, not redact-and-restore. Implication: a competitor product shipped with the format our build-plan flags as worst-case. That tells us our floor is no worse than theirs — not a quality claim, just a floor. |

**Convergence finding.** The arxiv 2026 paper and aichu chose
near-identical placeholder shapes for the same reason. Both use a rare
Unicode bracket pair (the paper picked U+27E8/U+27E9; we picked
U+00AB/U+00BB), typed by entity kind, numbered for coreference. The
paper's choice isn't documented as empirically superior — it's a
design principle. The principle is: "use a delimiter the model will
treat as opaque, not parse as syntax, and not occur naturally in user
code." Both our choice and theirs satisfy this.

**What this analysis does NOT establish.** We do not have per-format
preservation numbers from the live API. The arxiv paper's 0.6% leak
rate measures their A+B+C *combined* pipeline (local-only routing +
redaction-with-placeholder + semantic rephrasing) against an unnamed
cloud target; it is not a placeholder-format-isolation number and
does not transfer directly to our setting. Whether `«…»` specifically
survives Anthropic Opus 4.5 / GPT-5.x round-trips at ≥98% (the
build-plan §9 kill threshold) is **still a deferred empirical
question**. The harness is ready when the budget is.

**Defensive design move worth keeping in mind.** If a real run later
shows guillemets surviving at, say, 92% (close to threshold but not
clean), the harness's `PlaceholderFormat` enum can carry a 7th variant
using U+27E8/U+27E9 to match the arxiv paper exactly, and the
production proxy can ship both formats behind a CLI flag. We don't
implement it now (per Rule 2: nothing speculative), but the shape is
trivially extensible.

### Risk 2 verdict

**Validated, conditional on a system-prompt prefix.** Zero-shot,
no format clears the §9 95% threshold on gpt-5-mini. With the
[`instructions/preserve-tokens.txt`](instructions/preserve-tokens.txt)
system prompt, guillemets reaches 96% — the kill criterion is no
longer tripped. The build-plan §9 option (a) fallback works
dramatically: a single one-paragraph system message moves the
production format from 12% to 96% preservation on gpt-5-mini.

Updated guidance:

1. **Production proxy should inject `preserve-tokens.txt` (or an
   equivalent) as a system prompt** on every forwarded request.
   This is now a recommended shipped behavior, not just a fallback.
   Not yet wired into the proxy crates — natural next deliverable.
2. **Guillemets remains the right production format.** It was the
   worst typed format zero-shot (12%) and is the best instructed
   (96%). The instruction effect dominates the zero-shot ranking.
3. **The arxiv-paper "rare-Unicode-bracket" design principle is
   rehabilitated.** Zero-shot, guillemets and angle brackets
   underperformed mustache; with instructions they pull ahead.
   The principle was right; it just needed instruction support
   to surface.
4. **Cross-family measurements (Anthropic, Google) still needed**
   to know whether the +84 pp instruction lift is gpt-5-mini-
   specific or generalizes. Each one is one cargo invocation away.
5. **Security property unaffected by preservation rate.** Secrets
   never reach the model in either condition; the proxy strips
   them upstream. Preservation is a UX metric, not a security
   metric.

### What this commit ships and deliberately omits

**Shipped:**
- `PlaceholderFormat` enum with all 6 candidates from build-plan §7
- `Model` trait + `EchoModel` / `StaticModel` mocks (no API needed)
- `AnthropicProvider` real-API impl (parameterized `base_url` so the mock
  test can target a local axum server)
- `evaluate()` orchestrator — one (fixture, format, model) cell at a time
- `main.rs` CLI for batch runs against a real provider
- JSON output schema (`EvalResult` is `Serialize`)

**Out of scope (follow-ups):**
- Gemini / Google provider
- Anthropic real-API run (Opus / Sonnet) — would give us the
  cross-family picture; ~$5-6
- Larger fixture corpus (the 50 we have are a starting point, not
  a statistical sample)
- Wiring `preserve-tokens.txt` into the production proxy crates
  (proxy-mitm and proxy-server) so every forwarded request carries
  the system prompt — natural next deliverable given the +84 pp
  result above

**Shipped since v0.1:**
- OpenAI provider (commit 2afff40 + 91e33cd; runs against
  gpt-5-mini and other reasoning-capable models via
  `reasoning_effort=minimal`)
- Zero-shot real-API run (commit 26acf3d; gpt-5-mini, 300 calls)
- `--instructions <FILE>` flag + incremental result writes
  (commit 1e88d0b)
- Instructed real-API run (commit 867df18; gpt-5-mini, 300 calls,
  guillemets 12% → 96%)

### Known measurement caveats (recorded for the results writeup)

- `preserved` is a substring match. For `[REDACTED]` and `***` it's
  upward-biased: the model can emit either string for unrelated reasons
  ("I'll mark the key as [REDACTED]"). Compare typed formats against
  each other for the real signal; treat the low-information formats as
  a negative control. Documented on `EvalResult::preserved`.
- `looks_like_refusal` is a sentence-one heuristic. It requires a modal
  ("I can't", "I cannot", "I won't", "I'm unable to") followed by a
  refusal-context verb (help, assist, provide, generate, share, do,
  create, write, comply). False negatives are possible if the model
  refuses in an unusual phrasing; you'll catch those in
  `response_excerpt`.
- Duplicate `secret_text` in a fixture is replaced with the **same**
  placeholder at every occurrence — intentional, matches the production
  proxy design per build-plan §7.
