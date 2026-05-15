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

### Manual (real Anthropic run)

> Not yet run. Requires `ANTHROPIC_API_KEY` and a fixture corpus
> (`prompts/` currently empty). When ready:
>
> ```bash
> export ANTHROPIC_API_KEY=sk-ant-...
> cargo run --release -p e03-placeholder-eval -- \
>     --prompts prompts/ \
>     --provider anthropic \
>     --model claude-opus-4-7-20250514 \
>     --formats all \
>     --out results.json
> ```

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
- OpenAI provider — same recipe as Anthropic; add when needed
- Gemini / Google provider
- The 50-fixture corpus from the build-plan suggestions
- Actually running the eval against real APIs — gated on your API budget

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
