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

> Not yet run.
