// e03-placeholder-eval — Week 1, Risk 2
//
// Eval harness that measures verbatim preservation of placeholder formats
// across model families. Throwaway: results matter, code does not.
//
// See README.md in this crate for goal, kill criteria, and how to run.

fn main() {
    // TODO(e03): implement once dependencies resolve.
    //   1. clap CLI: --prompts <dir> --models <list> --formats <list> --out <path>
    //   2. Load .txt fixtures from --prompts. Each fixture is treated as a template.
    //   3. For each (fixture, format) pair, substitute the placeholder and send.
    //   4. Hit Anthropic /v1/messages and OpenAI /v1/chat/completions (non-streaming).
    //   5. Check response text for verbatim placeholder presence (exact-match substring).
    //   6. Track: preserved (bool), refused (bool), latency, tokens used.
    //   7. Write JSON results to --out.
    eprintln!("e03-placeholder-eval: not implemented yet — see README.md");
    std::process::exit(2);
}
