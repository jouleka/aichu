// e02-base-url-relay — Week 1, Risk 3 (passthrough mode)
//
// Smallest possible axum-based relay that forwards /v1/messages and
// /v1/chat/completions to their real upstreams and streams SSE back without
// modification. Throwaway validation code.
//
// See README.md in this crate for goal, kill criteria, and how to run.

fn main() {
    // TODO(e02): implement once dependencies resolve.
    //   1. axum::Router with /v1/messages and /v1/chat/completions handlers.
    //   2. For each route, re-issue with reqwest preserving headers + body.
    //   3. If response is text/event-stream, wrap reqwest::Response::bytes_stream()
    //      and forward bytes 1:1 (we do NOT parse SSE here — pass-through only).
    //   4. Log (method, path, status, content-type) per request.
    //   5. Listen on 127.0.0.1:8788. Graceful shutdown on SIGINT.
    eprintln!("e02-base-url-relay: not implemented yet — see README.md");
    std::process::exit(2);
}
