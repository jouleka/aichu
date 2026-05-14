// e01-hudsucker-mitm — Week 1, Risk 1
//
// Smallest possible Hudsucker MITM proxy that logs request/response traffic.
// Throwaway: this is validation code, not production architecture.
//
// See README.md in this crate for goal, kill criteria, and how to run.

fn main() {
    // TODO(e01): implement once dependencies resolve.
    //   1. Generate or load CA from ./ca/, error if directory unwritable.
    //   2. Build Hudsucker proxy on 127.0.0.1:8788 with HTTP/2 enabled.
    //   3. Implement a HttpHandler that logs request line and SSE response chunks.
    //   4. Run until SIGINT.
    eprintln!("e01-hudsucker-mitm: not implemented yet — see README.md");
    std::process::exit(2);
}
