# e01-hudsucker-mitm

**Risk under test:** Can a Hudsucker-based MITM proxy (HTTP/2 + rustls + on-the-fly rcgen CA) successfully intercept streaming `/v1/messages` traffic from Claude Code CLI? Same question for Codex CLI's `/v1/responses`.

## Goal

Stand up the smallest possible Hudsucker proxy that:

1. Generates a CA on first run, writes the public cert to `./ca/aichu-ca.pem`.
2. Listens on `127.0.0.1:8788`.
3. Logs every intercepted request line (method, host, path).
4. Logs every SSE `data:` frame from the response side, without modifying the stream.
5. Survives a complete streaming `claude` CLI conversation end-to-end.

## How to run

```bash
# 1. Build and start the proxy
cargo run --release

# 2. In another shell, trust the generated CA (one-time, manual)
#    macOS:
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain \
    ./ca/aichu-ca.pem

# 3. Point Claude Code at the proxy
export HTTPS_PROXY=http://127.0.0.1:8788
export NODE_EXTRA_CA_CERTS=$PWD/ca/aichu-ca.pem
claude  # interact normally

# 4. To clean up after testing.
#    Note: -c matches by common name. The actual CN is set by rcgen at proxy
#    startup and logged at INFO level on first run. Use that exact CN here,
#    or use -Z <SHA1> after `security find-certificate -a -c <prefix> -Z`.
sudo security delete-certificate -c "<CA-COMMON-NAME-FROM-STARTUP-LOG>" /Library/Keychains/System.keychain
rm -rf ./ca
```

## Success criteria

- ✅ Claude Code completes a multi-turn streaming conversation through the proxy with no errors.
- ✅ Proxy logs show the request body and at least one full SSE response.
- ✅ HTTP/2 ALPN negotiates without falling back to HTTP/1.1 (check tracing output).

## Kill criteria

- ❌ Cannot MITM Claude Code CLI end-to-end within 2 days of focused work.
- ❌ HTTP/2 GOAWAY errors mid-stream that cannot be resolved by feature flags or hudsucker config.
- ❌ Claude Code rejects the CA even after `NODE_EXTRA_CA_CERTS` is set correctly.

If killed: pivot architecture to Mode A only (no MITM, base-URL relay). See `e02-base-url-relay`.

## Result

### Automated (`cargo test`)

✅ Five tests passing as of the initial implementation:

- `proxy_relays_sse_stream_and_logs_request` (integration) — a plain-HTTP
  `GET /sse` routed through aichu reaches the upstream, the SSE body
  round-trips intact, and `AichuHandler::handle_request` runs exactly once.
- `ca::first_call_writes_cert_and_key_files` — first call persists the CA.
- `ca::cert_file_is_a_pem_certificate` — cert is PEM-formatted on disk.
- `ca::second_call_reuses_existing_ca_without_regenerating` — subsequent
  calls do **not** mint a new CA (critical: regenerating would invalidate
  the user's system-store trust install).
- `ca::key_file_has_owner_only_permissions` (Unix) — key file is mode 0o600.

This proves the **wiring** survives: hudsucker `HttpHandler` runs, the
proxy relays bodies unmodified, the CA persistence story is correct.

### Manual (Claude Code through HTTPS MITM)

> Not yet run. This is the actual Risk 1 validation — the automated tests
> cover wiring only, not the HTTPS/cert-pinning question. Until a real
> `claude` CLI completes a streaming `/v1/messages` call through the
> proxy, Risk 1 is not validated.
