//! Integration test: a plain-HTTP request routed through the aichu proxy
//! must reach the upstream, return its SSE stream unmodified to the client,
//! AND be observed by the AichuHandler.
//!
//! Validates the shape of the wire — handler observes, body unmodified, no
//! errors — without exercising the HTTPS/CA round-trip (that requires real
//! coding-agent traffic and is validated manually).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use axum::{
    response::sse::{Event, Sse},
    routing::get,
    Router,
};
use futures_util::stream;
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use proxy_mitm::{ca::load_or_create_ca, handler::AichuHandler, run_proxy};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_relays_sse_stream_and_logs_request() -> Result<()> {
    let upstream_addr = spawn_upstream().await?;
    let ca_dir = TempDir::new()?;
    let ca = load_or_create_ca(ca_dir.path())?;

    let handler = AichuHandler::new();
    let request_count = handler.request_count();

    let (proxy_addr, shutdown_tx) = spawn_proxy(ca.authority, handler).await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_addr}"))?)
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = client
        .get(format!("http://{upstream_addr}/sse"))
        .send()
        .await?;

    assert_eq!(resp.status(), 200, "upstream should respond 200 through proxy");

    let ct = resp
        .headers()
        .get("content-type")
        .expect("missing content-type")
        .to_str()?;
    assert!(
        ct.starts_with("text/event-stream"),
        "expected SSE content-type, got {ct:?}"
    );

    let text = resp.text().await?;

    // The three SSE events emitted by the upstream must arrive intact. We do
    // not assert byte-for-byte equality because SSE serialization
    // (line endings, keep-alive comments) is implementation-defined; we
    // assert each event payload is present.
    assert!(text.contains("data: hello"), "missing 'hello' in: {text:?}");
    assert!(text.contains("data: world"), "missing 'world' in: {text:?}");
    assert!(text.contains("data: done"), "missing 'done' in: {text:?}");

    // The handler is the whole point of e01 — if the request counter didn't
    // tick, our log path is broken regardless of byte-correctness above.
    assert_eq!(
        request_count.load(Ordering::Relaxed),
        1,
        "AichuHandler::handle_request did not run"
    );

    let _ = shutdown_tx.send(());
    Ok(())
}

async fn spawn_upstream() -> Result<SocketAddr> {
    let app = Router::new().route("/sse", get(sse_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

async fn sse_handler() -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let events = stream::iter(vec![
        Ok(Event::default().data("hello")),
        Ok(Event::default().data("world")),
        Ok(Event::default().data("done")),
    ]);
    Sse::new(events)
}

async fn spawn_proxy(
    ca: hudsucker::certificate_authority::RcgenAuthority,
    handler: AichuHandler,
) -> Result<(SocketAddr, oneshot::Sender<()>)> {
    // Bind to port 0 to discover a free port, then drop the listener so
    // hudsucker can bind to that port itself. Tiny race window; negligible
    // in practice for localhost test ports.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        let _ = run_proxy(addr, ca, handler, async move {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    // Poll-connect instead of a fixed sleep: fast on the happy path, robust
    // on slow CI runners. Total budget: 50 × 20ms = 1s.
    wait_for_listener(addr).await?;

    Ok((addr, shutdown_tx))
}

async fn wait_for_listener(addr: SocketAddr) -> Result<()> {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("proxy never accepted a TCP connection on {addr}")
}
