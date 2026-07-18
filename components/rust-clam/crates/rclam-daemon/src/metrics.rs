//! Minimal `/healthz` + Prometheus-text `/metrics` endpoint.
//!
//! Without this, an operator has logs but no signal an orchestrator can act
//! on programmatically: a crash gets noticed and restarted, but "the scan
//! queue is growing and requests are queuing up" produces no log line to
//! page on. This is a deliberately small hand-rolled HTTP/1.x responder
//! (parse the request line, ignore everything else, write a fixed response,
//! close the connection) rather than pulling in a full HTTP server
//! dependency -- a metrics/health endpoint has exactly two routes and is
//! polled by tools (Prometheus, `curl`, an orchestrator's liveness probe)
//! that all speak plain HTTP/1.0-compatible requests, so there is no
//! keep-alive, chunked encoding, or routing complexity actually needed
//! here.
//!
//! Bound to loopback by default and on a separate port from the scan
//! protocol -- metrics/health should stay reachable (and cheap to serve)
//! even under scan-side load, and shouldn't share a port with a protocol
//! that has nothing to do with HTTP.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How long a connection to the metrics/health endpoint may sit without
/// sending a complete request line before it's dropped. Without this, a
/// client that connects and never sends anything (accidentally, or as a
/// deliberate slow-loris-style flood) ties up its `tokio::spawn`'d task
/// forever -- individually cheap, but with no cap on how many such
/// connections this listener will accept, unboundedly many of them add up.
/// This endpoint is polled by health-check/scrape tooling that always
/// sends its request immediately, so a generous multi-second timeout costs
/// nothing for any legitimate caller.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
pub struct Metrics {
    pub connections_total: AtomicU64,
    pub connections_rejected_busy: AtomicU64,
    pub connections_rejected_rate_limited: AtomicU64,
    pub connections_rejected_concurrency: AtomicU64,
    pub connections_rejected_path: AtomicU64,
    pub scans_total: AtomicU64,
    pub files_scanned_total: AtomicU64,
    pub files_infected_total: AtomicU64,
    pub scan_errors_total: AtomicU64,
}

pub struct MetricsHandle {
    pub metrics: Arc<Metrics>,
    pub start: Instant,
    pub queue_capacity: usize,
    pub queue_available: Arc<tokio::sync::Semaphore>,
}

impl Metrics {
    fn render_prometheus(
        &self,
        uptime_secs: u64,
        queue_capacity: usize,
        queue_available: usize,
    ) -> String {
        let g = |name: &str, help: &str, value: u64, out: &mut String| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        };
        let mut out = String::new();
        g(
            "rclamd_connections_total",
            "Total connections accepted",
            self.connections_total.load(Ordering::Relaxed),
            &mut out,
        );
        g(
            "rclamd_connections_rejected_busy_total",
            "Connections rejected because the global connection cap was reached",
            self.connections_rejected_busy.load(Ordering::Relaxed),
            &mut out,
        );
        g(
            "rclamd_connections_rejected_rate_limited_total",
            "Connections rejected by per-peer rate limiting",
            self.connections_rejected_rate_limited
                .load(Ordering::Relaxed),
            &mut out,
        );
        g(
            "rclamd_connections_rejected_concurrency_total",
            "Connections rejected by the per-peer concurrency cap",
            self.connections_rejected_concurrency
                .load(Ordering::Relaxed),
            &mut out,
        );
        g(
            "rclamd_connections_rejected_path_total",
            "SCAN requests rejected because the path was not in an allowed root",
            self.connections_rejected_path.load(Ordering::Relaxed),
            &mut out,
        );
        g(
            "rclamd_scans_total",
            "Total SCAN/CONTSCAN requests handled",
            self.scans_total.load(Ordering::Relaxed),
            &mut out,
        );
        g(
            "rclamd_files_scanned_total",
            "Total individual files scanned (including archive members)",
            self.files_scanned_total.load(Ordering::Relaxed),
            &mut out,
        );
        g(
            "rclamd_files_infected_total",
            "Total individual files that produced a signature match",
            self.files_infected_total.load(Ordering::Relaxed),
            &mut out,
        );
        g(
            "rclamd_scan_errors_total",
            "Total scan requests that errored",
            self.scan_errors_total.load(Ordering::Relaxed),
            &mut out,
        );
        out.push_str(&format!(
            "# HELP rclamd_uptime_seconds Seconds since daemon start\n# TYPE rclamd_uptime_seconds gauge\nrclamd_uptime_seconds {uptime_secs}\n"
        ));
        out.push_str(&format!(
            "# HELP rclamd_connection_queue_capacity Configured max_connections\n# TYPE rclamd_connection_queue_capacity gauge\nrclamd_connection_queue_capacity {queue_capacity}\n"
        ));
        out.push_str(&format!(
            "# HELP rclamd_connection_queue_available Free connection slots right now\n# TYPE rclamd_connection_queue_available gauge\nrclamd_connection_queue_available {queue_available}\n"
        ));
        out
    }
}

/// Runs the metrics/health HTTP listener until the process exits. Errors
/// binding the listener are logged and treated as non-fatal to the daemon
/// as a whole -- losing the metrics endpoint shouldn't take down scanning.
pub async fn serve(addr: (std::net::IpAddr, u16), handle: Arc<MetricsHandle>) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, ?addr, "failed to bind metrics/health listener, continuing without it");
            return;
        }
    };
    tracing::info!(?addr, "metrics/health listening (/healthz, /metrics)");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "metrics listener accept error");
                continue;
            }
        };
        let handle = Arc::clone(&handle);
        tokio::spawn(async move {
            handle_connection(stream, handle, READ_TIMEOUT).await;
        });
    }
}

/// Serves exactly one request on `stream` and closes it. Split out from
/// `serve`'s accept loop so tests can drive it directly against an
/// in-process `TcpStream` pair without needing a real listener.
async fn handle_connection(mut stream: TcpStream, handle: Arc<MetricsHandle>, read_timeout: Duration) {
    let mut buf = [0u8; 2048];
    // Read once, with a bound on how long we'll wait for it; a request
    // line comfortably fits in one read for any well-behaved client, and
    // this endpoint doesn't need to handle bodies or pipelining.
    let n = match tokio::time::timeout(read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(_)) | Err(_) => return, // read error, or timed out waiting for data
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, body) = match path {
        "/healthz" => ("200 OK", "ok\n".to_string()),
        "/metrics" => {
            let uptime = handle.start.elapsed().as_secs();
            let available = handle.queue_available.available_permits();
            (
                "200 OK",
                handle
                    .metrics
                    .render_prometheus(uptime, handle.queue_capacity, available),
            )
        }
        _ => ("404 Not Found", "not found\n".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener as TokioTcpListener;

    fn test_handle() -> Arc<MetricsHandle> {
        Arc::new(MetricsHandle {
            metrics: Arc::new(Metrics::default()),
            start: Instant::now(),
            queue_capacity: 64,
            queue_available: Arc::new(tokio::sync::Semaphore::new(64)),
        })
    }

    /// Spins up a one-shot real TCP listener, sends `request_bytes` to it,
    /// and returns whatever bytes came back (empty if the connection was
    /// dropped without a response). Exercises the exact same code path
    /// `serve`'s accept loop uses, over a real socket -- not an in-memory
    /// duplex stream -- so partial reads/writes behave the same as they
    /// would against a real client.
    async fn round_trip(request_bytes: &[u8], read_timeout: Duration) -> Vec<u8> {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = test_handle();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, handle, read_timeout).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(request_bytes).await.unwrap();
        client.shutdown().await.ok();

        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response).await;
        let _ = server.await;
        response
    }

    #[tokio::test]
    async fn healthz_returns_200_ok() {
        let response = round_trip(b"GET /healthz HTTP/1.1\r\n\r\n", Duration::from_secs(2)).await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
        assert!(text.ends_with("ok\n"));
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_text() {
        let response = round_trip(b"GET /metrics HTTP/1.1\r\n\r\n", Duration::from_secs(2)).await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
        assert!(text.contains("rclamd_uptime_seconds"));
    }

    #[tokio::test]
    async fn unknown_path_returns_404_not_panic() {
        let response = round_trip(b"GET /whatever HTTP/1.1\r\n\r\n", Duration::from_secs(2)).await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 404 Not Found"), "got: {text}");
    }

    #[tokio::test]
    async fn empty_request_does_not_panic() {
        // Client connects and immediately closes without sending anything
        // -- read() returns Ok(0), not an error; must fall through to a
        // clean default rather than panicking on an empty path.
        let response = round_trip(b"", Duration::from_secs(2)).await;
        let text = String::from_utf8_lossy(&response);
        // Empty request line -> no path -> falls back to "/" -> 404. The
        // property under test is "responds cleanly or closes quietly",
        // not the exact status; a panic or hang is the only failure mode.
        assert!(text.is_empty() || text.starts_with("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    async fn malformed_non_utf8_request_does_not_panic() {
        let mut garbage: Vec<u8> = b"GET ".to_vec();
        garbage.extend_from_slice(&[0xFF, 0xFE, 0xC0, 0x80, 0x00, 0xFF, 0xFF]);
        garbage.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        let response = round_trip(&garbage, Duration::from_secs(2)).await;
        // Invalid UTF-8 must be lossily replaced, not panic the task --
        // whatever status comes back, the connection must complete.
        assert!(!response.is_empty(), "connection should complete, not hang or panic silently");
    }

    #[tokio::test]
    async fn oversized_request_line_does_not_panic_or_hang() {
        // Much larger than the 2048-byte read buffer -- the handler only
        // ever reads once, so this arrives truncated from its point of
        // view; that must be handled the same as any other malformed
        // input, not panic on a slice boundary.
        let huge = vec![b'A'; 64 * 1024];
        let response = round_trip(&huge, Duration::from_secs(2)).await;
        assert!(!response.is_empty());
    }

    #[tokio::test]
    async fn silent_connection_is_dropped_after_read_timeout_not_held_forever() {
        // A client that connects and then sends nothing at all (the
        // slow-loris pattern) must be dropped once the read timeout
        // elapses, not held open indefinitely. Uses a short timeout here
        // so the test itself stays fast; production uses READ_TIMEOUT.
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = test_handle();
        let short_timeout = Duration::from_millis(150);

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, handle, short_timeout).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // Deliberately send nothing and don't close our end either --
        // the only thing that should end this connection is the server's
        // own read timeout.
        let started = Instant::now();
        let mut buf = [0u8; 16];
        let _ = client.read(&mut buf).await; // blocks until server closes
        let elapsed = started.elapsed();

        server.await.unwrap();
        assert!(
            elapsed < Duration::from_secs(2),
            "connection should have been dropped by the read timeout quickly, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn many_concurrent_connections_are_all_served_correctly() {
        // A burst of simultaneous scrapes/health-checks (e.g. several
        // orchestrator probes and a Prometheus scrape landing at once)
        // must all get correct, independent responses -- no cross-talk
        // between connections and no deadlock under concurrent load.
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = test_handle();

        let accept_loop = tokio::spawn(async move {
            for _ in 0..200 {
                let (stream, _) = listener.accept().await.unwrap();
                let handle = Arc::clone(&handle);
                tokio::spawn(async move {
                    handle_connection(stream, handle, Duration::from_secs(2)).await;
                });
            }
        });

        let mut clients = Vec::new();
        for _ in 0..200 {
            clients.push(tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                stream.write_all(b"GET /healthz HTTP/1.1\r\n\r\n").await.unwrap();
                stream.shutdown().await.ok();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                response
            }));
        }

        let mut ok_count = 0;
        for c in clients {
            let response = c.await.unwrap();
            if String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK") {
                ok_count += 1;
            }
        }
        accept_loop.await.unwrap();
        assert_eq!(ok_count, 200, "every one of 200 concurrent requests should get a valid 200");
    }
}
