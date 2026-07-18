//! `rclam-sigupdate`: a small, `freshclam`-equivalent CLI. Fetches a
//! manifest (optionally checking an Ed25519 signature over it), downloads
//! every listed file, verifies each one's SHA-256 against the manifest,
//! stages them all in a temp directory, and only then atomically swaps
//! that staging directory into place as the live signature directory --
//! see `sig_update::apply` for why the swap is structured that way.
//!
//! This intentionally does not run as a daemon/timer itself; run it from
//! cron/systemd-timer, same as `freshclam` traditionally is. It exits
//! non-zero on any verification failure, so a scheduler treats a bad update
//! as a failed job rather than silently leaving stale-but-safe signatures
//! in place (which is what happens automatically anyway, since nothing is
//! touched in `sig_dir` until every check passes).

use clap::Parser;
use sig_update::{apply_update, parse_manifest, verify_manifest_signature, verify_sha256};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "rclam-sigupdate")]
struct Args {
    /// URL of the JSON manifest listing signature files and their SHA-256s.
    #[arg(long)]
    manifest_url: String,

    /// Live signature directory rclamd reads from. Replaced atomically on
    /// success; the prior generation is kept as `<sig_dir>.previous`.
    #[arg(long)]
    sig_dir: PathBuf,

    /// Hex-encoded Ed25519 public key. If given, the manifest fetch must
    /// also find a signature at `<manifest_url>.sig` (64 raw bytes,
    /// hex-encoded) and it must verify, or the update is refused. Without
    /// this flag, integrity relies on TLS-on-the-manifest-fetch plus the
    /// per-file SHA-256 checks alone -- fine against a flaky mirror,
    /// weaker against a fully compromised origin.
    #[arg(long)]
    public_key: Option<String>,

    /// Print what would happen without touching sig_dir.
    #[arg(long)]
    dry_run: bool,
}

fn fetch(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, String> {
    let response = agent
        .get(url)
        .call()
        .map_err(|e| format!("GET {url} failed: {e}"))?;
    let mut buf = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("reading response body from {url} failed: {e}"))?;
    Ok(buf)
}

fn run(args: Args, agent: &ureq::Agent) -> Result<(), String> {
    let manifest_bytes = fetch(agent, &args.manifest_url)?;

    if let Some(pubkey) = &args.public_key {
        let sig_url = format!("{}.sig", args.manifest_url);
        let sig_bytes = fetch(agent, &sig_url)?;
        let sig_hex = String::from_utf8_lossy(&sig_bytes).trim().to_string();
        verify_manifest_signature(&manifest_bytes, pubkey, &sig_hex)
            .map_err(|e| format!("manifest signature verification failed: {e}"))?;
        println!("manifest signature OK ({sig_url})");
    } else {
        eprintln!(
            "warning: no --public-key given; manifest integrity relies on TLS alone, not on an independent signature"
        );
    }

    let manifest_text =
        String::from_utf8(manifest_bytes).map_err(|_| "manifest is not valid UTF-8".to_string())?;
    let manifest = parse_manifest(&manifest_text).map_err(|e| e.to_string())?;
    println!(
        "manifest version {} lists {} file(s)",
        manifest.version,
        manifest.files.len()
    );

    if args.dry_run {
        for f in &manifest.files {
            println!("  would fetch {} <- {}", f.name, f.url);
        }
        println!("dry run: sig_dir not touched");
        return Ok(());
    }

    let staging = tempfile::Builder::new()
        .prefix(".rclam-sigupdate-staging-")
        .tempdir_in(
            args.sig_dir
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
        )
        .map_err(|e| format!("creating staging directory failed: {e}"))?;

    for f in &manifest.files {
        let data = fetch(agent, &f.url)?;
        verify_sha256(&data, &f.sha256)
            .map_err(|e| format!("{}: integrity check failed: {e}", f.name))?;
        let out_path = staging.path().join(&f.name);
        let mut file = std::fs::File::create(&out_path)
            .map_err(|e| format!("writing {}: {e}", out_path.display()))?;
        file.write_all(&data)
            .map_err(|e| format!("writing {}: {e}", out_path.display()))?;
        println!("  verified and staged {}", f.name);
    }

    // Record the version alongside the files themselves so it moves
    // atomically with everything else in the same swap, rather than being
    // written to sig_dir in a separate step that could observe a
    // half-updated state if this process is killed mid-way.
    std::fs::write(
        staging.path().join(".rclam-sigversion"),
        format!("{}\n", manifest.version),
    )
    .map_err(|e| format!("writing version file: {e}"))?;

    // `apply_update` renames (moves) the staging directory into place, so
    // hand it the path and let the TempDir guard go out of scope without
    // trying to clean up a directory that's already been moved elsewhere.
    let staging_path = staging.into_path();
    apply_update(&staging_path, &args.sig_dir).map_err(|e| e.to_string())?;

    println!(
        "signature update applied: {} now at version {}",
        args.sig_dir.display(),
        manifest.version
    );
    Ok(())
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args, &ureq::agent()) {
        eprintln!("rclam-sigupdate: error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tls_end_to_end_tests {
    //! Drives the real `fetch`/`run` code path -- the same functions
    //! `main()` calls -- against an actual local TLS server speaking real
    //! TLS 1.2/1.3 (via `rustls`, the same TLS implementation `ureq` uses
    //! in production here, not a mock), rather than only exercising
    //! `apply`/`verify`/`manifest` directly. This is what closes the gap
    //! the README used to call out: "not the same as running it against a
    //! production distribution point over real TLS."
    //!
    //! What's still *not* covered here, and can't be from a unit test:
    //! a real public CA-issued certificate chain (we mint our own
    //! self-signed root and trust it explicitly, which exercises the same
    //! TLS handshake and record-layer code but not certificate-chain
    //! validation against the public WebPKI), and a genuinely remote
    //! network path (latency, MTU weirdness, a real CDN in front of the
    //! origin). Both of those remain "run it against a production
    //! distribution point before depending on it" territory.
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, Stream};
    use sig_update::sha256_hex;
    use std::collections::HashMap;
    use std::io::Read as _;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;

    /// A canned set of path -> response-body pairs served over TLS on a
    /// background thread for exactly `routes.len()` requests, then the
    /// listener thread exits. Good enough for these tests, which always
    /// know up front exactly which URLs `run()` will fetch.
    ///
    /// Split into `bind()` (learn the port, build TLS configs) and
    /// `serve(routes)` (start accepting) as two steps deliberately: tests
    /// need the port *before* they can construct a manifest referencing
    /// `https://localhost:<port>/...`, but the routes (which include that
    /// same manifest) aren't known until after that.
    struct BoundTlsServer {
        listener: TcpListener,
        port: u16,
        server_config: Arc<ServerConfig>,
        client_config: Arc<rustls::ClientConfig>,
    }

    struct RunningTlsServer {
        port: u16,
        client_config: Arc<rustls::ClientConfig>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl BoundTlsServer {
        fn bind() -> Self {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let cert_der = Certificate(cert.serialize_der().unwrap());
            let key_der = PrivateKey(cert.serialize_private_key_der());

            let server_config = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], key_der)
                .unwrap();

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();

            // Trust our freshly-minted self-signed cert as a root -- this
            // is the test's stand-in for a real CA trust chain.
            let mut roots = rustls::RootCertStore::empty();
            roots.add(&cert_der).unwrap();
            let client_config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(roots)
                .with_no_client_auth();

            Self {
                listener,
                port,
                server_config: Arc::new(server_config),
                client_config: Arc::new(client_config),
            }
        }

        fn serve(self, routes: HashMap<String, Vec<u8>>) -> RunningTlsServer {
            let request_count = routes.len();
            let server_config = self.server_config;
            let handle = std::thread::spawn(move || {
                for stream in self.listener.incoming().take(request_count) {
                    let stream = match stream {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    handle_one_request(stream, server_config.clone(), &routes);
                }
            });

            RunningTlsServer {
                port: self.port,
                client_config: self.client_config,
                handle: Some(handle),
            }
        }
    }

    impl RunningTlsServer {
        fn base_url(&self) -> String {
            format!("https://localhost:{}", self.port)
        }

        fn agent(&self) -> ureq::Agent {
            ureq::AgentBuilder::new()
                .tls_config(self.client_config.clone())
                .build()
        }
    }

    impl Drop for RunningTlsServer {
        fn drop(&mut self) {
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn handle_one_request(
        tcp: TcpStream,
        server_config: Arc<ServerConfig>,
        routes: &HashMap<String, Vec<u8>>,
    ) {
        let mut tcp = tcp;
        let mut conn = match ServerConnection::new(server_config) {
            Ok(c) => c,
            Err(_) => return,
        };
        let mut tls = Stream::new(&mut conn, &mut tcp);

        // Minimal HTTP/1.1 request-line parsing -- we only need the path,
        // and only ever handle GET. Reads until the blank line that ends
        // the headers, ignoring header content entirely.
        let mut buf = [0u8; 4096];
        let mut request = Vec::new();
        loop {
            let n = match tls.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let request_text = String::from_utf8_lossy(&request);
        let path = request_text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string();

        let body = routes.get(&path).cloned().unwrap_or_default();
        let status = if routes.contains_key(&path) {
            "200 OK"
        } else {
            "404 Not Found"
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = tls.write_all(response.as_bytes());
        let _ = tls.write_all(&body);
        let _ = tls.conn.complete_io(tls.sock);
    }

    #[test]
    fn update_succeeds_end_to_end_over_real_tls_with_valid_signature() {
        let main_ndb = b"Sig.Test:74657374\n".to_vec();
        let daily_hdb = b"d41d8cd98f00b204e9800998ecf8427e:0:empty\n".to_vec();

        let bound = BoundTlsServer::bind();
        let port = bound.port;

        let manifest_json = format!(
            r#"{{"version":"2026.07.15-01","files":[
                {{"name":"main.ndb","sha256":"{}","url":"https://localhost:{port}/main.ndb"}},
                {{"name":"daily.hdb","sha256":"{}","url":"https://localhost:{port}/daily.hdb"}}
            ]}}"#,
            sha256_hex(&main_ndb),
            sha256_hex(&daily_hdb),
        );

        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(manifest_json.as_bytes());

        let mut routes = HashMap::new();
        routes.insert("/manifest.json".to_string(), manifest_json.into_bytes());
        routes.insert(
            "/manifest.json.sig".to_string(),
            hex::encode(signature.to_bytes()).into_bytes(),
        );
        routes.insert("/main.ndb".to_string(), main_ndb.clone());
        routes.insert("/daily.hdb".to_string(), daily_hdb);

        let server = bound.serve(routes);

        let sig_dir = tempfile::tempdir().unwrap();
        let args = Args {
            manifest_url: format!("{}/manifest.json", server.base_url()),
            sig_dir: sig_dir.path().join("sigs"),
            public_key: Some(hex::encode(verifying_key.to_bytes())),
            dry_run: false,
        };

        let result = run(args, &server.agent());
        assert!(result.is_ok(), "update over real TLS failed: {result:?}");

        let installed = std::fs::read(sig_dir.path().join("sigs").join("main.ndb")).unwrap();
        assert_eq!(installed, main_ndb);
    }

    #[test]
    fn tampered_file_over_tls_is_rejected_and_sig_dir_is_untouched() {
        let main_ndb = b"Sig.Test:74657374\n".to_vec();
        let wrong_sha = sha256_hex(b"this is not the real content");

        let bound = BoundTlsServer::bind();
        let port = bound.port;
        let manifest_json = format!(
            r#"{{"version":"2026.07.15-01","files":[
                {{"name":"main.ndb","sha256":"{wrong_sha}","url":"https://localhost:{port}/main.ndb"}}
            ]}}"#
        );

        let mut routes = HashMap::new();
        routes.insert("/manifest.json".to_string(), manifest_json.into_bytes());
        routes.insert("/main.ndb".to_string(), main_ndb);
        let server = bound.serve(routes);

        let sig_dir = tempfile::tempdir().unwrap();
        let live_sigs = sig_dir.path().join("sigs");
        std::fs::create_dir(&live_sigs).unwrap();
        std::fs::write(live_sigs.join("main.ndb"), "previous, valid generation").unwrap();

        let args = Args {
            manifest_url: format!("{}/manifest.json", server.base_url()),
            sig_dir: live_sigs.clone(),
            public_key: None,
            dry_run: false,
        };

        let result = run(args, &server.agent());
        assert!(result.is_err(), "a SHA-256 mismatch over TLS must be rejected");

        // The live directory must still hold the previous, valid
        // generation -- a failed download+verify must never touch it.
        assert_eq!(
            std::fs::read_to_string(live_sigs.join("main.ndb")).unwrap(),
            "previous, valid generation"
        );
    }
}
