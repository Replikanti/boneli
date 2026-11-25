//! Pulls through an HTTP proxy (ADR-039, D5 and D10): the production
//! `TlsDial` of a proxied `TlsConfig` against a fake proxy on 127.0.0.1
//! that records every head it receives and tunnels `CONNECT` to a local
//! rustls registry, which serves the fake private registry of
//! `support::registry` and records every request. The registry's
//! certificate is the `localhost` leaf of `boneli-https`'s test data
//! (`crates/boneli-https/tests/data/README.md`); it names no CRL or OCSP
//! point, so no revocation fetch is made.

mod support;

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use boneli_app::{ImageError, ImageOrigin, ImageRef, ImageStore};
use boneli_https::{BasicCredentials, Proxy, Roots, TlsConfig};
use boneli_oci::{OciImageStore, Registry, StoreConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use support::TempDir;
use support::images::{Layer, Pushed, push};
use support::registry::{Flow, Handler, Hub, Private, Seen, answer};

const CA: &[u8] = include_bytes!("../../boneli-https/tests/data/ca.pem");
const LEAF: &[u8] = include_bytes!("../../boneli-https/tests/data/leaf.pem");
const LEAF_KEY: &[u8] = include_bytes!("../../boneli-https/tests/data/leaf.key");
const OTHER_LEAF: &[u8] = include_bytes!("../../boneli-https/tests/data/other-leaf.pem");
const OTHER_LEAF_KEY: &[u8] = include_bytes!("../../boneli-https/tests/data/other-leaf.key");

/// Registry credentials and proxy credentials, distinctive, so a scan
/// for them cannot match by chance.
const USER: &str = "pXy-u5Er9q8RzT3vW1xY7kLm";
const PASS: &str = "pXy-pA55w0rD9xK2mN7qR4tV6yZ8bC1dF3gH5jL7";
const PROXY_USER: &str = "pRx-oNLy-u5Er9q8RzT3vW1x";
const PROXY_PASS: &str = "pRx-oNLy-pA55w0rD9xK2mN7qR4tV6yZ8bC1dF3g";

const REPO: &str = "library/app";

/// Bounds every blocking call of the fakes, so that a bug ends in a
/// failure instead of a hang.
const GUARD: Duration = Duration::from_secs(10);

fn server_config(chain_pem: &[u8], key: &[u8]) -> Arc<ServerConfig> {
    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("cert PEM");
    let key = PrivateKeyDer::from_pem_slice(key).expect("key PEM");
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server cert");
    config.send_tls13_tickets = 0;
    Arc::new(config)
}

/// A registry behind TLS on 127.0.0.1: every connection that completes
/// the handshake gets one request answered by `handler`, recorded as if
/// sent to Docker Hub's API host (the fake private registry's). A failed
/// handshake records nothing.
struct Origin {
    addr: SocketAddr,
    log: Arc<Mutex<Vec<Seen>>>,
}

impl Origin {
    fn start(config: Arc<ServerConfig>, handler: Arc<Handler>) -> Origin {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let log = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&log);
        thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { continue };
                let (config, record, handler) = (
                    Arc::clone(&config),
                    Arc::clone(&record),
                    Arc::clone(&handler),
                );
                thread::spawn(move || {
                    let _ = tcp.set_read_timeout(Some(GUARD));
                    let _ = tcp.set_write_timeout(Some(GUARD));
                    let Ok(conn) = ServerConnection::new(config) else {
                        return;
                    };
                    let mut tls = StreamOwned::new(conn, tcp);
                    answer(
                        &mut tls,
                        "registry-1.docker.io".to_owned(),
                        443,
                        &*handler,
                        &record,
                    );
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        Origin { addr, log }
    }

    fn seen(&self) -> Vec<Seen> {
        self.log.lock().expect("log").clone()
    }
}

/// A fake HTTP proxy on 127.0.0.1: records every head; a `CONNECT` to a
/// target in `tunnels` gets `200` and a relay to its address, any other
/// request `403`.
struct FakeProxy {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

impl FakeProxy {
    fn start(tunnels: Vec<(String, SocketAddr)>) -> FakeProxy {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&heads);
        let tunnels = Arc::new(tunnels);
        thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { continue };
                let (record, tunnels) = (Arc::clone(&record), Arc::clone(&tunnels));
                thread::spawn(move || proxy_connection(tcp, &record, &tunnels));
            }
        });
        FakeProxy { addr, heads }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("heads").clone()
    }

    fn proxy(&self) -> Proxy {
        Proxy::new("127.0.0.1", self.addr.port()).expect("proxy")
    }
}

fn proxy_connection(
    mut client: TcpStream,
    record: &Mutex<Vec<String>>,
    tunnels: &[(String, SocketAddr)],
) {
    let _ = client.set_read_timeout(Some(GUARD));
    let _ = client.set_write_timeout(Some(GUARD));
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 65_536 {
        match client.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    record.lock().expect("record").push(head.clone());
    let target = head
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_default();
    let Some((_, origin)) = tunnels.iter().find(|(t, _)| t == target) else {
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return;
    };
    let Ok(upstream) = TcpStream::connect(origin) else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        return;
    };
    let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
    let (Ok(mut client_read), Ok(mut upstream_read)) = (client.try_clone(), upstream.try_clone())
    else {
        return;
    };
    let (mut client_write, mut upstream_write) = (client, upstream);
    let up = thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = up.join();
}

fn credentials() -> BasicCredentials {
    BasicCredentials::new(USER, PASS).expect("credentials")
}

fn proxy_credentials() -> BasicCredentials {
    BasicCredentials::new(PROXY_USER, PROXY_PASS).expect("proxy credentials")
}

/// Every run of 16 bytes of `secrets` and of `Basic` base64 of the pairs.
fn assert_clean(text: &str, what: &str) {
    let mut secrets = vec![
        USER.to_owned(),
        PASS.to_owned(),
        PROXY_USER.to_owned(),
        PROXY_PASS.to_owned(),
    ];
    for c in [credentials(), proxy_credentials()] {
        secrets.push(c.header_value()["Basic ".len()..].to_owned());
    }
    for secret in &secrets {
        for window in secret.as_bytes().windows(16) {
            let window = String::from_utf8_lossy(window);
            assert!(!text.contains(&*window), "{what}: {window:?} in {text:?}");
        }
    }
}

/// A private registry in the Basic flow over `library/app`, served behind
/// TLS with `chain_pem`; blobs redirected through `cdn` when given.
fn registry_origin(chain_pem: &[u8], key: &[u8], cdn: Option<&str>) -> (Origin, Pushed) {
    let mut hub = Hub::default();
    let pushed = push(
        &mut hub,
        REPO,
        &[Layer::file("etc/a", b"a\n"), Layer::file("etc/b", b"b\n")],
        r#"{"Cmd":["tool"]}"#,
    );
    let mut private = Private::new(hub, Flow::Basic, &credentials().header_value(), "unused");
    private.chain = cdn.map(str::to_owned).into_iter().collect();
    let handler: Arc<Handler> = Arc::new(move |s: &Seen| private.handle(s));
    (
        Origin::start(server_config(chain_pem, key), handler),
        pushed,
    )
}

/// A store over the production dial with `proxy`, trusting the test CA,
/// whose one registry is `localhost:<port>` with the test credentials and
/// the redirect suffix `.docker.com`.
fn store(tmp: &TempDir, port: u16, proxy: Proxy) -> OciImageStore {
    let mut roots = Roots::empty();
    roots.add_pem(CA).expect("test CA");
    let tls = TlsConfig::new(roots).expect("tls").with_proxy(proxy);
    let mut config = StoreConfig::production(tls).expect("config");
    let registry = Registry::new(
        "localhost",
        &format!("localhost:{port}"),
        &[],
        &[".docker.com"],
    )
    .expect("registry")
    .with_credentials(credentials());
    config.registries = vec![registry.clone()];
    config.default_registry = registry;
    OciImageStore::open(&tmp.path().join("store"), config).expect("open")
}

fn pull(store: &OciImageStore, digest: &str) -> Result<String, ImageError> {
    store
        .pull(&ImageRef {
            name: format!("localhost/{REPO}"),
            digest: digest.to_owned(),
            platform: "linux/amd64".to_owned(),
            origin: ImageOrigin::Operator,
        })
        .map(|p| p.rootfs.as_str().to_owned())
}

fn entries(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|d| {
            d.map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// A pull through the proxy: every connection is a `CONNECT` to the
/// registry carrying the proxy's credentials and nothing else; the
/// registry sees its own credentials after its challenge and never the
/// proxy's; the proxy never sees the registry's.
#[test]
fn pull_through_proxy() {
    let (origin, pushed) = registry_origin(LEAF, LEAF_KEY, None);
    let target = format!("localhost:{}", origin.addr.port());
    let proxy = FakeProxy::start(vec![(target.clone(), origin.addr)]);
    let tmp = TempDir::new("proxy-pull");
    let store = store(
        &tmp,
        origin.addr.port(),
        proxy.proxy().with_credentials(proxy_credentials()),
    );
    assert_eq!(pull(&store, &pushed.index).expect("pull"), pushed.manifest);
    let heads = proxy.heads();
    let seen = origin.seen();
    assert_eq!(heads.len(), seen.len(), "one tunnel per request");
    let proxy_auth = format!(
        "\r\nProxy-Authorization: {}\r\n",
        proxy_credentials().header_value()
    );
    for head in &heads {
        assert!(
            head.starts_with(&format!("CONNECT {target} HTTP/1.1\r\n")),
            "{head:?}"
        );
        assert!(head.contains(&proxy_auth), "{head:?}");
        assert!(
            !head.to_ascii_lowercase().contains("\r\nauthorization:"),
            "{head:?}"
        );
        assert_clean(&head.replace(&proxy_auth, "\r\n"), "a CONNECT head");
    }
    let registry_auth = credentials().header_value();
    assert_eq!(seen[0].header("authorization"), None);
    for s in &seen[1..] {
        assert_eq!(s.header("authorization"), Some(registry_auth.as_str()));
    }
    for s in &seen {
        assert_eq!(s.header("proxy-authorization"), None);
    }
    let layers = entries(&tmp.path().join("store/layers/sha256"));
    assert_eq!(layers.iter().filter(|n| !n.ends_with(".stats")).count(), 2);
}

/// A registry whose certificate the runner does not trust is refused
/// behind the proxy as on a direct connection: the TLS check runs end to
/// end, the registry receives no request and nothing is committed.
#[test]
fn untrusted_registry_refused_behind_proxy() {
    let (origin, pushed) = registry_origin(OTHER_LEAF, OTHER_LEAF_KEY, None);
    let target = format!("localhost:{}", origin.addr.port());
    let proxy = FakeProxy::start(vec![(target.clone(), origin.addr)]);
    let tmp = TempDir::new("proxy-untrusted");
    let store = store(&tmp, origin.addr.port(), proxy.proxy());
    let detail = match pull(&store, &pushed.index) {
        Err(ImageError::Failed { detail }) => detail,
        other => panic!("expected Failed, got {other:?}"),
    };
    assert!(detail.contains(&target), "{detail}");
    assert_clean(&detail, "the detail");
    assert_eq!(proxy.heads().len(), 1, "{:?}", proxy.heads());
    assert!(origin.seen().is_empty(), "{:?}", origin.seen());
    assert!(entries(&tmp.path().join("store/layers/sha256")).is_empty());
    assert!(entries(&tmp.path().join("store/blobs/sha256")).is_empty());
}

/// The proxy refusing `CONNECT` to the CDN a blob is redirected to fails
/// the pull with a detail that names the proxy, the CDN host and the
/// status, and no secret.
#[test]
fn proxy_refusing_the_cdn_is_failed() {
    let (origin, pushed) = registry_origin(LEAF, LEAF_KEY, Some("cdn.docker.com"));
    let target = format!("localhost:{}", origin.addr.port());
    let proxy = FakeProxy::start(vec![(target, origin.addr)]);
    let tmp = TempDir::new("proxy-cdn");
    let store = store(
        &tmp,
        origin.addr.port(),
        proxy.proxy().with_credentials(proxy_credentials()),
    );
    let detail = match pull(&store, &pushed.index) {
        Err(ImageError::Failed { detail }) => detail,
        other => panic!("expected Failed, got {other:?}"),
    };
    let expected = format!(
        "the proxy 127.0.0.1:{} answered 403 to CONNECT cdn.docker.com:443",
        proxy.addr.port()
    );
    assert!(detail.contains(&expected), "{detail}");
    assert_clean(&detail, "the detail");
    assert!(
        proxy
            .heads()
            .iter()
            .any(|h| h.starts_with("CONNECT cdn.docker.com:443 "))
    );
}
