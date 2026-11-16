use std::path::Path;
use std::process::Command;
use std::thread;

use edgekms_cli::login::{
    self, Body, HttpReply, LoginError, Signer, SshKeygen, Transport, UreqTransport, check_addr,
};
use edgekms_core::keyops::SoftKeyOps;
use edgekms_core::ssh;
use edgekms_core::transit::{Id, RootKey};
use serde_json::{Value, json};

struct FakeSigner(&'static str);

impl Signer for FakeSigner {
    fn sign(&self, namespace: &str, challenge: &str) -> Result<String, LoginError> {
        // `login ssh` signs only under the data plane's namespace.
        assert_eq!(namespace, "edgekms");
        assert!(challenge.starts_with("ekmsc."), "{challenge}");
        Ok(self.0.to_owned())
    }
}

/// A genuine challenge, as a Worker at `origin` would mint it.
fn challenge_for(origin: &str) -> String {
    let ops = SoftKeyOps::new(RootKey::new(Id::new("r1").unwrap(), [1; 32]), rand::rng());
    pollster::block_on(ssh::new_challenge(&ops, 1_000, origin)).unwrap()
}

/// A stub server whose replies need its own URL: binds first, then serves `replies(url)`.
fn stub_with(
    replies: impl FnOnce(&str) -> Vec<(u16, Value)>,
) -> (String, thread::JoinHandle<Vec<(String, Value)>>) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    let replies = replies(&url);
    (url, serve(server, replies))
}

/// Serves `replies` in order, one per request, and returns (url, join handle yielding the
/// (path, body) of every request seen).
fn stub(replies: Vec<(u16, Value)>) -> (String, thread::JoinHandle<Vec<(String, Value)>>) {
    stub_with(|_| replies)
}

fn serve(
    server: tiny_http::Server,
    replies: Vec<(u16, Value)>,
) -> thread::JoinHandle<Vec<(String, Value)>> {
    thread::spawn(move || {
        let mut seen = Vec::new();
        for (status, body) in replies {
            let mut req = server.recv().unwrap();
            let mut text = String::new();
            req.as_reader().read_to_string(&mut text).unwrap();
            assert_eq!(req.method(), &tiny_http::Method::Post);
            seen.push((req.url().to_owned(), serde_json::from_str(&text).unwrap()));
            let resp = tiny_http::Response::from_string(body.to_string())
                .with_status_code(status)
                .with_header(
                    "Content-Type: application/json"
                        .parse::<tiny_http::Header>()
                        .unwrap(),
                );
            req.respond(resp).unwrap();
        }
        seen
    })
}

#[test]
fn login_posts_challenge_then_signed_login_and_returns_only_the_token() {
    let mut chal = String::new();
    let (url, h) = stub_with(|url| {
        chal = challenge_for(url);
        vec![
            (200, json!({"data": {"challenge": chal, "expires_in": 60}})),
            (
                200,
                json!({"auth": {"client_token": "ekms.tok", "lease_duration": 3600}}),
            ),
        ]
    });
    let token = login::login_ssh(
        &UreqTransport::new(),
        &FakeSigner("-----BEGIN SSH SIGNATURE-----\nAAA\n-----END SSH SIGNATURE-----\n"),
        &url,
        "ssh",
        "operator",
    )
    .unwrap();
    assert_eq!(token, "ekms.tok");
    let seen = h.join().unwrap();
    assert_eq!(seen[0].0, "/v1/auth/ssh/challenge");
    assert_eq!(seen[0].1, json!({"role": "operator"}));
    assert_eq!(seen[1].0, "/v1/auth/ssh/login");
    assert_eq!(
        seen[1].1,
        json!({
            "role": "operator",
            "challenge": chal,
            "signature": "-----BEGIN SSH SIGNATURE-----\nAAA\n-----END SSH SIGNATURE-----\n"
        })
    );
}

#[test]
fn custom_mount_goes_into_the_path() {
    let (url, h) = stub_with(|url| {
        vec![
            (200, json!({"data": {"challenge": challenge_for(url)}})),
            (200, json!({"auth": {"client_token": "t"}})),
        ]
    });
    login::login_ssh(
        &UreqTransport::new(),
        &FakeSigner("s"),
        &url,
        "ops-ssh",
        "r",
    )
    .unwrap();
    let seen = h.join().unwrap();
    assert_eq!(seen[0].0, "/v1/auth/ops-ssh/challenge");
    assert_eq!(seen[1].0, "/v1/auth/ops-ssh/login");
}

#[test]
fn rejected_login_surfaces_the_servers_error_and_no_token() {
    let (url, h) = stub_with(|url| {
        vec![
            (200, json!({"data": {"challenge": challenge_for(url)}})),
            (400, json!({"errors": ["permission denied"]})),
        ]
    });
    let err =
        login::login_ssh(&UreqTransport::new(), &FakeSigner("s"), &url, "ssh", "r").unwrap_err();
    h.join().unwrap();
    assert!(err.to_string().contains("permission denied"), "{err}");
    assert!(err.to_string().contains("400"), "{err}");
}

#[test]
fn signer_failure_stops_before_the_login_request() {
    struct Failing;
    impl Signer for Failing {
        fn sign(&self, _: &str, _: &str) -> Result<String, LoginError> {
            Err(LoginError::Sign("no agent".into()))
        }
    }
    let (url, h) = stub_with(|url| vec![(200, json!({"data": {"challenge": challenge_for(url)}}))]);
    let err = login::login_ssh(&UreqTransport::new(), &Failing, &url, "ssh", "r").unwrap_err();
    assert!(err.to_string().contains("no agent"), "{err}");
    assert_eq!(h.join().unwrap().len(), 1);
}

#[test]
fn transport_trait_is_injectable() {
    struct Canned;
    impl Transport for Canned {
        fn post(&self, url: &str, body: Body<'_>) -> Result<HttpReply, LoginError> {
            let body = if url.ends_with("/challenge") {
                assert!(matches!(body, Body::Json(v) if v == &json!({"role": "r"})));
                json!({"data": {"challenge": challenge_for("https://kms.example")}})
            } else {
                json!({"auth": {"client_token": "canned"}})
            };
            Ok(HttpReply { status: 200, body })
        }
    }
    let t = login::login_ssh(&Canned, &FakeSigner("s"), "https://kms.example", "ssh", "r").unwrap();
    assert_eq!(t, "canned");
}

#[test]
fn plain_http_is_refused_except_for_loopback() {
    for ok in [
        "https://kms.example.com",
        "https://kms.example.com:8443/",
        "http://127.0.0.1:8787",
        "http://localhost:8787",
        "http://[::1]:8787",
    ] {
        assert!(check_addr(ok).is_ok(), "{ok}");
    }
    for bad in [
        "http://kms.example.com",
        "http://127.0.0.1.evil.com",
        "http://localhost@evil.com",
        "http://localhost.evil.com:80",
        "ftp://kms.example.com",
        "kms.example.com",
    ] {
        assert!(check_addr(bad).is_err(), "{bad}");
    }
    let err = login::login_ssh(
        &UreqTransport::new(),
        &FakeSigner("s"),
        "http://kms.example.com",
        "ssh",
        "r",
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::Insecure(_)), "{err}");
}

#[test]
fn names_under_localhost_pass_without_a_lookup() {
    // No resolver is asked, here or when the request goes out (the next test), so these pass
    // whatever the system resolver would say about them.
    for ok in [
        "http://alice.localhost:8787",
        "http://API.localhost:8787/",
        "http://a.b.localhost",
    ] {
        assert!(check_addr(ok).is_ok(), "{ok}");
    }
    for bad in [
        "http://.localhost:8787",
        "http://alice.localhost.evil.com:8787",
        "http://alice_x.localhost:8787",
        "http://localhost@alice.localhost:8787",
        "http://alicelocalhost:8787",
    ] {
        assert!(check_addr(bad).is_err(), "{bad}");
    }
}

#[test]
fn names_under_localhost_connect_to_loopback_without_a_lookup() {
    // The stub listens on 127.0.0.1 only. `edgekms-test-nonexistent.localhost` reaches it
    // because the transport maps every .localhost name to loopback itself; the Host header
    // still names the tenant, as wrangler dev routes on it.
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let h = thread::spawn(move || {
        let req = server.recv().unwrap();
        let host = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| h.value.to_string());
        req.respond(tiny_http::Response::from_string(r#"{"ok": true}"#))
            .unwrap();
        host
    });
    let url = format!("http://edgekms-test-nonexistent.localhost:{port}/v1/sys/health");
    let reply = UreqTransport::new().get(check_addr(&url).unwrap()).unwrap();
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, json!({"ok": true}));
    assert_eq!(
        h.join().unwrap().as_deref(),
        Some(format!("edgekms-test-nonexistent.localhost:{port}").as_str())
    );
}

#[test]
fn github_stub_endpoints_are_loopback_http_only() {
    let (code, token) = login::stub_endpoints("http://127.0.0.1:9000/").unwrap();
    assert_eq!(code, "http://127.0.0.1:9000/login/device/code");
    assert_eq!(token, "http://127.0.0.1:9000/login/oauth/access_token");
    for bad in [
        "https://github.example",
        "http://github.example",
        "https://127.0.0.1:9000",
    ] {
        let err = login::stub_endpoints(bad).unwrap_err();
        assert!(matches!(err, LoginError::Insecure(_)), "{bad}: {err}");
    }
}

#[test]
fn bad_mount_names_are_refused() {
    let err = login::login_ssh(
        &UreqTransport::new(),
        &FakeSigner("s"),
        "https://k.example",
        "a/../b",
        "r",
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::BadMount(_)), "{err}");
}

#[test]
fn ssh_keygen_signs_with_the_namespace_it_is_given() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let allowed = dir.path().join("allowed");
    let pubkey = std::fs::read_to_string(dir.path().join("id.pub")).unwrap();
    std::fs::write(&allowed, format!("op {pubkey}")).unwrap();
    let sigfile = dir.path().join("sig");
    let verify = |ns: &str| {
        use std::io::Write;
        let mut c = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-I", "op", "-n", ns, "-f"])
            .arg(&allowed)
            .arg("-s")
            .arg(&sigfile)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(b"ekmsc.abc").unwrap();
        c.wait().unwrap().success()
    };
    for (ns, other) in [
        (login::NAMESPACE, ssh::REGISTER_NAMESPACE),
        (ssh::REGISTER_NAMESPACE, login::NAMESPACE),
    ] {
        // Test only: the private key path stands in for the agent. Production passes the .pub
        // path.
        let sig = SshKeygen::new(&key).sign(ns, "ekmsc.abc").unwrap();
        assert!(sig.starts_with("-----BEGIN SSH SIGNATURE-----"), "{sig}");
        // ssh-keygen itself accepts it only under the namespace it was signed with.
        std::fs::write(&sigfile, &sig).unwrap();
        assert!(verify(ns), "{ns}");
        assert!(!verify(other), "{ns} verified as {other}");
        assert!(!verify("other"));
    }
}

#[test]
fn ssh_keygen_failure_surfaces_its_stderr() {
    let err = SshKeygen::new(Path::new("/nonexistent/key.pub"))
        .sign(login::NAMESPACE, "ekmsc.abc")
        .unwrap_err();
    assert!(
        matches!(err, LoginError::Sign(ref m) if !m.is_empty()),
        "{err}"
    );
}

struct NeverSign;

impl Signer for NeverSign {
    fn sign(&self, _: &str, challenge: &str) -> Result<String, LoginError> {
        panic!("asked to sign {challenge}");
    }
}

#[test]
fn challenge_for_another_origin_is_never_signed() {
    // A hostile server relays a genuine challenge it fetched from another deployment.
    let (url, h) = stub(vec![(
        200,
        json!({"data": {"challenge": challenge_for("https://kms.victim.example")}}),
    )]);
    let err = login::login_ssh(&UreqTransport::new(), &NeverSign, &url, "ssh", "r").unwrap_err();
    assert!(matches!(err, LoginError::WrongOrigin { .. }), "{err}");
    assert!(err.to_string().contains("kms.victim.example"), "{err}");
    assert_eq!(h.join().unwrap().len(), 1, "no login request may follow");
}

#[test]
fn malformed_or_oversized_challenges_are_never_signed() {
    let huge = format!("ekmsc.{}", "A".repeat(4096));
    for bad in ["ekmsc.abc", "sign me", huge.as_str()] {
        let (url, h) = stub(vec![(200, json!({"data": {"challenge": bad}}))]);
        let err =
            login::login_ssh(&UreqTransport::new(), &NeverSign, &url, "ssh", "r").unwrap_err();
        assert!(matches!(err, LoginError::Response(_)), "{err}");
        h.join().unwrap();
    }
}

#[test]
fn origin_comparison_ignores_default_ports_case_and_trailing_slashes() {
    struct Canned(String);
    impl Transport for Canned {
        fn post(&self, url: &str, _: Body<'_>) -> Result<HttpReply, LoginError> {
            let body = if url.ends_with("/challenge") {
                json!({"data": {"challenge": challenge_for(&self.0)}})
            } else {
                json!({"auth": {"client_token": "t"}})
            };
            Ok(HttpReply { status: 200, body })
        }
    }
    let canned = Canned("https://kms.example.com".into());
    for addr in ["https://KMS.example.com/", "https://kms.example.com:443"] {
        assert!(
            login::login_ssh(&canned, &FakeSigner("s"), addr, "ssh", "r").is_ok(),
            "{addr}"
        );
    }
}

#[test]
fn redirects_are_never_followed() {
    // The redirect target would see the login body; it must see nothing.
    let target = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let target_url = format!("http://{}", target.server_addr().to_ip().unwrap());
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}", server.server_addr().to_ip().unwrap());
    let h = thread::spawn(move || {
        let req = server.recv().unwrap();
        let resp = tiny_http::Response::empty(307).with_header(
            format!("Location: {target_url}/v1/auth/ssh/challenge")
                .parse::<tiny_http::Header>()
                .unwrap(),
        );
        req.respond(resp).unwrap();
    });
    let err = login::login_ssh(&UreqTransport::new(), &NeverSign, &url, "ssh", "r").unwrap_err();
    h.join().unwrap();
    assert!(
        matches!(err, LoginError::Rejected { status: 307, .. }),
        "{err}"
    );
    assert!(
        target
            .recv_timeout(std::time::Duration::from_millis(200))
            .unwrap()
            .is_none(),
        "the redirect was followed"
    );
}

#[test]
fn a_server_that_never_answers_times_out() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let started = std::time::Instant::now();
    let err = login::login_ssh(
        &UreqTransport::with_timeout(std::time::Duration::from_millis(300)),
        &NeverSign,
        &url,
        "ssh",
        "r",
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::Http(_)), "{err}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    drop(listener);
}

#[test]
fn ipv6_loopback_and_literal_addresses_match_their_challenges() {
    struct Canned(String);
    impl Transport for Canned {
        fn post(&self, url: &str, _: Body<'_>) -> Result<HttpReply, LoginError> {
            let body = if url.ends_with("/challenge") {
                json!({"data": {"challenge": challenge_for(&self.0)}})
            } else {
                json!({"auth": {"client_token": "t"}})
            };
            Ok(HttpReply { status: 200, body })
        }
    }
    for (addr, origin) in [
        ("http://[::1]:8787", "http://[::1]:8787"),
        ("https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"),
        ("https://[2001:DB8::1]:443", "https://[2001:db8::1]"),
    ] {
        assert_eq!(login::origin_of(check_addr(addr).unwrap()).unwrap(), origin);
        let canned = Canned(origin.to_owned());
        assert!(
            login::login_ssh(&canned, &FakeSigner("s"), addr, "ssh", "r").is_ok(),
            "{addr}"
        );
    }
    // The bracketed loopback is loopback; another literal over plain http is not.
    assert!(check_addr("http://[2001:db8::1]:8787").is_err());
}
