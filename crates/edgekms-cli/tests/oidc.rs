//! `login oidc` against a stub that plays the identity provider and the Worker, with a fake
//! browser that follows the authorization URL straight back to the loopback listener.

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Seen, routed};
use edgekms_cli::login::{self, Browser, LoginError, OidcClient, UreqTransport};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Params = Arc<Mutex<HashMap<String, String>>>;

/// What the fake browser sends back to the redirect URI.
#[derive(Clone, Copy)]
enum Reply {
    Code,
    WrongState,
    WrongStateThenCode,
    Denied,
    Nothing,
    /// Connects to the redirect URI and sends a request one byte at a time, never finishing.
    Trickle,
}

struct FakeBrowser {
    params: Params,
    reply: Reply,
    opened: Mutex<Vec<String>>,
}

impl FakeBrowser {
    fn new(params: &Params, reply: Reply) -> Self {
        Self {
            params: params.clone(),
            reply,
            opened: Mutex::new(Vec::new()),
        }
    }
}

/// A raw GET, as a browser following the redirect would send.
fn browser_get(url: &str) {
    let u = url::Url::parse(url).unwrap();
    let mut s = TcpStream::connect((u.host_str().unwrap(), u.port().unwrap())).unwrap();
    let target = format!("{}?{}", u.path(), u.query().unwrap_or_default());
    write!(s, "GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
    let mut s = TcpStream::connect((u.host_str().unwrap(), u.port().unwrap())).unwrap();
    write!(s, "GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let _ = s.read_to_end(&mut sink);
}

impl Browser for FakeBrowser {
    fn open(&self, url: &str) -> Result<(), LoginError> {
        self.opened.lock().unwrap().push(url.to_owned());
        let u = url::Url::parse(url).unwrap();
        let p: HashMap<String, String> = u.query_pairs().into_owned().collect();
        self.params.lock().unwrap().clone_from(&p);
        let redirect = p["redirect_uri"].clone();
        let back = match self.reply {
            Reply::Code => format!("{redirect}?code=the-code&state={}", p["state"]),
            Reply::WrongState => format!("{redirect}?code=the-code&state=forged"),
            Reply::WrongStateThenCode => {
                let forged = format!("{redirect}?code=evil-code&state=forged");
                let good = format!("{redirect}?code=the-code&state={}", p["state"]);
                std::thread::spawn(move || {
                    browser_get(&forged);
                    browser_get(&good);
                });
                return Ok(());
            }
            Reply::Denied => format!(
                "{redirect}?error=access_denied&error_description=nope&state={}",
                p["state"]
            ),
            Reply::Nothing => return Ok(()),
            Reply::Trickle => {
                let u = url::Url::parse(&redirect).unwrap();
                let addr = (u.host_str().unwrap().to_owned(), u.port().unwrap());
                std::thread::spawn(move || {
                    let mut s = TcpStream::connect(addr).unwrap();
                    // Until the listener gives up on it and the write fails, or 30 s.
                    for _ in 0..300 {
                        if s.write_all(b"G").is_err() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                });
                return Ok(());
            }
        };
        std::thread::spawn(move || browser_get(&back));
        Ok(())
    }
}

fn id_token(nonce: &str) -> String {
    let enc = |v: Value| URL_SAFE_NO_PAD.encode(v.to_string());
    format!(
        "{}.{}.c2ln",
        enc(json!({"alg": "RS256", "kid": "k"})),
        enc(json!({"iss": "x", "sub": "user-1", "nonce": nonce}))
    )
}

/// The identity provider's discovery and token endpoints plus the Worker's login, all on one stub. The token
/// endpoint checks the PKCE verifier against the challenge the browser carried.
fn idp(
    params: &Params,
    nonce_override: Option<&'static str>,
) -> (String, std::thread::JoinHandle<Vec<Seen>>) {
    let params = params.clone();
    routed(10, move |base, s| match s.url.as_str() {
        "/.well-known/openid-configuration" => (
            200,
            json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "code_challenge_methods_supported": ["S256"]
            }),
        ),
        "/token" => {
            let p = params.lock().unwrap();
            let verifier = s.form("code_verifier").unwrap();
            let ok = s.form("grant_type").as_deref() == Some("authorization_code")
                && s.form("code").as_deref() == Some("the-code")
                && s.form("redirect_uri").as_ref() == p.get("redirect_uri")
                && s.form("client_id").as_deref() == Some("cli-client")
                && URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
                    == p["code_challenge"];
            if !ok {
                return (400, json!({"error": "invalid_grant"}));
            }
            let nonce = nonce_override.unwrap_or(&p["nonce"]);
            (
                200,
                json!({"id_token": id_token(nonce), "access_token": "at", "token_type": "Bearer"}),
            )
        }
        "/v1/auth/oidc/login" => (200, json!({"auth": {"client_token": "ekms.oidc"}})),
        other => panic!("unexpected {other}"),
    })
}

fn client(issuer: &str) -> OidcClient<'_> {
    OidcClient {
        issuer,
        client_id: "cli-client",
        client_secret: None,
        scopes: "openid email",
        port: 0,
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn authorization_code_with_pkce_logs_in_with_the_id_token() {
    let params = Params::default();
    let (base, h) = idp(&params, None);
    let browser = FakeBrowser::new(&params, Reply::Code);
    let tok = login::login_oidc(
        &UreqTransport::new(),
        &browser,
        &client(&base),
        &base,
        "oidc",
        "op",
    )
    .unwrap();
    assert_eq!(tok, "ekms.oidc");

    let p = params.lock().unwrap().clone();
    assert_eq!(p["response_type"], "code");
    assert_eq!(p["client_id"], "cli-client");
    assert_eq!(p["scope"], "openid email");
    assert_eq!(p["code_challenge_method"], "S256");
    assert!(p["redirect_uri"].starts_with("http://127.0.0.1:"));
    assert!(p["redirect_uri"].ends_with("/oidc/callback"));
    assert!(p["state"].len() >= 22 && p["nonce"].len() >= 22);

    let seen = h.join().unwrap();
    let login = seen
        .iter()
        .find(|s| s.url == "/v1/auth/oidc/login")
        .unwrap();
    assert_eq!(
        login.json(),
        json!({"role": "op", "jwt": id_token(&p["nonce"])})
    );
    // The browser is shown the authorization URL, never the ID token.
    let opened = browser.opened.lock().unwrap();
    assert!(opened[0].starts_with(&format!("{base}/authorize?")));
    assert!(!opened[0].contains(&id_token(&p["nonce"])));
}

#[test]
fn reply_with_the_wrong_state_is_ignored_and_never_exchanged() {
    // Another page can make the browser hit the loopback; that mustn't end or hijack the login.
    let params = Params::default();
    let (base, h) = idp(&params, None);
    let mut c = client(&base);
    c.timeout = Duration::from_millis(500);
    let err = login::login_oidc(
        &UreqTransport::new(),
        &FakeBrowser::new(&params, Reply::WrongState),
        &c,
        &base,
        "oidc",
        "op",
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::Timeout(_)), "{err}");
    assert!(h.join().unwrap().iter().all(|s| s.url != "/token"));
}

#[test]
fn the_real_reply_after_a_forged_one_still_logs_in() {
    let params = Params::default();
    let (base, h) = idp(&params, None);
    let tok = login::login_oidc(
        &UreqTransport::new(),
        &FakeBrowser::new(&params, Reply::WrongStateThenCode),
        &client(&base),
        &base,
        "oidc",
        "op",
    )
    .unwrap();
    assert_eq!(tok, "ekms.oidc");
    let seen = h.join().unwrap();
    let exchanges: Vec<_> = seen.iter().filter(|s| s.url == "/token").collect();
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].form("code").as_deref(), Some("the-code"));
}

#[test]
fn provider_refusal_is_reported() {
    let params = Params::default();
    let (base, h) = idp(&params, None);
    let err = login::login_oidc(
        &UreqTransport::new(),
        &FakeBrowser::new(&params, Reply::Denied),
        &client(&base),
        &base,
        "oidc",
        "op",
    )
    .unwrap_err();
    assert!(err.to_string().contains("access_denied: nope"), "{err}");
    h.join().unwrap();
}

#[test]
fn id_token_with_another_nonce_is_never_sent_to_the_worker() {
    let params = Params::default();
    let (base, h) = idp(&params, Some("someone-elses-nonce"));
    let err = login::login_oidc(
        &UreqTransport::new(),
        &FakeBrowser::new(&params, Reply::Code),
        &client(&base),
        &base,
        "oidc",
        "op",
    )
    .unwrap_err();
    assert!(err.to_string().contains("nonce"), "{err}");
    assert!(!err.to_string().contains(&id_token("someone-elses-nonce")));
    assert!(h.join().unwrap().iter().all(|s| !s.url.starts_with("/v1/")));
}

#[test]
fn rejected_worker_login_never_echoes_the_id_token() {
    let params = Params::default();
    let inner = params.clone();
    let (base, h) = routed(10, move |base, s| match s.url.as_str() {
        "/.well-known/openid-configuration" => (
            200,
            json!({"issuer": base, "authorization_endpoint": format!("{base}/a"),
                   "token_endpoint": format!("{base}/t")}),
        ),
        "/t" => (
            200,
            json!({"id_token": id_token(&inner.lock().unwrap()["nonce"])}),
        ),
        _ => (400, json!({"errors": ["permission denied"]})),
    });
    let err = login::login_oidc(
        &UreqTransport::new(),
        &FakeBrowser::new(&params, Reply::Code),
        &client(&base),
        &base,
        "oidc",
        "op",
    )
    .unwrap_err();
    h.join().unwrap();
    let token = id_token(&params.lock().unwrap()["nonce"]);
    assert!(err.to_string().contains("permission denied"), "{err}");
    assert!(!format!("{err} {err:?}").contains(&token));
}

#[test]
fn discovery_naming_another_issuer_is_refused() {
    let (base, h) = routed(1, |_, _| {
        (
            200,
            json!({"issuer": "https://evil.example", "authorization_endpoint": "https://evil.example/a",
                   "token_endpoint": "https://evil.example/t"}),
        )
    });
    let err = login::oidc_id_token(
        &UreqTransport::new(),
        &FakeBrowser::new(&Params::default(), Reply::Nothing),
        &client(&base),
    )
    .unwrap_err();
    assert!(err.to_string().contains("different issuer"), "{err}");
    h.join().unwrap();
}

#[test]
fn plain_http_endpoints_are_refused() {
    let (base, h) = routed(1, |base, _| {
        (
            200,
            json!({"issuer": base, "authorization_endpoint": "http://idp.example/a",
                   "token_endpoint": format!("{base}/t")}),
        )
    });
    let err = login::oidc_id_token(
        &UreqTransport::new(),
        &FakeBrowser::new(&Params::default(), Reply::Nothing),
        &client(&base),
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::Insecure(_)), "{err}");
    h.join().unwrap();
    let err = login::oidc_id_token(
        &UreqTransport::new(),
        &FakeBrowser::new(&Params::default(), Reply::Nothing),
        &client("http://idp.example"),
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::Insecure(_)), "{err}");
}

#[test]
fn a_browser_that_never_returns_times_out() {
    let params = Params::default();
    let (base, h) = idp(&params, None);
    let mut c = client(&base);
    c.timeout = Duration::from_millis(300);
    let err = login::oidc_id_token(
        &UreqTransport::new(),
        &FakeBrowser::new(&params, Reply::Nothing),
        &c,
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::Timeout(_)), "{err}");
    h.join().unwrap();
}

#[test]
fn a_callback_trickled_in_slowly_still_times_out_at_the_deadline() {
    // Each read used to have its own 5 s timeout and the deadline was checked only while no
    // connection was waiting, so one client sending a byte at a time held the login open for
    // hours. The deadline now bounds every read.
    let params = Params::default();
    let (base, h) = idp(&params, None);
    let mut c = client(&base);
    c.timeout = Duration::from_secs(1);
    let started = std::time::Instant::now();
    let err = login::oidc_id_token(
        &UreqTransport::new(),
        &FakeBrowser::new(&params, Reply::Trickle),
        &c,
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::Timeout(_)), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "took {:?}",
        started.elapsed()
    );
    h.join().unwrap();
}

#[test]
fn debug_leaves_out_the_client_secret() {
    let mut c = client("https://idp.example");
    c.client_secret = Some("very-secret-value");
    let shown = format!("{c:?}");
    assert!(!shown.contains("very-secret-value"), "{shown}");
    assert!(shown.contains("<redacted>"), "{shown}");
    assert!(shown.contains("cli-client"), "{shown}");
}
