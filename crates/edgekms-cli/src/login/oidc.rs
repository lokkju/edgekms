//! `login oidc`: the OIDC authorization code flow with PKCE (S256) through a browser and
//! a loopback redirect on 127.0.0.1 (RFC 8252), then the ID token to a JWT mount. Works with
//! any provider that publishes a discovery document: Google, Clerk, Cloudflare Access, others.
//!
//! The ID token is a bearer credential for the Worker: it is never printed, logged or put in an
//! error message, and is zeroized after use.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Body, LoginError, Transport, check_addr, check_mount, vault_login, zeroize_json};

/// The path the provider redirects back to on the loopback listener.
pub const CALLBACK_PATH: &str = "/oidc/callback";
/// Largest callback request read from the browser.
const MAX_CALLBACK_BYTES: usize = 16 * 1024;
/// How long one connection to the loopback listener may take to send its request.
const REQUEST_SECS: u64 = 5;

/// The provider and the client registered with it. Its `Debug` leaves out the client secret.
#[derive(Clone)]
pub struct OidcClient<'a> {
    /// The issuer URL; its discovery document must name exactly this issuer.
    pub issuer: &'a str,
    pub client_id: &'a str,
    /// Some providers (Google's desktop clients) issue a secret even to public clients.
    pub client_secret: Option<&'a str>,
    /// Space-separated; must include `openid`.
    pub scopes: &'a str,
    /// Port for `http://127.0.0.1:<port>/oidc/callback`; 0 picks a free one. Providers that
    /// match redirect URIs exactly need the registered port.
    pub port: u16,
    /// How long to wait for the browser to come back.
    pub timeout: Duration,
}

impl std::fmt::Debug for OidcClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcClient")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.map(|_| "<redacted>"))
            .field("scopes", &self.scopes)
            .field("port", &self.port)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Shows the operator the authorization URL.
pub trait Browser {
    /// # Errors
    /// Only if the operator can't be shown the URL at all.
    fn open(&self, url: &str) -> Result<(), LoginError>;
}

/// Prints the URL to stderr and, unless told not to, asks the desktop to open it.
pub struct SystemBrowser {
    pub launch: bool,
}

impl Browser for SystemBrowser {
    fn open(&self, url: &str) -> Result<(), LoginError> {
        eprintln!("Open this URL in a browser to log in:\n\n    {url}\n");
        if self.launch {
            let (cmd, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
                ("open", &[])
            } else if cfg!(windows) {
                ("rundll32", &["url.dll,FileProtocolHandler"])
            } else {
                ("xdg-open", &[])
            };
            // Best effort: the printed URL works without it.
            let _ = Command::new(cmd)
                .args(args)
                .arg(url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }
        Ok(())
    }
}

fn random_b64(n: usize) -> Result<String, LoginError> {
    let mut buf = Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut buf).map_err(|_| LoginError::Http("no system randomness".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(&*buf))
}

struct Endpoints {
    authorization: String,
    token: String,
}

/// Fetches the discovery document and checks it names `issuer` and offers S256 PKCE.
fn discover(t: &impl Transport, issuer: &str) -> Result<Endpoints, LoginError> {
    let url = format!("{issuer}/.well-known/openid-configuration");
    let reply = t.get(&url)?;
    if !reply.ok() || !reply.body.is_object() {
        return Err(LoginError::Rejected {
            status: reply.status,
            message: format!("no OpenID discovery document at {url}"),
        });
    }
    let doc = reply.body;
    let named = doc["issuer"].as_str().unwrap_or_default();
    if named.trim_end_matches('/') != issuer {
        return Err(LoginError::Response(
            "the discovery document names a different issuer",
        ));
    }
    if let Some(methods) = doc["code_challenge_methods_supported"].as_array()
        && !methods.iter().any(|m| m == "S256")
    {
        return Err(LoginError::Response(
            "the provider doesn't support S256 PKCE",
        ));
    }
    let endpoint = |name: &str, what| -> Result<String, LoginError> {
        let u = doc[name].as_str().ok_or(LoginError::Response(what))?;
        Ok(check_addr(u)?.to_owned())
    };
    Ok(Endpoints {
        authorization: endpoint(
            "authorization_endpoint",
            "the discovery document has no authorization_endpoint",
        )?,
        token: endpoint(
            "token_endpoint",
            "the discovery document has no token_endpoint",
        )?,
    })
}

/// What came back to the loopback listener.
enum Callback {
    Code(Zeroizing<String>),
    Error(String),
}

/// Answers the browser with a fixed plain-text page; nothing from the request is echoed.
fn respond(stream: &mut TcpStream, status: &str, text: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.flush();
}

/// The request target of one HTTP request, read with a bound on size and time: the whole
/// request must arrive within [`REQUEST_SECS`] and before `deadline`, however slowly a client
/// trickles it in. Writes to the stream get the same bound.
fn read_target(stream: &mut TcpStream, deadline: Instant) -> Option<String> {
    let deadline = deadline.min(Instant::now() + Duration::from_secs(REQUEST_SECS));
    stream.set_nonblocking(false).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(REQUEST_SECS)))
        .ok()?;
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_CALLBACK_BYTES));
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < MAX_CALLBACK_BYTES {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        stream.set_read_timeout(Some(left)).ok()?;
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    chunk.fill(0);
    let line = buf.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split_whitespace();
    (parts.next()? == "GET").then_some(())?;
    parts.next().map(str::to_owned)
}

/// Waits for the provider's redirect until `deadline`. Requests for other paths (a browser's
/// favicon) get a 404 and callbacks with the wrong `state` a 400; the wait goes on after both.
fn await_callback(
    listener: &TcpListener,
    state: &str,
    deadline: Instant,
) -> Result<Callback, LoginError> {
    listener
        .set_nonblocking(true)
        .map_err(|e| LoginError::Http(e.to_string()))?;
    loop {
        // Checked on every pass, not only when no connection is waiting: a stream of
        // connections (or one slow one) must not keep the wait going past the deadline.
        if Instant::now() >= deadline {
            return Err(LoginError::Timeout(
                "no reply from the browser; run the login again",
            ));
        }
        let mut stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => return Err(LoginError::Http(e.to_string())),
        };
        let Some(target) = read_target(&mut stream, deadline) else {
            respond(&mut stream, "400 Bad Request", "bad request");
            continue;
        };
        let target = Zeroizing::new(target);
        let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{}", target.as_str())) else {
            respond(&mut stream, "400 Bad Request", "bad request");
            continue;
        };
        if url.path() != CALLBACK_PATH {
            respond(&mut stream, "404 Not Found", "not found");
            continue;
        }
        let mut got_state = None;
        let mut code = None;
        let mut error = None;
        let mut description = None;
        for (k, v) in url.query_pairs() {
            match &*k {
                "state" => got_state = Some(v.into_owned()),
                "code" => code = Some(Zeroizing::new(v.into_owned())),
                "error" => error = Some(v.into_owned()),
                "error_description" => description = Some(v.into_owned()),
                _ => {}
            }
        }
        if got_state.as_deref() != Some(state) {
            // Not from the authorization this process started (another page can make the
            // browser call the loopback): refuse it and keep waiting for the real one.
            respond(
                &mut stream,
                "400 Bad Request",
                "edgekms: this login reply doesn't match the login in progress.",
            );
            continue;
        }
        if let Some(e) = error {
            respond(
                &mut stream,
                "200 OK",
                "edgekms: the login was refused. See the terminal.",
            );
            let msg = match description {
                Some(d) => format!("{e}: {d}"),
                None => e,
            };
            return Ok(Callback::Error(msg));
        }
        let Some(code) = code else {
            respond(&mut stream, "400 Bad Request", "bad request");
            return Err(LoginError::Response("the provider's reply had no code"));
        };
        respond(
            &mut stream,
            "200 OK",
            "edgekms: login complete. You can close this tab.",
        );
        return Ok(Callback::Code(code));
    }
}

/// The `nonce` claim of an ID token, read without verifying it (the Worker verifies).
fn nonce_of(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(payload).ok()?);
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims["nonce"].as_str().map(str::to_owned)
}

/// Runs the browser flow and returns the ID token.
///
/// # Errors
/// [`LoginError::Authorization`] if the provider refuses, [`LoginError::Timeout`] if the
/// browser never comes back, or a transport, discovery or reply error.
pub fn oidc_id_token(
    t: &impl Transport,
    browser: &impl Browser,
    client: &OidcClient<'_>,
) -> Result<Zeroizing<String>, LoginError> {
    let issuer = check_addr(client.issuer)?;
    let endpoints = discover(t, issuer)?;

    let listener = TcpListener::bind(("127.0.0.1", client.port)).map_err(|e| {
        LoginError::Http(format!("cannot listen on 127.0.0.1:{}: {e}", client.port))
    })?;
    let port = listener
        .local_addr()
        .map_err(|e| LoginError::Http(e.to_string()))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");

    let verifier = Zeroizing::new(random_b64(32)?);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_b64(16)?;
    let nonce = random_b64(16)?;
    let mut auth_url = url::Url::parse(&endpoints.authorization)
        .map_err(|_| LoginError::Response("the authorization_endpoint is not a URL"))?;
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", client.scopes)
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    browser.open(auth_url.as_str())?;

    let code = match await_callback(&listener, &state, Instant::now() + client.timeout)? {
        Callback::Code(c) => c,
        Callback::Error(e) => return Err(LoginError::Authorization(e)),
    };
    drop(listener);

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", client.client_id),
        ("code_verifier", verifier.as_str()),
    ];
    if let Some(secret) = client.client_secret {
        form.push(("client_secret", secret));
    }
    let mut reply = t.post(&endpoints.token, Body::Form(&form))?;
    let id_token = reply.body["id_token"]
        .as_str()
        .map(|s| Zeroizing::new(s.to_owned()));
    let failure = id_token
        .is_none()
        .then(|| token_error(reply.status, &reply.body));
    // The reply also holds access and refresh tokens; none of it is kept.
    zeroize_json(&mut reply.body);
    let Some(id_token) = id_token else {
        return Err(failure.unwrap_or(LoginError::Response("no ID token")));
    };
    if nonce_of(&id_token).as_deref() != Some(nonce.as_str()) {
        return Err(LoginError::Response(
            "the ID token's nonce doesn't match this login",
        ));
    }
    Ok(id_token)
}

/// Why a token reply had no ID token: the provider's OAuth error code and description if it
/// sent one (these never carry credentials), else a fixed message.
fn token_error(status: u16, body: &Value) -> LoginError {
    match body["error"].as_str() {
        Some(code) => LoginError::Authorization(match body["error_description"].as_str() {
            Some(d) => format!("{code}: {d}"),
            None => code.to_owned(),
        }),
        None => LoginError::Rejected {
            status,
            message: "the token endpoint returned no ID token".into(),
        },
    }
}

/// The whole login: browser flow, then the ID token to `auth/<mount>/login` as
/// `{"role", "jwt"}`. Returns the edgekms client token. The address and mount are checked
/// before the provider is contacted.
///
/// # Errors
/// A [`LoginError`] from the checks, the browser flow, or the Worker.
pub fn login_oidc(
    t: &impl Transport,
    browser: &impl Browser,
    client: &OidcClient<'_>,
    addr: &str,
    mount: &str,
    role: &str,
) -> Result<String, LoginError> {
    let addr = check_addr(addr)?;
    check_mount(mount)?;
    let id_token = oidc_id_token(t, browser, client)?;
    vault_login(t, addr, mount, role, "jwt", &id_token)
}
