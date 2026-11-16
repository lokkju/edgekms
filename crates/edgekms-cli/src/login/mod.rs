//! Operator login: each method ends by posting a credential to `auth/<mount>/login` on the
//! Worker and returning only the edgekms token.
//!
//! - [`login_ssh`]: a challenge signed through ssh-agent.
//! - [`login_github`]: GitHub's OAuth device flow, for a machine without the operator's agent.
//! - [`login_oidc`]: authorization code with PKCE in a browser, through a loopback redirect.
//!
//! Every HTTP call goes through [`Transport`], so tests run against stub servers. No credential
//! (signature, GitHub token, ID token) is ever printed or put in an error message.

mod github;
mod oidc;
mod ssh;

use std::io::Read;
use std::time::Duration;

use serde_json::{Value, json};
use zeroize::Zeroizing;

pub use github::{
    DeviceFlow, DevicePrompt, GITHUB_DEVICE_CODE_URL, GITHUB_OAUTH_BASE_ENV, GITHUB_TOKEN_URL,
    github_device_token, login_github, stub_endpoints,
};
pub use oidc::{Browser, OidcClient, SystemBrowser, login_oidc, oidc_id_token};
pub use ssh::{NAMESPACE, REGISTER_NAMESPACE, Signer, SshKeygen, login_ssh};

/// How long one HTTP exchange may take, connect to last byte.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest reply body read.
const MAX_REPLY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error(
        "refusing {0}: plain http is allowed only for 127.0.0.1, ::1, localhost and names \
         under localhost"
    )]
    Insecure(String),
    #[error("{0:?} is not an http(s) URL")]
    BadAddr(String),
    #[error("mount name {0:?} must be letters, digits, '-' or '_'")]
    BadMount(String),
    #[error("request failed: {0}")]
    Http(String),
    #[error("login failed (HTTP {status}): {message}")]
    Rejected { status: u16, message: String },
    #[error("unexpected response from the server: {0}")]
    Response(&'static str),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error(
        "refusing to sign: the challenge was issued for {got}, not {expected}; \
         the server may be relaying another deployment's challenge"
    )]
    WrongOrigin { expected: String, got: String },
    /// An OAuth or OIDC provider refused; carries its error code and description.
    #[error("authorization failed: {0}")]
    Authorization(String),
    #[error("timed out: {0}")]
    Timeout(&'static str),
}

/// A request body.
#[derive(Debug, Clone, Copy)]
pub enum Body<'a> {
    Json(&'a Value),
    /// `application/x-www-form-urlencoded`, as OAuth token endpoints require.
    Form(&'a [(&'a str, &'a str)]),
}

/// A reply of any status. `body` is [`Value::Null`] when the reply isn't JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpReply {
    pub status: u16,
    pub body: Value,
}

impl HttpReply {
    #[must_use]
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// HTTP with `Accept: application/json`, injectable so tests need no network. Redirects are
/// never followed: a 3xx comes back as the reply.
pub trait Transport {
    /// # Errors
    /// [`LoginError::Http`] when no reply arrives.
    fn post(&self, url: &str, body: Body<'_>) -> Result<HttpReply, LoginError>;

    /// # Errors
    /// [`LoginError::Http`] when no reply arrives.
    fn get(&self, url: &str) -> Result<HttpReply, LoginError> {
        Err(LoginError::Http(format!("GET {url}: not supported here")))
    }
}

/// Resolves `localhost` and every name under it to the loopback addresses without asking any
/// resolver (RFC 6761 section 6.3), and every other host as ureq does by default. [`check_addr`]
/// lets plain http go to `<name>.localhost` because every agent the CLI builds
/// ([`loopback_pinned_agent`]) connects through this: a resolver that sends `.localhost` names
/// to DNS never gets the chance to point one elsewhere.
#[derive(Debug, Default)]
struct LoopbackResolver(ureq::unversioned::resolver::DefaultResolver);

/// Whether `host` (lowercase) is `localhost` or a name under it.
fn is_localhost_name(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

impl ureq::unversioned::resolver::Resolver for LoopbackResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let host = uri.host().unwrap_or_default().to_ascii_lowercase();
        if !is_localhost_name(&host) {
            return self.0.resolve(uri, config, timeout);
        }
        let port = uri
            .port_u16()
            .or(match uri.scheme_str() {
                Some("http") => Some(80),
                Some("https") => Some(443),
                _ => None,
            })
            .ok_or(ureq::Error::HostNotFound)?;
        let mut out = self.empty();
        out.push(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            port,
        )));
        out.push(std::net::SocketAddr::from((
            std::net::Ipv6Addr::LOCALHOST,
            port,
        )));
        Ok(out)
    }
}

/// An agent with ureq's default connector and [`LoopbackResolver`]. Every HTTP client in the CLI
/// is built with this, which is what makes [`check_addr`]'s `*.localhost` rule hold.
pub(crate) fn loopback_pinned_agent(config: ureq::config::Config) -> ureq::Agent {
    ureq::Agent::with_parts(
        config,
        ureq::unversioned::transport::DefaultConnector::default(),
        LoopbackResolver::default(),
    )
}

pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    /// No redirects (a redirect could carry a login to a host [`check_addr`] never saw, or to
    /// plain http) and a [`HTTP_TIMEOUT`] bound on every exchange.
    #[must_use]
    pub fn new() -> Self {
        Self::with_timeout(HTTP_TIMEOUT)
    }

    #[must_use]
    pub fn with_timeout(timeout: Duration) -> Self {
        let agent = loopback_pinned_agent(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .timeout_global(Some(timeout))
                .build(),
        );
        Self { agent }
    }

    fn finish(
        result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<HttpReply, LoginError> {
        let mut resp = result.map_err(|e| LoginError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let mut text = Zeroizing::new(String::new());
        resp.body_mut()
            .as_reader()
            .take(MAX_REPLY_BYTES)
            .read_to_string(&mut text)
            .map_err(|e| LoginError::Http(e.to_string()))?;
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Ok(HttpReply { status, body })
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for UreqTransport {
    fn post(&self, url: &str, body: Body<'_>) -> Result<HttpReply, LoginError> {
        let req = self.agent.post(url).header("Accept", "application/json");
        Self::finish(match body {
            Body::Json(v) => req.send_json(v),
            Body::Form(pairs) => req.send_form(pairs.iter().copied()),
        })
    }

    fn get(&self, url: &str) -> Result<HttpReply, LoginError> {
        Self::finish(
            self.agent
                .get(url)
                .header("Accept", "application/json")
                .call(),
        )
    }
}

/// POSTs JSON to the Worker and returns the reply of a 2xx; anything else is
/// [`LoginError::Rejected`] with Vault's `errors`.
///
/// # Errors
/// [`LoginError::Http`], [`LoginError::Rejected`], or [`LoginError::Response`] for a 2xx that
/// isn't JSON.
pub fn vault_post(t: &impl Transport, url: &str, body: &Value) -> Result<Value, LoginError> {
    let reply = t.post(url, Body::Json(body))?;
    if reply.ok() {
        if reply.body.is_null() {
            return Err(LoginError::Response("reply is not JSON"));
        }
        return Ok(reply.body);
    }
    let message = reply.body["errors"]
        .as_array()
        .map(|e| {
            e.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("; ")
        })
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "no error message".to_owned());
    Err(LoginError::Rejected {
        status: reply.status,
        message,
    })
}

/// Returns `addr` without a trailing slash if it is `https://`, or `http://` to a loopback host:
/// `127.0.0.1`, `::1`, `localhost`, or a name under `localhost`. The CLI's HTTP clients connect
/// to a name under `localhost` at `127.0.0.1` or `::1` without resolving it
/// ([`LoopbackResolver`]), so the address checked here is the one connected to.
///
/// # Errors
/// [`LoginError::BadAddr`] for anything else that is not an http(s) URL; [`LoginError::Insecure`]
/// for `http://` to a non-loopback host.
pub fn check_addr(addr: &str) -> Result<&str, LoginError> {
    let addr = addr.trim_end_matches('/');
    if addr.strip_prefix("https://").is_some_and(|r| !r.is_empty()) {
        return Ok(addr);
    }
    let Some(rest) = addr.strip_prefix("http://") else {
        return Err(LoginError::BadAddr(addr.to_owned()));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    // Userinfo ('@') would let "localhost@evil.com" read as localhost; it is refused with the rest.
    if authority.contains('@') {
        return Err(LoginError::Insecure(addr.to_owned()));
    }
    let host = host.to_ascii_lowercase();
    if matches!(host.as_str(), "127.0.0.1" | "::1" | "localhost") {
        return Ok(addr);
    }
    // A name under localhost (RFC 6761 section 6.3), such as a hosted tenant under `wrangler
    // dev` (`http://<tenant>.localhost:8787`). It isn't resolved here or later: the CLI's HTTP
    // clients connect to it at loopback without asking a resolver (LoopbackResolver). A
    // resolver that sends `.localhost` names to DNS could otherwise send a plain-http login
    // anywhere, and a lookup here followed by another at connect time could disagree.
    if let Some(label) = host.strip_suffix(".localhost")
        && !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Ok(addr);
    }
    Err(LoginError::Insecure(addr.to_owned()))
}

/// The origin (`scheme://host[:port]`, default port dropped, host lowercased) of a checked
/// address, serialized the way the Worker serializes its request URL's origin.
///
/// # Errors
/// [`LoginError::BadAddr`] if `addr` doesn't parse as a URL with a host.
pub fn origin_of(addr: &str) -> Result<String, LoginError> {
    let url = url::Url::parse(addr).map_err(|_| LoginError::BadAddr(addr.to_owned()))?;
    let origin = url.origin();
    if !origin.is_tuple() {
        return Err(LoginError::BadAddr(addr.to_owned()));
    }
    Ok(origin.ascii_serialization())
}

/// # Errors
/// [`LoginError::BadMount`] unless `mount` is a non-empty run of `[A-Za-z0-9_-]`.
fn check_mount(mount: &str) -> Result<(), LoginError> {
    if mount.is_empty()
        || !mount
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(LoginError::BadMount(mount.to_owned()));
    }
    Ok(())
}

/// Overwrites every string in `v`: for parsed replies that held credentials. Copies the HTTP
/// client made while reading the reply are out of reach.
pub(crate) fn zeroize_json(v: &mut Value) {
    match v {
        Value::String(s) => zeroize::Zeroize::zeroize(s),
        Value::Array(a) => a.iter_mut().for_each(zeroize_json),
        Value::Object(m) => m.values_mut().for_each(zeroize_json),
        _ => {}
    }
}

/// The `auth.client_token` of a Worker login reply; the parsed reply is zeroized either way.
fn take_client_token(mut reply: Value) -> Result<String, LoginError> {
    let token =
        str_at(&reply, &["auth", "client_token"], "no token in the reply").map(str::to_owned);
    zeroize_json(&mut reply);
    token
}

fn str_at<'v>(v: &'v Value, path: &[&str], what: &'static str) -> Result<&'v str, LoginError> {
    path.iter()
        .try_fold(v, |v, k| v.get(*k))
        .and_then(Value::as_str)
        .ok_or(LoginError::Response(what))
}

/// `POST <addr>/v1/auth/<mount>/login` with `{"role": role, <field>: credential}`; returns the
/// client token. `addr` and `mount` must already be checked.
fn vault_login(
    t: &impl Transport,
    addr: &str,
    mount: &str,
    role: &str,
    field: &str,
    credential: &str,
) -> Result<String, LoginError> {
    let mut body = json!({ "role": role });
    body[field] = Value::String(credential.to_owned());
    let reply = vault_post(t, &format!("{addr}/v1/auth/{mount}/login"), &body);
    // The body held the credential; clear it before anything else happens.
    if let Value::String(s) = &mut body[field] {
        zeroize::Zeroize::zeroize(s);
    }
    take_client_token(reply?)
}
