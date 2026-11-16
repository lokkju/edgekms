//! The hosted control plane client: `edgekms account login` (GitHub device flow with the hosted
//! App, whose client id comes from `GET /v1/info`, exchanged for a control token at
//! `POST /v1/login/github`, or an ssh-agent signature exchanged at `POST /v1/login/ssh`; see
//! the `ssh` submodule), `edgekms account logout`, `edgekms account ssh-keys`,
//! `edgekms account request-invite`, the
//! `edgekms tenant` commands and the operator's `edgekms ops allowlist`, `edgekms ops tenant`
//! and `edgekms ops invite-requests` commands, with
//! the login commands' HTTP rules (no redirects, 30 seconds, no credential in argv, output or
//! errors). The control plane in `edgekms-worker`'s `control` module is the source of truth
//! for every route and shape used here.
//!
//! The control token is printed once by `account login` for the user to export as
//! [`CONTROL_TOKEN_ENV`]; it lasts [`CONTROL_TOKEN_SECS`], and nothing here writes a credential
//! file. A tenant's root key leaves [`Client::export`] only as a zeroizing string for the
//! caller to put on stdout.

use std::io::{self, Read};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_core::config::Config;
use edgekms_core::hosted::{HostedRules, MAX_CONFIG_BYTES, invite_note, validate_hosted};
use edgekms_core::tenant::{TenantName, TenantNameError};
use edgekms_core::transit::Id;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::login::{
    DeviceFlow, DevicePrompt, HTTP_TIMEOUT, HttpReply, LoginError, Transport, check_addr,
    github_device_token, zeroize_json,
};

mod ssh;

pub use ssh::{
    AgentKeys, ChosenKey, FRESH_LOGIN_CODE, SshAdd, SshKey, SshKeys, choose_key, printable_ascii,
    ssh_login, token_account,
};

/// Where `edgekms account login` and `edgekms tenant` go without `--api`: the hosted control
/// plane, whose host is the first of [`HOSTED_API_HOSTS`].
pub const DEFAULT_API: &str = "https://api.edgekms.dev";
/// The only hosts the hosted App's GitHub tokens are sent to, and whose `/v1/info` is trusted to
/// name that App. Each is the control plane of an official apex; a second apex (`edge.km` is a
/// possible later alias) adds its `api.` host here and nowhere else.
pub const HOSTED_API_HOSTS: &[&str] = &["api.edgekms.dev"];
/// The hosted edgekms GitHub App's client id (the hosted Worker's `GITHUB_CLIENT_ID`).
/// Its tokens go only to [`HOSTED_API_HOSTS`], even when `--client-id` names it.
pub const HOSTED_CLIENT_ID: &str = "Iv23liTHp7alz5DRy7Wg";
/// Names the hosted App's client id, which then goes only to [`HOSTED_API_HOSTS`]. Without it
/// (and without `--client-id`) `account login` reads the id from `GET /v1/info`.
pub const HOSTED_CLIENT_ID_ENV: &str = "EDGEKMS_HOSTED_CLIENT_ID";
/// How long a control token lasts, as the control plane issues them.
pub const CONTROL_TOKEN_SECS: u64 = 1800;
/// The control plane's error for an export whose login is too old.
pub const FRESH_LOGIN_REQUIRED: &str = "fresh login required";
/// Where someone refused at login because signups are closed can ask for an invite: the web
/// console's page, which runs the same request as `edgekms account request-invite`.
pub const INVITE_URL: &str = "https://app.edgekms.dev/request-invite";
/// The `code` the control plane gives a login it refuses because signups are closed.
pub const SIGNUP_CLOSED_CODE: &str = "signup_closed";
/// The `code` the control plane gives a tenant name outside the creator's login prefix.
pub const TENANT_NAME_PREFIX_CODE: &str = "tenant_name_prefix";
/// Where every `edgekms tenant` command reads the control token. Never a flag, so it stays out
/// of shell history and `ps`.
pub const CONTROL_TOKEN_ENV: &str = "EDGEKMS_CONTROL_TOKEN";

/// Largest reply body read.
const MAX_REPLY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error(transparent)]
    Login(#[from] LoginError),
    #[error("the control plane refused (HTTP {status}): {message}")]
    Rejected { status: u16, message: String },
    #[error("unexpected response from the control plane: {0}")]
    Response(&'static str),
    #[error(
        "{CONTROL_TOKEN_ENV} is not set; run `edgekms account login` and export the token it prints"
    )]
    NoToken,
    #[error(
        "refusing to send a GitHub token for the hosted edgekms App to {0}: it goes only to \
         {DEFAULT_API}; pass --client-id with your own App's client id to log in elsewhere"
    )]
    HostedClientIdElsewhere(String),
    #[error("tenant name {name:?}: {reason}")]
    TenantName {
        name: String,
        reason: TenantNameError,
    },
    #[error("config: {0}")]
    Config(String),
    #[error(
        "the config changed after version {0}; run `edgekms tenant config get`, \
         reapply your change and set it again"
    )]
    Stale(u64),
    #[error(
        "export needs a login less than five minutes old; run `edgekms account login`, \
         export the new token and try again"
    )]
    StaleLogin,
    #[error(
        "edgekms.dev is invite-only. Run `edgekms account request-invite` to ask for an invite, \
         or open {INVITE_URL}."
    )]
    SignupClosed,
    #[error("you can sign in now: run `edgekms account login`")]
    AlreadyAdmitted,
    #[error("you have already asked for an invite")]
    AlreadyRequested,
    #[error("your invite request wasn't approved")]
    RequestDeclined,
    #[error("edgekms.dev isn't taking invite requests right now")]
    RequestsClosed,
    #[error("edgekms.dev isn't taking more invite requests right now; try again later")]
    RequestsFull,
    /// The invite request's note breaks a rule (`edgekms_core::hosted::invite_note`).
    #[error("note: {0}")]
    Note(String),
    /// The control plane's naming-rule refusal, with the rule spelled out.
    #[error("{0}")]
    TenantNamePrefix(String),
    /// `POST /v1/login/ssh` refused: the uniform `400 permission denied`, which never says
    /// which check failed.
    #[error(
        "the control plane refused the login (HTTP 400): permission denied; the key isn't \
         registered to an edgekms account that can log in, or the signature was refused; \
         register keys with `edgekms account ssh-keys add` from a GitHub login"
    )]
    SshLoginRefused,
    #[error(
        "run `edgekms account login` (GitHub or `--ssh`) again; adding a key needs a login \
         under five minutes old"
    )]
    SshKeyFreshLogin,
    /// A coded refusal of `POST /v1/me/ssh-keys`, explained.
    #[error("{0}")]
    SshKeyRefused(&'static str),
    /// The registration challenge names another account than the one expected, so it was
    /// never signed (lokkju/edgekms#17). `got.login` is a GitHub login's shape, checked when
    /// the challenge was parsed, so it is safe on a terminal.
    #[error(
        "the control plane's registration challenge is for GitHub account {} ({}), not GitHub \
         id {expected}; refusing to sign it. Check which account EDGEKMS_CONTROL_TOKEN is for \
         (`edgekms tenant list` shows it), or pass --expect-github-id",
        got.login,
        got.github_id
    )]
    SshKeyWrongAccount {
        expected: u64,
        got: edgekms_core::ssh::RegisterAccount,
    },
    /// No account to check a registration challenge against: the control token doesn't say
    /// whose it is, and `--expect-github-id` wasn't given.
    #[error(
        "can't tell which GitHub account EDGEKMS_CONTROL_TOKEN is for; pass --expect-github-id \
         with your GitHub id so the key is registered to that account only"
    )]
    SshKeyNoAccount,
    #[error("no such key on this account")]
    NoSuchSshKey,
    #[error(
        "{0:?} is neither a key id (43 characters, as `edgekms account ssh-keys list` prints) \
         nor a fingerprint (SHA256:...)"
    )]
    SshKeyId(String),
    /// The label breaks a rule (`edgekms_core::hosted::ssh_key_label`).
    #[error("label: {0}")]
    Label(String),
    /// A public key the control plane wouldn't register.
    #[error("public key: {0}")]
    PublicKey(String),
    /// `--key` isn't a readable public key file of a supported type.
    #[error("--key: {0}")]
    KeyFile(String),
    /// `ssh-add -L` couldn't list the agent's keys.
    #[error("cannot list ssh-agent's keys: {0}")]
    Agent(String),
    #[error(
        "ssh-agent holds no Ed25519, sk-ssh-ed25519 or ECDSA P-256 key; add one with ssh-add, \
         or pass --key <file.pub>"
    )]
    AgentNoKeys,
    /// The agent holds several supported keys, listed one per line; edgekms never guesses.
    #[error(
        "ssh-agent holds several keys edgekms could use; pass --key <file.pub> to pick one:\n{0}"
    )]
    AgentManyKeys(String),
    #[error("cannot write the agent's public key for ssh-keygen: {0}")]
    TempKey(String),
}

/// Checks `api` with [`check_addr`] and, unless the client id was given explicitly, that it is
/// exactly `https://<host>` for a host in [`HOSTED_API_HOSTS`] (no port, no userinfo): a token
/// for the hosted App sent to any other server could be replayed to the hosted service before
/// the Worker revokes it. Returns `api`
/// without a trailing slash.
///
/// # Errors
/// A [`LoginError`] from [`check_addr`], or [`ControlError::HostedClientIdElsewhere`].
pub fn check_api(api: &str, explicit_client_id: bool) -> Result<&str, ControlError> {
    let api = check_addr(api)?;
    if explicit_client_id {
        return Ok(api);
    }
    let hosted = url::Url::parse(api).is_ok_and(|u| {
        u.scheme() == "https"
            && u.username().is_empty()
            && u.password().is_none()
            && u.port().is_none()
            && u.host_str().is_some_and(|h| HOSTED_API_HOSTS.contains(&h))
            && matches!(u.path(), "" | "/")
            && u.query().is_none()
            && u.fragment().is_none()
    });
    if hosted {
        Ok(api)
    } else {
        Err(ControlError::HostedClientIdElsewhere(api.to_owned()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

/// One control-plane request. No `Debug`: it carries the bearer token.
pub struct Request<'a> {
    pub method: Method,
    pub url: &'a str,
    /// The control token, sent as `Authorization: Bearer <token>`.
    pub bearer: Option<&'a str>,
    /// Sent as `If-Match: "<version>"`.
    pub if_match: Option<u64>,
    /// A JSON body, sent with `Content-Type: application/json`.
    pub body: Option<&'a [u8]>,
}

/// HTTP for the control plane, injectable as [`Transport`] is for logins. Redirects are never
/// followed: a 3xx comes back as the reply.
pub trait ControlTransport {
    /// # Errors
    /// [`LoginError::Http`] when no reply arrives.
    fn send(&self, req: &Request<'_>) -> Result<HttpReply, LoginError>;
}

pub struct UreqControl {
    agent: ureq::Agent,
}

impl UreqControl {
    /// No redirects and a [`HTTP_TIMEOUT`] bound, as [`crate::login::UreqTransport`].
    #[must_use]
    pub fn new() -> Self {
        let agent = crate::login::loopback_pinned_agent(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .timeout_global(Some(HTTP_TIMEOUT))
                .build(),
        );
        Self { agent }
    }
}

impl Default for UreqControl {
    fn default() -> Self {
        Self::new()
    }
}

fn with_headers<B>(
    mut rb: ureq::RequestBuilder<B>,
    auth: Option<&str>,
    if_match: Option<&str>,
) -> ureq::RequestBuilder<B> {
    rb = rb.header("Accept", "application/json");
    if let Some(a) = auth {
        rb = rb.header("Authorization", a);
    }
    if let Some(m) = if_match {
        rb = rb.header("If-Match", m);
    }
    rb
}

impl ControlTransport for UreqControl {
    fn send(&self, req: &Request<'_>) -> Result<HttpReply, LoginError> {
        let auth = req.bearer.map(|t| Zeroizing::new(format!("Bearer {t}")));
        let auth = auth.as_deref().map(String::as_str);
        let if_match = req.if_match.map(|v| format!("\"{v}\""));
        let if_match = if_match.as_deref();
        let body = req.body.unwrap_or_default();
        let result = match req.method {
            Method::Get => with_headers(self.agent.get(req.url), auth, if_match).call(),
            Method::Delete => with_headers(self.agent.delete(req.url), auth, if_match).call(),
            Method::Post => with_headers(self.agent.post(req.url), auth, if_match)
                .header("Content-Type", "application/json")
                .send(body),
            Method::Put => with_headers(self.agent.put(req.url), auth, if_match)
                .header("Content-Type", "application/json")
                .send(body),
        };
        let mut resp = result.map_err(|e| LoginError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        // A 204 has no body by definition. workerd marks the Worker's 204s (which carry
        // `Content-Type: application/json`, as OpenBao's do) `Content-Encoding: gzip` when the
        // client accepts gzip, and decoding an empty body as gzip fails; so it isn't read.
        if status == 204 {
            return Ok(HttpReply {
                status,
                body: Value::Null,
            });
        }
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

/// Serializes `v` into a buffer of exactly its length, so nothing reallocates and leaves a
/// copy of a secret in freed memory; the buffer is zeroized on drop.
fn json_bytes(v: &Value) -> Zeroizing<Vec<u8>> {
    struct Count(usize);
    impl io::Write for Count {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    // Serializing a Value into memory can't fail.
    let _ = serde_json::to_writer(&mut count, v);
    let mut buf = Zeroizing::new(Vec::with_capacity(count.0));
    let _ = serde_json::to_writer(&mut *buf, v);
    buf
}

/// The `errors` of a Vault-style error reply, joined.
fn error_message(body: &Value) -> String {
    body["errors"]
        .as_array()
        .map(|e| {
            e.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("; ")
        })
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "no error message".to_owned())
}

/// Whether `reply` is a `403` with the stable `code`.
fn refused_with(reply: &HttpReply, code: &str) -> bool {
    reply.status == 403 && reply.body["code"].as_str() == Some(code)
}

/// `ms` (Unix milliseconds) as a UTC calendar date, `YYYY-MM-DD`.
#[must_use]
pub fn utc_date(ms: u64) -> String {
    // Howard Hinnant's `civil_from_days`, on days since 1970-01-01.
    let days = i64::try_from(ms / 86_400_000).unwrap_or(i64::MAX / 2);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The naming rule's refusal for `name`, explained: the server's message names the prefix.
fn name_prefix_error(reply: &HttpReply, name: &str) -> ControlError {
    let message = error_message(&reply.body);
    let example = message
        .strip_prefix("tenant name must start with ")
        .map(|prefix| format!(", for example {prefix}{name}"))
        .unwrap_or_default();
    ControlError::TenantNamePrefix(format!(
        "{message}: besides your personal tenant, the tenants you create are named after your \
         GitHub login, as <login>-<suffix>{example}"
    ))
}

/// The body of a 2xx reply (`Value::Null` for an empty one), or [`ControlError::Rejected`].
fn expect_ok(reply: HttpReply) -> Result<Value, ControlError> {
    if reply.ok() {
        return Ok(reply.body);
    }
    Err(ControlError::Rejected {
        status: reply.status,
        message: error_message(&reply.body),
    })
}

/// `GET /v1/info`: the hosted App's client id and the service's apex, which the control plane
/// checks configs against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub github_client_id: String,
    pub apex: String,
}

/// `GET <api>/v1/info`, unauthenticated. Its reply is the whole body, not wrapped in `data`.
///
/// # Errors
/// A transport error, the control plane's refusal, or a reply without both fields.
pub fn fetch_info(c: &impl ControlTransport, api: &str) -> Result<Info, ControlError> {
    let url = format!("{}/v1/info", check_addr(api)?);
    let reply = expect_ok(c.send(&Request {
        method: Method::Get,
        url: &url,
        bearer: None,
        if_match: None,
        body: None,
    })?)?;
    let field = |name: &str| {
        reply[name]
            .as_str()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };
    Ok(Info {
        github_client_id: field("github_client_id")
            .ok_or(ControlError::Response("no github_client_id in /v1/info"))?,
        apex: field("apex").ok_or(ControlError::Response("no apex in /v1/info"))?,
    })
}

/// The client id `account login` runs the device flow with, and whether it was given
/// explicitly (`--client-id`, the `flag`), which is what lets it go to a control plane other
/// than the hosted one ([`HOSTED_API_HOSTS`]). A `--client-id` naming the hosted App
/// ([`HOSTED_CLIENT_ID`], or the value of `env`) doesn't count as explicit: its tokens stay
/// pinned to the hosted API whichever way the id arrived. Otherwise the id is the hosted App's: `env` (the value of
/// [`HOSTED_CLIENT_ID_ENV`]) if set, else the one `GET <api>/v1/info` names. Either way `api` must
/// pass [`check_api`] first, so a server that isn't an official API host is never asked for a client
/// id it would then receive tokens for.
///
/// # Errors
/// [`ControlError::HostedClientIdElsewhere`] or another [`check_api`] error before any request,
/// or an error from [`fetch_info`].
pub fn login_client_id(
    c: &impl ControlTransport,
    api: &str,
    flag: Option<&str>,
    env: Option<&str>,
) -> Result<(String, bool), ControlError> {
    let given = |v: Option<&str>| {
        v.map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };
    let env = given(env);
    if let Some(id) = given(flag) {
        let explicit = id != HOSTED_CLIENT_ID && env.as_deref() != Some(id.as_str());
        check_api(api, explicit)?;
        return Ok((id, explicit));
    }
    let api = check_api(api, false)?;
    if let Some(id) = env {
        return Ok((id, false));
    }
    Ok((fetch_info(c, api)?.github_client_id, false))
}

/// What `account login` got back. Only `token` is a secret.
pub struct AccountLogin {
    pub token: Zeroizing<String>,
    pub expires_in: Option<u64>,
    pub github_id: Option<u64>,
    pub login: Option<String>,
    /// The personal tenant this login created, on a first login.
    pub created_tenant: Option<String>,
    /// The key an SSH login signed with; `None` for a GitHub login.
    pub ssh_fingerprint: Option<String>,
    /// How many SSH keys can log in to the account, when the control plane says.
    pub ssh_keys: Option<u64>,
}

impl std::fmt::Debug for AccountLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountLogin")
            .field("token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("github_id", &self.github_id)
            .field("login", &self.login)
            .field("created_tenant", &self.created_tenant)
            .field("ssh_fingerprint", &self.ssh_fingerprint)
            .field("ssh_keys", &self.ssh_keys)
            .finish()
    }
}

impl AccountLogin {
    /// A line for stderr naming the user, the SSH key of an SSH login and any tenant created;
    /// never the token.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut who = match (&self.login, self.github_id) {
            (Some(l), Some(id)) => format!("{} (GitHub id {id})", printable_ascii(l)),
            (Some(l), None) => printable_ascii(l),
            (None, Some(id)) => format!("GitHub id {id}"),
            (None, None) => "your GitHub account".to_owned(),
        };
        if let Some(fp) = &self.ssh_fingerprint {
            who = format!("{who} with SSH key {}", printable_ascii(fp));
        }
        let lasts = self
            .expires_in
            .map(|e| format!("; the token lasts {} minutes", e / 60))
            .unwrap_or_default();
        let created = self
            .created_tenant
            .as_ref()
            .map(|t| format!(" Created your tenant {t}."))
            .unwrap_or_default();
        format!("Logged in to the edgekms control plane as {who}{lasts}.{created}")
    }

    /// A line for stderr saying how many SSH keys can log in to the account, so a key added
    /// behind the owner's back shows at their next login; `None` when the control plane didn't
    /// say.
    #[must_use]
    pub fn ssh_keys_line(&self) -> Option<String> {
        Some(match self.ssh_keys? {
            0 => "No SSH keys can log in to this account; add one for when GitHub is unavailable \
                  with `edgekms account ssh-keys add`."
                .to_owned(),
            1 => "1 SSH key can log in to this account; see `edgekms account ssh-keys list`."
                .to_owned(),
            n => format!(
                "{n} SSH keys can log in to this account; see `edgekms account ssh-keys list`."
            ),
        })
    }
}

/// The [`AccountLogin`] in a control plane login reply of either kind; the parsed reply is
/// zeroized either way.
fn take_login(reply: HttpReply) -> Result<AccountLogin, ControlError> {
    let mut reply = expect_ok(reply)?;
    let data = &reply["data"];
    let token = data["token"]
        .as_str()
        .filter(|t| !t.is_empty())
        .map(|t| Zeroizing::new(t.to_owned()));
    let out = token.map(|token| AccountLogin {
        token,
        expires_in: data["expires_in"].as_u64(),
        github_id: data["github_id"].as_u64(),
        login: data["login"].as_str().map(str::to_owned),
        created_tenant: data["created_tenant"].as_str().map(str::to_owned),
        ssh_fingerprint: data["ssh_fingerprint"].as_str().map(str::to_owned),
        ssh_keys: data["ssh_keys"].as_u64(),
    });
    zeroize_json(&mut reply);
    out.ok_or(ControlError::Response("no token in the reply"))
}

/// The device flow and the control plane login both account commands share: checks `api`
/// against the client id ([`check_api`]) before GitHub is contacted, runs the device flow over
/// `gh`, and posts the GitHub token to `<api>/v1/login/github` over `c`. Returns the reply.
fn control_login(
    gh: &impl Transport,
    c: &impl ControlTransport,
    flow: &DeviceFlow<'_>,
    explicit_client_id: bool,
    prompt: impl FnOnce(&DevicePrompt),
    sleep: impl FnMut(std::time::Duration),
    api: &str,
) -> Result<HttpReply, ControlError> {
    let api = check_api(api, explicit_client_id)?;
    let gh_token = github_device_token(gh, flow, prompt, sleep)?;
    let mut body = json!({ "token": gh_token.as_str() });
    let bytes = json_bytes(&body);
    zeroize_json(&mut body);
    let url = format!("{api}/v1/login/github");
    let reply = c.send(&Request {
        method: Method::Post,
        url: &url,
        bearer: None,
        if_match: None,
        body: Some(&bytes),
    })?;
    drop(bytes);
    Ok(reply)
}

/// The whole account login: [`control_login`], then the control token and who it's for.
///
/// # Errors
/// [`ControlError::HostedClientIdElsewhere`], a [`LoginError`] from the address check or the
/// device flow, [`ControlError::SignupClosed`], or the control plane's refusal.
pub fn account_login(
    gh: &impl Transport,
    c: &impl ControlTransport,
    flow: &DeviceFlow<'_>,
    explicit_client_id: bool,
    prompt: impl FnOnce(&DevicePrompt),
    sleep: impl FnMut(std::time::Duration),
    api: &str,
) -> Result<AccountLogin, ControlError> {
    let reply = control_login(gh, c, flow, explicit_client_id, prompt, sleep, api)?;
    if refused_with(&reply, SIGNUP_CLOSED_CODE) {
        return Err(ControlError::SignupClosed);
    }
    take_login(reply)
}

/// What the login of `edgekms account request-invite` came to.
pub enum InviteLogin {
    /// The control plane let the user in: there is nothing to ask for. The control token in the
    /// reply was zeroized, not kept.
    Admitted,
    /// Refused with a request token, good for 15 minutes, for [`Requester`].
    Refused(Zeroizing<String>),
    /// Refused without one: the control plane isn't taking invite requests.
    Closed,
}

impl std::fmt::Debug for InviteLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Admitted => "Admitted",
            Self::Refused(_) => "Refused(<redacted>)",
            Self::Closed => "Closed",
        })
    }
}

/// The login `edgekms account request-invite` runs: [`control_login`], then the request token
/// a `signup_closed` refusal carries, if any.
///
/// # Errors
/// As [`account_login`], except that a `signup_closed` refusal is an answer, not an error.
pub fn request_invite_login(
    gh: &impl Transport,
    c: &impl ControlTransport,
    flow: &DeviceFlow<'_>,
    explicit_client_id: bool,
    prompt: impl FnOnce(&DevicePrompt),
    sleep: impl FnMut(std::time::Duration),
    api: &str,
) -> Result<InviteLogin, ControlError> {
    let mut reply = control_login(gh, c, flow, explicit_client_id, prompt, sleep, api)?;
    let out = if refused_with(&reply, SIGNUP_CLOSED_CODE) {
        match reply.body["request_token"]
            .as_str()
            .filter(|t| !t.is_empty())
        {
            Some(t) => Ok(InviteLogin::Refused(Zeroizing::new(t.to_owned()))),
            None => Ok(InviteLogin::Closed),
        }
    } else if reply.ok() {
        Ok(InviteLogin::Admitted)
    } else {
        Err(ControlError::Rejected {
            status: reply.status,
            message: error_message(&reply.body),
        })
    };
    // The control token of an admitted user, or the request token, isn't left in the reply.
    zeroize_json(&mut reply.body);
    out
}

/// A requester's invite request, as `GET /v1/invite-requests/mine` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestState {
    /// `pending`, `approved` or `declined`.
    pub status: String,
    pub created_ms: u64,
    pub decided_ms: Option<u64>,
}

/// `GET /v1/invite-requests/mine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyRequest {
    pub github_id: u64,
    pub login: String,
    /// Whether the control plane takes new requests.
    pub accepting: bool,
    pub request: Option<RequestState>,
}

/// The requester routes, authenticated with a request token. No `Debug`: it holds the token.
pub struct Requester<'a, T> {
    t: &'a T,
    api: String,
    token: &'a str,
}

impl<'a, T: ControlTransport> Requester<'a, T> {
    /// # Errors
    /// A [`LoginError`] if `api` fails [`check_addr`].
    pub fn new(t: &'a T, api: &str, token: &'a str) -> Result<Self, ControlError> {
        let api = check_addr(api)?.to_owned();
        Ok(Self { t, api, token })
    }

    fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpReply, ControlError> {
        let url = format!("{}{path}", self.api);
        Ok(self.t.send(&Request {
            method,
            url: &url,
            bearer: Some(self.token),
            if_match: None,
            body,
        })?)
    }

    /// `GET /v1/invite-requests/mine`.
    ///
    /// # Errors
    /// A transport error, the refusal, or a reply missing a field.
    pub fn mine(&self) -> Result<MyRequest, ControlError> {
        let reply = expect_ok(self.send(Method::Get, "/v1/invite-requests/mine", None)?)?;
        let d = &reply["data"];
        let request = match &d["request"] {
            Value::Null => None,
            r => Some(RequestState {
                status: r["status"]
                    .as_str()
                    .ok_or(ControlError::Response("a request without a status"))?
                    .to_owned(),
                created_ms: r["created_ms"]
                    .as_u64()
                    .ok_or(ControlError::Response("a request without a date"))?,
                decided_ms: r["decided_ms"].as_u64(),
            }),
        };
        Ok(MyRequest {
            github_id: d["github_id"]
                .as_u64()
                .ok_or(ControlError::Response("no github_id in the reply"))?,
            login: d["login"].as_str().unwrap_or_default().to_owned(),
            accepting: d["accepting"].as_bool().unwrap_or(false),
            request,
        })
    }

    /// `POST /v1/invite-requests` with `note`, checked and trimmed here first by the rules the
    /// control plane applies. Returns when the request was filed (Unix milliseconds).
    ///
    /// # Errors
    /// [`ControlError::Note`] before any request; [`ControlError::AlreadyAdmitted`],
    /// [`ControlError::AlreadyRequested`], [`ControlError::RequestDeclined`],
    /// [`ControlError::RequestsClosed`] or [`ControlError::RequestsFull`] for the control
    /// plane's coded refusals; a transport error or another refusal.
    pub fn file(&self, note: &str) -> Result<u64, ControlError> {
        let note = invite_note(note).map_err(|e| ControlError::Note(e.to_string()))?;
        let body = serde_json::to_vec(&json!({ "note": note }))
            .map_err(|_| ControlError::Response("unserializable note"))?;
        let reply = self.send(Method::Post, "/v1/invite-requests", Some(&body))?;
        let coded = match (reply.status, reply.body["code"].as_str()) {
            (409, Some("already_admitted")) => Some(ControlError::AlreadyAdmitted),
            (409, Some("already_requested")) => Some(ControlError::AlreadyRequested),
            (409, Some("request_declined")) => Some(ControlError::RequestDeclined),
            (403, Some("invite_requests_closed")) => Some(ControlError::RequestsClosed),
            (503, Some("invite_requests_full")) => Some(ControlError::RequestsFull),
            _ => None,
        };
        if let Some(e) = coded {
            return Err(e);
        }
        expect_ok(reply)?["data"]["created_ms"]
            .as_u64()
            .ok_or(ControlError::Response("no created_ms in the reply"))
    }
}

/// One invite request, as `GET /v1/ops/invite-requests` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRequest {
    pub github_id: u64,
    /// The GitHub login when the request was filed.
    pub login: String,
    /// Plain text: no control character but a newline, no bidirectional formatting.
    pub note: String,
    pub created_ms: u64,
    /// `pending`, `approved` or `declined`.
    pub status: String,
    pub decided_by: Option<u64>,
    pub decided_ms: Option<u64>,
}

/// `GET /v1/ops/invite-requests`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRequests {
    /// Every pending request, oldest first, then the most recently decided.
    pub requests: Vec<InviteRequest>,
    /// GitHub ids of rows whose MAC doesn't verify: written to D1 without the control plane.
    pub unverified: Vec<u64>,
    pub pending: u64,
}

/// A tenant member's control-plane role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Member => "member",
        }
    }
}

/// `GET /v1/me`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Me {
    pub github_id: u64,
    pub login: String,
    /// `(name, role)` for each tenant the user is a member of (accepted memberships only).
    pub tenants: Vec<(String, String)>,
    /// `(name, role)` for each pending invite, which grants nothing until accepted.
    pub invites: Vec<(String, String)>,
}

/// What a member grant did, as the tenant reads afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// A pending invite, which grants nothing until the invitee runs `edgekms tenant accept`.
    Invited,
    /// The member holds the role now: an owner lowered to member, or a role they already held.
    Applied,
    /// The grant was accepted but the tenant couldn't be read back to tell which.
    Unconfirmed,
}

/// A tenant's status, as `PUT /v1/ops/tenants/<name>/status` takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    Active,
    Suspended,
}

impl TenantStatus {
    /// The wire form: `active` or `suspended`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

/// `GET /v1/ops/allowlist`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    /// `(github_id, added_by, added_ms)` for each row that verifies, by GitHub id.
    pub entries: Vec<(u64, u64, u64)>,
    /// GitHub ids of rows whose MAC doesn't verify: written to D1 without the control plane.
    pub unverified: Vec<u64>,
}

/// An existing root key to bring into a new tenant.
#[derive(Clone, Copy)]
pub struct Import<'a> {
    pub root_id: &'a Id,
    pub root_key: &'a [u8; 32],
}

/// What [`Client::export`] returns.
pub struct Exported {
    pub root_id: String,
    /// Standard base64 of the 32-byte root key.
    pub root_key: Zeroizing<String>,
}

impl std::fmt::Debug for Exported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exported")
            .field("root_id", &self.root_id)
            .field("root_key", &"<redacted>")
            .finish()
    }
}

/// The tenant commands, authenticated with a control token.
pub struct Client<'a, T> {
    t: &'a T,
    api: String,
    token: &'a str,
}

fn tenant_name(name: &str) -> Result<TenantName, ControlError> {
    TenantName::new(name).map_err(|reason| ControlError::TenantName {
        name: name.to_owned(),
        reason,
    })
}

/// A root id that stands in for the one the control plane generates, so a config for a new
/// tenant without an import can be checked locally: the server overwrites `root_id` before it
/// checks.
const PENDING_ROOT_ID: &str = "r_pending";

fn config_error(e: impl std::fmt::Display) -> ControlError {
    ControlError::Config(e.to_string())
}

fn too_large(len: usize) -> ControlError {
    ControlError::Config(format!(
        "{len} bytes; the control plane takes at most {MAX_CONFIG_BYTES}"
    ))
}

/// Parses `text` as a config object and checks what needs no tenant and no rules: the size the
/// control plane measures (with `raw_size` the bytes as sent, which `PUT` checks; always the
/// compacted JSON, which `POST` checks and both store) and [`Config::from_json`], after setting
/// `root_id` to `root_override` if given. Returns the parsed JSON.
fn parse_config(
    text: &str,
    raw_size: bool,
    root_override: Option<&Id>,
) -> Result<Value, ControlError> {
    if raw_size && text.len() > MAX_CONFIG_BYTES {
        return Err(too_large(text.len()));
    }
    let value: Value = serde_json::from_str(text).map_err(config_error)?;
    if !value.is_object() {
        return Err(ControlError::Config("must be a JSON object".into()));
    }
    let compact = value.to_string();
    if compact.len() > MAX_CONFIG_BYTES {
        return Err(too_large(compact.len()));
    }
    with_root(&value, root_override)?;
    Ok(value)
}

/// [`Config::from_json`] on `value`, with its `root_id` replaced by `root_override` if given.
fn with_root(value: &Value, root_override: Option<&Id>) -> Result<Config, ControlError> {
    let mut check = value.clone();
    if let (Some(root), Some(obj)) = (root_override, check.as_object_mut()) {
        obj.insert("root_id".to_owned(), json!(root.as_str()));
    }
    Config::from_json(&check.to_string()).map_err(config_error)
}

/// [`validate_hosted`] on `value` with the rules the control plane applies: its root `root_id`
/// (set into the config first when `overwrite`, as the server does for a new tenant) and the
/// client id and apex from its [`Info`].
fn check_hosted(
    value: &Value,
    root_id: &Id,
    overwrite: bool,
    info: &Info,
) -> Result<(), ControlError> {
    let config = with_root(value, overwrite.then_some(root_id))?;
    let rules = HostedRules {
        root_id,
        github_client_id: &info.github_client_id,
        apex: &info.apex,
    };
    validate_hosted(&config, &rules).map_err(config_error)
}

impl<'a, T: ControlTransport> Client<'a, T> {
    /// # Errors
    /// A [`LoginError`] if `api` fails [`check_addr`].
    pub fn new(t: &'a T, api: &str, token: &'a str) -> Result<Self, ControlError> {
        let api = check_addr(api)?.to_owned();
        Ok(Self { t, api, token })
    }

    fn send(
        &self,
        method: Method,
        path: &str,
        if_match: Option<u64>,
        body: Option<&[u8]>,
    ) -> Result<HttpReply, ControlError> {
        let url = format!("{}{path}", self.api);
        Ok(self.t.send(&Request {
            method,
            url: &url,
            bearer: Some(self.token),
            if_match,
            body,
        })?)
    }

    fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, ControlError> {
        let bytes = body.map(json_bytes);
        expect_ok(self.send(method, path, None, bytes.as_deref().map(Vec::as_slice))?)
    }

    /// `GET /v1/info`, without the control token: the rules configs are checked against.
    ///
    /// # Errors
    /// As [`fetch_info`].
    pub fn info(&self) -> Result<Info, ControlError> {
        fetch_info(self.t, &self.api)
    }

    /// `POST /v1/logout` (`204`): every control token the user holds stops working, this one
    /// included.
    ///
    /// # Errors
    /// A transport error, or the refusal.
    pub fn logout(&self) -> Result<(), ControlError> {
        expect_ok(self.send(Method::Post, "/v1/logout", None, Some(b"{}"))?).map(drop)
    }

    /// `GET /v1/me`: who the token is for, their tenants and their pending invites.
    ///
    /// # Errors
    /// A transport error, the control plane's refusal, or a reply missing a field.
    pub fn me(&self) -> Result<Me, ControlError> {
        fn pairs(v: &Value, what: &'static str) -> Result<Vec<(String, String)>, ControlError> {
            v.as_array()
                .ok_or(ControlError::Response(what))?
                .iter()
                .map(|t| {
                    Some((
                        t["name"].as_str()?.to_owned(),
                        t["role"].as_str()?.to_owned(),
                    ))
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(ControlError::Response("an entry without a name or role"))
        }
        let reply = self.call(Method::Get, "/v1/me", None)?;
        let d = &reply["data"];
        Ok(Me {
            github_id: d["github_id"]
                .as_u64()
                .ok_or(ControlError::Response("no github_id in the reply"))?,
            login: d["login"].as_str().unwrap_or_default().to_owned(),
            tenants: pairs(&d["tenants"], "no tenants in the reply")?,
            invites: pairs(&d["invites"], "no invites in the reply")?,
        })
    }

    /// `GET /v1/tenants/<name>`: the reply's `data`.
    ///
    /// # Errors
    /// [`ControlError::TenantName`] before any request, a transport error, or the refusal.
    pub fn show(&self, name: &str) -> Result<Value, ControlError> {
        let name = tenant_name(name)?;
        let mut reply = self.call(Method::Get, &format!("/v1/tenants/{}", name.as_str()), None)?;
        match reply.get_mut("data").map(Value::take) {
            Some(d @ Value::Object(_)) => Ok(d),
            _ => Err(ControlError::Response("no tenant in the reply")),
        }
    }

    /// `POST /v1/tenants`. A config is checked locally first against the control plane's
    /// [`Info`] (read from `/v1/info`): with an import, which requires a config, its `root_id`
    /// must be the imported one; without one the control plane replaces its `root_id` with
    /// the root it generates, so whatever the file names is ignored. Returns the reply's `data`.
    ///
    /// # Errors
    /// [`ControlError::TenantName`] before any request, [`ControlError::Config`] before the
    /// request that creates, a transport error, or the refusal.
    pub fn create(
        &self,
        name: &str,
        config: Option<&str>,
        import: Option<Import<'_>>,
    ) -> Result<Value, ControlError> {
        let name = tenant_name(name)?;
        let pending = Id::new(PENDING_ROOT_ID).map_err(config_error)?;
        let config = match (config, import) {
            (None, Some(_)) => {
                return Err(ControlError::Config(
                    "an import needs --config with the tenant's existing keys, \
                     or its old ciphertexts won't decrypt"
                        .into(),
                ));
            }
            (Some(text), Some(i)) => {
                let value = parse_config(text, false, None)?;
                check_hosted(&value, i.root_id, false, &self.info()?)?;
                Some(value)
            }
            (Some(text), None) => {
                let value = parse_config(text, false, Some(&pending))?;
                check_hosted(&value, &pending, true, &self.info()?)?;
                Some(value)
            }
            (None, None) => None,
        };
        let mut body = json!({ "name": name.as_str() });
        if let Some(c) = config {
            body["config"] = c;
        }
        if let Some(i) = import {
            // Exactly 44 characters: no reallocation leaves a copy behind.
            let mut key = Zeroizing::new(String::with_capacity(44));
            STANDARD.encode_string(i.root_key, &mut key);
            body["import"] = json!({ "root_id": i.root_id.as_str(), "root_key": key.as_str() });
        }
        let bytes = json_bytes(&body);
        zeroize_json(&mut body);
        let reply = self.send(Method::Post, "/v1/tenants", None, Some(&bytes));
        drop(bytes);
        let reply = reply?;
        if refused_with(&reply, TENANT_NAME_PREFIX_CODE) {
            return Err(name_prefix_error(&reply, name.as_str()));
        }
        let mut reply = expect_ok(reply)?;
        Ok(reply.get_mut("data").map(Value::take).unwrap_or_default())
    }

    /// `GET /v1/tenants/<name>`: the config as JSON text, and its version.
    ///
    /// # Errors
    /// As [`Client::show`], or a reply without a config object or version.
    pub fn config_get(&self, name: &str) -> Result<(String, u64), ControlError> {
        let d = self.show(name)?;
        let version = d["config_version"]
            .as_u64()
            .ok_or(ControlError::Response("no config_version in the reply"))?;
        match &d["config"] {
            v @ Value::Object(_) => Ok((v.to_string(), version)),
            _ => Err(ControlError::Response("no config in the reply")),
        }
    }

    /// `PUT /v1/tenants/<name>/config` with `If-Match`. Reads the tenant first for its root id
    /// (the config must name it) and, without `if_version`, its current version, which goes to
    /// `noticed`; and `/v1/info` for the rules the control plane checks. Returns the new
    /// version.
    ///
    /// # Errors
    /// [`ControlError::Config`] when the config fails locally (size and parsing before any
    /// request, the hosted rules before the `PUT`), [`ControlError::Stale`] on a `409`, a
    /// transport error, or the refusal.
    pub fn config_set(
        &self,
        name: &str,
        config: &str,
        if_version: Option<u64>,
        noticed: impl FnOnce(u64),
    ) -> Result<u64, ControlError> {
        let name = tenant_name(name)?;
        // Everything checkable without the tenant row runs before any request.
        let value = parse_config(config, true, None)?;
        let current = self.show(name.as_str())?;
        let root_id = current["root_id"]
            .as_str()
            .and_then(|r| Id::new(r).ok())
            .ok_or(ControlError::Response("no root_id in the reply"))?;
        check_hosted(&value, &root_id, false, &self.info()?)?;
        let version = if let Some(v) = if_version {
            v
        } else {
            let v = current["config_version"]
                .as_u64()
                .ok_or(ControlError::Response("no config_version in the reply"))?;
            noticed(v);
            v
        };
        let reply = self.send(
            Method::Put,
            &format!("/v1/tenants/{}/config", name.as_str()),
            Some(version),
            Some(config.as_bytes()),
        )?;
        if reply.status == 409 {
            return Err(ControlError::Stale(version));
        }
        expect_ok(reply)?["data"]["config_version"]
            .as_u64()
            .ok_or(ControlError::Response("no config_version in the reply"))
    }

    /// `PUT /v1/tenants/<name>/members/<github_id>` with `{"role"}` (`204`), then a read of the
    /// tenant to tell what it did: for anyone not already holding the role it records an
    /// invite, except that an owner lowered to member changes at once.
    ///
    /// # Errors
    /// [`ControlError::TenantName`], a transport error, or the refusal of the `PUT`. A failed
    /// read afterwards is [`Grant::Unconfirmed`], not an error.
    pub fn set_member(
        &self,
        name: &str,
        github_id: u64,
        role: Role,
    ) -> Result<Grant, ControlError> {
        let name = tenant_name(name)?;
        self.call(
            Method::Put,
            &format!("/v1/tenants/{}/members/{github_id}", name.as_str()),
            Some(&json!({ "role": role.as_str() })),
        )?;
        let Ok(t) = self.show(name.as_str()) else {
            return Ok(Grant::Unconfirmed);
        };
        let holds = |list: &str| {
            t[list].as_array().is_some_and(|v| {
                v.iter().any(|m| {
                    m["github_id"].as_u64() == Some(github_id) && m["role"] == role.as_str()
                })
            })
        };
        Ok(if holds("invites") {
            Grant::Invited
        } else if holds("members") {
            Grant::Applied
        } else {
            Grant::Unconfirmed
        })
    }

    /// `DELETE /v1/tenants/<name>/members/<github_id>` (`204`): removes a member or withdraws
    /// a pending invite.
    ///
    /// # Errors
    /// [`ControlError::TenantName`], a transport error, or the refusal (the last owner can't
    /// be removed).
    pub fn remove_member(&self, name: &str, github_id: u64) -> Result<(), ControlError> {
        let name = tenant_name(name)?;
        self.call(
            Method::Delete,
            &format!("/v1/tenants/{}/members/{github_id}", name.as_str()),
            None,
        )
        .map(drop)
    }

    /// `POST /v1/tenants/<name>/accept` (body `{}`): accepts the caller's pending invite.
    /// Returns the role now held, which is never lower than one already held.
    ///
    /// # Errors
    /// [`ControlError::TenantName`], a transport error, or the refusal (`404 tenant not found`
    /// with no invite, `403 tenant is suspended`).
    pub fn accept(&self, name: &str) -> Result<String, ControlError> {
        let name = tenant_name(name)?;
        let reply = self.call(
            Method::Post,
            &format!("/v1/tenants/{}/accept", name.as_str()),
            Some(&json!({})),
        )?;
        reply["data"]["role"]
            .as_str()
            .map(str::to_owned)
            .ok_or(ControlError::Response("no role in the reply"))
    }

    /// `POST /v1/tenants/<name>/decline` (body `{}`, `204`): declines the caller's pending
    /// invite.
    ///
    /// # Errors
    /// [`ControlError::TenantName`], a transport error, or the refusal (`404 tenant not found`
    /// with no invite).
    pub fn decline(&self, name: &str) -> Result<(), ControlError> {
        let name = tenant_name(name)?;
        self.call(
            Method::Post,
            &format!("/v1/tenants/{}/decline", name.as_str()),
            Some(&json!({})),
        )
        .map(drop)
    }

    /// `PUT /v1/ops/tenants/<name>/status` (body `{"status"}`, `204`, operators only). A
    /// suspended tenant's host refuses every request and its config and members can't change;
    /// its owners can still export.
    ///
    /// # Errors
    /// [`ControlError::TenantName`], a transport error, or the refusal (`404 tenant not found`,
    /// `403 permission denied` for a non-operator).
    pub fn set_tenant_status(&self, name: &str, status: TenantStatus) -> Result<(), ControlError> {
        let name = tenant_name(name)?;
        self.call(
            Method::Put,
            &format!("/v1/ops/tenants/{}/status", name.as_str()),
            Some(&json!({ "status": status.as_str() })),
        )
        .map(drop)
    }

    /// `PUT /v1/ops/allowlist/<github_id>` (body `{}`, `204`, operators only): lets the user
    /// sign up while `SIGNUP_MODE` is `invite`.
    ///
    /// # Errors
    /// A transport error, or the refusal (`403 permission denied` for a non-operator).
    pub fn allowlist_add(&self, github_id: u64) -> Result<(), ControlError> {
        self.call(
            Method::Put,
            &format!("/v1/ops/allowlist/{github_id}"),
            Some(&json!({})),
        )
        .map(drop)
    }

    /// `DELETE /v1/ops/allowlist/<github_id>` (`204`, operators only).
    ///
    /// # Errors
    /// A transport error, or the refusal (`404 not on the allowlist`).
    pub fn allowlist_remove(&self, github_id: u64) -> Result<(), ControlError> {
        self.call(
            Method::Delete,
            &format!("/v1/ops/allowlist/{github_id}"),
            None,
        )
        .map(drop)
    }

    /// `GET /v1/ops/allowlist` (operators only).
    ///
    /// # Errors
    /// A transport error, the refusal, or a reply missing a field.
    pub fn allowlist(&self) -> Result<Allowlist, ControlError> {
        let reply = self.call(Method::Get, "/v1/ops/allowlist", None)?;
        let d = &reply["data"];
        let entries = d["allowlist"]
            .as_array()
            .ok_or(ControlError::Response("no allowlist in the reply"))?
            .iter()
            .map(|e| {
                Some((
                    e["github_id"].as_u64()?,
                    e["added_by"].as_u64()?,
                    e["added_ms"].as_u64()?,
                ))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(ControlError::Response(
                "an allowlist entry without its fields",
            ))?;
        let unverified = d["unverified"]
            .as_array()
            .map(|v| v.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();
        Ok(Allowlist {
            entries,
            unverified,
        })
    }

    /// `GET /v1/ops/invite-requests` (operators only).
    ///
    /// # Errors
    /// A transport error, the refusal, or a reply missing a field.
    pub fn invite_requests(&self) -> Result<InviteRequests, ControlError> {
        let reply = self.call(Method::Get, "/v1/ops/invite-requests", None)?;
        let d = &reply["data"];
        let requests = d["requests"]
            .as_array()
            .ok_or(ControlError::Response("no requests in the reply"))?
            .iter()
            .map(|r| {
                Some(InviteRequest {
                    github_id: r["github_id"].as_u64()?,
                    login: r["login"].as_str()?.to_owned(),
                    note: r["note"].as_str()?.to_owned(),
                    created_ms: r["created_ms"].as_u64()?,
                    status: r["status"].as_str()?.to_owned(),
                    decided_by: r["decided_by"].as_u64(),
                    decided_ms: r["decided_ms"].as_u64(),
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(ControlError::Response(
                "an invite request without its fields",
            ))?;
        Ok(InviteRequests {
            requests,
            unverified: d["unverified"]
                .as_array()
                .map(|v| v.iter().filter_map(Value::as_u64).collect())
                .unwrap_or_default(),
            pending: d["pending"].as_u64().unwrap_or_default(),
        })
    }

    /// `POST /v1/ops/invite-requests/<github_id>/approve` (body `{}`, `204`, operators only):
    /// puts the user on the signup allowlist and marks the request approved.
    ///
    /// # Errors
    /// A transport error, or the refusal (`404 request_not_found`, `409 request_unverified` or
    /// `request_not_pending`).
    pub fn invite_request_approve(&self, github_id: u64) -> Result<(), ControlError> {
        self.call(
            Method::Post,
            &format!("/v1/ops/invite-requests/{github_id}/approve"),
            Some(&json!({})),
        )
        .map(drop)
    }

    /// `POST /v1/ops/invite-requests/<github_id>/decline` (body `{}`, `204`, operators only).
    ///
    /// # Errors
    /// As [`Client::invite_request_approve`].
    pub fn invite_request_decline(&self, github_id: u64) -> Result<(), ControlError> {
        self.call(
            Method::Post,
            &format!("/v1/ops/invite-requests/{github_id}/decline"),
            Some(&json!({})),
        )
        .map(drop)
    }

    /// `DELETE /v1/ops/invite-requests/<github_id>` (`204`, operators only): removes the
    /// request, whatever its status. A declined user can then ask again.
    ///
    /// # Errors
    /// A transport error, or the refusal (`404 request_not_found`).
    pub fn invite_request_delete(&self, github_id: u64) -> Result<(), ControlError> {
        self.call(
            Method::Delete,
            &format!("/v1/ops/invite-requests/{github_id}"),
            None,
        )
        .map(drop)
    }

    /// `POST /v1/tenants/<name>/export`: the tenant's root id and base64 root key. The parsed
    /// reply is zeroized; the key is checked to be base64 of 32 bytes.
    ///
    /// # Errors
    /// [`ControlError::StaleLogin`] on `403 fresh login required`, [`ControlError::Response`]
    /// for a reply without a well-formed key, a transport error, or the refusal.
    pub fn export(&self, name: &str) -> Result<Exported, ControlError> {
        let name = tenant_name(name)?;
        let reply = self.send(
            Method::Post,
            &format!("/v1/tenants/{}/export", name.as_str()),
            None,
            Some(b"{}"),
        )?;
        if reply.status == 403 && error_message(&reply.body) == FRESH_LOGIN_REQUIRED {
            return Err(ControlError::StaleLogin);
        }
        let mut reply = expect_ok(reply)?;
        let d = &reply["data"];
        let root_id = d["root_id"].as_str().map(str::to_owned);
        let root_key = d["root_key"].as_str().map(|k| Zeroizing::new(k.to_owned()));
        zeroize_json(&mut reply);
        let root_id = root_id.ok_or(ControlError::Response("no root_id in the reply"))?;
        let root_key = root_key.ok_or(ControlError::Response("no root_key in the reply"))?;
        let mut decoded = Zeroizing::new([0u8; 48]);
        match STANDARD.decode_slice(root_key.as_bytes(), &mut decoded[..]) {
            Ok(32) => Ok(Exported { root_id, root_key }),
            _ => Err(ControlError::Response("root_key is not base64 of 32 bytes")),
        }
    }
}
