//! `login github`: GitHub's OAuth device flow with edgekms's OAuth App, then the user token to
//! the Worker's `github-user` mount. The Worker checks the token belongs to that App and reads
//! the user id from GitHub; the CLI only fetches the token and hands it over.

use std::time::Duration;

use serde_json::Value;
use zeroize::Zeroizing;

use super::{Body, LoginError, Transport, check_addr, check_mount, vault_login, zeroize_json};

pub const GITHUB_DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
pub const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
/// Names a stand-in for `https://github.com` in the device flow's two endpoints, for the hosted
/// end-to-end run's GitHub stub. Only a plain-http loopback address is accepted
/// ([`stub_endpoints`]), so it can't point a real login at another server.
pub const GITHUB_OAUTH_BASE_ENV: &str = "EDGEKMS_GITHUB_OAUTH_BASE";

/// The device-code and token URLs under `base`, a stand-in for `https://github.com` named by
/// [`GITHUB_OAUTH_BASE_ENV`].
///
/// # Errors
/// [`LoginError::Insecure`] unless `base` is `http://` to a loopback host as [`check_addr`]
/// defines it; `https://` is refused too, since the variable exists only for a local stub.
pub fn stub_endpoints(base: &str) -> Result<(String, String), LoginError> {
    let base = check_addr(base)?;
    if !base.starts_with("http://") {
        return Err(LoginError::Insecure(base.to_owned()));
    }
    Ok((
        format!("{base}/login/device/code"),
        format!("{base}/login/oauth/access_token"),
    ))
}

/// GitHub's default polling interval, and its `slow_down` increment.
const DEFAULT_INTERVAL_SECS: u64 = 5;
const DEFAULT_EXPIRES_SECS: u64 = 900;
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The OAuth App and the endpoints its device flow runs against.
#[derive(Debug, Clone, Copy)]
pub struct DeviceFlow<'a> {
    pub client_id: &'a str,
    pub device_code_url: &'a str,
    pub token_url: &'a str,
}

impl<'a> DeviceFlow<'a> {
    /// github.com's endpoints.
    #[must_use]
    pub fn github(client_id: &'a str) -> Self {
        Self {
            client_id,
            device_code_url: GITHUB_DEVICE_CODE_URL,
            token_url: GITHUB_TOKEN_URL,
        }
    }
}

/// What the operator must do in a browser: open `verification_uri` and type `user_code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePrompt {
    pub verification_uri: String,
    pub user_code: String,
    pub expires_in: u64,
}

fn oauth_error(body: &Value) -> Option<String> {
    let code = body["error"].as_str()?;
    Some(match body["error_description"].as_str() {
        Some(d) => format!("{code}: {d}"),
        None => code.to_owned(),
    })
}

/// Runs the device flow and returns the GitHub user token. `prompt` shows the operator the code;
/// `sleep` waits between polls (injectable so tests don't wait). Gives up when the device code
/// expires, counting the time slept.
///
/// # Errors
/// [`LoginError::Authorization`] if the operator declines or GitHub refuses,
/// [`LoginError::Timeout`] when the code expires, or a transport or reply error.
pub fn github_device_token(
    t: &impl Transport,
    flow: &DeviceFlow<'_>,
    prompt: impl FnOnce(&DevicePrompt),
    mut sleep: impl FnMut(Duration),
) -> Result<Zeroizing<String>, LoginError> {
    let device_code_url = check_addr(flow.device_code_url)?;
    let token_url = check_addr(flow.token_url)?;
    let mut reply = t.post(
        device_code_url,
        Body::Form(&[("client_id", flow.client_id)]),
    )?;
    if let Some(e) = oauth_error(&reply.body) {
        return Err(LoginError::Authorization(e));
    }
    if !reply.ok() {
        return Err(LoginError::Rejected {
            status: reply.status,
            message: "GitHub refused the device code request".into(),
        });
    }
    let field = |name, what| {
        reply.body[name]
            .as_str()
            .map(str::to_owned)
            .ok_or(LoginError::Response(what))
    };
    let device_code = Zeroizing::new(field("device_code", "GitHub sent no device_code")?);
    let p = DevicePrompt {
        verification_uri: field("verification_uri", "GitHub sent no verification_uri")?,
        user_code: field("user_code", "GitHub sent no user_code")?,
        expires_in: reply.body["expires_in"]
            .as_u64()
            .unwrap_or(DEFAULT_EXPIRES_SECS),
    };
    // A hostile or broken server's 0 would make this a busy loop.
    let mut interval = reply.body["interval"]
        .as_u64()
        .unwrap_or(DEFAULT_INTERVAL_SECS)
        .max(1);
    zeroize_json(&mut reply.body);
    let expires_in = p.expires_in;
    prompt(&p);

    let mut waited = 0u64;
    loop {
        if waited.saturating_add(interval) > expires_in {
            return Err(LoginError::Timeout(
                "the device code expired before it was approved",
            ));
        }
        sleep(Duration::from_secs(interval));
        waited += interval;
        let mut reply = t.post(
            token_url,
            Body::Form(&[
                ("client_id", flow.client_id),
                ("device_code", device_code.as_str()),
                ("grant_type", GRANT_TYPE),
            ]),
        )?;
        let token = reply.body["access_token"]
            .as_str()
            .map(|s| Zeroizing::new(s.to_owned()));
        let error = reply.body["error"].as_str().map(str::to_owned);
        let described = oauth_error(&reply.body);
        let next_interval = reply.body["interval"].as_u64();
        // The reply holds the access token (and possibly a refresh token).
        zeroize_json(&mut reply.body);
        if let Some(token) = token {
            return Ok(token);
        }
        match error.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => {
                interval = next_interval
                    .unwrap_or(interval + DEFAULT_INTERVAL_SECS)
                    .max(1);
            }
            Some("expired_token") => {
                return Err(LoginError::Timeout(
                    "the device code expired before it was approved",
                ));
            }
            Some(_) => {
                return Err(LoginError::Authorization(described.unwrap_or_default()));
            }
            None => {
                return Err(LoginError::Response(
                    "GitHub's token reply had neither a token nor an error",
                ));
            }
        }
    }
}

/// The whole login: device flow, then the token to `auth/<mount>/login` as
/// `{"role", "token"}`. Returns the edgekms client token. The address and mount are checked
/// before GitHub is contacted.
///
/// # Errors
/// A [`LoginError`] from the checks, the device flow, or the Worker.
pub fn login_github(
    t: &impl Transport,
    flow: &DeviceFlow<'_>,
    prompt: impl FnOnce(&DevicePrompt),
    sleep: impl FnMut(Duration),
    addr: &str,
    mount: &str,
    role: &str,
) -> Result<String, LoginError> {
    let addr = check_addr(addr)?;
    check_mount(mount)?;
    let token = github_device_token(t, flow, prompt, sleep)?;
    vault_login(t, addr, mount, role, "token", &token)
}
