//! GitHub user tokens for `github-user` mounts. A token is accepted only if GitHub confirms it
//! was issued to the mount's own OAuth App (`POST /applications/{client_id}/token`,
//! authenticated with the App's client secret), so a token some other app holds can't be
//! replayed here. The same reply names the user, whose numeric id the role binds.
//!
//! The web console's sign-in also exchanges a web-flow `code` (with its PKCE verifier) for a
//! user token here ([`GithubApi::exchange_code`]); that token then takes the same path as one
//! from the device flow.

use std::future::Future;
use std::pin::Pin;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect};
use zeroize::Zeroizing;

use crate::vault::log_internal;

const API: &str = "https://api.github.com";
/// Where the web flow's code exchange goes when [`API`] is the API base.
const WEB: &str = "https://github.com";
/// Largest reply read from GitHub.
const MAX_REPLY_BYTES: usize = 64 * 1024;
/// Longest token sent to GitHub; real ones are far shorter.
pub const MAX_TOKEN_LEN: usize = 255;

/// The GitHub account a token belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubUser {
    pub id: u64,
    pub login: String,
}

/// Why a token wasn't accepted. `Denied` is the caller's fault (a token that isn't this App's,
/// or no token at all); `Unavailable` is the Worker's or GitHub's. Labels are fixed strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubError {
    Denied(&'static str),
    Unavailable(&'static str),
}

/// A boxed, non-`Send` future, as Workers' single-threaded runtime allows.
pub type LocalFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Where the login handler checks GitHub tokens; a trait object so tests can stub GitHub.
pub trait GithubApi {
    /// The user `token` belongs to, if it was issued to the OAuth App `client_id`.
    fn check_token<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a str,
    ) -> LocalFuture<'a, Result<GithubUser, GithubError>>;

    /// Revokes `token` (`DELETE /applications/{client_id}/token`), so a token that reached this
    /// deployment can't be replayed here or anywhere else. Errors are fixed labels.
    fn revoke_token<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a str,
    ) -> LocalFuture<'a, Result<(), &'static str>>;

    /// Exchanges a web-flow authorization `code` for a user token of the App `client_id`
    /// (`POST https://github.com/login/oauth/access_token`), proving the PKCE `verifier` and
    /// the `redirect_uri` the code was issued for.
    fn exchange_code<'a>(
        &'a self,
        client_id: &'a str,
        code: &'a str,
        redirect_uri: &'a str,
        verifier: &'a str,
    ) -> LocalFuture<'a, Result<Zeroizing<String>, GithubError>>;
}

/// Refuses every check: the Worker has no `GITHUB_CLIENT_SECRET`.
pub struct NoGithub;

impl GithubApi for NoGithub {
    fn check_token<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> LocalFuture<'a, Result<GithubUser, GithubError>> {
        Box::pin(async { Err(GithubError::Unavailable("github_secret_missing")) })
    }

    fn revoke_token<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> LocalFuture<'a, Result<(), &'static str>> {
        Box::pin(async { Err("github_secret_missing") })
    }

    fn exchange_code<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> LocalFuture<'a, Result<Zeroizing<String>, GithubError>> {
        Box::pin(async { Err(GithubError::Unavailable("github_secret_missing")) })
    }
}

/// Where GitHub's API is: [`API`], unless the hosted Worker runs under `wrangler dev`
/// (`hosted_apex` is `localhost`) and `configured` (the `GITHUB_API_BASE` var) names an
/// `http(s)://` stub for the e2e run. A single-tenant Worker ignores the var, as it always has.
///
/// # Errors
/// `github_api_base_refused` for an override on any other hosted apex, or one that isn't an
/// `http://` or `https://` URL: the App's client secret must only ever go to GitHub.
pub fn api_base(
    hosted_apex: Option<&str>,
    configured: Option<&str>,
) -> Result<String, &'static str> {
    let (Some(apex), Some(base)) = (hosted_apex, configured) else {
        return Ok(API.to_owned());
    };
    let base = base.trim().trim_end_matches('/');
    let scheme_ok = base.starts_with("http://") || base.starts_with("https://");
    if apex.trim().eq_ignore_ascii_case("localhost") && scheme_ok {
        Ok(base.to_owned())
    } else {
        Err("github_api_base_refused")
    }
}

/// The production [`GithubApi`]: GitHub's REST API with the App's client secret.
pub struct FetchGithub {
    secret: Zeroizing<String>,
    /// [`API`], or the e2e stub (see [`api_base`]).
    api_base: String,
}

impl FetchGithub {
    /// `None` when the Worker has no `GITHUB_CLIENT_SECRET` secret, or (logged) when
    /// `GITHUB_API_BASE` is refused by [`api_base`]; `state::mode` refuses every request in
    /// that case anyway.
    #[must_use]
    pub fn from_env(env: &Env) -> Option<Self> {
        let var = |name: &str| env.var(name).ok().map(|v| v.to_string());
        let api_base = match api_base(
            var("HOSTED_APEX").as_deref(),
            var("GITHUB_API_BASE").as_deref(),
        ) {
            Ok(base) => base,
            Err(label) => {
                log_internal(label);
                return None;
            }
        };
        let secret = Zeroizing::new(env.secret("GITHUB_CLIENT_SECRET").ok()?.to_string());
        (!secret.trim().is_empty()).then_some(Self { secret, api_base })
    }

    /// `method /applications/{client_id}/token` with `{"access_token": token}`, authenticated
    /// as the App. Returns the status and the JSON body (`Null` if it isn't JSON).
    async fn call(
        &self,
        method: Method,
        client_id: &str,
        token: &str,
    ) -> Result<(u16, Value), &'static str> {
        let basic = Zeroizing::new(format!("{client_id}:{}", self.secret.trim()));
        let auth = Zeroizing::new(format!("Basic {}", STANDARD.encode(basic.as_bytes())));
        let headers = Headers::new();
        for (k, v) in [
            ("Authorization", auth.as_str()),
            ("Accept", "application/vnd.github+json"),
            ("Content-Type", "application/json"),
            ("User-Agent", "edgekms"),
            ("X-GitHub-Api-Version", "2022-11-28"),
        ] {
            headers.set(k, v).map_err(|_| "github_bad_header")?;
        }
        let body = Zeroizing::new(json!({ "access_token": token }).to_string());
        let mut init = RequestInit::new();
        init.with_method(method)
            .with_headers(headers)
            .with_body(Some(body.as_str().into()));
        // workerd rejects `redirect: "error"` when the Request is built (only "follow" and
        // "manual" exist at the edge), so take redirects manually and refuse any 3xx: the Basic
        // credentials must never follow a redirect anywhere.
        init.redirect = RequestRedirect::Manual;
        let url = format!("{}/applications/{client_id}/token", self.api_base);
        let req = Request::new_with_init(&url, &init).map_err(|_| "github_bad_request")?;
        let mut resp = Fetch::Request(req)
            .send()
            .await
            .map_err(|_| "github_unreachable")?;
        let status = resp.status_code();
        if (300..400).contains(&status) {
            return Err("github_redirected");
        }
        let bytes = Zeroizing::new(resp.bytes().await.map_err(|_| "github_unreadable_reply")?);
        if bytes.len() > MAX_REPLY_BYTES {
            return Err("github_reply_too_large");
        }
        Ok((
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        ))
    }

    async fn check(&self, client_id: &str, token: &str) -> Result<GithubUser, GithubError> {
        let (status, mut body) = self
            .call(Method::Post, client_id, token)
            .await
            .map_err(GithubError::Unavailable)?;
        let result = interpret(status, &body, client_id);
        // The reply echoes the token.
        zeroize_json(&mut body);
        result
    }

    /// `POST /login/oauth/access_token` with the code, the PKCE verifier and the App's
    /// credentials in a JSON body.
    async fn exchange(
        &self,
        client_id: &str,
        code: &str,
        redirect_uri: &str,
        verifier: &str,
    ) -> Result<Zeroizing<String>, GithubError> {
        const FAILED: GithubError = GithubError::Unavailable("github_exchange_failed");
        let fail = |label: &'static str| {
            log_internal(label);
            FAILED
        };
        let headers = Headers::new();
        for (k, v) in [
            ("Accept", "application/json"),
            ("Content-Type", "application/json"),
            ("User-Agent", "edgekms"),
        ] {
            headers.set(k, v).map_err(|_| fail("github_bad_header"))?;
        }
        let body = exchange_body(client_id, self.secret.trim(), code, redirect_uri, verifier);
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(body.as_str().into()));
        // As in `call`: the client secret must never follow a redirect, and a 3xx is refused
        // below as a reply that isn't a token.
        init.redirect = RequestRedirect::Manual;
        let req = Request::new_with_init(&exchange_url(&self.api_base), &init)
            .map_err(|_| fail("github_bad_request"))?;
        let mut resp = Fetch::Request(req)
            .send()
            .await
            .map_err(|_| fail("github_unreachable"))?;
        let status = resp.status_code();
        let bytes = Zeroizing::new(
            resp.bytes()
                .await
                .map_err(|_| fail("github_unreadable_reply"))?,
        );
        if bytes.len() > MAX_REPLY_BYTES {
            return Err(fail("github_reply_too_large"));
        }
        parse_exchange(status, std::str::from_utf8(&bytes).unwrap_or_default())
    }

    async fn revoke(&self, client_id: &str, token: &str) -> Result<(), &'static str> {
        match self.call(Method::Delete, client_id, token).await? {
            (204 | 200, _) => Ok(()),
            _ => Err("github_revoke_refused"),
        }
    }
}

impl GithubApi for FetchGithub {
    fn check_token<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a str,
    ) -> LocalFuture<'a, Result<GithubUser, GithubError>> {
        Box::pin(self.check(client_id, token))
    }

    fn revoke_token<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a str,
    ) -> LocalFuture<'a, Result<(), &'static str>> {
        Box::pin(self.revoke(client_id, token))
    }

    fn exchange_code<'a>(
        &'a self,
        client_id: &'a str,
        code: &'a str,
        redirect_uri: &'a str,
        verifier: &'a str,
    ) -> LocalFuture<'a, Result<Zeroizing<String>, GithubError>> {
        Box::pin(self.exchange(client_id, code, redirect_uri, verifier))
    }
}

/// The code exchange endpoint: github.com's, or the e2e stub's when [`api_base`] picked one.
#[must_use]
pub fn exchange_url(api_base: &str) -> String {
    let base = if api_base == API { WEB } else { api_base };
    format!("{base}/login/oauth/access_token")
}

/// The code exchange's JSON body. It holds the client secret, so it's zeroized on drop.
#[must_use]
pub fn exchange_body(
    client_id: &str,
    secret: &str,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Zeroizing<String> {
    let mut v = json!({
        "client_id": client_id,
        "client_secret": secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    });
    let body = Zeroizing::new(v.to_string());
    zeroize_json(&mut v);
    body
}

/// Reads GitHub's reply to the code exchange. GitHub answers refusals with `200` and an
/// `error` field: a bad, used or expired code (or a verifier that doesn't match) is the
/// caller's, while wrong App credentials or a redirect URI the App doesn't list are ours.
///
/// # Errors
/// [`GithubError::Denied`] (`github_code_rejected`) for a refused code;
/// [`GithubError::Unavailable`] for a misconfigured App (`github_exchange_misconfigured`) or a
/// reply that isn't a token (`github_exchange_failed`).
pub fn parse_exchange(status: u16, body: &str) -> Result<Zeroizing<String>, GithubError> {
    const FAILED: GithubError = GithubError::Unavailable("github_exchange_failed");
    if !(200..300).contains(&status) {
        return Err(FAILED);
    }
    let mut v: Value = serde_json::from_str(body).map_err(|_| FAILED)?;
    let result = if let Some(error) = v.get("error").and_then(Value::as_str) {
        match error {
            "incorrect_client_credentials" | "redirect_uri_mismatch" => {
                Err(GithubError::Unavailable("github_exchange_misconfigured"))
            }
            _ => Err(GithubError::Denied("github_code_rejected")),
        }
    } else {
        match v.get("access_token").and_then(Value::as_str) {
            Some(t) if plausible_token(t) => Ok(Zeroizing::new(t.to_owned())),
            _ => Err(FAILED),
        }
    };
    zeroize_json(&mut v);
    result
}

/// Overwrites every string in `v`.
fn zeroize_json(v: &mut Value) {
    match v {
        Value::String(s) => zeroize::Zeroize::zeroize(s),
        Value::Array(a) => a.iter_mut().for_each(zeroize_json),
        Value::Object(m) => m.values_mut().for_each(zeroize_json),
        _ => {}
    }
}

/// Reads GitHub's reply to `POST /applications/{client_id}/token`. 404 and 422 mean the token
/// isn't one of this App's (or isn't a token); 401 and 403 mean the App's credentials or rate
/// limit are the problem, not the caller.
///
/// # Errors
/// [`GithubError::Denied`] for a token that isn't this App's; [`GithubError::Unavailable`] for
/// any reply that says nothing about the token.
pub fn interpret(status: u16, body: &Value, client_id: &str) -> Result<GithubUser, GithubError> {
    match status {
        200 => {}
        404 | 422 => {
            return Err(GithubError::Denied("github_token_not_for_app"));
        }
        401 | 403 => {
            return Err(GithubError::Unavailable(
                "github_app_refused_or_rate_limited",
            ));
        }
        _ => return Err(GithubError::Unavailable("github_unexpected_status")),
    }
    if body["app"]["client_id"].as_str() != Some(client_id) {
        return Err(GithubError::Denied("github_token_not_for_app"));
    }
    let id = body["user"]["id"]
        .as_u64()
        .ok_or(GithubError::Unavailable("github_reply_without_user"))?;
    let login = body["user"]["login"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    Ok(GithubUser { id, login })
}

/// Whether `token` is worth sending to GitHub: non-empty, bounded, printable ASCII.
#[must_use]
pub fn plausible_token(token: &str) -> bool {
    (1..=MAX_TOKEN_LEN).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(client_id: &str, user_id: &Value) -> Value {
        json!({
            "id": 1,
            "token": "gho_x",
            "app": { "client_id": client_id, "name": "edgekms" },
            "user": { "login": "octocat", "id": user_id }
        })
    }

    #[test]
    fn a_token_of_this_app_names_its_user() {
        assert_eq!(
            interpret(200, &reply("Iv1.a", &json!(583_231)), "Iv1.a"),
            Ok(GithubUser {
                id: 583_231,
                login: "octocat".into()
            })
        );
    }

    #[test]
    fn a_token_of_another_app_is_denied_even_on_200() {
        assert!(matches!(
            interpret(200, &reply("Iv1.other", &json!(1)), "Iv1.a"),
            Err(GithubError::Denied(_))
        ));
    }

    #[test]
    fn unknown_tokens_are_denied_and_app_trouble_is_unavailable() {
        for s in [404, 422] {
            assert!(matches!(
                interpret(s, &json!({}), "Iv1.a"),
                Err(GithubError::Denied(_))
            ));
        }
        for s in [401, 403, 500, 502] {
            assert!(matches!(
                interpret(s, &json!({}), "Iv1.a"),
                Err(GithubError::Unavailable(_))
            ));
        }
        assert!(matches!(
            interpret(200, &reply("Iv1.a", &json!("1")), "Iv1.a"),
            Err(GithubError::Unavailable(_))
        ));
    }

    #[test]
    fn exchange_reply_with_a_token_is_ok() {
        let token = parse_exchange(
            200,
            r#"{"access_token":"ghu_abc123","token_type":"bearer","scope":""}"#,
        )
        .unwrap();
        assert_eq!(token.as_str(), "ghu_abc123");
    }

    #[test]
    fn exchange_refusals_are_denied_and_trouble_is_unavailable() {
        assert_eq!(
            parse_exchange(200, r#"{"error":"bad_verification_code"}"#),
            Err(GithubError::Denied("github_code_rejected"))
        );
        assert_eq!(
            parse_exchange(200, r#"{"error":"access_denied"}"#),
            Err(GithubError::Denied("github_code_rejected"))
        );
        for misconfigured in ["incorrect_client_credentials", "redirect_uri_mismatch"] {
            assert_eq!(
                parse_exchange(200, &format!(r#"{{"error":"{misconfigured}"}}"#)),
                Err(GithubError::Unavailable("github_exchange_misconfigured")),
                "{misconfigured}"
            );
        }
        for (status, body) in [
            (500, r#"{"access_token":"ghu_x"}"#),
            (404, "{}"),
            (200, "not json"),
            (200, "{}"),
            (200, r#"{"access_token":7}"#),
            (200, r#"{"access_token":""}"#),
            (200, r#"{"access_token":"has space"}"#),
        ] {
            assert_eq!(
                parse_exchange(status, body),
                Err(GithubError::Unavailable("github_exchange_failed")),
                "{status} {body}"
            );
        }
    }

    #[test]
    fn exchange_body_carries_the_pkce_verifier_and_the_secret() {
        let body = exchange_body(
            "Iv1.a",
            "s3cret",
            "code1",
            "https://app.x/auth/callback",
            "ver",
        );
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v,
            json!({
                "client_id": "Iv1.a",
                "client_secret": "s3cret",
                "code": "code1",
                "redirect_uri": "https://app.x/auth/callback",
                "code_verifier": "ver",
            })
        );
    }

    #[test]
    fn exchange_goes_to_github_or_the_e2e_stub() {
        assert_eq!(
            exchange_url(API),
            "https://github.com/login/oauth/access_token"
        );
        assert_eq!(
            exchange_url("http://127.0.0.1:9999"),
            "http://127.0.0.1:9999/login/oauth/access_token"
        );
    }

    #[test]
    fn implausible_tokens_are_not_sent() {
        assert!(plausible_token("gho_16C7e42F292c6912E7710c838347Ae178B4a"));
        for bad in ["", "a b", "x\n", &"a".repeat(MAX_TOKEN_LEN + 1)] {
            assert!(!plausible_token(bad), "{bad:?}");
        }
    }
}
