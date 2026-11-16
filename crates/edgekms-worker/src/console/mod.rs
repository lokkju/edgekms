//! The web console on `app.<apex>`: GitHub web-flow sign-in, a session cookie holding the
//! control token, an in-process proxy from `/api/v1/*` to the control plane, and the
//! single-page app's static assets for everything else.
//!
//! | Route | What it does |
//! |---|---|
//! | `GET /auth/login?return_to=<path>` | Starts the web flow: state and PKCE in the auth cookie, `302` to GitHub. |
//! | `GET /auth/callback?code&state` | Checks the state, exchanges the code, logs in through `POST /v1/login/github`, sets the session cookie, `302` to `return_to` with `signed_in=1` added to its query. |
//! | `POST /auth/logout` | `POST /v1/logout` with the session's token, then clears the cookie (kept, with the `5xx` passed on, if the logout failed). |
//! | `* /api/v1/<rest>` | The control API as `/v1/<rest>`, with the session cookie as the bearer token; for `rest` exactly `invite-requests` or `invite-requests/mine`, the request cookie instead. |
//! | `GET`/`HEAD` anything else | The SPA's static assets ([`ConsoleReply::Asset`]). |
//!
//! Sign-in failures redirect to `/signin?error=<code>` with one of `state`, `github_denied`,
//! `signup_closed`, `rate_limited` or `login_failed`, and never say more. The one exception is a
//! `signup_closed` refusal that carries a request token (`invite` mode, lokkju/edgekms#12): the
//! callback keeps the token in the request cookie and sends the browser to `/request-invite`,
//! where the refused user can ask for an invite. The request cookie goes only to the two
//! requester paths and the session cookie never does, so neither token is ever presented where
//! the other belongs.
//!
//! The console decides nothing about permissions: every API call, and the login itself, goes
//! through [`control::handle`], so the control plane's rate limits, audit events and
//! authorization apply unchanged. The one call the console makes on its own, the callback's
//! exchange of GitHub's code for a user token, is metered the same way before it reaches
//! GitHub: refused without a client IP, counted against `CONTROL_LIMIT` (so a sign-in costs two
//! units, this one and the login's), a rejected code counted against `AUTH_FAIL_LIMIT`, and
//! every refusal or failure written as a metric. What it adds is the browser's side of the bargain: the token
//! lives only in an `HttpOnly` cookie, an incoming `Authorization` or `X-Vault-Token` header is
//! discarded, the API's login route is unreachable, and every state change must come from the
//! console's own origin (`Origin` checked, `SameSite=Strict`, and a JSON content type that keeps
//! it out of the requests a browser sends cross-site without a preflight).

pub mod cookie;
pub mod flow;
pub mod headers;

use serde_json::Value;
use worker::Method;
use zeroize::{Zeroize as _, Zeroizing};

use crate::audit::{AuditEvent, AuditSink, Limit, RateLimit};
use crate::control::{self, Control};
use crate::github::{GithubError, plausible_token};
use crate::handlers::ApiRequest;
use crate::store::TenantStore;
use crate::vault::{Reply, log_internal};
use cookie::{AUTH_COOKIE, REQUEST_COOKIE, SESSION_COOKIE, SameSite};

/// How long a sign-in may take, in seconds.
pub const AUTH_MAX_AGE: u32 = 600;
/// The session cookie's lifetime when the login reply doesn't say: the control token's.
pub const SESSION_MAX_AGE: u32 = 1800;
/// The request cookie's lifetime, and its most: the request token's.
pub const REQUEST_MAX_AGE: u32 = 900;
/// The page a refused user with a request token lands on.
pub const REQUEST_PAGE: &str = "/request-invite";

/// A `Set-Cookie` value; the session's holds the control token, so each is zeroized on drop.
pub type SetCookie = Zeroizing<String>;

/// A request to `app.<apex>`.
pub struct ConsoleRequest {
    /// Method, path, client IP and body, as [`crate::handlers::ApiRequest`] reads them.
    pub api: ApiRequest,
    /// The URL's query string, without its `?`.
    pub query: String,
    /// `Cookie`.
    pub cookie: Option<String>,
    /// `Origin`.
    pub origin_header: Option<String>,
    /// `Content-Type`.
    pub content_type: Option<String>,
}

/// What the Worker sends back.
#[derive(Debug)]
pub enum ConsoleReply {
    /// A JSON reply (the control plane's, or the console's own refusal).
    Json {
        reply: Reply,
        set_cookies: Vec<SetCookie>,
    },
    /// `302` to `location`, a same-origin path or GitHub's authorize page.
    Redirect {
        location: String,
        set_cookies: Vec<SetCookie>,
    },
    /// Serve the request from the static assets.
    Asset,
}

impl ConsoleReply {
    /// `reply` with no cookies.
    #[must_use]
    pub fn json(reply: Reply) -> Self {
        Self::Json {
            reply,
            set_cookies: Vec::new(),
        }
    }
}

fn json(reply: Reply) -> ConsoleReply {
    ConsoleReply::json(reply)
}

/// `status {"errors": [msg], "code": code}`, as the control plane writes its coded refusals.
fn coded(status: u16, msg: &str, code: &str) -> Reply {
    let mut r = Reply::error(status, msg);
    if let Some(Value::Object(body)) = r.body.as_mut() {
        body.insert("code".to_owned(), Value::from(code));
    }
    r
}

/// Whether `path` is `prefix` or below it.
fn under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Whether [`handle`] answers `method path` with [`ConsoleReply::Asset`]: a `GET` or `HEAD`
/// outside `/api` and `/auth`. The Worker checks this first, so serving an asset reads neither
/// the body nor the control plane's bindings.
#[must_use]
pub fn is_asset(method: &Method, path: &str) -> bool {
    matches!(method, Method::Get | Method::Head) && !under(path, "/api") && !under(path, "/auth")
}

/// Serves one request to `app.<apex>`. `origin_template` is `HOSTED_ORIGIN_TEMPLATE`.
pub async fn handle<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    origin_template: &str,
    mut req: ConsoleRequest,
) -> ConsoleReply {
    // The cookie may hold the control token; this copy is the only one kept, and it's zeroized
    // when the request is done.
    let cookies = Zeroizing::new(req.cookie.take().unwrap_or_default());
    let s = Site {
        origin_template,
        cookies: &cookies,
    };
    let method = req.api.method.clone();
    let path = req.api.path.clone();
    if is_asset(&method, &path) {
        return ConsoleReply::Asset;
    }
    match (method, path.as_str()) {
        (Method::Get, "/auth/login") => login(c, &s, &req).await,
        (Method::Get, "/auth/callback") => callback(c, &s, &req).await,
        (Method::Post, "/auth/logout") => logout(c, &s, &req).await,
        (_, "/auth/login" | "/auth/callback" | "/auth/logout") => json(Reply::method_not_allowed()),
        (_, p) if under(p, "/api") || under(p, "/auth") => match p.strip_prefix("/api/v1/") {
            Some(rest) => proxy(c, &s, req, rest).await,
            None => json(Reply::error(404, "unsupported path")),
        },
        _ => json(Reply::method_not_allowed()),
    }
}

/// What every route needs besides the request.
struct Site<'a> {
    origin_template: &'a str,
    /// The `Cookie` header, empty when there was none.
    cookies: &'a str,
}

impl Site<'_> {
    /// Whether the request's `Origin` is exactly the console's.
    fn same_origin(&self, req: &ConsoleRequest) -> bool {
        req.origin_header.as_deref() == Some(flow::console_origin(self.origin_template).as_str())
    }

    /// The session's control token, if the browser sent a non-empty one.
    fn session(&self) -> Option<&str> {
        cookie::get(Some(self.cookies), SESSION_COOKIE).filter(|t| !t.is_empty())
    }

    /// The request token, if the browser sent a non-empty one.
    fn request_token(&self) -> Option<&str> {
        cookie::get(Some(self.cookies), REQUEST_COOKIE).filter(|t| !t.is_empty())
    }
}

/// An internal control-plane request on behalf of `req`'s client: same IP, limit key, country
/// and host, so limits and audit events see the real caller.
fn on_behalf(
    req: &ApiRequest,
    method: Method,
    path: &str,
    authorization: Option<String>,
    body: Zeroizing<Vec<u8>>,
) -> ApiRequest {
    ApiRequest {
        method,
        path: path.to_owned(),
        origin: req.origin.clone(),
        host: req.host.clone(),
        vault_token: None,
        authorization,
        if_match: None,
        limit_key: req.limit_key.clone(),
        ip: req.ip.clone(),
        country: req.country.clone(),
        body,
    }
}

/// Overwrites the bearer token an internal request carried.
fn forget_authorization(api: &mut ApiRequest) {
    if let Some(a) = api.authorization.as_mut() {
        a.zeroize();
    }
}

fn cross_origin() -> ConsoleReply {
    json(Reply::error(403, "cross-origin request refused"))
}

/// `GET /auth/login`.
async fn login<S, A, L>(
    c: &Control<'_, S, A, L>,
    s: &Site<'_>,
    req: &ConsoleRequest,
) -> ConsoleReply {
    let start = match flow::start().await {
        Ok(start) => start,
        Err(reply) => return json(reply),
    };
    let return_to = flow::safe_return_to(flow::query_param(&req.query, "return_to").as_deref());
    let value = Zeroizing::new(flow::pack(&start.state, &start.verifier, &return_to));
    ConsoleReply::Redirect {
        location: flow::authorize_url(
            &c.settings.github_client_id,
            &flow::redirect_uri(s.origin_template),
            &start.state,
            &start.challenge,
        ),
        set_cookies: vec![Zeroizing::new(cookie::set(
            AUTH_COOKIE,
            &value,
            SameSite::Lax,
            AUTH_MAX_AGE,
        ))],
    }
}

/// `/signin?error=<code>`, clearing the auth cookie.
fn signin_error(code: &'static str) -> ConsoleReply {
    ConsoleReply::Redirect {
        location: format!("/signin?error={code}"),
        set_cookies: vec![Zeroizing::new(cookie::clear(AUTH_COOKIE, SameSite::Lax))],
    }
}

/// `{"token": "<token>"}` in a buffer sized so serializing never reallocates (a JSON escape
/// is at most six bytes per input byte), so no copy of the token is left behind.
fn login_body(token: &str) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(token.len() * 6 + 16));
    body.extend_from_slice(b"{\"token\":");
    // Writing a string into a Vec can't fail.
    let _ = serde_json::to_writer(&mut *body, token);
    body.push(b'}');
    body
}

/// The audit op of a code exchange the callback refused or GitHub didn't complete; metrics
/// only, like the control plane's other refusals.
const EXCHANGE_OP: &str = "console_code_exchange";

/// Exchanges GitHub's `code` for a user token, or says which `/signin` error to show.
///
/// The exchange spends the App's client secret on GitHub's token endpoint, and a script that
/// holds its own auth cookie can replay the callback at will, so the exchange is metered before
/// it happens: refused without a client IP, as `control::handle` refuses, and counted against
/// `CONTROL_LIMIT`. A successful sign-in then counts a second unit in the login the callback
/// makes; two per sign-in is the price of metering the exchange. A code GitHub rejects counts
/// against `AUTH_FAIL_LIMIT`. Every refusal or failure is written as a metric.
async fn exchange<S, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    s: &Site<'_>,
    req: &ConsoleRequest,
    code: &str,
    verifier: &str,
) -> Result<Zeroizing<String>, &'static str> {
    let mut ev = AuditEvent::new(EXCHANGE_OP);
    ev.control = true;
    ev.ts = c.now_ms;
    ev.ip.clone_from(&req.api.ip);
    ev.country.clone_from(&req.api.country);
    let key = req
        .api
        .limit_key
        .as_deref()
        .filter(|_| req.api.ip.is_some());
    let refused = match key {
        None => Some((control::NO_CLIENT_IP, "login_failed")),
        Some(key) if !c.limits.allow(Limit::Control, key).await => {
            Some((control::RATE_LIMITED, "rate_limited"))
        }
        Some(_) => None,
    };
    if let Some((label, error)) = refused {
        ev.result = "denied";
        ev.error = Some(label);
        c.audit.metric(&ev);
        return Err(error);
    }
    let redirect_uri = flow::redirect_uri(s.origin_template);
    let result = c
        .github
        .exchange_code(&c.settings.github_client_id, code, &redirect_uri, verifier)
        .await;
    let error = match result {
        Ok(token) => return Ok(token),
        // A rejected code is a failed authentication from this IP, counted against
        // AUTH_FAIL_LIMIT as a refused `edgekms login` is.
        Err(GithubError::Denied(label)) => {
            let r = control::auth_failed(c, &req.api, &mut ev, label, Reply::denied()).await;
            if r.status == 429 {
                "rate_limited"
            } else {
                "github_denied"
            }
        }
        Err(GithubError::Unavailable(label)) => {
            log_internal(label);
            ev.error = Some(label);
            "login_failed"
        }
    };
    c.audit.metric(&ev);
    Err(error)
}

/// `GET /auth/callback`. Every outcome clears the auth cookie, so a code and state work once.
async fn callback<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    s: &Site<'_>,
    req: &ConsoleRequest,
) -> ConsoleReply {
    let Some((state, verifier, return_to)) =
        cookie::get(Some(s.cookies), AUTH_COOKIE).and_then(flow::unpack)
    else {
        return signin_error("state");
    };
    let verifier = Zeroizing::new(verifier);
    let Some(got_state) = flow::query_param(&req.query, "state") else {
        return signin_error("state");
    };
    if !flow::same(&state, &got_state) {
        return signin_error("state");
    }
    // The user declined on GitHub's page.
    if flow::query_param(&req.query, "error").is_some() {
        return signin_error("github_denied");
    }
    let Some(code) = flow::query_param(&req.query, "code").map(Zeroizing::new) else {
        return signin_error("state");
    };
    if !plausible_token(&code) {
        return signin_error("github_denied");
    }
    let token = match exchange(c, s, req, &code, &verifier).await {
        Ok(token) => token,
        Err(error) => return signin_error(error),
    };
    // The same login as `edgekms login`: user check, token revocation, SIGNUP_MODE, personal
    // tenant, CONTROL_LIMIT and AUTH_FAIL_LIMIT counting, and the durable audit record.
    let api = on_behalf(
        &req.api,
        Method::Post,
        "/v1/login/github",
        None,
        login_body(&token),
    );
    let reply = control::handle(c, &api).await;
    // A refusal before the login reached `check_token` (its own control limit check) never
    // burned the token, so burn it here. After `check_token` the login already revoked it, and a
    // second revoke is harmless. A failure is logged, not fatal, as in the login itself.
    if reply.status != 200
        && let Err(label) = c
            .github
            .revoke_token(&c.settings.github_client_id, &token)
            .await
    {
        log_internal(label);
    }
    drop(token);
    match reply.status {
        200 => {}
        403 if reply
            .body
            .as_ref()
            .and_then(|b| b.get("code"))
            .and_then(Value::as_str)
            == Some("signup_closed") =>
        {
            return refused(&reply);
        }
        429 => return signin_error("rate_limited"),
        _ => return signin_error("login_failed"),
    }
    let data = reply.body.as_ref().map(|b| &b["data"]);
    let Some(session) = data
        .and_then(|d| d["token"].as_str())
        .filter(|t| !t.is_empty() && cookie::valid_value(t))
    else {
        log_internal("console: login reply without a usable token");
        return signin_error("login_failed");
    };
    let max_age = data
        .and_then(|d| d["expires_in"].as_u64())
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(SESSION_MAX_AGE);
    let session = Zeroizing::new(cookie::set(
        SESSION_COOKIE,
        session,
        SameSite::Strict,
        max_age,
    ));
    ConsoleReply::Redirect {
        // Checked when the sign-in started; checked again, since it came back from a cookie.
        // Marked so the SPA can tell a session refused right after sign-in (which would loop
        // through GitHub again) from one that expired.
        location: flow::mark_signed_in(&flow::safe_return_to(Some(&return_to))),
        set_cookies: vec![
            Zeroizing::new(cookie::clear(AUTH_COOKIE, SameSite::Lax)),
            session,
            // A request token from an earlier refusal is stale once the user is in.
            Zeroizing::new(cookie::clear(REQUEST_COOKIE, SameSite::Strict)),
        ],
    }
}

/// The callback's answer to a `signup_closed` refusal: with a request token (`invite` mode),
/// the request cookie and `302` to [`REQUEST_PAGE`]; without one, `/signin?error=signup_closed`.
/// The auth cookie is cleared either way, and `return_to` is ignored: a refused sign-in has
/// nowhere else to go.
fn refused(reply: &Reply) -> ConsoleReply {
    let body = reply.body.as_ref();
    let Some(token) = body
        .and_then(|b| b.get("request_token"))
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty() && cookie::valid_value(t))
    else {
        return signin_error("signup_closed");
    };
    let max_age = body
        .and_then(|b| b.get("request_expires_in"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| (1..=REQUEST_MAX_AGE).contains(n))
        .unwrap_or(REQUEST_MAX_AGE);
    ConsoleReply::Redirect {
        location: REQUEST_PAGE.to_owned(),
        set_cookies: vec![
            Zeroizing::new(cookie::clear(AUTH_COOKIE, SameSite::Lax)),
            // Another account's session in this browser would show a second identity beside
            // the refused one.
            Zeroizing::new(cookie::clear(SESSION_COOKIE, SameSite::Strict)),
            Zeroizing::new(cookie::set(
                REQUEST_COOKIE,
                token,
                SameSite::Strict,
                max_age,
            )),
        ],
    }
}

/// Whether `rest` (below `/api/v1/`) is one of the two requester paths, which take the request
/// cookie instead of the session cookie. Exact matches only.
fn requester_path(rest: &str) -> bool {
    matches!(rest, "invite-requests" | "invite-requests/mine")
}

/// `POST /auth/logout`: the control logout (every control token of the user stops working,
/// CLI sessions included), then the cookie is cleared. A session the control plane already
/// refuses is simply cleared; on a control-plane failure the cookie is kept and the `5xx`
/// passed on, so the browser doesn't claim a sign-out that didn't happen.
async fn logout<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    s: &Site<'_>,
    req: &ConsoleRequest,
) -> ConsoleReply {
    if !s.same_origin(req) {
        return cross_origin();
    }
    if let Some(token) = s.session() {
        let mut api = on_behalf(
            &req.api,
            Method::Post,
            "/v1/logout",
            Some(format!("Bearer {token}")),
            Zeroizing::new(Vec::new()),
        );
        let r = control::handle(c, &api).await;
        forget_authorization(&mut api);
        // The sessions are all still live, so the cookie stays and the SPA says so.
        if r.status >= 500 {
            return json(r);
        }
    }
    ConsoleReply::Json {
        reply: Reply::no_content(),
        set_cookies: vec![Zeroizing::new(cookie::clear(
            SESSION_COOKIE,
            SameSite::Strict,
        ))],
    }
}

/// Whether `content_type` is JSON (`application/json`, any parameters).
fn is_json(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|ct| ct.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
}

/// `/api/v1/<rest>`: the control API with the session as the bearer token, or, for the two
/// requester paths, the request token.
async fn proxy<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    s: &Site<'_>,
    req: ConsoleRequest,
    rest: &str,
) -> ConsoleReply {
    // The console signs in only through `/auth/callback`.
    if rest.starts_with("login") {
        return json(Reply::error(404, "unsupported path"));
    }
    if !matches!(req.api.method, Method::Get | Method::Head) {
        if !s.same_origin(&req) {
            return cross_origin();
        }
        if !req.api.body.is_empty() && !is_json(req.content_type.as_deref()) {
            return json(Reply::error(415, "content type must be application/json"));
        }
    }
    // Chosen by path after the origin and content type checks, which apply to both.
    let token = if requester_path(rest) {
        s.request_token()
            .ok_or_else(|| coded(401, "sign in to request an invite", "no_request_session"))
    } else {
        s.session()
            .ok_or_else(|| coded(401, "sign in required", "no_session"))
    };
    let token = match token {
        Ok(t) => t,
        Err(refusal) => return json(refusal),
    };
    let mut api = req.api;
    api.path = format!("/v1/{rest}");
    // The control plane binds SSH challenges to the origin it's addressed under; through the
    // console that is still the control origin, never the console's.
    api.origin = flow::control_origin(s.origin_template);
    // Whatever the browser sent in these headers, only the session cookie authenticates.
    api.vault_token = None;
    api.authorization = Some(format!("Bearer {token}"));
    let reply = control::handle(c, &api).await;
    forget_authorization(&mut api);
    json(reply)
}
