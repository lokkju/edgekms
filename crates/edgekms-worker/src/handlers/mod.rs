//! The Vault-compatible API as plain functions: an [`ApiRequest`] in, a [`Reply`] out. The
//! Workers glue in `lib.rs` only converts to and from these types, so every rule here (routing,
//! body cap, authentication, policy, audit, rate limits) is testable without a Workers runtime.
//!
//! [`handle`] audits every routed request except `sys/health`: handlers fill in the event as
//! they learn things (key, role, token id), and `handle` writes it before returning the reply.
//! If the write fails, the reply is dropped and the caller gets `500 audit log unavailable`.
//! Two classes of request perform no operation and are only counted as a metric, never written
//! to the durable log: rate-limited ones (every `429`), logins on a mount the config doesn't
//! have, and challenges on any mount that isn't SSH. That keeps durable writes bounded by the
//! rate limits.

pub(crate) mod login;
mod token;
mod transit;

use std::cell::{RefCell, RefMut};
use std::collections::BTreeMap;
use std::ops::Deref;

use edgekms_core::keyops::KeyOps;
use edgekms_core::token::{self as core_token, TokenClaims};
use serde_json::{Map, Value, json};
use worker::Method;
use zeroize::Zeroizing;

use crate::audit::{AuditEvent, AuditSink, Limit, RateLimit, allowed_meta};
use crate::auth::{Caller, Revocations, authenticate};
use crate::github::{GithubApi, NoGithub};
use crate::jwks::JwksSource;
use crate::state::State;
use crate::vault::{Reply, log_internal, zeroize_value};

/// Login tokens with a TTL over a day are "long": checked against the revocation list on every
/// use. Tokens from `auth/token/create` are always long, so revoking one always takes effect.
pub const LONG_TOKEN_SECS: u64 = 86_400;

/// The audit reason for a `429`; events with it go to metrics only.
const RATE_LIMITED: &str = "rate_limited";

/// The audit reason for a request a per-IP limit refused because it had no
/// `CF-Connecting-IP`. Metrics only, like a `429`, since no limiter bounds these.
const NO_CLIENT_IP: &str = "no_client_ip";

/// Largest request body accepted; anything larger is `413` before parsing.
pub const MAX_BODY: usize = 65_536;

/// The parts of an HTTP request the API looks at.
pub struct ApiRequest {
    pub method: Method,
    /// URL path, e.g. `/v1/transit/encrypt/app`.
    pub path: String,
    /// The request URL's origin, `scheme://host[:port]` (`https://kms.example.com`). SSH
    /// challenges are bound to it.
    pub origin: String,
    /// The request URL's host, lowercased, with its port when it has one
    /// (`acme.edgekms.dev`, `alice.localhost:8787`). Hosted mode routes on it.
    pub host: String,
    /// `X-Vault-Token`.
    pub vault_token: Option<String>,
    /// `Authorization`.
    pub authorization: Option<String>,
    /// `If-Match`. Only the hosted control plane reads it (optimistic locking on config
    /// edits); the Vault API ignores it.
    pub if_match: Option<String>,
    /// `CF-Connecting-IP`.
    pub ip: Option<String>,
    /// What the per-IP limiters count this request against. Today a copy of `ip`; the hosted
    /// tier keys calls from other Workers on `CF-Worker` too
    /// (`edgekms_core::clientip::limit_key`).
    pub limit_key: Option<String>,
    /// `request.cf.country`.
    pub country: Option<String>,
    /// Raw body; zeroized on drop since it may carry plaintext.
    pub body: Zeroizing<Vec<u8>>,
}

/// What a handler needs besides the request. Built per request with [`Deps::new`].
pub struct Deps<'a, K, R, J, A, L> {
    pub state: &'a State<K>,
    pub revocations: &'a R,
    /// Keys for `jwks_url` mounts.
    pub jwks: &'a J,
    pub audit: &'a A,
    pub limits: &'a L,
    /// GitHub token checks for `github-user` mounts; [`NoGithub`] unless set with
    /// [`Deps::with_github`].
    pub github: &'a dyn GithubApi,
    /// Unix seconds.
    pub now: u64,
    /// Unix milliseconds, the audit event's timestamp.
    pub now_ms: u64,
    /// The hosted tenant's id; `None` in single-tenant mode. Set with [`Deps::with_tenant`].
    pub tenant: Option<String>,
    /// The audit event of the request in progress.
    event: RefCell<AuditEvent>,
}

impl<'a, K, R, J, A, L> Deps<'a, K, R, J, A, L> {
    #[must_use]
    pub fn new(
        state: &'a State<K>,
        revocations: &'a R,
        jwks: &'a J,
        audit: &'a A,
        limits: &'a L,
        now_ms: u64,
    ) -> Self {
        Self {
            state,
            revocations,
            jwks,
            audit,
            limits,
            github: &NoGithub,
            now: now_ms / 1000,
            now_ms,
            tenant: None,
            event: RefCell::new(AuditEvent::new("")),
        }
    }

    /// Serves the hosted tenant `tenant_id`.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: String) -> Self {
        self.tenant = Some(tenant_id);
        self
    }

    /// Checks GitHub tokens with `github` instead of refusing them all.
    #[must_use]
    pub fn with_github(mut self, github: &'a dyn GithubApi) -> Self {
        self.github = github;
        self
    }

    /// The audit event in progress. Never held across an `.await`.
    fn event(&self) -> RefMut<'_, AuditEvent> {
        self.event.borrow_mut()
    }

    /// Marks the request denied for `label` (a fixed reason).
    fn deny(&self, label: &'static str) {
        let mut ev = self.event();
        ev.result = "denied";
        ev.error = Some(label);
    }

    /// Marks the request failed on the server's side for `label` (a fixed reason).
    fn fail(&self, label: &'static str) {
        let mut ev = self.event();
        ev.result = "error";
        ev.error = Some(label);
    }

    fn rate_limited(&self, req: &ApiRequest) -> Reply {
        self.deny(RATE_LIMITED);
        rate_limit_reply(&req.path)
    }
}

impl<K, R, J, A, L: RateLimit> Deps<'_, K, R, J, A, L> {
    /// Counts the request against a per-IP `limit`, keyed by its [`ApiRequest::limit_key`];
    /// `Err` is the reply to send: the `429` when the limit is reached, or `refusal` when there
    /// is no `CF-Connecting-IP` (and so no limit key).
    ///
    /// Cloudflare's edge sets that header on every request and `wrangler dev` sets it too, so
    /// a request without it came from neither (a service binding, say). Putting every such
    /// request in one shared bucket would let one client exhaust it for all the others, and
    /// giving each its own would leave them unlimited, so it is refused with the route's
    /// ordinary refusal. Not a `429`: Vault's Go clients retry those, and this never clears.
    async fn limit_ip(&self, limit: Limit, req: &ApiRequest, refusal: Reply) -> Result<(), Reply> {
        let (Some(_), Some(key)) = (req.ip.as_deref(), req.limit_key.as_deref()) else {
            self.deny(NO_CLIENT_IP);
            return Err(refusal);
        };
        if self.limits.allow(limit, key).await {
            Ok(())
        } else {
            Err(self.rate_limited(req))
        }
    }

    /// Hosted: counts the request once against the tenant's own `TENANT_LIMIT` budget, which
    /// bounds the R2 writes and store reads one tenant's traffic can cause. Called only once a
    /// per-IP gate has passed (after authentication succeeds, or after the login limit on login
    /// and challenge), so tokenless traffic from an IP that is already limited can't spend
    /// another caller's tenant budget. Single-tenant: nothing.
    async fn limit_tenant(&self, req: &ApiRequest) -> Result<(), Reply> {
        match &self.tenant {
            Some(tenant) if !self.limits.allow(Limit::Tenant, tenant).await => {
                Err(self.rate_limited(req))
            }
            _ => Ok(()),
        }
    }
}

/// OpenBao's answer when a rate limit quota refuses a request: `429` naming the path after
/// `/v1/`, quoted as Go's `%q` quotes it, e.g.
/// `{"errors":["request path \"auth/ssh/login\": rate limit quota exceeded"]}`.
///
/// A Workers URL path is already percent-encoded (`"` arrives as `%22`, control characters
/// likewise, and `\` as `/`), so escaping `"` and `\` covers everything `%q` would change.
fn rate_limit_reply(path: &str) -> Reply {
    let rest = path.strip_prefix("/v1/").unwrap_or(path);
    let mut quoted = String::with_capacity(rest.len() + 2);
    quoted.push('"');
    for c in rest.chars() {
        if matches!(c, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    Reply::error(
        429,
        &format!("request path {quoted}: rate limit quota exceeded"),
    )
}

impl<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit> Deps<'_, K, R, J, A, L> {
    /// Authenticates, records the caller in the audit event, then counts the request against
    /// the caller's token id. A failure is counted against the client IP's failed
    /// authentication limit instead, so bad tokens can't buy unlimited MAC checks and audit
    /// writes, and can't use up the IP's login limit either.
    async fn authenticate(&self, req: &ApiRequest) -> Result<Caller, Reply> {
        let caller = match authenticate(req, self.state, self.revocations, self.now).await {
            Ok(c) => c,
            Err(failure) => {
                if let Some((jti, role)) = failure.token {
                    self.note_token(jti, role);
                }
                self.limit_ip(Limit::AuthFailure, req, Reply::denied())
                    .await?;
                self.deny(failure.label);
                return Err(Reply::denied());
            }
        };
        self.note_token(caller.claims.jti.clone(), caller.claims.role.clone());
        self.event().meta = allowed_meta(&caller.claims.meta);
        self.limit_tenant(req).await?;
        // Hosted: `<tenant id>:<jti>`, so token ids from different tenants never share a bucket.
        let token_key = match &self.tenant {
            Some(tenant) => format!("{tenant}:{}", caller.claims.jti),
            None => caller.claims.jti.clone(),
        };
        if !self.limits.allow(Limit::Token, &token_key).await {
            return Err(self.rate_limited(req));
        }
        Ok(caller)
    }

    /// Records an authentic token's id, role and the role's mount.
    fn note_token(&self, jti: String, role: String) {
        let mut ev = self.event();
        ev.mount = self.state.config.roles.get(&role).map(|r| r.mount.clone());
        ev.jti = Some(jti);
        ev.role = Some(role);
    }

    /// Writes the request's audit event and returns `reply`, or `500 audit log unavailable`
    /// in its place if the durable write fails. A rate-limited request (including one refused
    /// for having no client IP), or one for a mount the config doesn't have (`unrouted`), is
    /// only counted as a metric.
    async fn finish(&self, req: &ApiRequest, reply: Reply, unrouted: bool) -> Reply {
        let mut ev = self.event.replace(AuditEvent::new(""));
        ev.ts = self.now_ms;
        ev.tenant.clone_from(&self.tenant);
        ev.ip.clone_from(&req.ip);
        ev.country.clone_from(&req.country);
        if ev.error.is_none() {
            (ev.result, ev.error) = outcome(reply.status);
        }
        if unrouted || matches!(ev.error, Some(RATE_LIMITED | NO_CLIENT_IP)) {
            self.audit.metric(&ev);
            return reply;
        }
        if self.audit.record(&ev).await.is_ok() {
            self.audit.metric(&ev);
            reply
        } else {
            log_internal("audit log write failed");
            // The data point is the only trace of the attempt, and what makes an audit outage
            // visible on a dashboard or alert.
            ev.result = "error";
            ev.error = Some("audit_unavailable");
            self.audit.metric(&ev);
            Reply::error(500, "audit log unavailable")
        }
    }
}

/// The audit result and reason for a reply nothing more specific was recorded for.
fn outcome(status: u16) -> (&'static str, Option<&'static str>) {
    match status {
        200..=299 => ("ok", None),
        403 => ("denied", Some("permission_denied")),
        429 => ("denied", Some(RATE_LIMITED)),
        400 => ("error", Some("bad_request")),
        404 => ("error", Some("not_found")),
        500..=599 => ("error", Some("internal")),
        _ => ("error", Some("other")),
    }
}

/// Which methods a path takes.
#[derive(Clone, Copy)]
enum Allow {
    Get,
    Write,
}

impl Allow {
    fn permits(self, m: &Method) -> bool {
        match self {
            Self::Get => *m == Method::Get,
            Self::Write => matches!(m, Method::Put | Method::Post),
        }
    }
}

enum Route<'p> {
    Health,
    Transit(transit::Op, &'p str),
    Keys(&'p str),
    Login(&'p str),
    Challenge(&'p str),
    LookupSelf,
    RenewSelf,
    TokenCreate,
    RevokeAccessor,
}

fn route(path: &str) -> Option<(Route<'_>, Allow)> {
    let rest = path.strip_prefix("/v1/")?;
    let segs: Vec<&str> = rest.split('/').collect();
    let r = match segs.as_slice() {
        ["sys", "health"] => (Route::Health, Allow::Get),
        ["transit", "encrypt", name] => (Route::Transit(transit::Op::Encrypt, name), Allow::Write),
        ["transit", "decrypt", name] => (Route::Transit(transit::Op::Decrypt, name), Allow::Write),
        ["transit", "rewrap", name] => (Route::Transit(transit::Op::Rewrap, name), Allow::Write),
        ["transit", "keys", name] => (Route::Keys(name), Allow::Get),
        ["auth", "token", "lookup-self"] => (Route::LookupSelf, Allow::Get),
        ["auth", "token", "renew-self"] => (Route::RenewSelf, Allow::Write),
        ["auth", "token", "create"] => (Route::TokenCreate, Allow::Write),
        ["auth", "token", "revoke-accessor"] => (Route::RevokeAccessor, Allow::Write),
        ["auth", mount, "login"] if *mount != "token" => (Route::Login(mount), Allow::Write),
        ["auth", mount, "challenge"] if *mount != "token" => {
            (Route::Challenge(mount), Allow::Write)
        }
        _ => return None,
    };
    match &r.0 {
        Route::Transit(_, name)
        | Route::Keys(name)
        | Route::Login(name)
        | Route::Challenge(name)
            if name.is_empty() =>
        {
            None
        }
        _ => Some(r),
    }
}

/// The answer to a request that can be given from its path and declared `Content-Length`
/// alone, before any body is read: a bare `404` outside `/v1/`, then `413` for a declared body
/// over [`MAX_BODY`].
///
/// Nothing outside `/v1/` is an operation, so it is neither audited nor counted, and its body
/// is never read. (OpenBao redirects `/` to its UI and serves a robots.txt; edgekms has
/// neither.)
#[must_use]
pub fn before_body(path: &str, content_length: Option<u64>) -> Option<Reply> {
    if !path.starts_with("/v1/") {
        return Some(Reply::bare_404());
    }
    content_length
        .is_some_and(|n| n > MAX_BODY as u64)
        .then(Reply::too_large)
}

/// Routes and runs one request.
pub async fn handle<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
) -> Reply {
    if let Some(reply) = before_body(&req.path, None) {
        return reply;
    }
    if req.body.len() > MAX_BODY {
        return Reply::too_large();
    }
    // Observed on OpenBao 2 (`server -dev`) with no token: an unknown `/v1/` path, and any
    // `/v1/` path with the wrong method, is `403 {"errors":["permission denied"]}`
    // (`application/json`); with a root token the unknown path is `404 {"errors":["no handler
    // for route \"nope\". route entry not found."]}`. edgekms checks no token for a path it
    // doesn't route, so it answers as OpenBao does without one. The one exception is
    // `/v1/sys/health`: HEAD is GET without the body, and any other method is
    // `405 {"errors":[]}`, with or without a token.
    let Some((route, allow)) = route(&req.path) else {
        return Reply::denied();
    };
    if matches!(route, Route::Health) && req.method == Method::Head {
        return Reply::head_ok();
    }
    if !allow.permits(&req.method) {
        return if matches!(route, Route::Health) {
            Reply::method_not_allowed()
        } else {
            Reply::denied()
        };
    }
    let op = match route {
        Route::Health => {
            return Reply::raw(json!({
                "initialized": true,
                "sealed": false,
                "standby": false,
            }));
        }
        Route::Transit(op, _) => op.name(),
        Route::Keys(_) => "keys_read",
        Route::Login(_) => "login",
        Route::Challenge(_) => "challenge",
        Route::LookupSelf => "token_lookup",
        Route::RenewSelf => "token_renew",
        Route::TokenCreate => "token_create",
        Route::RevokeAccessor => "token_revoke",
    };
    // A challenge only exists on SSH mounts, so one on any other mount is as unrouted as a
    // login to a mount the config doesn't have.
    let unrouted = match route {
        Route::Login(mount) => !deps.state.config.mounts.contains_key(mount),
        Route::Challenge(mount) => !matches!(
            deps.state.config.mounts.get(mount),
            Some(edgekms_core::config::Mount::Ssh {})
        ),
        _ => false,
    };
    deps.event.replace(AuditEvent::new(op));
    let reply = dispatch(deps, req, route).await;
    deps.finish(req, reply, unrouted).await
}

async fn dispatch<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
    route: Route<'_>,
) -> Reply {
    match route {
        Route::Health => Reply::internal(), // answered in `handle`
        Route::Transit(op, name) => transit::transit(deps, req, op, name).await,
        Route::Keys(name) => transit::keys(deps, req, name).await,
        Route::Login(mount) | Route::Challenge(mount) => {
            // Only a configured mount's name goes in the event; the path is caller input.
            if deps.state.config.mounts.contains_key(mount) {
                deps.event().mount = Some(mount.to_owned());
            }
            // Without a client IP, the refusal the route gives anyway: a login on a configured
            // mount refuses with the uniform `400`, everything else here with `403`.
            let refusal = if matches!(route, Route::Login(_))
                && deps.state.config.mounts.contains_key(mount)
            {
                Reply::error(400, "permission denied")
            } else {
                Reply::denied()
            };
            if let Err(reply) = deps.limit_ip(Limit::Login, req, refusal).await {
                return reply;
            }
            if let Err(reply) = deps.limit_tenant(req).await {
                return reply;
            }
            if matches!(route, Route::Login(_)) {
                login::login(deps, req, mount).await
            } else {
                login::challenge(deps, req, mount).await
            }
        }
        Route::LookupSelf => token::lookup_self(deps, req).await,
        Route::RenewSelf => token::renew_self(deps, req).await,
        Route::TokenCreate => token::create(deps, req).await,
        Route::RevokeAccessor => token::revoke_accessor(deps, req).await,
    }
}

/// Mints a token for `role` and returns Vault's `auth` block for it, with the new token's id.
/// A `long` token is checked against the revocation list on every use.
async fn issue<K: KeyOps, R, J, A, L>(
    deps: &Deps<'_, K, R, J, A, L>,
    role: &str,
    policies: Vec<String>,
    ttl: u64,
    long: bool,
    meta: BTreeMap<String, String>,
) -> Result<(Reply, String), Reply> {
    let ops = crate::auth::Logged(&deps.state.ops);
    let claims = TokenClaims {
        v: 1,
        jti: core_token::new_jti(&ops),
        role: role.to_owned(),
        policies,
        iat: deps.now,
        exp: deps.now.saturating_add(ttl),
        long,
        meta,
    };
    // `json!` copies the token into the reply, which zeroizes its own copy on drop.
    let client_token = Zeroizing::new(
        core_token::mint(&ops, &claims)
            .await
            .map_err(|_| Reply::internal())?,
    );
    let reply = Reply::auth(json!({
        "client_token": *client_token,
        "accessor": claims.jti,
        "policies": claims.policies,
        "token_policies": claims.policies,
        "lease_duration": ttl,
        "renewable": false,
        "metadata": { "role": role },
    }));
    Ok((reply, claims.jti))
}

/// A parsed request body. Its strings may be plaintext, a JWT or a GitHub token, so they are
/// zeroized when it is dropped.
pub(crate) struct Body(Map<String, Value>);

impl Deref for Body {
    type Target = Map<String, Value>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        self.0.values_mut().for_each(zeroize_value);
    }
}

/// The body as a JSON object; an empty body is an empty object. A body that parses but isn't
/// an object is zeroized before the error goes back.
pub(crate) fn json_body(body: &[u8]) -> Result<Body, Reply> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Body(Map::new()));
    }
    match serde_json::from_slice(body) {
        Ok(Value::Object(m)) => Ok(Body(m)),
        Ok(mut other) => {
            zeroize_value(&mut other);
            Err(Reply::error(400, "failed to parse JSON input"))
        }
        Err(_) => Err(Reply::error(400, "failed to parse JSON input")),
    }
}
