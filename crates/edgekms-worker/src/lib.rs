//! edgekms on Cloudflare Workers: a Vault Transit compatible HTTP API whose key operations run
//! in `WebCrypto`.
//!
//! This file is the only Workers glue: it turns a `worker::Request` into an
//! [`handlers::ApiRequest`], builds [`handlers::Deps`] from the environment, and turns the
//! [`vault::Reply`] back into a `worker::Response`. The binding-backed implementations it plugs
//! in (`KvRevocations`, `R2Audit`, `WorkerLimits`) sit beside the traits they implement.
//!
//! Without `HOSTED_APEX` the Worker is single-tenant, exactly as before the hosted tier. With
//! it, the Host header picks the tenant ([`dispatch_host`]): `api.<apex>` is the control
//! plane, `app.<apex>` the web console ([`console`], with its static assets from the `ASSETS`
//! binding), a tenant name is served by [`serve_tenant`] from the tenant store, and anything
//! else is a bare `404`. The assets binding is only ever asked on `app.<apex>`.

pub mod audit;
pub mod auth;
pub mod console;
pub mod control;
pub mod github;
pub mod handlers;
pub mod jwks;
pub mod master;
pub mod state;
pub mod store;
pub mod tenants;
pub mod vault;
pub mod webcrypto;
pub mod webjws;

use edgekms_core::tenant::{HostRoute, TenantName, route_host, tenant_origin};
use futures_util::StreamExt as _;
use worker::{Context, Date, Env, Headers, Request, Response, event};
use zeroize::Zeroizing;

use crate::audit::{AuditEvent, AuditSink, R2Audit, RateLimit, WorkerLimits};
use crate::auth::{KvRevocations, RevocationStore};
use crate::console::{ConsoleReply, ConsoleRequest, headers};
use crate::github::{FetchGithub, GithubApi, NoGithub};
use crate::handlers::{ApiRequest, Deps, MAX_BODY, before_body, handle};
use crate::jwks::{FetchedJwks, JwksSource};
use crate::master::MasterUnwrap;
use crate::state::Mode;
use crate::store::{D1Store, TenantStore};
use crate::tenants::LoadError;
use crate::vault::{Reply, log_internal};

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    match state::mode(&env) {
        Ok(Mode::SingleTenant) => single_tenant(&mut req, &env).await,
        Ok(Mode::Hosted {
            apex,
            origin_template,
        }) => hosted(&mut req, &env, &apex, &origin_template).await,
        Err(label) => {
            log_internal(label);
            Reply::internal().into_response()
        }
    }
}

/// The single-tenant Worker: one config, one root, `revoked:<jti>` revocations.
async fn single_tenant(req: &mut Request, env: &Env) -> worker::Result<Response> {
    let api = match read_request(req, false).await {
        Ok(api) => api,
        Err(reply) => return reply.into_response(),
    };
    let Ok(st) = state::state(env).await else {
        // `state` has logged which binding is wrong.
        return Reply::internal().into_response();
    };
    let Ok(kv) = env.kv("REVOKED") else {
        log_internal("REVOKED KV binding is missing");
        return Reply::internal().into_response();
    };
    let audit = audit_sink(env);
    let limits = limits(env);
    let revocations = KvRevocations::single_tenant(kv);
    let github = FetchGithub::from_env(env);
    let deps = Deps::new(
        &st,
        &revocations,
        &FetchedJwks,
        &audit,
        &limits,
        Date::now().as_millis(),
    );
    let deps = match &github {
        Some(g) => deps.with_github(g),
        None => deps,
    };
    handle(&deps, &api).await.into_response()
}

/// A missing AUDIT bucket fails every audited request in `record`; metrics are optional.
fn audit_sink(env: &Env) -> R2Audit {
    R2Audit {
        bucket: env.bucket("AUDIT").ok(),
        metrics: env.analytics_engine("METRICS").ok(),
    }
}

/// The rate limiters; each is optional (see [`WorkerLimits`]).
fn limits(env: &Env) -> WorkerLimits {
    WorkerLimits {
        login: env.rate_limiter("LOGIN_LIMIT").ok(),
        auth_failure: env.rate_limiter("AUTH_FAIL_LIMIT").ok(),
        token: env.rate_limiter("TOKEN_LIMIT").ok(),
        tenant: env.rate_limiter("TENANT_LIMIT").ok(),
        control: env.rate_limiter("CONTROL_LIMIT").ok(),
    }
}

/// Where a hosted Worker sends a request, by its Host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostDispatch {
    /// `api.<apex>`: [`control::serve`].
    Control,
    /// `app.<apex>`: the web console ([`console`]).
    Console,
    /// A tenant's host: [`serve_tenant`].
    Tenant(TenantName),
    /// A reserved name, the apex, a deeper or foreign host, or an invalid label: the bare
    /// `404`, before the body is read.
    NotFound,
}

/// Routes `host` (the request URL's host, possibly with a port) under `apex`.
#[must_use]
pub fn dispatch_host(apex: &str, host: &str) -> HostDispatch {
    match route_host(host, apex) {
        HostRoute::Control => HostDispatch::Control,
        HostRoute::Console => HostDispatch::Console,
        HostRoute::Tenant(name) => HostDispatch::Tenant(name),
        HostRoute::Reserved | HostRoute::Foreign => HostDispatch::NotFound,
    }
}

/// The hosted Worker: the control plane on `api.<apex>`, tenants on `<name>.<apex>`.
async fn hosted(
    req: &mut Request,
    env: &Env,
    apex: &str,
    origin_template: &str,
) -> worker::Result<Response> {
    let host = req.url().map(|u| host_of(&u)).unwrap_or_default();
    let name = match dispatch_host(apex, &host) {
        HostDispatch::NotFound => return Reply::bare_404().into_response(),
        // Before `read_request`, which turns away every path outside `/v1/`.
        HostDispatch::Console => return serve_console(req, env, origin_template).await,
        HostDispatch::Control => None,
        HostDispatch::Tenant(name) => Some(name),
    };
    let api = match read_request(req, true).await {
        Ok(api) => api,
        Err(reply) => return reply.into_response(),
    };
    let now_ms = Date::now().as_millis();
    let Some(name) = name else {
        return control::serve(env, api, now_ms).await.into_response();
    };
    let Ok(github_client_id) = env.var("GITHUB_CLIENT_ID").map(|v| v.to_string()) else {
        log_internal("GITHUB_CLIENT_ID var is missing");
        return Reply::internal().into_response();
    };
    let Ok(db) = env.d1("TENANTS") else {
        log_internal("TENANTS D1 binding is missing");
        return Reply::internal().into_response();
    };
    let Ok(kv) = env.kv("REVOKED") else {
        log_internal("REVOKED KV binding is missing");
        return Reply::internal().into_response();
    };
    let Ok(master) = state::master_unwrap(env).await else {
        // `MasterUnwrap::from_env` has logged which binding is wrong.
        return Reply::internal().into_response();
    };
    // One store per request: the version read and the row read share its D1 session.
    let store = D1Store::new(db);
    let audit = audit_sink(env);
    let limits = limits(env);
    let github = FetchGithub::from_env(env);
    let deps = TenantDeps {
        store: &store,
        master: &master,
        origin_template,
        github_client_id: &github_client_id,
        revoked: &kv,
        jwks: &FetchedJwks,
        audit: &audit,
        limits: &limits,
        github: match &github {
            Some(g) => g,
            None => &NoGithub,
        },
        now_ms,
    };
    serve_tenant(&deps, &name, &api).await.into_response()
}

/// What [`serve_tenant`] needs besides the request: binding-backed in `fetch`, in-memory in
/// tests. Every binding is shared by all tenants; [`serve_tenant`] scopes each to the tenant.
pub struct TenantDeps<'a, S, V, J, A, L> {
    /// The tenant store, built for this request.
    pub store: &'a S,
    pub master: &'a MasterUnwrap,
    /// `HOSTED_ORIGIN_TEMPLATE`, e.g. `https://{tenant}.edgekms.dev`.
    pub origin_template: &'a str,
    /// `GITHUB_CLIENT_ID`: the hosted service's GitHub App, the only one a tenant's
    /// `github-user` mount may name.
    pub github_client_id: &'a str,
    /// The one revocation namespace; each tenant's keys are prefixed with its id.
    pub revoked: &'a V,
    pub jwks: &'a J,
    pub audit: &'a A,
    pub limits: &'a L,
    pub github: &'a dyn GithubApi,
    /// Unix milliseconds.
    pub now_ms: u64,
}

/// Serves one data-plane request for the tenant `name`.
///
/// The tenant comes from the per-isolate cache ([`tenants::load`]). An unknown name is the bare
/// `404`, a suspended tenant `403 permission denied`, and a row that fails a check or a store
/// that fails `500`. None of these performs an operation, so each is only counted as a metric,
/// never written to the durable audit log. A loaded tenant's request then runs through the
/// ordinary handlers with its own state, its own revocation list (`revoked:<tenant id>:`),
/// audit events and metrics tagged with its id, and its own `TENANT_LIMIT` budget.
pub async fn serve_tenant<S, V, J, A, L>(
    d: &TenantDeps<'_, S, V, J, A, L>,
    name: &TenantName,
    req: &ApiRequest,
) -> Reply
where
    S: TenantStore,
    V: RevocationStore,
    J: JwksSource,
    A: AuditSink,
    L: RateLimit,
{
    let origin = tenant_origin(d.origin_template, name);
    let loaded = match tenants::load(
        d.store,
        d.master,
        name,
        origin,
        d.github_client_id,
        d.now_ms,
    )
    .await
    {
        Ok(loaded) => loaded,
        Err(e) => return refuse_tenant(d, req, e),
    };
    let revocations = KvRevocations::for_tenant(d.revoked, &loaded.tenant_id);
    let deps = Deps::new(
        &loaded.state,
        &revocations,
        d.jwks,
        d.audit,
        d.limits,
        d.now_ms,
    )
    .with_tenant(loaded.tenant_id.clone())
    .with_github(d.github);
    handle(&deps, req).await
}

/// The reply for a tenant that can't be served, counted as one metric.
fn refuse_tenant<S, V, J, A: AuditSink, L>(
    d: &TenantDeps<'_, S, V, J, A, L>,
    req: &ApiRequest,
    e: LoadError,
) -> Reply {
    let (reply, result, label) = match e {
        LoadError::Unknown => (Reply::bare_404(), "error", "unknown_tenant"),
        LoadError::Suspended => (Reply::denied(), "denied", "tenant_suspended"),
        // `tenants::load` has logged which check failed.
        LoadError::Invalid(_) => (Reply::internal(), "error", "tenant_invalid"),
        LoadError::Backend(label) => {
            log_internal(label);
            (Reply::internal(), "error", "tenant_unavailable")
        }
    };
    let mut ev = AuditEvent::new("tenant_route");
    ev.ts = d.now_ms;
    ev.result = result;
    ev.error = Some(label);
    ev.ip.clone_from(&req.ip);
    ev.country.clone_from(&req.country);
    d.audit.metric(&ev);
    reply
}

/// Reads the method, path, token headers and at most [`MAX_BODY`] bytes of body. A path
/// outside `/v1/` is a bare `404` before any of the body is read, and a body that declares or
/// turns out to be larger than the cap is `413` without reading the rest.
///
/// The per-IP limit key is the client IP; a `hosted` Worker keys calls from other Workers on
/// their `CF-Worker` zone too ([`edgekms_core::clientip::limit_key`]).
async fn read_request(req: &mut Request, hosted: bool) -> Result<ApiRequest, Reply> {
    if let Some(reply) = before_body(&req.path(), declared_length(req)) {
        return Err(reply);
    }
    read_api(req, hosted).await
}

/// `Content-Length`, if the client sent a well-formed one.
fn declared_length(req: &Request) -> Option<u64> {
    let v = req.headers().get("Content-Length").ok().flatten()?;
    v.trim().parse::<u64>().ok()
}

/// [`read_request`] after its path and size checks.
async fn read_api(req: &mut Request, hosted: bool) -> Result<ApiRequest, Reply> {
    let header = |name: &str| req.headers().get(name).ok().flatten();
    let path = req.path();
    let vault_token = header("X-Vault-Token");
    let ip = header("CF-Connecting-IP");
    let limit_key = if hosted {
        edgekms_core::clientip::limit_key(ip.as_deref(), header("CF-Worker").as_deref())
    } else {
        ip.clone()
    };
    let country = req.cf().and_then(worker::Cf::country);
    let authorization = header("Authorization");
    let if_match = header("If-Match");
    let url = req.url().ok();
    let body = match req.stream() {
        Ok(stream) => read_body(stream).await?,
        Err(_) => Zeroizing::new(Vec::new()),
    };
    Ok(ApiRequest {
        method: req.method(),
        path,
        // An unparsable URL leaves it empty, which no challenge can be minted for or match.
        origin: url
            .as_ref()
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_default(),
        host: url.as_ref().map(host_of).unwrap_or_default(),
        vault_token,
        authorization,
        if_match,
        limit_key,
        ip,
        country,
        body,
    })
}

/// The web console on `app.<apex>`. A `GET` or `HEAD` outside `/api` and `/auth` is a static
/// asset, served without reading the body or the control plane's bindings; anything else goes
/// through [`console::handle`] with the control plane built as [`control::serve`] builds it.
/// Every response, assets included, carries [`headers::security`].
async fn serve_console(
    req: &mut Request,
    env: &Env,
    origin_template: &str,
) -> worker::Result<Response> {
    let path = req.path();
    if console::is_asset(&req.method(), &path) {
        return serve_asset(req, env, &path).await;
    }
    let creq = match read_console_request(req).await {
        Ok(r) => r,
        Err(reply) => return console_response(ConsoleReply::json(reply), &path),
    };
    let bindings = match control::Bindings::from_env(env) {
        Ok(b) => b,
        Err(reply) => return console_response(ConsoleReply::json(reply), &path),
    };
    let c = bindings.control(Date::now().as_millis());
    match console::handle(&c, origin_template, creq).await {
        // `is_asset` answered this request above.
        ConsoleReply::Asset => console_response(ConsoleReply::json(Reply::internal()), &path),
        reply => console_response(reply, &path),
    }
}

/// [`read_request`] without the `/v1/` path check (the body cap stays), plus the headers and
/// query string the console reads.
async fn read_console_request(req: &mut Request) -> Result<ConsoleRequest, Reply> {
    if declared_length(req).is_some_and(|n| n > MAX_BODY as u64) {
        return Err(Reply::too_large());
    }
    let header = |name: &str| req.headers().get(name).ok().flatten();
    let cookie = header("Cookie");
    let origin_header = header("Origin");
    let content_type = header("Content-Type");
    let query = req
        .url()
        .ok()
        .and_then(|u| u.query().map(str::to_owned))
        .unwrap_or_default();
    let api = read_api(req, true).await?;
    Ok(ConsoleRequest {
        api,
        query,
        cookie,
        origin_header,
        content_type,
    })
}

/// Sets the console's security headers for `path` on `h`.
fn secure(h: &Headers, path: &str) -> worker::Result<()> {
    for (name, value) in headers::security(path) {
        h.set(name, value)?;
    }
    Ok(())
}

/// The `worker::Response` for a console reply other than [`ConsoleReply::Asset`].
fn console_response(reply: ConsoleReply, path: &str) -> worker::Result<Response> {
    let (resp, set_cookies) = match reply {
        ConsoleReply::Json { reply, set_cookies } => (reply.into_response()?, set_cookies),
        ConsoleReply::Redirect {
            location,
            set_cookies,
        } => {
            let resp = Response::empty()?.with_status(302);
            resp.headers().set("Location", &location)?;
            (resp, set_cookies)
        }
        ConsoleReply::Asset => (Reply::internal().into_response()?, Vec::new()),
    };
    let h = resp.headers();
    secure(h, path)?;
    for c in &set_cookies {
        h.append("Set-Cookie", c)?;
    }
    Ok(resp)
}

/// A static asset from the `ASSETS` binding, with the console's headers. The binding's
/// response headers may be immutable, so they're copied into a fresh set first. Under
/// `/assets/`, only a real file is cached as immutable: a miss there gets the SPA's
/// `index.html` (`not_found_handling`), which must not be cached for a year under that name.
async fn serve_asset(req: &Request, env: &Env, path: &str) -> worker::Result<Response> {
    let Ok(assets) = env.assets("ASSETS") else {
        log_internal("ASSETS binding is missing");
        return console_response(ConsoleReply::json(Reply::internal()), path);
    };
    let fetched = assets.fetch_request(req.clone()?).await?;
    let h = Headers::new();
    for (name, value) in fetched.headers().entries() {
        h.append(&name, &value)?;
    }
    secure(&h, path)?;
    let html = h
        .get("Content-Type")?
        .is_some_and(|t| t.starts_with("text/html"));
    if headers::cache_control(path) == headers::IMMUTABLE && (fetched.status_code() != 200 || html)
    {
        h.set("Cache-Control", headers::NO_CACHE)?;
    }
    Ok(fetched.with_headers(h))
}

/// The URL's host, lowercased, with its port when it has a non-default one.
fn host_of(url: &worker::Url) -> String {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

/// Reads a request body stream, refusing it with `413` as soon as more than [`MAX_BODY`]
/// bytes have arrived (the rest is never pulled) and with the truncated-body `400` if the
/// stream breaks off. The body may carry plaintext, so every buffer it passes through is
/// zeroized, including the ones growing it leaves behind.
async fn read_body(
    mut stream: impl futures_util::Stream<Item = worker::Result<Vec<u8>>> + Unpin,
) -> Result<Zeroizing<Vec<u8>>, Reply> {
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = stream.next().await {
        let chunk = Zeroizing::new(chunk.map_err(|_| Reply::truncated_body())?);
        if body.len() + chunk.len() > MAX_BODY {
            return Err(Reply::too_large());
        }
        vault::extend_zeroizing(&mut body, &chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use futures_util::stream;

    use super::*;

    #[test]
    fn body_within_the_cap_is_read_whole() {
        let chunks = stream::iter([Ok(vec![1u8; MAX_BODY - 1]), Ok(vec![2u8])]);
        let body = pollster::block_on(read_body(chunks)).unwrap();
        assert_eq!(body.len(), MAX_BODY);
        assert_eq!(body[MAX_BODY - 1], 2);
    }

    #[test]
    fn body_that_streams_past_the_cap_is_413_without_reading_the_rest() {
        let pulled = Cell::new(0);
        let chunks = stream::iter((0..100).map(|_| {
            pulled.set(pulled.get() + 1);
            Ok(vec![0u8; 16 * 1024])
        }));
        let reply = pollster::block_on(read_body(chunks)).unwrap_err();
        assert_eq!(reply, Reply::too_large());
        assert_eq!(pulled.get(), 5, "stops at the chunk that crosses 64 KiB");
    }

    #[test]
    fn one_byte_over_the_cap_is_413() {
        let chunks = stream::iter([Ok(vec![0u8; MAX_BODY]), Ok(vec![0u8])]);
        let reply = pollster::block_on(read_body(chunks)).unwrap_err();
        assert_eq!(reply, Reply::too_large());
    }

    #[test]
    fn body_stream_that_breaks_off_is_the_truncated_body_400() {
        let chunks = stream::iter([
            Ok(b"{\"plaintext\":".to_vec()),
            Err(worker::Error::RustError("connection reset".into())),
        ]);
        let reply = pollster::block_on(read_body(chunks)).unwrap_err();
        assert_eq!(reply, Reply::truncated_body());
    }

    #[test]
    fn empty_stream_is_an_empty_body() {
        let chunks = stream::iter(Vec::<worker::Result<Vec<u8>>>::new());
        assert!(pollster::block_on(read_body(chunks)).unwrap().is_empty());
    }

    #[test]
    fn many_small_chunks_arrive_in_order() {
        let chunks = stream::iter((0..=255u8).map(|b| Ok(vec![b; 3])));
        let body = pollster::block_on(read_body(chunks)).unwrap();
        let want: Vec<u8> = (0..=255u8).flat_map(|b| [b; 3]).collect();
        assert_eq!(*body, want);
    }
}
