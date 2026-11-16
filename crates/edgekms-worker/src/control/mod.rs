//! The hosted control plane at `api.<apex>`: GitHub login, control tokens, tenants, config,
//! members, root import and export, and the operator routes (master rewrap, suspension).
//!
//! Bodies use Vault's envelope (`{"data": ...}`, `{"errors": [...]}`). Every route except
//! `GET /v1/info`, `POST /v1/login/github` and the two requester routes (which take the request
//! token a refused login carries, `auth::requester`) takes
//! `Authorization: Bearer <control token>`,
//! every request counts against `CONTROL_LIMIT` per limit key, and every state change writes two
//! control audit events: an `attempt` before the change, which fails the request closed (no
//! change) if it can't be stored, and the outcome after. Reads are counted as metrics only.
//! Failed logins and failed control-token checks also count against `AUTH_FAIL_LIMIT` per IP.
//!
//! The control plane reads and writes D1's primary only ([`D1Store::primary`]): an owner who
//! has just edited a config or a membership must see the edit on the next request.
//!
//! | Route | Who |
//! |---|---|
//! | `GET /v1/info` | anyone: `{"github_client_id", "apex"}`, unwrapped |
//! | `POST /v1/login/github` | anyone with a GitHub token for the hosted App |
//! | `GET /v1/me` | any user: accepted tenants and pending invites, listed apart |
//! | `POST /v1/logout` | any user: every control token issued so far stops working |
//! | `POST /v1/tenants` | any user, at most `MAX_TENANTS_PER_USER` created (operators exempt) |
//! | `GET /v1/tenants/:name` | owners and members |
//! | `PUT /v1/tenants/:name/config` | owners, with `If-Match: "<version>"`; not when suspended |
//! | `PUT /v1/tenants/:name/members/:github_id` | owners: invites, or demotes a member; not when suspended |
//! | `DELETE /v1/tenants/:name/members/:github_id` | owners: removes a member or withdraws an invite; never the last owner; not when suspended |
//! | `POST /v1/tenants/:name/accept` | the invitee; not when suspended |
//! | `POST /v1/tenants/:name/decline` | the invitee |
//! | `POST /v1/tenants/:name/export` | owners whose login is under five minutes old, suspended or not |
//! | `POST /v1/ops/rewrap` | operators (`OPERATOR_GITHUB_IDS`) |
//! | `PUT /v1/ops/tenants/:name/status` | operators |
//! | `PUT`/`DELETE /v1/ops/allowlist/:github_id`, `GET /v1/ops/allowlist` | operators |
//! | `GET /v1/invite-requests/mine` | a request token's user: their invite request, if any |
//! | `POST /v1/invite-requests` | a request token's user, once, while `SIGNUP_MODE` is `invite` |
//! | `GET /v1/ops/invite-requests` | operators: pending requests, then the latest decided |
//! | `POST /v1/ops/invite-requests/:github_id/approve`, `/decline` | operators; approve also allowlists |
//! | `DELETE /v1/ops/invite-requests/:github_id` | operators |
//!
//! `SIGNUP_MODE` ([`SignupMode`]) decides who `POST /v1/login/github` lets in: operators and
//! users who already hold a membership that verifies always, the signup allowlist's users too
//! in `invite` mode, and anyone in `open` mode. Everyone else gets `403 signups are closed`
//! (with `"code": "signup_closed"`) after their GitHub token is checked and revoked.
//!
//! A tenant the caller isn't a member of is `404 tenant not found`, exactly as one that doesn't
//! exist, so membership can't be probed; a member asking for an owner action is
//! `403 permission denied`. Only accepted memberships count for anything: a pending invite
//! grants nothing until its invitee accepts it, so no one can be made an owner (and so the
//! last owner, unable to leave) without their consent. Accepting can raise a member to owner
//! but never lowers a role. Every membership and invite row carries a MAC under the control
//! root, and a row whose MAC doesn't verify counts as absent (`members`), so a row written
//! straight to D1 without the master grants nothing.
//!
//! A suspended tenant's owners can still export its root (a way out), but its config and
//! memberships are frozen: those changes are `403 tenant is suspended`.
//!
//! [`serve`] reads the bindings and hands them to [`handle`], which the tests call with the
//! in-memory store, audit sink, limiter and a stub GitHub. The master key's encrypt/decrypt
//! handle ([`MasterAdmin`]) is only ever built here, on a control-plane request that needs it.

mod auth;
pub(crate) use auth::failed as auth_failed;
mod keys;
mod login;
mod members;
mod ops;
mod requests;
mod ssh;
mod tenants;

use std::cell::RefCell;
use std::rc::Rc;

use serde_json::json;
use worker::{Env, Method};

use crate::audit::{AuditEvent, AuditSink, Limit, R2Audit, RateLimit, WorkerLimits};
use crate::github::{FetchGithub, GithubApi, NoGithub};
use crate::handlers::ApiRequest;
use crate::master::{MasterAdmin, MasterUnwrap};
use crate::store::{D1Store, RequestStatus, TenantStore};
use crate::vault::{Reply, log_internal};

/// The per-user cap on created tenants when `MAX_TENANTS_PER_USER` isn't set.
pub const DEFAULT_MAX_TENANTS_PER_USER: u64 = 5;

/// The cap on pending invite requests when `MAX_PENDING_INVITE_REQUESTS` isn't set.
pub const DEFAULT_MAX_PENDING_INVITE_REQUESTS: u64 = 200;

/// The audit reason for a `429`; such events go to metrics only.
pub(crate) const RATE_LIMITED: &str = "rate_limited";
/// The audit reason for a request with no `CF-Connecting-IP`; metrics only, like a `429`.
pub(crate) const NO_CLIENT_IP: &str = "no_client_ip";
/// The audit result of the event written before a state change.
pub const ATTEMPT: &str = "attempt";

/// `SIGNUP_MODE`: who may log in to the control plane (the signup gate). Operators can
/// always log in, and so can a user who already holds a membership that verifies, so no mode
/// locks anyone out of their own tenants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupMode {
    /// Operators and existing users only.
    Closed,
    /// Also the GitHub users on the operator-managed signup allowlist.
    Invite,
    /// Anyone with a GitHub account.
    Open,
}

impl SignupMode {
    /// The var's value: exactly `closed`, `invite` or `open` once trimmed.
    fn parse(v: &str) -> Option<Self> {
        match v {
            "closed" => Some(Self::Closed),
            "invite" => Some(Self::Invite),
            "open" => Some(Self::Open),
            _ => None,
        }
    }
}

/// The control plane's settings, from the Worker's vars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// `HOSTED_APEX` (`edgekms.dev`).
    pub apex: String,
    /// `GITHUB_CLIENT_ID`: the hosted App, the only one control-plane logins and tenant
    /// `github-user` mounts accept.
    pub github_client_id: String,
    /// `OPERATOR_GITHUB_IDS`, comma-separated GitHub user ids.
    pub operators: Vec<u64>,
    /// `MAX_TENANTS_PER_USER`, default [`DEFAULT_MAX_TENANTS_PER_USER`].
    pub max_tenants_per_user: u64,
    /// `MASTER_KEY_PREVIOUS`: the master version a rotation is moving rows away from.
    pub previous_master: Option<String>,
    /// `SIGNUP_MODE`, required.
    pub signup: SignupMode,
    /// `MAX_PENDING_INVITE_REQUESTS`, default [`DEFAULT_MAX_PENDING_INVITE_REQUESTS`]: how many
    /// invite requests may be pending at once. `0` takes no new ones.
    pub max_pending_invite_requests: u64,
}

impl Settings {
    /// Reads the vars. A missing `HOSTED_APEX`, `GITHUB_CLIENT_ID` or `SIGNUP_MODE`, or a
    /// malformed `OPERATOR_GITHUB_IDS`, `MAX_TENANTS_PER_USER`, `SIGNUP_MODE` or
    /// `MAX_PENDING_INVITE_REQUESTS`, is an error (a fixed label): an operator list that doesn't parse must not silently become an empty one,
    /// and a signup mode that doesn't parse must not become any mode at all.
    ///
    /// # Errors
    /// The label of the first var that's missing or malformed.
    pub fn from_env(env: &Env) -> Result<Self, &'static str> {
        let var = |name: &str| env.var(name).ok().map(|v| v.to_string());
        Self::from_vars(
            var("HOSTED_APEX").as_deref(),
            var("GITHUB_CLIENT_ID").as_deref(),
            var("OPERATOR_GITHUB_IDS").as_deref(),
            var("MAX_TENANTS_PER_USER").as_deref(),
            var("MASTER_KEY_PREVIOUS").as_deref(),
            var("SIGNUP_MODE").as_deref(),
            var("MAX_PENDING_INVITE_REQUESTS").as_deref(),
        )
    }

    /// [`Settings::from_env`] on the vars' values.
    ///
    /// # Errors
    /// As [`Settings::from_env`].
    pub fn from_vars(
        apex: Option<&str>,
        github_client_id: Option<&str>,
        operators: Option<&str>,
        max_tenants_per_user: Option<&str>,
        previous_master: Option<&str>,
        signup_mode: Option<&str>,
        max_pending_invite_requests: Option<&str>,
    ) -> Result<Self, &'static str> {
        fn present(v: Option<&str>) -> Option<&str> {
            v.map(str::trim).filter(|v| !v.is_empty())
        }
        let apex = present(apex).ok_or("hosted_apex_missing")?.to_owned();
        let github_client_id = present(github_client_id)
            .ok_or("github_client_id_missing")?
            .to_owned();
        let operators = match present(operators) {
            None => Vec::new(),
            Some(list) => list
                .split(',')
                .map(|id| id.trim().parse::<u64>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "operator_github_ids_invalid")?,
        };
        let max_tenants_per_user = match present(max_tenants_per_user) {
            None => DEFAULT_MAX_TENANTS_PER_USER,
            Some(n) => n.parse().map_err(|_| "max_tenants_per_user_invalid")?,
        };
        let signup = SignupMode::parse(present(signup_mode).ok_or("signup_mode_missing")?)
            .ok_or("signup_mode_invalid")?;
        let max_pending_invite_requests = match present(max_pending_invite_requests) {
            None => DEFAULT_MAX_PENDING_INVITE_REQUESTS,
            Some(n) => n
                .parse()
                .map_err(|_| "max_pending_invite_requests_invalid")?,
        };
        Ok(Self {
            apex,
            github_client_id,
            operators,
            max_tenants_per_user,
            previous_master: present(previous_master).map(str::to_owned),
            signup,
            max_pending_invite_requests,
        })
    }

    #[must_use]
    pub fn is_operator(&self, github_id: u64) -> bool {
        self.operators.contains(&github_id)
    }
}

thread_local! {
    static ADMIN: RefCell<Option<Rc<MasterAdmin>>> = const { RefCell::new(None) };
}

/// The master key handles the control plane uses, built on first use: the encrypt/decrypt
/// handle for new, imported, exported and rewrapped roots, and an unwrap handle for opening
/// existing roots (a tenant's, to MAC a config edit; the control plane's own, to check
/// tokens). The encrypt/decrypt handle is built from the environment once per isolate, and
/// only on `api.<apex>`; the unwrap handle is the isolate's shared one
/// ([`crate::state::master_unwrap`]), which the data plane uses too.
pub struct Masters {
    env: Option<Env>,
    admin: RefCell<Option<Rc<MasterAdmin>>>,
    unwrap: RefCell<Option<Rc<MasterUnwrap>>>,
}

impl Masters {
    /// Fixed handles, for tests and e2e.
    #[must_use]
    pub fn fixed(admin: MasterAdmin, unwrap: MasterUnwrap) -> Self {
        Self {
            env: None,
            admin: RefCell::new(Some(Rc::new(admin))),
            unwrap: RefCell::new(Some(Rc::new(unwrap))),
        }
    }

    /// Handles built from `env`'s master bindings when first asked for, and kept for the
    /// isolate's life.
    #[must_use]
    pub fn from_env(env: &Env) -> Self {
        Self {
            env: Some(env.clone()),
            admin: RefCell::new(None),
            unwrap: RefCell::new(None),
        }
    }

    /// The encrypt/decrypt handle; `500` if the master bindings are missing or broken.
    async fn admin(&self) -> Result<Rc<MasterAdmin>, Reply> {
        if let Some(a) = self.admin.borrow().clone() {
            return Ok(a);
        }
        let a = if let Some(a) = ADMIN.with(|c| c.borrow().clone()) {
            a
        } else {
            let env = self.env.as_ref().ok_or_else(Reply::internal)?;
            // `from_env` has logged which binding is wrong.
            let a = Rc::new(
                MasterAdmin::from_env(env)
                    .await
                    .map_err(|_| Reply::internal())?,
            );
            ADMIN.with(|c| *c.borrow_mut() = Some(a.clone()));
            a
        };
        *self.admin.borrow_mut() = Some(a.clone());
        Ok(a)
    }

    /// The unwrap handle; `500` if `MASTER_KEY_CURRENT` is missing.
    async fn unwrap(&self) -> Result<Rc<MasterUnwrap>, Reply> {
        if let Some(u) = self.unwrap.borrow().clone() {
            return Ok(u);
        }
        let env = self.env.as_ref().ok_or_else(Reply::internal)?;
        // `from_env` has logged which binding is wrong.
        let u = crate::state::master_unwrap(env)
            .await
            .map_err(|_| Reply::internal())?;
        *self.unwrap.borrow_mut() = Some(u.clone());
        Ok(u)
    }
}

/// What a control-plane request needs besides the request itself.
pub struct Control<'a, S, A, L> {
    pub store: &'a S,
    pub masters: &'a Masters,
    pub audit: &'a A,
    pub limits: &'a L,
    pub github: &'a dyn GithubApi,
    pub settings: &'a Settings,
    /// Unix milliseconds.
    pub now_ms: u64,
}

impl<S, A, L> Control<'_, S, A, L> {
    /// Unix seconds.
    fn now(&self) -> u64 {
        self.now_ms / 1000
    }
}

/// Serves one control-plane request. `now_ms` is Unix milliseconds.
pub async fn serve(env: &Env, req: ApiRequest, now_ms: u64) -> Reply {
    match Bindings::from_env(env) {
        Ok(b) => handle(&b.control(now_ms), &req).await,
        Err(reply) => reply,
    }
}

/// The control plane's settings and bindings, read from the environment for one request: what
/// [`serve`] runs on, and what the web console (`crate::console`) runs the control plane with.
pub struct Bindings {
    settings: Settings,
    store: D1Store,
    masters: Masters,
    audit: R2Audit,
    limits: WorkerLimits,
    github: Option<FetchGithub>,
}

impl Bindings {
    /// Reads the vars and bindings.
    ///
    /// # Errors
    /// `500` (the cause logged) if a var is missing or malformed or `TENANTS` isn't bound.
    pub fn from_env(env: &Env) -> Result<Self, Reply> {
        let settings = Settings::from_env(env).map_err(|label| {
            log_internal(label);
            Reply::internal()
        })?;
        let Ok(db) = env.d1("TENANTS") else {
            log_internal("TENANTS D1 binding is missing");
            return Err(Reply::internal());
        };
        Ok(Self {
            settings,
            // The primary, never a replica: the control plane must read its own writes.
            store: D1Store::primary(db),
            masters: Masters::from_env(env),
            audit: R2Audit {
                bucket: env.bucket("AUDIT").ok(),
                metrics: env.analytics_engine("METRICS").ok(),
            },
            limits: WorkerLimits {
                login: env.rate_limiter("LOGIN_LIMIT").ok(),
                auth_failure: env.rate_limiter("AUTH_FAIL_LIMIT").ok(),
                token: env.rate_limiter("TOKEN_LIMIT").ok(),
                tenant: env.rate_limiter("TENANT_LIMIT").ok(),
                control: env.rate_limiter("CONTROL_LIMIT").ok(),
            },
            github: FetchGithub::from_env(env),
        })
    }

    /// The [`Control`] for a request at `now_ms` (Unix milliseconds).
    #[must_use]
    pub fn control(&self, now_ms: u64) -> Control<'_, D1Store, R2Audit, WorkerLimits> {
        Control {
            store: &self.store,
            masters: &self.masters,
            audit: &self.audit,
            limits: &self.limits,
            github: match &self.github {
                Some(g) => g,
                None => &NoGithub,
            },
            settings: &self.settings,
            now_ms,
        }
    }
}

#[derive(Clone, Copy)]
enum Route<'p> {
    Info,
    Login,
    Logout,
    Me,
    Create,
    Show(&'p str),
    Config(&'p str),
    SetMember(&'p str, &'p str),
    RemoveMember(&'p str, &'p str),
    Accept(&'p str),
    Decline(&'p str),
    Export(&'p str),
    Rewrap,
    Status(&'p str),
    AllowAdd(&'p str),
    AllowRemove(&'p str),
    AllowList,
    RequestMine,
    RequestCreate,
    RequestList,
    RequestApprove(&'p str),
    RequestDecline(&'p str),
    RequestDelete(&'p str),
    LoginSshChallenge,
    LoginSsh,
    SshKeys,
    SshKeyChallenge,
    SshKeyAdd,
    SshKeyRemove(&'p str),
    OpsRevokeSshKeys(&'p str),
}

impl Route<'_> {
    /// The audit operation.
    fn op(self) -> &'static str {
        match self {
            Self::Info => "control_info",
            Self::Login => "control_login",
            Self::Logout => "control_logout",
            Self::Me => "control_me",
            Self::Create => "tenant_create",
            Self::Show(_) => "tenant_read",
            Self::Config(_) => "tenant_config",
            Self::SetMember(..) => "member_set",
            Self::RemoveMember(..) => "member_remove",
            Self::Accept(_) => "invite_accept",
            Self::Decline(_) => "invite_decline",
            Self::Export(_) => "tenant_export",
            Self::Rewrap => "master_rewrap",
            Self::Status(_) => "tenant_status",
            Self::AllowAdd(_) => "allowlist_add",
            Self::AllowRemove(_) => "allowlist_remove",
            Self::AllowList => "allowlist_list",
            Self::RequestMine => "invite_request_mine",
            Self::RequestCreate => "invite_request_create",
            Self::RequestList => "invite_request_list",
            Self::RequestApprove(_) => "invite_request_approve",
            Self::RequestDecline(_) => "invite_request_decline",
            Self::RequestDelete(_) => "invite_request_delete",
            Self::LoginSshChallenge => "control_ssh_challenge",
            Self::LoginSsh => "control_login_ssh",
            Self::SshKeys => "ssh_key_list",
            Self::SshKeyChallenge => "ssh_key_challenge",
            Self::SshKeyAdd => "ssh_key_add",
            Self::SshKeyRemove(_) => "ssh_key_remove",
            Self::OpsRevokeSshKeys(_) => "ssh_keys_revoke",
        }
    }

    /// Whether the route changes state (or hands out the root), and so writes a durable audit
    /// event; reads are only counted as metrics.
    fn durable(self) -> bool {
        !matches!(
            self,
            Self::Info
                | Self::Me
                | Self::Show(_)
                | Self::AllowList
                | Self::RequestMine
                | Self::RequestList
                | Self::LoginSshChallenge
                | Self::SshKeys
                | Self::SshKeyChallenge
        )
    }
}

fn route<'p>(method: &Method, path: &'p str) -> Option<Route<'p>> {
    let rest = path.strip_prefix("/v1/")?;
    let segs: Vec<&str> = rest.split('/').collect();
    let r = match (method, segs.as_slice()) {
        (Method::Get, ["info"]) => Route::Info,
        (Method::Post, ["login", "github"]) => Route::Login,
        (Method::Post, ["logout"]) => Route::Logout,
        (Method::Get, ["me"]) => Route::Me,
        (Method::Post, ["tenants"]) => Route::Create,
        (Method::Get, ["tenants", name]) => Route::Show(name),
        (Method::Put, ["tenants", name, "config"]) => Route::Config(name),
        (Method::Put, ["tenants", name, "members", id]) => Route::SetMember(name, id),
        (Method::Delete, ["tenants", name, "members", id]) => Route::RemoveMember(name, id),
        (Method::Post, ["tenants", name, "accept"]) => Route::Accept(name),
        (Method::Post, ["tenants", name, "decline"]) => Route::Decline(name),
        (Method::Post, ["tenants", name, "export"]) => Route::Export(name),
        (Method::Post, ["ops", "rewrap"]) => Route::Rewrap,
        (Method::Put, ["ops", "tenants", name, "status"]) => Route::Status(name),
        (Method::Put, ["ops", "allowlist", id]) => Route::AllowAdd(id),
        (Method::Delete, ["ops", "allowlist", id]) => Route::AllowRemove(id),
        (Method::Get, ["ops", "allowlist"]) => Route::AllowList,
        (Method::Get, ["invite-requests", "mine"]) => Route::RequestMine,
        (Method::Post, ["invite-requests"]) => Route::RequestCreate,
        (Method::Get, ["ops", "invite-requests"]) => Route::RequestList,
        (Method::Post, ["ops", "invite-requests", id, "approve"]) => Route::RequestApprove(id),
        (Method::Post, ["ops", "invite-requests", id, "decline"]) => Route::RequestDecline(id),
        (Method::Delete, ["ops", "invite-requests", id]) => Route::RequestDelete(id),
        (Method::Post, ["login", "ssh", "challenge"]) => Route::LoginSshChallenge,
        (Method::Post, ["login", "ssh"]) => Route::LoginSsh,
        (Method::Get, ["me", "ssh-keys"]) => Route::SshKeys,
        (Method::Post, ["me", "ssh-keys", "challenge"]) => Route::SshKeyChallenge,
        (Method::Post, ["me", "ssh-keys"]) => Route::SshKeyAdd,
        (Method::Delete, ["me", "ssh-keys", id]) => Route::SshKeyRemove(id),
        (Method::Delete, ["ops", "users", id, "ssh-keys"]) => Route::OpsRevokeSshKeys(id),
        _ => return None,
    };
    Some(r)
}

/// Marks `ev` denied for `label` (a fixed reason).
fn deny(ev: &mut AuditEvent, label: &'static str) {
    ev.result = "denied";
    ev.error = Some(label);
}

/// Marks `ev` failed on the server's side for `label` (a fixed reason), logging it.
fn fail(ev: &mut AuditEvent, label: &'static str) {
    log_internal(label);
    ev.result = "error";
    ev.error = Some(label);
}

/// `500 internal error`, with `label` logged and recorded.
fn internal(ev: &mut AuditEvent, label: &'static str) -> Reply {
    fail(ev, label);
    Reply::internal()
}

/// `status {"errors": [msg], "code": code}`: a refusal with a stable `code` the CLI matches on,
/// besides Vault's envelope.
fn coded(status: u16, msg: &str, code: &str) -> Reply {
    let mut r = Reply::error(status, msg);
    if let Some(serde_json::Value::Object(body)) = r.body.as_mut() {
        body.insert("code".to_owned(), json!(code));
    }
    r
}

/// Durably records that the state change `ev` describes is about to happen. Call it after
/// every check and immediately before the change: if the record fails, the change must not
/// happen, and the request ends in `500 audit log unavailable` (whose outcome event goes to
/// metrics only, the durable log being down).
async fn attempt<S, A: AuditSink, L>(
    c: &Control<'_, S, A, L>,
    ev: &mut AuditEvent,
) -> Result<(), Reply> {
    let mut pre = ev.clone();
    pre.result = ATTEMPT;
    pre.error = None;
    if c.audit.record(&pre).await.is_ok() {
        Ok(())
    } else {
        log_internal("audit log write failed");
        ev.result = "error";
        ev.error = Some(AUDIT_UNAVAILABLE);
        Err(Reply::error(500, "audit log unavailable"))
    }
}

/// The audit reason when the durable log can't be written.
const AUDIT_UNAVAILABLE: &str = "audit_unavailable";

/// Routes and runs one control-plane request.
pub async fn handle<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
) -> Reply {
    let route = route(&req.method, &req.path);
    let mut ev = AuditEvent::new(route.map_or("control_unrouted", Route::op));
    ev.control = true;
    ev.ts = c.now_ms;
    ev.ip.clone_from(&req.ip);
    ev.country.clone_from(&req.country);

    // Every request counts, routed or not. Without a client IP there is no fair bucket to
    // count it in, so it's refused, as on the data plane.
    let limited = match req.limit_key.as_deref().filter(|_| req.ip.is_some()) {
        None => Some((NO_CLIENT_IP, Reply::denied())),
        Some(key) if !c.limits.allow(Limit::Control, key).await => {
            Some((RATE_LIMITED, Reply::error(429, "rate limit quota exceeded")))
        }
        Some(_) => None,
    };
    if let Some((label, reply)) = limited {
        deny(&mut ev, label);
        return finish(c, req, ev, reply, false).await;
    }
    let Some(route) = route else {
        return finish(c, req, ev, Reply::error(404, "unsupported path"), false).await;
    };
    let reply = dispatch(c, req, route, &mut ev).await;
    finish(c, req, ev, reply, route.durable()).await
}

async fn dispatch<S: TenantStore, A: AuditSink, L: RateLimit>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    route: Route<'_>,
    ev: &mut AuditEvent,
) -> Reply {
    match route {
        Route::Info => {
            return Reply::raw(json!({
                "github_client_id": c.settings.github_client_id,
                "apex": c.settings.apex,
            }));
        }
        Route::Login => return login::login(c, req, ev).await,
        Route::LoginSshChallenge => return ssh::challenge(c, req, ev).await,
        Route::LoginSsh => return ssh::login(c, req, ev).await,
        // The requester routes take a request token, never a control token.
        Route::RequestMine | Route::RequestCreate => {
            let who = match auth::requester(c, req, ev).await {
                Ok(w) => w,
                Err(reply) => return reply,
            };
            let result = match route {
                Route::RequestMine => requests::mine(c, ev, &who).await,
                Route::RequestCreate => requests::create(c, req, ev, &who).await,
                _ => Err(Reply::internal()),
            };
            return result.unwrap_or_else(|reply| reply);
        }
        _ => {}
    }
    let user = match auth::authenticate(c, req, ev).await {
        Ok(u) => u,
        Err(reply) => return reply,
    };
    let result = match route {
        // Answered above.
        Route::Info
        | Route::Login
        | Route::LoginSshChallenge
        | Route::LoginSsh
        | Route::RequestMine
        | Route::RequestCreate => Err(Reply::internal()),
        Route::Logout => auth::logout(c, ev, &user).await,
        Route::Me => tenants::me(c, &user).await,
        Route::Create => tenants::create(c, req, ev, &user).await,
        Route::Show(name) => tenants::show(c, ev, &user, name).await,
        Route::Config(name) => tenants::put_config(c, req, ev, &user, name).await,
        Route::SetMember(name, id) => tenants::set_member(c, req, ev, &user, name, id).await,
        Route::RemoveMember(name, id) => tenants::remove_member(c, ev, &user, name, id).await,
        Route::Accept(name) => tenants::accept(c, ev, &user, name).await,
        Route::Decline(name) => tenants::decline(c, ev, &user, name).await,
        Route::Export(name) => keys::export(c, ev, &user, name).await,
        Route::Rewrap => ops::rewrap(c, req, ev, &user).await,
        Route::Status(name) => ops::set_status(c, req, ev, &user, name).await,
        Route::AllowAdd(id) => ops::allow(c, ev, &user, id).await,
        Route::AllowRemove(id) => ops::disallow(c, ev, &user, id).await,
        Route::AllowList => ops::allowlist(c, ev, &user).await,
        Route::RequestList => requests::list(c, ev, &user).await,
        Route::RequestApprove(id) => {
            requests::decide(c, ev, &user, id, RequestStatus::Approved).await
        }
        Route::RequestDecline(id) => {
            requests::decide(c, ev, &user, id, RequestStatus::Declined).await
        }
        Route::RequestDelete(id) => requests::delete(c, ev, &user, id).await,
        Route::SshKeys => ssh::list(c, ev, &user).await,
        Route::SshKeyChallenge => ssh::proof_challenge(c, req, ev, &user).await,
        Route::SshKeyAdd => ssh::add(c, req, ev, &user).await,
        Route::SshKeyRemove(id) => ssh::remove(c, ev, &user, id).await,
        Route::OpsRevokeSshKeys(id) => ssh::revoke(c, ev, &user, id).await,
    };
    result.unwrap_or_else(|reply| reply)
}

/// The audit result and reason for a reply nothing more specific was recorded for.
fn outcome(status: u16) -> (&'static str, Option<&'static str>) {
    match status {
        200..=299 => ("ok", None),
        403 => ("denied", Some("permission_denied")),
        404 => ("error", Some("not_found")),
        409 => ("error", Some("conflict")),
        400..=499 => ("error", Some("bad_request")),
        _ => ("error", Some("internal")),
    }
}

/// Writes the request's audit event (durably when `durable`, always as a metric) and returns
/// `reply`, or `500 audit log unavailable` in its place if the durable write fails.
async fn finish<S, A: AuditSink, L>(
    c: &Control<'_, S, A, L>,
    req: &ApiRequest,
    mut ev: AuditEvent,
    reply: Reply,
    durable: bool,
) -> Reply {
    ev.ts = c.now_ms;
    ev.ip.clone_from(&req.ip);
    ev.country.clone_from(&req.country);
    if ev.error.is_none() {
        (ev.result, ev.error) = outcome(reply.status);
    }
    // The attempt event already failed to store; the outcome can only be a metric.
    if !durable || ev.error == Some(AUDIT_UNAVAILABLE) {
        c.audit.metric(&ev);
        return reply;
    }
    if c.audit.record(&ev).await.is_ok() {
        c.audit.metric(&ev);
        reply
    } else {
        log_internal("audit log write failed");
        ev.result = "error";
        ev.error = Some(AUDIT_UNAVAILABLE);
        c.audit.metric(&ev);
        Reply::error(500, "audit log unavailable")
    }
}

/// A fresh id: `prefix` and 16 lowercase hex digits from the platform's CSPRNG.
fn random_id(prefix: &str) -> Result<String, Reply> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| {
        log_internal("control: no randomness");
        Reply::internal()
    })?;
    Ok(format!("{prefix}{}", hex(&bytes)))
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String can't fail.
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_parse_operators_and_the_cap() {
        let s = Settings::from_vars(
            Some("edge.km"),
            Some("Iv1.x"),
            Some("583231, 42"),
            None,
            Some(" "),
            Some("invite"),
            None,
        )
        .unwrap();
        assert_eq!(s.operators, vec![583_231, 42]);
        assert_eq!(s.max_tenants_per_user, DEFAULT_MAX_TENANTS_PER_USER);
        assert_eq!(s.previous_master, None);
        assert_eq!(s.signup, SignupMode::Invite);
        assert!(s.is_operator(42));
        assert!(!s.is_operator(43));
    }

    #[test]
    fn malformed_settings_fail_closed() {
        let ok = |o, m| {
            Settings::from_vars(
                Some("edge.km"),
                Some("Iv1.x"),
                o,
                m,
                None,
                Some("open"),
                None,
            )
        };
        assert_eq!(ok(Some("1,two"), None), Err("operator_github_ids_invalid"));
        assert_eq!(ok(Some("1,,2"), None), Err("operator_github_ids_invalid"));
        assert_eq!(ok(None, Some("-1")), Err("max_tenants_per_user_invalid"));
        assert_eq!(
            Settings::from_vars(None, Some("Iv1.x"), None, None, None, Some("open"), None),
            Err("hosted_apex_missing")
        );
        assert_eq!(
            Settings::from_vars(
                Some("edge.km"),
                Some(""),
                None,
                None,
                None,
                Some("open"),
                None
            ),
            Err("github_client_id_missing")
        );
    }

    /// `SIGNUP_MODE` is one of three exact words; anything else, or nothing, fails the parse,
    /// so a typo never opens signups.
    #[test]
    fn signup_mode_is_required_and_exact() {
        let mode = |m| {
            Settings::from_vars(Some("edge.km"), Some("Iv1.x"), None, None, None, m, None)
                .map(|s| s.signup)
        };
        assert_eq!(mode(Some("closed")), Ok(SignupMode::Closed));
        assert_eq!(mode(Some(" invite ")), Ok(SignupMode::Invite));
        assert_eq!(mode(Some("open")), Ok(SignupMode::Open));
        assert_eq!(mode(None), Err("signup_mode_missing"));
        assert_eq!(mode(Some(" ")), Err("signup_mode_missing"));
        for bad in [
            "Open",
            "OPEN",
            "invite-only",
            "true",
            "opened",
            "closed,open",
        ] {
            assert_eq!(mode(Some(bad)), Err("signup_mode_invalid"), "{bad}");
        }
    }

    /// `MAX_PENDING_INVITE_REQUESTS` defaults to 200, may be 0 (no new requests), and fails the
    /// parse when malformed, like `MAX_TENANTS_PER_USER`.
    #[test]
    fn pending_invite_request_cap_parses_and_fails_closed() {
        let cap = |v| {
            Settings::from_vars(
                Some("edge.km"),
                Some("Iv1.x"),
                None,
                None,
                None,
                Some("invite"),
                v,
            )
            .map(|s| s.max_pending_invite_requests)
        };
        assert_eq!(cap(None), Ok(DEFAULT_MAX_PENDING_INVITE_REQUESTS));
        assert_eq!(DEFAULT_MAX_PENDING_INVITE_REQUESTS, 200);
        assert_eq!(cap(Some(" ")), Ok(200));
        assert_eq!(cap(Some("0")), Ok(0));
        assert_eq!(cap(Some(" 50 ")), Ok(50));
        for bad in ["-1", "x", "1.5", "200 requests"] {
            assert_eq!(
                cap(Some(bad)),
                Err("max_pending_invite_requests_invalid"),
                "{bad}"
            );
        }
    }

    #[test]
    fn routes_match_method_and_path() {
        assert!(matches!(route(&Method::Get, "/v1/info"), Some(Route::Info)));
        assert!(matches!(
            route(&Method::Delete, "/v1/tenants/a/members/1"),
            Some(Route::RemoveMember("a", "1"))
        ));
        assert!(route(&Method::Get, "/v1/tenants/a/config").is_none());
        assert!(route(&Method::Post, "/v1/me").is_none());
        assert!(matches!(
            route(&Method::Post, "/v1/tenants/a/accept"),
            Some(Route::Accept("a"))
        ));
        assert!(matches!(
            route(&Method::Post, "/v1/logout"),
            Some(Route::Logout)
        ));
        assert!(route(&Method::Get, "/v1/tenants/a/b/c").is_none());
        assert!(matches!(
            route(&Method::Put, "/v1/ops/allowlist/42"),
            Some(Route::AllowAdd("42"))
        ));
        assert!(matches!(
            route(&Method::Delete, "/v1/ops/allowlist/42"),
            Some(Route::AllowRemove("42"))
        ));
        assert!(matches!(
            route(&Method::Get, "/v1/ops/allowlist"),
            Some(Route::AllowList)
        ));
        assert!(route(&Method::Post, "/v1/ops/allowlist").is_none());
        assert!(route(&Method::Get, "/v1/ops/allowlist/42").is_none());
        assert!(route(&Method::Get, "/v2/me").is_none());
        assert!(matches!(
            route(&Method::Get, "/v1/invite-requests/mine"),
            Some(Route::RequestMine)
        ));
        assert!(matches!(
            route(&Method::Post, "/v1/invite-requests"),
            Some(Route::RequestCreate)
        ));
        assert!(matches!(
            route(&Method::Post, "/v1/ops/invite-requests/42/approve"),
            Some(Route::RequestApprove("42"))
        ));
        assert!(matches!(
            route(&Method::Delete, "/v1/ops/invite-requests/42"),
            Some(Route::RequestDelete("42"))
        ));
        assert!(matches!(
            route(&Method::Post, "/v1/login/ssh/challenge"),
            Some(Route::LoginSshChallenge)
        ));
        assert!(matches!(
            route(&Method::Post, "/v1/login/ssh"),
            Some(Route::LoginSsh)
        ));
        assert!(matches!(
            route(&Method::Delete, "/v1/me/ssh-keys/abc"),
            Some(Route::SshKeyRemove("abc"))
        ));
        assert!(matches!(
            route(&Method::Delete, "/v1/ops/users/42/ssh-keys"),
            Some(Route::OpsRevokeSshKeys("42"))
        ));
        assert!(!Route::LoginSshChallenge.durable());
        assert!(Route::LoginSsh.durable());
        assert!(!Route::SshKeys.durable() && !Route::SshKeyChallenge.durable());
        assert!(Route::SshKeyAdd.durable() && Route::SshKeyRemove("x").durable());
        for (m, p) in [
            (Method::Get, "/v1/login/ssh"),
            (Method::Get, "/v1/login/ssh/challenge"),
            (Method::Put, "/v1/me/ssh-keys"),
            (Method::Get, "/v1/me/ssh-keys/abc"),
            (Method::Delete, "/v1/me/ssh-keys"),
            (Method::Get, "/v1/invite-requests"),
            (Method::Post, "/v1/invite-requests/mine"),
            (Method::Get, "/v1/ops/invite-requests/42"),
            (Method::Post, "/v1/ops/invite-requests"),
            (Method::Put, "/v1/ops/invite-requests/42/approve"),
        ] {
            assert!(route(&m, p).is_none(), "{m:?} {p}");
        }
    }
}
