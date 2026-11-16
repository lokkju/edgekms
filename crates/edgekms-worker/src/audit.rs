//! The audit log and rate limits.
//!
//! Every audited request produces one [`AuditEvent`], written through an [`AuditSink`] before
//! the response goes back; if the write fails the request fails (no audit, no operation).
//! Requests that perform no operation (rate-limited, or for an unconfigured mount) are only
//! counted as a metric. The
//! event's fields are an allowlist: no plaintext, ciphertext, key or token can be put in one,
//! and the ciphertext is identified only by its `ct_mac`.
//!
//! [`R2Audit`] and [`WorkerLimits`] are the Workers implementations; the handler layer sees only
//! the traits, so tests run with in-memory doubles.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;
use worker::{AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset, Bucket, Date, RateLimiter};

use crate::vault::log_internal;

/// Token and login metadata an event may carry. Anything else in a token's `meta` (such as a
/// created token's free-text `display_name`) is dropped.
pub const META_ALLOWLIST: [&str; 6] = [
    "sub",
    "repository",
    "ref",
    "workflow",
    "job_workflow_ref",
    "ssh_fingerprint",
];

/// One audited operation. Every string field is either a fixed label or a name from config
/// (key, mount, role) or a token id; none is request content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    /// Unix milliseconds when the request arrived.
    pub ts: u64,
    pub op: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// The auth mount: the login's, or the one the caller's role belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The caller's token id (accessor), or the new token's for a login. Never the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// The token id a `token_create` minted or a `token_revoke` revoked (only once it is a
    /// well-formed id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_jti: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// `ok`, `denied` or `error`.
    pub result: &'static str,
    /// A fixed reason label for anything but `ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    /// base64url (no padding) of the audit MAC of the ciphertext string (`vault:vN:...`) as
    /// received (decrypt, rewrap) or produced (encrypt).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ct_mac: Option<String>,
    /// For a rewrap, the same MAC of the ciphertext string it produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_ct_mac: Option<String>,
    /// Hosted tier: the id of the tenant served, or for a control-plane event the tenant acted
    /// on. `None` in single-tenant mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Hosted tier: a control-plane event, stored apart from tenants' data-plane events.
    #[serde(skip)]
    pub control: bool,
    /// Control plane: the caller's GitHub user id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_id: Option<u64>,
    /// Control plane: the GitHub user id a member change is about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_github_id: Option<u64>,
    /// Control plane: a config edit's previous version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_config_version: Option<u64>,
    /// Control plane: the config version written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_version: Option<u64>,
    /// Control plane: lowercase hex SHA-256 of the config written; never the config itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_sha256: Option<String>,
    /// Control plane: how the caller's control token was obtained, `github` or `ssh`, on every
    /// event made under one, and on a successful login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<&'static str>,
    /// Control plane: the SSH key behind the caller's token (its `SHA256:` fingerprint), on
    /// every event made under an SSH-minted token, and the authenticating key of an SSH login
    /// once its signature has verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_ssh_fingerprint: Option<String>,
    /// Control plane: the SSH key added or removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ssh_fingerprint: Option<String>,
    /// Control plane: the type of the SSH key added.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ssh_key_type: Option<String>,
    /// Control plane: how many SSH keys an operator's revoke removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_keys_removed: Option<u64>,
}

impl AuditEvent {
    /// An event for `op` with nothing else known yet.
    #[must_use]
    pub fn new(op: &'static str) -> Self {
        Self {
            ts: 0,
            op,
            key: None,
            version: None,
            mount: None,
            role: None,
            jti: None,
            target_jti: None,
            meta: BTreeMap::new(),
            ip: None,
            country: None,
            result: "error",
            error: None,
            ct_mac: None,
            new_ct_mac: None,
            tenant: None,
            control: false,
            github_id: None,
            target_github_id: None,
            old_config_version: None,
            config_version: None,
            config_sha256: None,
            auth_method: None,
            auth_ssh_fingerprint: None,
            target_ssh_fingerprint: None,
            target_ssh_key_type: None,
            ssh_keys_removed: None,
        }
    }
}

/// `meta` restricted to [`META_ALLOWLIST`].
#[must_use]
pub fn allowed_meta(meta: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    meta.iter()
        .filter(|(k, _)| META_ALLOWLIST.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Where audit events go.
#[allow(async_fn_in_trait)]
pub trait AuditSink {
    /// Durably records `ev`.
    ///
    /// # Errors
    /// If the event could not be stored; the caller then fails the request.
    async fn record(&self, ev: &AuditEvent) -> worker::Result<()>;

    /// Counts `ev` as one metrics data point. Best effort: never fails the request.
    fn metric(&self, ev: &AuditEvent);
}

/// Which rate limit a check counts against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Per client IP, on login and challenge.
    Login,
    /// Per client IP, on every failed authentication. Kept apart from [`Limit::Login`] so a
    /// client retrying with a broken token can't lock its IP (and its NAT neighbours) out of
    /// logging in.
    AuthFailure,
    /// Per token id, on every authenticated route.
    Token,
    /// Hosted tier: per tenant id, once on every routed data-plane request.
    Tenant,
    /// Hosted tier: per limit key, on every control-plane request.
    Control,
}

/// Rate limiting. Implementations decide what an unavailable limiter means; the Workers one
/// allows the request.
#[allow(async_fn_in_trait)]
pub trait RateLimit {
    /// Whether one more request under `key` is within `limit`.
    async fn allow(&self, limit: Limit, key: &str) -> bool;
}

/// `audit/YYYY/MM/DD/HH/<ts_ms>-<jti>-<random>.json` (UTC hour of `ts`), or
/// `.../<ts_ms>-<random>.json` without a token id. The random suffix keeps two events for one
/// token in the same millisecond from overwriting each other.
///
/// Hosted tier: a tenant's data-plane event goes under `audit/<tenant id>/YYYY/...`, and a
/// control-plane event under `control/YYYY/...` whichever tenant it acted on. A tenant id is
/// `t_<16 hex>`, set by the control plane, never request content.
#[must_use]
pub fn object_key(ev: &AuditEvent, random: [u8; 8]) -> String {
    let secs = ev.ts / 1000;
    let (y, m, d) = civil_from_days(secs / 86_400);
    let h = secs % 86_400 / 3600;
    let prefix = match (&ev.tenant, ev.control) {
        (_, true) => "control/".to_owned(),
        (Some(tenant), false) => format!("audit/{tenant}/"),
        (None, false) => "audit/".to_owned(),
    };
    let mut key = format!("{prefix}{y:04}/{m:02}/{d:02}/{h:02}/{}-", ev.ts);
    if let Some(jti) = &ev.jti {
        key.push_str(jti);
        key.push('-');
    }
    for b in random {
        // Writing to a String can't fail.
        let _ = write!(key, "{b:02x}");
    }
    key.push_str(".json");
    key
}

/// Days since 1970-01-01 to a proleptic Gregorian `(year, month, day)` (Howard Hinnant's
/// `civil_from_days`, restricted to non-negative days).
#[must_use]
pub fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

/// [`AuditSink`] on R2 (`record`) and Analytics Engine (`metric`).
///
/// A missing bucket binding fails every record, so audited routes return 500 until it is
/// fixed. A missing or failing metrics binding is ignored: R2 is the record.
pub struct R2Audit {
    pub bucket: Option<Bucket>,
    pub metrics: Option<AnalyticsEngineDataset>,
}

impl AuditSink for R2Audit {
    async fn record(&self, ev: &AuditEvent) -> worker::Result<()> {
        let Some(bucket) = &self.bucket else {
            log_internal("AUDIT R2 binding is missing");
            return Err(worker::Error::RustError("AUDIT binding is missing".into()));
        };
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(|_| {
            log_internal("audit: no randomness for the object key");
            worker::Error::RustError("no randomness".into())
        })?;
        let body = serde_json::to_vec(ev)?;
        bucket.put(object_key(ev, random), body).execute().await?;
        Ok(())
    }

    fn metric(&self, ev: &AuditEvent) {
        if let Some(metrics) = &self.metrics {
            metric(metrics, ev);
        }
    }
}

/// Writes `ev` as one Analytics Engine data point laid out by [`metric_point`], with doubles
/// `1` and the latency in milliseconds. Errors are ignored.
pub fn metric(dataset: &AnalyticsEngineDataset, ev: &AuditEvent) {
    // Request start to now; the clock is coarse in Workers but still bounds slow requests.
    #[allow(clippy::cast_precision_loss)] // latencies are far below 2^52 ms
    let latency = Date::now().as_millis().saturating_sub(ev.ts) as f64;
    let (index, blobs) = metric_point(ev);
    let written = AnalyticsEngineDataPointBuilder::new()
        .indexes([index.as_str()])
        .blobs(blobs)
        .doubles([1.0, latency])
        .write_to(dataset);
    if written.is_err() {
        log_internal("audit: metrics data point not written");
    }
}

/// The index and blobs of `ev`'s data point: index `op`; blobs `op`, `result`, `key`, `role`,
/// `mount`, `country`, `error`. `error` is how a `429` (`rate_limited`), which is only ever a
/// metric, is told apart from other denials.
///
/// Hosted tier: an event with a tenant is indexed by the tenant id instead, so sampling keeps
/// each tenant's share, and the tenant id is an eighth blob. A single-tenant event is laid out
/// exactly as before the hosted tier.
#[must_use]
pub fn metric_point(ev: &AuditEvent) -> (String, Vec<String>) {
    let opt = |v: &Option<String>| v.clone().unwrap_or_default();
    let mut blobs = vec![
        ev.op.to_owned(),
        ev.result.to_owned(),
        opt(&ev.key),
        opt(&ev.role),
        opt(&ev.mount),
        opt(&ev.country),
        ev.error.unwrap_or_default().to_owned(),
    ];
    let index = match &ev.tenant {
        Some(tenant) => {
            blobs.push(tenant.clone());
            tenant.clone()
        }
        None => ev.op.to_owned(),
    };
    (index, blobs)
}

/// [`RateLimit`] on the `LOGIN_LIMIT`, `AUTH_FAIL_LIMIT` and `TOKEN_LIMIT` bindings (and, in
/// the hosted tier, `TENANT_LIMIT` and `CONTROL_LIMIT`). Without
/// `AUTH_FAIL_LIMIT`, failed authentications count against `LOGIN_LIMIT` as they did before
/// that binding existed. Otherwise a missing binding or a limiter error allows the request
/// (logged), so a local setup without the bindings still runs; the audit log is the control
/// that fails closed, not the limiter.
pub struct WorkerLimits {
    pub login: Option<RateLimiter>,
    pub auth_failure: Option<RateLimiter>,
    pub token: Option<RateLimiter>,
    /// `TENANT_LIMIT`, hosted tier only.
    pub tenant: Option<RateLimiter>,
    /// `CONTROL_LIMIT`, hosted tier only.
    pub control: Option<RateLimiter>,
}

impl RateLimit for WorkerLimits {
    async fn allow(&self, limit: Limit, key: &str) -> bool {
        let limiter = match limit {
            Limit::Login => self.login.as_ref(),
            Limit::AuthFailure => self.auth_failure.as_ref().or(self.login.as_ref()),
            Limit::Token => self.token.as_ref(),
            Limit::Tenant => self.tenant.as_ref(),
            Limit::Control => self.control.as_ref(),
        };
        let Some(limiter) = limiter else {
            log_internal(match limit {
                Limit::Login => "LOGIN_LIMIT binding is missing; not limiting",
                Limit::AuthFailure => {
                    "AUTH_FAIL_LIMIT and LOGIN_LIMIT bindings are missing; not limiting"
                }
                Limit::Token => "TOKEN_LIMIT binding is missing; not limiting",
                Limit::Tenant => "TENANT_LIMIT binding is missing; not limiting",
                Limit::Control => "CONTROL_LIMIT binding is missing; not limiting",
            });
            return true;
        };
        if let Ok(outcome) = limiter.limit(key.to_owned()).await {
            outcome.success
        } else {
            log_internal("rate limiter failed; allowing the request");
            true
        }
    }
}
