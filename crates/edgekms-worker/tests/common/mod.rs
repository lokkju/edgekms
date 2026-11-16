//! Shared harness for the handler and audit tests: a real `WebCryptoKeyOps`, in-memory
//! revocation list, audit sink and rate limiter, and a config with every kind of mount, role
//! and policy.
#![allow(dead_code)] // each test crate uses a different subset
#![allow(clippy::unused_async_trait_impl)] // test doubles satisfy async traits without awaiting

pub mod memstore;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_core::config::Config;
use edgekms_core::jwt::Jwks;
use edgekms_core::keyops::KeyOps;
use edgekms_core::token::{self, TokenClaims};
use edgekms_core::transit::Id;
use edgekms_worker::audit::{AuditEvent, AuditSink, Limit, RateLimit};
use edgekms_worker::auth::Revocations;
use edgekms_worker::handlers::{ApiRequest, Deps, handle};
use edgekms_worker::jwks::JwksSource;
use edgekms_worker::state::State;
use edgekms_worker::vault::Reply;
use edgekms_worker::webcrypto::WebCryptoKeyOps;
use serde_json::{Value, json};
use worker::Method;
use zeroize::Zeroizing;

/// `CF-Connecting-IP` on every test request.
pub const TEST_IP: &str = "203.0.113.7";
/// The origin every test request is addressed to.
pub const TEST_ORIGIN: &str = "https://kms.test";
/// [`TEST_ORIGIN`]'s host.
pub const TEST_HOST: &str = "kms.test";

pub const NOW: u64 = 2_000_000_000;
pub const JWT_FIXTURES: &str = include_str!("../../../edgekms-core/tests/fixtures/jwt.json");
pub const SSH_ED25519_PUB: &str =
    include_str!("../../../edgekms-core/tests/fixtures/ssh/ed25519.pub");

pub fn config_json() -> Value {
    let fx: Value = serde_json::from_str(JWT_FIXTURES).unwrap();
    json!({
        "root_id": "r1",
        "keys": {
            "app": { "id": "k_app", "latest_version": 3, "min_decryption_version": 2 },
            "other": { "id": "k_other", "latest_version": 1, "min_decryption_version": 1 }
        },
        "mounts": {
            "jwt": { "type": "jwt", "issuer": fx["issuer"], "jwks": fx["jwks"] },
            "jwt-url": {
                "type": "jwt",
                "issuer": fx["issuer"],
                "jwks_url": "https://issuer.test/jwks"
            },
            "ssh": { "type": "ssh" }
        },
        "roles": {
            "ci-url": {
                "mount": "jwt-url",
                "bound_audiences": ["https://kms.test"],
                "bound_claims": { "repository_id": "42" },
                "policies": ["app-decrypt"],
                "token_ttl_secs": 900
            },
            "ci": {
                "mount": "jwt",
                "bound_audiences": ["https://kms.test"],
                "bound_claims": { "repository_id": "42" },
                "policies": ["app-decrypt"],
                "token_ttl_secs": 900
            },
            "op": {
                "mount": "ssh",
                "ssh_keys": [SSH_ED25519_PUB.trim(), test_ssh_public_key()],
                "policies": ["admin", "app-all"],
                "token_ttl_secs": 3600
            },
            "fresh": {
                "mount": "ssh",
                "ssh_keys": [SSH_ED25519_PUB.trim()],
                "policies": ["app-all"],
                "token_ttl_secs": 3600,
                "not_before": NOW - 100
            }
        },
        "policies": {
            "app-all": { "keys": { "app": ["encrypt", "decrypt", "rewrap", "read"] } },
            "app-decrypt": { "keys": { "app": ["decrypt"] } },
            "seal": { "keys": { "app": ["encrypt", "decrypt"] } },
            "other-all": { "keys": { "other": ["encrypt", "decrypt", "rewrap", "read"] } },
            "admin": { "admin": ["token-create", "token-revoke"] }
        }
    })
}

/// The OpenSSH line for the in-test signing key (see `ssh_sign`).
pub fn test_ssh_public_key() -> String {
    ssh_test_key().public_key().to_openssh().unwrap()
}

pub fn ssh_test_key() -> ssh_key::PrivateKey {
    ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]))
}

pub fn root_bytes() -> [u8; 32] {
    std::array::from_fn(|i| u8::try_from(i).unwrap())
}

pub async fn web_ops() -> WebCryptoKeyOps {
    WebCryptoKeyOps::import(&root_bytes(), Id::new("r1").unwrap())
        .await
        .unwrap()
}

pub async fn state() -> State<WebCryptoKeyOps> {
    let config = Config::from_json(&config_json().to_string()).unwrap();
    State::new(config, web_ops().await).unwrap()
}

#[derive(Default)]
pub struct MemRevocations(pub RefCell<HashSet<String>>);

impl Revocations for MemRevocations {
    async fn is_revoked(&self, jti: &str) -> worker::Result<bool> {
        Ok(self.0.borrow().contains(jti))
    }
    async fn revoke(&self, jti: &str, _ttl_secs: u64) -> worker::Result<()> {
        self.0.borrow_mut().insert(jti.to_owned());
        Ok(())
    }
}

/// A JWKS source for `jwks_url` mounts: `normal` for ordinary lookups, `forced` for the refetch
/// after an unknown `kid`. Records each call's `force_refresh`.
#[derive(Default)]
pub struct FakeJwks {
    pub normal: Option<Value>,
    pub forced: Option<Value>,
    pub calls: RefCell<Vec<bool>>,
}

impl JwksSource for FakeJwks {
    async fn jwks(&self, mount: &str, url: &str, force_refresh: bool) -> worker::Result<Jwks> {
        assert_eq!((mount, url), ("jwt-url", "https://issuer.test/jwks"));
        self.calls.borrow_mut().push(force_refresh);
        let doc = if force_refresh {
            &self.forced
        } else {
            &self.normal
        };
        doc.clone()
            .map(|v| serde_json::from_value(v).unwrap())
            .ok_or_else(|| worker::Error::RustError("unreachable issuer".into()))
    }
}

pub struct Harness<K = WebCryptoKeyOps> {
    pub st: State<K>,
    pub rev: MemRevocations,
    pub jwks: FakeJwks,
    pub audit: MemAudit,
    pub limits: MemLimits,
    pub now: u64,
}

impl Harness {
    pub async fn new() -> Self {
        Self {
            st: state().await,
            rev: MemRevocations::default(),
            jwks: FakeJwks::default(),
            audit: MemAudit::default(),
            limits: MemLimits::default(),
            now: NOW,
        }
    }
}

impl<K: KeyOps> Harness<K> {
    pub async fn call(&self, req: ApiRequest) -> Reply {
        self.call_with(&self.rev, req).await
    }

    /// Like [`Harness::call`] with a different revocation list.
    pub async fn call_with(&self, rev: &impl Revocations, req: ApiRequest) -> Reply {
        let deps = Deps::new(
            &self.st,
            rev,
            &self.jwks,
            &self.audit,
            &self.limits,
            self.now * 1000,
        );
        handle(&deps, &req).await
    }

    pub async fn token(&self, role: &str, policies: &[&str], ttl: u64, iat: u64) -> String {
        let claims = TokenClaims {
            v: 1,
            jti: token::new_jti(&self.st.ops),
            role: role.into(),
            policies: policies.iter().map(|p| (*p).to_owned()).collect(),
            iat,
            exp: iat + ttl,
            long: ttl > 86_400,
            meta: BTreeMap::new(),
        };
        token::mint(&self.st.ops, &claims).await.unwrap()
    }

    pub async fn admin(&self) -> String {
        self.token("op", &["admin", "app-all"], 3600, self.now)
            .await
    }
}

pub fn req(method: Method, path: &str, token: Option<&str>, body: &Value) -> ApiRequest {
    raw(method, path, token, serde_json::to_vec(body).unwrap())
}

pub fn raw(method: Method, path: &str, token: Option<&str>, body: Vec<u8>) -> ApiRequest {
    ApiRequest {
        method,
        path: path.into(),
        vault_token: token.map(str::to_owned),
        authorization: None,
        if_match: None,
        origin: TEST_ORIGIN.to_owned(),
        host: TEST_HOST.to_owned(),
        ip: Some(TEST_IP.to_owned()),
        limit_key: Some(TEST_IP.to_owned()),
        country: Some("NZ".to_owned()),
        body: Zeroizing::new(body),
    }
}

/// An `Env` with no bindings at all, for code that takes one (`control::serve`) where the test
/// is about what happens without them.
pub fn empty_env() -> worker::Env {
    use wasm_bindgen::JsCast as _;
    js_sys::Object::new().unchecked_into()
}

pub fn b64(s: &[u8]) -> String {
    STANDARD.encode(s)
}

pub fn errors(r: &Reply) -> Vec<String> {
    serde_json::from_value(r.body.as_ref().unwrap()["errors"].clone()).unwrap()
}

#[track_caller]
pub fn assert_error(r: &Reply, status: u16, msg: &str) {
    assert_eq!(r.status, status, "{r:?}");
    assert_eq!(errors(r), vec![msg.to_owned()], "{r:?}");
}

pub fn data(r: &Reply) -> &Value {
    assert_eq!(r.status, 200, "{r:?}");
    &r.body.as_ref().unwrap()["data"]
}

pub async fn encrypt(h: &Harness, tok: &str, pt: &[u8]) -> String {
    let r = h
        .call(req(
            Method::Put,
            "/v1/transit/encrypt/app",
            Some(tok),
            &json!({ "plaintext": b64(pt) }),
        ))
        .await;
    data(&r)["ciphertext"].as_str().unwrap().to_owned()
}

pub fn jwt_case(name: &str) -> String {
    let fx: Value = serde_json::from_str(JWT_FIXTURES).unwrap();
    fx["cases"][name].as_str().unwrap().to_owned()
}

/// Every event recorded, serialized exactly as the sink received it: `events` is the durable
/// log (R2), `metrics` the data points (Analytics Engine). With `fail` set, `record` errors and
/// nothing is kept; metrics never fail.
#[derive(Default)]
pub struct MemAudit {
    pub events: RefCell<Vec<String>>,
    pub metrics: RefCell<Vec<String>>,
    pub fail: Cell<bool>,
}

impl MemAudit {
    /// The recorded events as JSON values.
    pub fn values(&self) -> Vec<Value> {
        self.events
            .borrow()
            .iter()
            .map(|e| serde_json::from_str(e).unwrap())
            .collect()
    }

    /// The only event recorded since the last `clear`.
    #[track_caller]
    pub fn only(&self) -> (Value, String) {
        let events = self.events.borrow();
        assert_eq!(events.len(), 1, "{events:?}");
        (serde_json::from_str(&events[0]).unwrap(), events[0].clone())
    }

    /// Asserts nothing reached the durable log since the last `clear` and exactly one data
    /// point was written; returns that data point's event.
    #[track_caller]
    pub fn only_metric(&self) -> Value {
        let events = self.events.borrow();
        assert!(events.is_empty(), "durable records: {events:?}");
        let metrics = self.metrics.borrow();
        assert_eq!(metrics.len(), 1, "{metrics:?}");
        serde_json::from_str(&metrics[0]).unwrap()
    }

    pub fn clear(&self) {
        self.events.borrow_mut().clear();
        self.metrics.borrow_mut().clear();
    }
}

impl AuditSink for MemAudit {
    async fn record(&self, ev: &AuditEvent) -> worker::Result<()> {
        if self.fail.get() {
            return Err(worker::Error::RustError("audit bucket down".into()));
        }
        self.events
            .borrow_mut()
            .push(serde_json::to_string(ev).unwrap());
        Ok(())
    }

    fn metric(&self, ev: &AuditEvent) {
        self.metrics
            .borrow_mut()
            .push(serde_json::to_string(ev).unwrap());
    }
}

/// Allows everything unless told to refuse a limiter, or `Login`, `AuthFailure` or `Control`
/// checks once that limiter's budget of them has been allowed; records each check.
#[derive(Default)]
pub struct MemLimits {
    pub deny_login: Cell<bool>,
    pub deny_token: Cell<bool>,
    pub deny_auth_failure: Cell<bool>,
    /// Hosted tier: refuse `Limit::Tenant` checks.
    pub deny_tenant: Cell<bool>,
    /// Hosted tier: refuse `Limit::Control` checks.
    pub deny_control: Cell<bool>,
    /// Hosted tier: refuse `Limit::Control` checks once this many have been allowed.
    pub control_budget: Cell<Option<u32>>,
    pub login_budget: Cell<Option<u32>>,
    pub auth_failure_budget: Cell<Option<u32>>,
    pub checks: RefCell<Vec<(Limit, String)>>,
}

/// Spends one of `budget`, if there is one; `false` once it is used up.
fn spend(budget: &Cell<Option<u32>>) -> bool {
    match budget.get() {
        None => true,
        Some(left) => {
            budget.set(Some(left.saturating_sub(1)));
            left > 0
        }
    }
}

impl RateLimit for MemLimits {
    async fn allow(&self, limit: Limit, key: &str) -> bool {
        self.checks.borrow_mut().push((limit, key.to_owned()));
        match limit {
            Limit::Login => spend(&self.login_budget) && !self.deny_login.get(),
            Limit::AuthFailure => spend(&self.auth_failure_budget) && !self.deny_auth_failure.get(),
            Limit::Token => !self.deny_token.get(),
            Limit::Tenant => !self.deny_tenant.get(),
            Limit::Control => spend(&self.control_budget) && !self.deny_control.get(),
        }
    }
}
