#![cfg(target_arch = "wasm32")]
//! SSH-key login to the hosted control plane and the keys behind it (lokkju/edgekms#16), with
//! the in-memory store, a stub GitHub and keys signed in the test.

mod common;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use common::memstore::MemStore;
use common::*;
use edgekms_core::keyops::MacPurpose;
use edgekms_core::ssh;
use edgekms_core::token::{self, TokenClaims};
use edgekms_core::transit::Id;
use edgekms_worker::audit::Limit;
use edgekms_worker::control::{self, Control, Masters, Settings, SignupMode};
use edgekms_worker::github::{GithubApi, GithubError, GithubUser, LocalFuture};
use edgekms_worker::handlers::ApiRequest;
use edgekms_worker::master::{MasterAdmin, MasterUnwrap};
use edgekms_worker::store::{SshKeyRow, TenantStore};
use edgekms_worker::vault::Reply;
use edgekms_worker::webcrypto::WebCryptoKeyOps;
use serde_json::{Value, json};
use wasm_bindgen_test::wasm_bindgen_test;
use worker::Method;

const CLIENT: &str = "Iv_hosted_test";
const M1: [u8; 32] = [0x41; 32];
const OPERATOR: u64 = 9_000;
const ORIGIN: &str = "https://api.edge.km";
const RSA_PUB: &str = include_str!("../../edgekms-core/tests/fixtures/ssh/rsa.pub");

// ---- GitHub, stubbed ----

#[derive(Default)]
struct FakeGithub {
    users: RefCell<HashMap<String, GithubUser>>,
}

impl FakeGithub {
    fn token_for(&self, id: u64, login: &str) -> String {
        let token = format!("gho_{id}_{login}");
        self.users.borrow_mut().insert(
            token.clone(),
            GithubUser {
                id,
                login: login.to_owned(),
            },
        );
        token
    }
}

impl GithubApi for FakeGithub {
    fn check_token<'a>(
        &'a self,
        client_id: &'a str,
        token: &'a str,
    ) -> LocalFuture<'a, Result<GithubUser, GithubError>> {
        let r = if client_id == CLIENT {
            self.users
                .borrow()
                .get(token)
                .cloned()
                .ok_or(GithubError::Denied("github_token_not_for_app"))
        } else {
            Err(GithubError::Denied("github_token_not_for_app"))
        };
        Box::pin(async move { r })
    }

    fn revoke_token<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> LocalFuture<'a, Result<(), &'static str>> {
        Box::pin(async { Ok(()) })
    }

    fn exchange_code<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> LocalFuture<'a, Result<zeroize::Zeroizing<String>, GithubError>> {
        Box::pin(async { Err(GithubError::Unavailable("not_in_this_test")) })
    }
}

// ---- Keys ----

/// A rewrite of a stored key row, as a D1 writer could make.
type Tamper = Box<dyn Fn(&mut SshKeyRow)>;

/// A key the test holds the private half of.
enum Key {
    /// Ed25519 or ECDSA P-256, signed by `ssh-key`.
    Plain(Box<ssh_key::PrivateKey>),
    /// A software `sk-ssh-ed25519` key; `touch` sets the user-presence flag.
    Sk { seed: u8, touch: bool },
}

impl Key {
    fn ed(seed: u8) -> Self {
        Self::Plain(Box::new(ssh_key::PrivateKey::from(
            ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]),
        )))
    }

    fn ecdsa(seed: u8) -> Self {
        let sk = p256::SecretKey::from_slice(&[seed; 32]).unwrap();
        let pair = ssh_key::private::EcdsaKeypair::NistP256 {
            public: sk.public_key().into(),
            private: sk.into(),
        };
        Self::Plain(Box::new(ssh_key::PrivateKey::from(pair)))
    }

    fn sk_data(seed: u8) -> ssh_key::public::KeyData {
        use ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        KeyData::SkEd25519(SkEd25519::new(
            Ed25519PublicKey(sk.verifying_key().to_bytes()),
            "ssh:",
        ))
    }

    /// The OpenSSH public key line, with a comment.
    fn line(&self) -> String {
        let bare = match self {
            Self::Plain(k) => k.public_key().to_openssh().unwrap(),
            Self::Sk { seed, .. } => ssh_key::PublicKey::from(Self::sk_data(*seed))
                .to_openssh()
                .unwrap(),
        };
        format!("{bare} me@laptop")
    }

    fn fingerprint(&self) -> String {
        ssh::parse_public_key(&self.line()).unwrap().fingerprint
    }

    fn id(&self) -> String {
        ssh::key_id(&self.fingerprint()).unwrap()
    }

    fn sign(&self, namespace: &str, msg: &str) -> String {
        match self {
            Self::Plain(k) => k
                .sign(namespace, ssh_key::HashAlg::Sha512, msg.as_bytes())
                .unwrap()
                .to_pem(ssh_key::LineEnding::LF)
                .unwrap(),
            Self::Sk { seed, touch } => {
                use ed25519_dalek::Signer as _;
                use sha2::{Digest, Sha256};
                use ssh_key::{Algorithm, HashAlg, LineEnding, Signature, SshSig};
                let sk = ed25519_dalek::SigningKey::from_bytes(&[*seed; 32]);
                let flags = u8::from(*touch);
                let counter = 1u32.to_be_bytes();
                let signed =
                    SshSig::signed_data(namespace, HashAlg::Sha512, msg.as_bytes()).unwrap();
                let mut data = Sha256::digest("ssh:").to_vec();
                data.push(flags);
                data.extend(counter);
                data.extend(Sha256::digest(&signed));
                let mut blob = sk.sign(&data).to_bytes().to_vec();
                blob.push(flags);
                blob.extend(counter);
                let sig = Signature::new(Algorithm::SkEd25519, blob).unwrap();
                SshSig::new(Self::sk_data(*seed), namespace, HashAlg::Sha512, sig)
                    .unwrap()
                    .to_pem(LineEnding::LF)
                    .unwrap()
            }
        }
    }
}

// ---- The fixture ----

struct Fx {
    store: MemStore,
    masters: Rc<Masters>,
    audit: MemAudit,
    limits: MemLimits,
    gh: FakeGithub,
    settings: RefCell<Rc<Settings>>,
    /// Unix seconds.
    now: Cell<u64>,
}

async fn fx() -> Fx {
    Fx {
        store: MemStore::default(),
        masters: Rc::new(Masters::fixed(
            MasterAdmin::from_bytes("m1", &[("m1", &M1)]).await.unwrap(),
            MasterUnwrap::from_bytes(&[("m1", &M1)]).await.unwrap(),
        )),
        audit: MemAudit::default(),
        limits: MemLimits::default(),
        gh: FakeGithub::default(),
        settings: RefCell::new(Rc::new(Settings {
            apex: "edge.km".into(),
            github_client_id: CLIENT.into(),
            operators: vec![OPERATOR],
            max_tenants_per_user: 5,
            previous_master: None,
            signup: SignupMode::Open,
            max_pending_invite_requests: 200,
        })),
        now: Cell::new(NOW),
    }
}

fn creq(method: Method, path: &str, token: Option<&str>, body: &Value) -> ApiRequest {
    let mut r = req(method, path, None, body);
    r.authorization = token.map(|t| format!("Bearer {t}"));
    r.host = "api.edge.km".into();
    r.origin = ORIGIN.into();
    r
}

/// The `data` of a 2xx reply.
fn ok_data(r: &Reply) -> &Value {
    assert!((200..300).contains(&r.status), "{r:?}");
    &r.body.as_ref().unwrap()["data"]
}

fn code(r: &Reply) -> Option<&str> {
    r.body.as_ref()?["code"].as_str()
}

impl Fx {
    async fn call(&self, req: ApiRequest) -> Reply {
        let settings = self.settings.borrow().clone();
        let c = Control {
            store: &self.store,
            masters: &self.masters,
            audit: &self.audit,
            limits: &self.limits,
            github: &self.gh,
            settings: &settings,
            now_ms: self.now.get() * 1000,
        };
        control::handle(&c, &req).await
    }

    fn mode(&self, signup: SignupMode) {
        let mut s = (**self.settings.borrow()).clone();
        s.signup = signup;
        *self.settings.borrow_mut() = Rc::new(s);
    }

    async fn post(&self, path: &str, token: Option<&str>, body: &Value) -> Reply {
        self.call(creq(Method::Post, path, token, body)).await
    }

    async fn get(&self, path: &str, token: &str) -> Reply {
        self.call(creq(Method::Get, path, Some(token), &json!({})))
            .await
    }

    async fn delete(&self, path: &str, token: &str) -> Reply {
        self.call(creq(Method::Delete, path, Some(token), &json!({})))
            .await
    }

    async fn github_reply(&self, id: u64, login: &str) -> Reply {
        let gh = self.gh.token_for(id, login);
        self.post("/v1/login/github", None, &json!({ "token": gh }))
            .await
    }

    /// A GitHub login's control token.
    async fn github(&self, id: u64, login: &str) -> String {
        let r = self.github_reply(id, login).await;
        ok_data(&r)["token"].as_str().unwrap().to_owned()
    }

    async fn challenge(&self) -> String {
        let r = self.post("/v1/login/ssh/challenge", None, &json!({})).await;
        assert_eq!(ok_data(&r)["expires_in"], json!(60));
        ok_data(&r)["challenge"].as_str().unwrap().to_owned()
    }

    async fn login_with(&self, challenge: &str, signature: &str) -> Reply {
        self.post(
            "/v1/login/ssh",
            None,
            &json!({ "challenge": challenge, "signature": signature }),
        )
        .await
    }

    /// A fresh challenge signed by `key` in `namespace`, posted to the login.
    async fn ssh_reply(&self, key: &Key, namespace: &str) -> Reply {
        let c = self.challenge().await;
        self.login_with(&c, &key.sign(namespace, &c)).await
    }

    async fn ssh(&self, key: &Key) -> String {
        let r = self.ssh_reply(key, ssh::NAMESPACE).await;
        ok_data(&r)["token"].as_str().unwrap().to_owned()
    }

    async fn proof_challenge(&self, token: &str) -> Reply {
        self.post("/v1/me/ssh-keys/challenge", Some(token), &json!({}))
            .await
    }

    async fn add_with(
        &self,
        token: &str,
        public_key: &str,
        label: &str,
        c: &str,
        sig: &str,
    ) -> Reply {
        self.post(
            "/v1/me/ssh-keys",
            Some(token),
            &json!({ "public_key": public_key, "label": label, "challenge": c, "signature": sig }),
        )
        .await
    }

    /// Registers `key` on the account behind `token`, with a proper proof.
    async fn add(&self, token: &str, key: &Key, label: &str) -> Reply {
        let r = self.proof_challenge(token).await;
        let c = ok_data(&r)["challenge"].as_str().unwrap().to_owned();
        self.add_with(
            token,
            &key.line(),
            label,
            &c,
            &key.sign(ssh::REGISTER_NAMESPACE, &c),
        )
        .await
    }

    /// The control root, opened as the control plane opens it.
    async fn control_ops(&self) -> WebCryptoKeyOps {
        let row = self.store.system_key("control").await.unwrap().unwrap();
        let root_id = Id::new(&row.root_id).unwrap();
        let unwrap = MasterUnwrap::from_bytes(&[("m1", &M1)]).await.unwrap();
        let key = unwrap
            .unwrap_root(
                &row.wrap_key,
                &row.wrapped_root,
                "_system/control",
                &root_id,
            )
            .await
            .unwrap();
        WebCryptoKeyOps::from_hkdf_key(key, root_id).unwrap()
    }

    /// The last durable event.
    fn last(&self) -> Value {
        self.audit.values().last().cloned().unwrap()
    }

    fn auth_fail_checks(&self) -> usize {
        self.limits
            .checks
            .borrow()
            .iter()
            .filter(|(l, _)| *l == Limit::AuthFailure)
            .count()
    }
}

/// `challenge` with one character of its random part changed: well formed, wrong MAC.
fn flip(challenge: &str) -> String {
    let mut b = challenge.as_bytes().to_vec();
    let i = "ekmsc.".len() + 14;
    b[i] = if b[i] == b'A' { b'B' } else { b'A' };
    String::from_utf8(b).unwrap()
}

#[track_caller]
fn assert_denied(r: &Reply) {
    assert_error(r, 400, "permission denied");
    assert_eq!(code(r), None, "{r:?}");
}

#[track_caller]
fn assert_auth_failed(r: &Reply) {
    assert_eq!(r.status, 403, "{r:?}");
    assert_eq!(code(r), Some("auth_failed"), "{r:?}");
}

/// An owner with a personal tenant and `key` registered; returns their GitHub token.
async fn owner_with_key(fx: &Fx, id: u64, login: &str, key: &Key) -> String {
    let token = fx.github(id, login).await;
    let r = fx.add(&token, key, "laptop").await;
    assert_eq!(r.status, 201, "{r:?}");
    token
}

// ---- Task 3: auth methods in tokens ----

#[wasm_bindgen_test]
async fn github_tokens_carry_auth_github() {
    let fx = fx().await;
    let r = fx.github_reply(1, "alice").await;
    let d = ok_data(&r);
    assert_eq!(d["auth"], json!("github"));
    assert_eq!(d["ssh_keys"], json!(0));
    assert_eq!(fx.last()["auth_method"], json!("github"));
    let token = d["token"].as_str().unwrap().to_owned();
    let claims = token::check(&fx.control_ops().await, &token, NOW)
        .await
        .unwrap();
    assert_eq!(claims.meta["auth"], "github");
    assert!(!claims.meta.contains_key("ssh_fingerprint"));
    fx.audit.clear();
    assert_eq!(fx.get("/v1/me", &token).await.status, 200);
    let ev = fx.audit.only_metric();
    assert_eq!(ev["auth_method"], json!("github"));
    assert!(ev.get("auth_ssh_fingerprint").is_none());
    // The next login counts the account's keys.
    assert_eq!(fx.add(&token, &Key::ed(1), "").await.status, 201);
    let r = fx.github_reply(1, "alice").await;
    assert_eq!(ok_data(&r)["ssh_keys"], json!(1));
}

async fn mint_meta(fx: &Fx, meta: &[(&str, &str)]) -> String {
    let ops = fx.control_ops().await;
    let claims = TokenClaims {
        v: 1,
        jti: token::new_jti(&ops),
        role: "control".into(),
        policies: vec![],
        iat: NOW,
        exp: NOW + 1800,
        long: false,
        meta: meta
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<BTreeMap<_, _>>(),
    };
    token::mint(&ops, &claims).await.unwrap()
}

#[wasm_bindgen_test]
async fn tokens_without_auth_are_github_and_unknown_auth_is_refused() {
    let fx = fx().await;
    fx.github(1, "alice").await;
    let iat_ms = (NOW * 1000 + 1).to_string();
    let base = [
        ("github_id", "1"),
        ("iat_ms", iat_ms.as_str()),
        ("login", "alice"),
    ];
    let old = mint_meta(&fx, &base).await;
    fx.now.set(NOW + 1);
    fx.audit.clear();
    assert_eq!(fx.get("/v1/me", &old).await.status, 200);
    assert_eq!(fx.audit.only_metric()["auth_method"], json!("github"));
    for extra in [
        vec![("auth", "magic")],
        vec![("auth", "ssh")],
        vec![("auth", "ssh"), ("ssh_fingerprint", "MD5:aa")],
    ] {
        let meta: Vec<_> = base.iter().copied().chain(extra.clone()).collect();
        let t = mint_meta(&fx, &meta).await;
        fx.audit.clear();
        let r = fx.get("/v1/me", &t).await;
        assert_auth_failed(&r);
        assert_eq!(
            fx.audit.only_metric()["error"],
            json!("invalid_token"),
            "{extra:?}"
        );
    }
}

#[wasm_bindgen_test]
async fn removing_a_key_ends_only_its_tokens() {
    let fx = fx().await;
    let key = Key::ed(1);
    let github = owner_with_key(&fx, 1, "alice", &key).await;
    let ssh_token = fx.ssh(&key).await;
    assert_eq!(fx.get("/v1/me", &ssh_token).await.status, 200);
    assert_eq!(
        fx.delete(&format!("/v1/me/ssh-keys/{}", key.id()), &github)
            .await,
        Reply::no_content()
    );
    fx.audit.clear();
    let r = fx.get("/v1/me", &ssh_token).await;
    assert_auth_failed(&r);
    assert_eq!(fx.audit.only_metric()["error"], json!("ssh_key_revoked"));
    // The owner's GitHub session, which did the removing, keeps working.
    assert_eq!(fx.get("/v1/me", &github).await.status, 200);
}

/// Security review finding 1: re-adding a removed key starts a new row, and the tokens the old
/// one minted stay dead.
#[wasm_bindgen_test]
async fn readding_a_removed_key_does_not_revive_its_tokens() {
    let fx = fx().await;
    let key = Key::ed(1);
    let github = owner_with_key(&fx, 1, "alice", &key).await;
    let old = fx.ssh(&key).await;
    fx.delete(&format!("/v1/me/ssh-keys/{}", key.id()), &github)
        .await;
    fx.now.set(NOW + 1);
    assert_eq!(fx.add(&github, &key, "laptop").await.status, 201);
    fx.audit.clear();
    assert_auth_failed(&fx.get("/v1/me", &old).await);
    assert_eq!(fx.audit.only_metric()["error"], json!("ssh_key_revoked"));
    // A login with the re-added key works.
    let new = fx.ssh(&key).await;
    assert_eq!(fx.get("/v1/me", &new).await.status, 200);
}

/// Security review finding 2: `key_type` must name the public key's own type, or the row
/// doesn't verify (the console's "no touch required" warning reads it).
#[wasm_bindgen_test]
async fn a_rewritten_key_type_fails_the_row() {
    let fx = fx().await;
    let key = Key::ed(1);
    let token = owner_with_key(&fx, 1, "alice", &key).await;
    fx.store.tamper_ssh_key(&key.fingerprint(), |r| {
        r.key_type = "sk-ssh-ed25519@openssh.com".into();
    });
    let r = fx.get("/v1/me/ssh-keys", &token).await;
    assert_eq!(ok_data(&r)["keys"], json!([]));
    assert_eq!(ok_data(&r)["unverified"], json!([key.fingerprint()]));
    assert_denied(&fx.ssh_reply(&key, ssh::NAMESPACE).await);
    assert_eq!(fx.last()["error"], json!("ssh_key_mac_invalid"));
}

#[wasm_bindgen_test]
async fn logout_ends_ssh_tokens_too() {
    let fx = fx().await;
    let key = Key::ed(1);
    let github = owner_with_key(&fx, 1, "alice", &key).await;
    let ssh_token = fx.ssh(&key).await;
    fx.now.set(NOW + 1);
    assert_eq!(
        fx.post("/v1/logout", Some(&github), &json!({})).await,
        Reply::no_content()
    );
    assert_auth_failed(&fx.get("/v1/me", &ssh_token).await);
}

#[wasm_bindgen_test]
async fn ssh_token_with_a_tampered_key_row_is_refused() {
    let fx = fx().await;
    let key = Key::ed(1);
    owner_with_key(&fx, 1, "alice", &key).await;
    let ssh_token = fx.ssh(&key).await;
    fx.store
        .tamper_ssh_key(&key.fingerprint(), |r| r.label = "not mine".into());
    fx.audit.clear();
    assert_auth_failed(&fx.get("/v1/me", &ssh_token).await);
    assert_eq!(fx.audit.only_metric()["error"], json!("ssh_key_revoked"));
}

// ---- Task 4: SSH login ----

#[wasm_bindgen_test]
async fn ssh_login_happy_path_for_each_key_type() {
    for (key, kt) in [
        (Key::ed(1), "ssh-ed25519"),
        (Key::ecdsa(2), "ecdsa-sha2-nistp256"),
        (
            Key::Sk {
                seed: 3,
                touch: true,
            },
            "sk-ssh-ed25519@openssh.com",
        ),
    ] {
        let fx = fx().await;
        owner_with_key(&fx, 1, "alice", &key).await;
        assert_eq!(fx.last()["target_ssh_key_type"], json!(kt));
        fx.audit.clear();
        let r = fx.ssh_reply(&key, ssh::NAMESPACE).await;
        let d = ok_data(&r);
        assert_eq!(d["auth"], json!("ssh"), "{kt}");
        assert_eq!(d["ssh_fingerprint"], json!(key.fingerprint()));
        assert_eq!(d["github_id"], json!(1));
        assert_eq!(d["login"], json!("alice"));
        assert_eq!(d["ssh_keys"], json!(1));
        assert_eq!(d["expires_in"], json!(1800));
        assert!(d.get("created_tenant").is_none());
        let token = d["token"].as_str().unwrap().to_owned();
        let claims = token::check(&fx.control_ops().await, &token, NOW)
            .await
            .unwrap();
        assert_eq!(claims.meta["auth"], "ssh");
        assert_eq!(claims.meta["ssh_fingerprint"], key.fingerprint());
        // The attempt, then the outcome, both naming the key.
        let evs = fx.audit.values();
        assert_eq!(evs.len(), 2, "{evs:?}");
        for (ev, result) in evs.iter().zip(["attempt", "ok"]) {
            assert_eq!(ev["op"], json!("control_login_ssh"));
            assert_eq!(ev["result"], json!(result));
            assert_eq!(ev["auth_method"], json!("ssh"));
            assert_eq!(ev["auth_ssh_fingerprint"], json!(key.fingerprint()));
            assert_eq!(ev["github_id"], json!(1));
        }
        assert_eq!(
            fx.store
                .ssh_key_row(&key.fingerprint())
                .unwrap()
                .last_used_ms,
            Some(NOW * 1000)
        );
        // The token works, and every event under it names the key.
        fx.audit.clear();
        assert_eq!(fx.get("/v1/me", &token).await.status, 200);
        let ev = fx.audit.only_metric();
        assert_eq!(ev["auth_method"], json!("ssh"));
        assert_eq!(ev["auth_ssh_fingerprint"], json!(key.fingerprint()));
    }
}

/// Review focus 1: before a signature verifies, the login reads nothing but the control root's
/// own row, whether the key is registered or not, and both refusals are identical.
#[wasm_bindgen_test]
async fn ssh_login_failures_before_the_signature_touch_no_store() {
    let fx = fx().await;
    let registered = Key::ed(1);
    owner_with_key(&fx, 1, "alice", &registered).await;
    let stranger = Key::ed(2);

    let mut bodies = Vec::new();
    for (key, msg_signed) in [(&stranger, "ekmsc.other"), (&registered, "ekmsc.other")] {
        let c = fx.challenge().await;
        // A signature over another message: valid armor, wrong bytes.
        let sig = key.sign(ssh::NAMESPACE, msg_signed);
        fx.audit.clear();
        let before = fx.store.calls();
        let r = fx.login_with(&c, &sig).await;
        // The one call is the `system_keys` row of the control root.
        assert_eq!(fx.store.calls() - before, 1, "{r:?}");
        assert_denied(&r);
        let ev = fx.last();
        assert_eq!(ev["error"], json!("ssh_bad_signature"));
        assert!(ev.get("auth_ssh_fingerprint").is_none(), "{ev}");
        assert!(ev.get("github_id").is_none(), "{ev}");
        bodies.push(r.body.clone());
    }
    assert_eq!(bodies[0], bodies[1]);
}

#[wasm_bindgen_test]
async fn ssh_login_refusals_are_uniform() {
    let fx = fx().await;
    let key = Key::ed(1);
    owner_with_key(&fx, 1, "alice", &key).await;
    let ops = fx.control_ops().await;
    let other_origin = ssh::new_challenge_with(
        &ops,
        MacPurpose::ControlChallenge,
        NOW,
        "https://evil.example",
    )
    .await
    .unwrap();
    let old = ssh::new_challenge_with(&ops, MacPurpose::ControlChallenge, NOW - 61, ORIGIN)
        .await
        .unwrap();
    let future = ssh::new_challenge_with(&ops, MacPurpose::ControlChallenge, NOW + 6, ORIGIN)
        .await
        .unwrap();
    let rsa_sig = include_str!("../../edgekms-core/tests/fixtures/ssh/rsa.sig");
    let c = fx.challenge().await;
    let untouched = Key::Sk {
        seed: 3,
        touch: false,
    };
    let cases: Vec<(&str, Value)> = vec![
        ("ssh_body_malformed", json!({ "challenge": c })),
        (
            "ssh_body_malformed",
            json!({ "challenge": 1, "signature": "x" }),
        ),
        (
            "ssh_challenge_malformed",
            json!({ "challenge": "nope", "signature": key.sign("edgekms", "nope") }),
        ),
        (
            "ssh_challenge_mac",
            json!({ "challenge": flip(&c), "signature": "x" }),
        ),
        (
            "ssh_challenge_wrong_origin",
            json!({ "challenge": other_origin, "signature": key.sign("edgekms", &other_origin) }),
        ),
        (
            "ssh_challenge_expired",
            json!({ "challenge": old, "signature": key.sign("edgekms", &old) }),
        ),
        (
            "ssh_challenge_from_future",
            json!({ "challenge": future, "signature": key.sign("edgekms", &future) }),
        ),
        (
            "ssh_signature_malformed",
            json!({ "challenge": c, "signature": "-----BEGIN SSH SIGNATURE-----" }),
        ),
        (
            "ssh_wrong_namespace",
            json!({ "challenge": c, "signature": key.sign("git", &c) }),
        ),
        (
            "ssh_unsupported_key_type",
            json!({ "challenge": c, "signature": rsa_sig }),
        ),
        (
            "ssh_bad_signature",
            json!({ "challenge": c, "signature": key.sign("edgekms", "ekmsc.x") }),
        ),
        (
            "ssh_user_not_present",
            json!({ "challenge": c, "signature": untouched.sign("edgekms", &c) }),
        ),
        (
            "ssh_key_unknown",
            json!({ "challenge": c, "signature": Key::ed(9).sign("edgekms", &c) }),
        ),
    ];
    for (label, body) in cases {
        // Every refusal counts once against AUTH_FAIL_LIMIT.
        let fails = fx.auth_fail_checks();
        fx.audit.clear();
        let r = fx.post("/v1/login/ssh", None, &body).await;
        assert_denied(&r);
        assert_eq!(fx.last()["error"], json!(label), "{body}");
        assert_eq!(fx.auth_fail_checks(), fails + 1, "{label}");
    }
    // Over AUTH_FAIL_LIMIT, the refusal becomes a 429.
    fx.limits.deny_auth_failure.set(true);
    let r = fx.post("/v1/login/ssh", None, &json!({})).await;
    assert_error(&r, 429, "rate limit quota exceeded");
}

/// Review focus 2.
#[wasm_bindgen_test]
async fn ssh_login_challenge_is_single_use() {
    let fx = fx().await;
    let key = Key::ed(1);
    owner_with_key(&fx, 1, "alice", &key).await;
    let c = fx.challenge().await;
    let sig = key.sign(ssh::NAMESPACE, &c);
    assert_eq!(fx.login_with(&c, &sig).await.status, 200);
    let r = fx.login_with(&c, &sig).await;
    assert_denied(&r);
    assert_eq!(fx.last()["error"], json!("ssh_challenge_replayed"));
    // Once its row could be purged, the challenge itself is past its minute.
    fx.now.set(NOW + 61);
    assert_denied(&fx.login_with(&c, &sig).await);
    assert_eq!(fx.last()["error"], json!("ssh_challenge_expired"));
}

/// Review focus 4, at login.
#[wasm_bindgen_test]
async fn ssh_login_refuses_foreign_challenges_and_namespaces() {
    let fx = fx().await;
    let key = Key::ed(1);
    let token = owner_with_key(&fx, 1, "alice", &key).await;
    let ops = fx.control_ops().await;
    // A data-plane challenge (purpose `Challenge`) under the same root, and one from another
    // root entirely, as a tenant's would be.
    let data_plane = ssh::new_challenge(&ops, NOW, ORIGIN).await.unwrap();
    let tenant_root = web_ops().await;
    let tenant = ssh::new_challenge(&tenant_root, NOW, ORIGIN).await.unwrap();
    for c in [data_plane, tenant] {
        assert_denied(&fx.login_with(&c, &key.sign(ssh::NAMESPACE, &c)).await);
        assert_eq!(fx.last()["error"], json!("ssh_challenge_mac"));
    }
    // A registration challenge, which names an account and isn't a login challenge's format.
    let r = fx.proof_challenge(&token).await;
    let registration = ok_data(&r)["challenge"].as_str().unwrap().to_owned();
    assert_denied(
        &fx.login_with(&registration, &key.sign(ssh::NAMESPACE, &registration))
            .await,
    );
    assert_eq!(fx.last()["error"], json!("ssh_challenge_malformed"));
    // A registration proof can't log in.
    let r = fx.ssh_reply(&key, ssh::REGISTER_NAMESPACE).await;
    assert_denied(&r);
    assert_eq!(fx.last()["error"], json!("ssh_wrong_namespace"));
}

/// Review focus 5: an SSH login reaches existing accounts only and never creates one.
#[wasm_bindgen_test]
async fn ssh_login_never_signs_anyone_up() {
    let fx = fx().await;
    let owner = fx.github(1, "alice").await;
    // Bob takes a seat in alice's tenant on her invite, in invite mode, so he gets no tenant
    // of his own, then registers a key.
    fx.mode(SignupMode::Invite);
    let r = fx
        .call(creq(
            Method::Put,
            "/v1/tenants/alice/members/2",
            Some(&owner),
            &json!({ "role": "member" }),
        ))
        .await;
    assert_eq!(r, Reply::no_content());
    let bob = fx.github(2, "bob").await;
    assert_eq!(
        fx.post("/v1/tenants/alice/accept", Some(&bob), &json!({}))
            .await
            .status,
        200
    );
    let key = Key::ed(2);
    assert_eq!(fx.add(&bob, &key, "").await.status, 201);
    assert_eq!(fx.ssh_reply(&key, ssh::NAMESPACE).await.status, 200);
    // Alice removes him: his key stays, but no longer logs in, in any mode, allowlisted or not.
    assert_eq!(
        fx.delete("/v1/tenants/alice/members/2", &owner).await,
        Reply::no_content()
    );
    let op = fx.github(OPERATOR, "op").await;
    assert_eq!(
        fx.call(creq(
            Method::Put,
            "/v1/ops/allowlist/2",
            Some(&op),
            &json!({})
        ))
        .await,
        Reply::no_content()
    );
    for mode in [SignupMode::Closed, SignupMode::Invite, SignupMode::Open] {
        fx.mode(mode);
        let tenants = fx.store.count_created(2).await.unwrap();
        let r = fx.ssh_reply(&key, ssh::NAMESPACE).await;
        assert_denied(&r);
        let ev = fx.last();
        assert_eq!(ev["error"], json!("ssh_not_existing"), "{mode:?}");
        // The key verified, so the event names it and its user.
        assert_eq!(ev["auth_ssh_fingerprint"], json!(key.fingerprint()));
        assert_eq!(fx.store.count_created(2).await.unwrap(), tenants);
        assert_eq!(tenants, 0);
    }
    assert!(fx.store.ssh_key_row(&key.fingerprint()).is_some());
}

#[wasm_bindgen_test]
async fn operators_and_suspended_owners_log_in_with_ssh() {
    let fx = fx().await;
    // An operator whose only tenant is gone still logs in.
    let op_key = Key::ed(9);
    let r = fx.github_reply(OPERATOR, "op").await;
    let op = ok_data(&r)["token"].as_str().unwrap().to_owned();
    let personal = ok_data(&r)["created_tenant"].as_str().unwrap().to_owned();
    assert_eq!(fx.add(&op, &op_key, "").await.status, 201);
    fx.store.delete_tenant(&personal);
    fx.mode(SignupMode::Closed);
    assert_eq!(fx.ssh_reply(&op_key, ssh::NAMESPACE).await.status, 200);
    // A suspended tenant's owner logs in and exports; its member doesn't log in on it.
    fx.mode(SignupMode::Open);
    let key = Key::ed(1);
    let owner = owner_with_key(&fx, 1, "alice", &key).await;
    fx.mode(SignupMode::Invite);
    fx.call(creq(
        Method::Put,
        "/v1/tenants/alice/members/2",
        Some(&owner),
        &json!({ "role": "member" }),
    ))
    .await;
    let bob = fx.github(2, "bob").await;
    fx.post("/v1/tenants/alice/accept", Some(&bob), &json!({}))
        .await;
    let bob_key = Key::ed(2);
    assert_eq!(fx.add(&bob, &bob_key, "").await.status, 201);
    let r = fx
        .call(creq(
            Method::Put,
            "/v1/ops/tenants/alice/status",
            Some(&op),
            &json!({ "status": "suspended" }),
        ))
        .await;
    assert!(r.status < 300, "{r:?}");
    let ssh_token = fx.ssh(&key).await;
    fx.audit.clear();
    let r = fx
        .post("/v1/tenants/alice/export", Some(&ssh_token), &json!({}))
        .await;
    assert_eq!(r.status, 200, "{r:?}");
    let ev = fx.last();
    assert_eq!(ev["op"], json!("tenant_export"));
    assert_eq!(ev["auth_method"], json!("ssh"));
    assert_eq!(ev["auth_ssh_fingerprint"], json!(key.fingerprint()));
    assert_denied(&fx.ssh_reply(&bob_key, ssh::NAMESPACE).await);
    assert_eq!(fx.last()["error"], json!("ssh_not_existing"));
}

/// Review focus 5: a row written without the master logs no one in.
#[wasm_bindgen_test]
async fn forged_or_moved_key_rows_log_no_one_in() {
    let fx = fx().await;
    let key = Key::ed(1);
    owner_with_key(&fx, 1, "alice", &key).await;
    fx.github(2, "bob").await;
    let real = fx.store.ssh_key_row(&key.fingerprint()).unwrap();
    let tamper: [(&str, Tamper); 4] = [
        ("moved", Box::new(|r| r.github_id = 2)),
        ("relabelled", Box::new(|r| r.label = "trusted".into())),
        ("lineage", Box::new(|r| r.added_via = "ssh:SHA256:x".into())),
        ("forged", Box::new(|r| r.mac = vec![0; 32])),
    ];
    for (what, f) in tamper {
        let mut row = real.clone();
        f(&mut row);
        fx.store.forge_ssh_key(row);
        let r = fx.ssh_reply(&key, ssh::NAMESPACE).await;
        assert_denied(&r);
        assert_eq!(fx.last()["error"], json!("ssh_key_mac_invalid"), "{what}");
    }
    fx.store.forge_ssh_key(real);
    assert_eq!(fx.ssh_reply(&key, ssh::NAMESPACE).await.status, 200);
}

#[wasm_bindgen_test]
async fn ssh_login_counts_login_limit() {
    let fx = fx().await;
    let key = Key::ed(1);
    owner_with_key(&fx, 1, "alice", &key).await;
    fx.limits.checks.borrow_mut().clear();
    assert_eq!(fx.ssh_reply(&key, ssh::NAMESPACE).await.status, 200);
    let logins = |fx: &Fx| {
        fx.limits
            .checks
            .borrow()
            .iter()
            .filter(|(l, _)| *l == Limit::Login)
            .count()
    };
    assert_eq!(logins(&fx), 2);
    fx.limits.login_budget.set(Some(0));
    let r = fx.post("/v1/login/ssh/challenge", None, &json!({})).await;
    assert_error(&r, 429, "rate limit quota exceeded");
    let r = fx.post("/v1/login/ssh", None, &json!({})).await;
    assert_error(&r, 429, "rate limit quota exceeded");
}

#[wasm_bindgen_test]
async fn ssh_login_audit_failure_withholds_the_token() {
    let fx = fx().await;
    let key = Key::ed(1);
    owner_with_key(&fx, 1, "alice", &key).await;
    let c = fx.challenge().await;
    fx.audit.fail.set(true);
    let r = fx.login_with(&c, &key.sign(ssh::NAMESPACE, &c)).await;
    assert_error(&r, 500, "audit log unavailable");
    assert_eq!(
        fx.store
            .ssh_key_row(&key.fingerprint())
            .unwrap()
            .last_used_ms,
        None
    );
}

// ---- Task 5: key management ----

#[wasm_bindgen_test]
async fn ssh_key_add_needs_a_fresh_login() {
    let fx = fx().await;
    let token = fx.github(1, "alice").await;
    let key = Key::ed(1);
    fx.now.set(NOW + 299);
    let r = fx.proof_challenge(&token).await;
    assert_eq!(ok_data(&r)["expires_in"], json!(300));
    assert_eq!(ok_data(&r)["namespace"], json!("edgekms-register"));
    let c = ok_data(&r)["challenge"].as_str().unwrap().to_owned();
    let sig = key.sign(ssh::REGISTER_NAMESPACE, &c);
    fx.now.set(NOW + 300);
    for r in [
        fx.proof_challenge(&token).await,
        fx.add_with(&token, &key.line(), "", &c, &sig).await,
    ] {
        assert_error(&r, 403, "fresh login required");
        assert_eq!(code(&r), Some("fresh_login_required"));
    }
    fx.now.set(NOW + 299);
    assert_eq!(
        fx.add_with(&token, &key.line(), "", &c, &sig).await.status,
        201
    );
    // An SSH login is fresh too.
    let ssh_token = fx.ssh(&key).await;
    assert_eq!(fx.add(&ssh_token, &Key::ed(2), "").await.status, 201);
}

#[wasm_bindgen_test]
async fn ssh_key_add_needs_proof_by_that_key() {
    let fx = fx().await;
    let token = fx.github(1, "alice").await;
    let (mine, theirs) = (Key::ed(1), Key::ed(2));
    let r = fx.proof_challenge(&token).await;
    let c = ok_data(&r)["challenge"].as_str().unwrap().to_owned();
    let fails = fx.auth_fail_checks();
    let r = fx
        .add_with(
            &token,
            &theirs.line(),
            "",
            &c,
            &mine.sign(ssh::REGISTER_NAMESPACE, &c),
        )
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(code(&r), Some("ssh_key_proof_failed"));
    assert_eq!(fx.last()["error"], json!("ssh_key_not_allowed"));
    assert_eq!(fx.auth_fail_checks(), fails + 1);
    assert!(fx.store.ssh_key_row(&theirs.fingerprint()).is_none());
}

/// Review focus 4, at registration.
#[wasm_bindgen_test]
async fn ssh_key_add_refuses_login_challenges_and_namespaces() {
    let fx = fx().await;
    let token = fx.github(1, "alice").await;
    let key = Key::ed(1);
    let login_challenge = fx.challenge().await;
    let r = fx
        .add_with(
            &token,
            &key.line(),
            "",
            &login_challenge,
            &key.sign(ssh::REGISTER_NAMESPACE, &login_challenge),
        )
        .await;
    assert_eq!(code(&r), Some("ssh_key_proof_failed"));
    assert_eq!(fx.last()["error"], json!("ssh_challenge_malformed"));
    // So is a registration challenge in the format from before the account was bound
    // (lokkju/edgekms#17), MAC'd as one then was.
    let old = ssh::new_challenge_with(
        &fx.control_ops().await,
        MacPurpose::SshKeyProof,
        NOW,
        ORIGIN,
    )
    .await
    .unwrap();
    let r = fx
        .add_with(
            &token,
            &key.line(),
            "",
            &old,
            &key.sign(ssh::REGISTER_NAMESPACE, &old),
        )
        .await;
    assert_eq!(code(&r), Some("ssh_key_proof_failed"));
    assert_eq!(fx.last()["error"], json!("ssh_challenge_malformed"));
    let r = fx.proof_challenge(&token).await;
    let c = ok_data(&r)["challenge"].as_str().unwrap().to_owned();
    let r = fx
        .add_with(&token, &key.line(), "", &c, &key.sign(ssh::NAMESPACE, &c))
        .await;
    assert_eq!(code(&r), Some("ssh_key_proof_failed"));
    assert_eq!(fx.last()["error"], json!("ssh_wrong_namespace"));
}

/// Review focus 2, at registration.
#[wasm_bindgen_test]
async fn ssh_key_proof_is_single_use() {
    let fx = fx().await;
    let alice = fx.github(1, "alice").await;
    let bob = fx.github(2, "bob").await;
    let key = Key::ed(1);
    let r = fx.proof_challenge(&alice).await;
    let c = ok_data(&r)["challenge"].as_str().unwrap().to_owned();
    let sig = key.sign(ssh::REGISTER_NAMESPACE, &c);
    assert_eq!(
        fx.add_with(&alice, &key.line(), "", &c, &sig).await.status,
        201
    );
    fx.delete(&format!("/v1/me/ssh-keys/{}", key.id()), &alice)
        .await;
    // Alice can't use it twice, and someone who saw the proof can't use it at all: it names
    // alice's account.
    for (t, label) in [
        (&alice, "ssh_challenge_replayed"),
        (&bob, "ssh_challenge_wrong_account"),
    ] {
        let r = fx.add_with(t, &key.line(), "", &c, &sig).await;
        assert_eq!(code(&r), Some("ssh_key_proof_failed"));
        assert_eq!(fx.last()["error"], json!(label));
    }
}

/// lokkju/edgekms#17: a registration challenge names the account it was minted for, in the
/// text the key signs, and registers the key to that account only.
#[wasm_bindgen_test]
async fn ssh_key_proof_is_bound_to_its_account() {
    let fx = fx().await;
    let alice = fx.github(1, "alice").await;
    let mallory = fx.github(2, "mallory").await;
    let r = fx.proof_challenge(&mallory).await;
    let d = ok_data(&r);
    assert_eq!(d["github_id"], json!(2));
    assert_eq!(d["login"], json!("mallory"));
    let c = d["challenge"].as_str().unwrap().to_owned();
    assert!(c.starts_with("ekmsr.2.mallory."), "{c}");
    // Mallory's challenge, signed by alice's key, doesn't register it to alice...
    let key = Key::ed(1);
    let sig = key.sign(ssh::REGISTER_NAMESPACE, &c);
    let fails = fx.auth_fail_checks();
    let r = fx.add_with(&alice, &key.line(), "", &c, &sig).await;
    assert_eq!(code(&r), Some("ssh_key_proof_failed"));
    assert_eq!(fx.last()["error"], json!("ssh_challenge_wrong_account"));
    assert_eq!(fx.auth_fail_checks(), fails + 1);
    assert!(fx.store.ssh_key_row(&key.fingerprint()).is_none());
    // ...and alice's challenge with its account rewritten to mallory's fails the MAC, so the
    // only way to put the key on mallory's account is a signature over text naming mallory.
    let r = fx.proof_challenge(&alice).await;
    let theirs = ok_data(&r)["challenge"].as_str().unwrap().to_owned();
    assert!(theirs.starts_with("ekmsr.1.alice."), "{theirs}");
    let forged = theirs.replacen("ekmsr.1.alice.", "ekmsr.2.mallory.", 1);
    let r = fx
        .add_with(
            &mallory,
            &key.line(),
            "",
            &forged,
            &key.sign(ssh::REGISTER_NAMESPACE, &forged),
        )
        .await;
    assert_eq!(code(&r), Some("ssh_key_proof_failed"));
    assert_eq!(fx.last()["error"], json!("ssh_challenge_mac"));
    assert!(fx.store.ssh_key_row(&key.fingerprint()).is_none());
    // Alice's own challenge still registers the key to alice.
    let r = fx
        .add_with(
            &alice,
            &key.line(),
            "",
            &theirs,
            &key.sign(ssh::REGISTER_NAMESPACE, &theirs),
        )
        .await;
    assert_eq!(r.status, 201, "{r:?}");
    assert_eq!(
        fx.store.ssh_key_row(&key.fingerprint()).unwrap().github_id,
        1
    );
}

#[wasm_bindgen_test]
async fn ssh_key_add_field_rules() {
    let fx = fx().await;
    let token = fx.github(1, "alice").await;
    let key = Key::ed(1);
    let r = fx.proof_challenge(&token).await;
    let c = ok_data(&r)["challenge"].as_str().unwrap().to_owned();
    let sig = key.sign(ssh::REGISTER_NAMESPACE, &c);
    for (public_key, label, want) in [
        (key.line(), "a\nb".to_owned(), "label_invalid"),
        (key.line(), "x".repeat(65), "label_invalid"),
        (key.line(), "a\u{202e}b".to_owned(), "label_invalid"),
        ("garbage".to_owned(), String::new(), "ssh_key_invalid"),
        (RSA_PUB.to_owned(), String::new(), "ssh_key_unsupported"),
    ] {
        let r = fx.add_with(&token, &public_key, &label, &c, &sig).await;
        assert_eq!(r.status, 400, "{want}");
        assert_eq!(code(&r), Some(want));
    }
    let r = fx
        .post(
            "/v1/me/ssh-keys",
            Some(&token),
            &json!({ "public_key": key.line(), "challenge": c }),
        )
        .await;
    assert_eq!(r.status, 400);
    // None of that burned the challenge.
    let r = fx
        .add_with(&token, &key.line(), "  laptop  ", &c, &sig)
        .await;
    assert_eq!(r.status, 201, "{r:?}");
    let d = ok_data(&r);
    assert_eq!(d["label"], json!("laptop"));
    assert_eq!(d["id"], json!(key.id()));
    assert_eq!(d["fingerprint"], json!(key.fingerprint()));
    assert!(!d["public_key"].as_str().unwrap().contains("me@laptop"));
    assert_eq!(d["last_used_ms"], Value::Null);
}

#[wasm_bindgen_test]
async fn ssh_key_add_is_capped_and_unique() {
    let fx = fx().await;
    let alice = fx.github(1, "alice").await;
    for seed in 0..10 {
        let r = fx.add(&alice, &Key::ed(seed + 10), "").await;
        assert_eq!(r.status, 201, "{seed}: {r:?}");
    }
    let r = fx.add(&alice, &Key::ed(99), "").await;
    assert_eq!((r.status, code(&r)), (409, Some("ssh_key_limit")));
    // A key registered to one account can't be registered to another, even by its holder.
    let bob = fx.github(2, "bob").await;
    let r = fx.add(&bob, &Key::ed(10), "").await;
    assert_eq!((r.status, code(&r)), (409, Some("ssh_key_in_use")));
    assert_eq!(
        fx.store
            .ssh_key_row(&Key::ed(10).fingerprint())
            .unwrap()
            .github_id,
        1
    );
}

#[wasm_bindgen_test]
async fn ssh_key_lineage() {
    let fx = fx().await;
    let first = Key::ed(1);
    let github = owner_with_key(&fx, 1, "alice", &first).await;
    let ev = fx.last();
    assert_eq!(ev["op"], json!("ssh_key_add"));
    assert_eq!(ev["auth_method"], json!("github"));
    assert_eq!(ev["target_ssh_fingerprint"], json!(first.fingerprint()));
    let ssh_token = fx.ssh(&first).await;
    let second = Key::ecdsa(2);
    // Later, so the listing (by `added_ms`) puts it second.
    fx.now.set(NOW + 1);
    fx.audit.clear();
    assert_eq!(fx.add(&ssh_token, &second, "").await.status, 201);
    let evs = fx.audit.values();
    assert_eq!(evs.len(), 2);
    for (ev, result) in evs.iter().zip(["attempt", "ok"]) {
        assert_eq!(ev["result"], json!(result));
        assert_eq!(ev["auth_method"], json!("ssh"));
        assert_eq!(ev["auth_ssh_fingerprint"], json!(first.fingerprint()));
        assert_eq!(ev["target_ssh_fingerprint"], json!(second.fingerprint()));
        assert_eq!(ev["target_ssh_key_type"], json!("ecdsa-sha2-nistp256"));
    }
    let r = fx.get("/v1/me/ssh-keys", &github).await;
    let keys = ok_data(&r)["keys"].as_array().unwrap().clone();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["added_via"], json!("github"));
    assert_eq!(
        keys[1]["added_via"],
        json!(format!("ssh:{}", first.fingerprint()))
    );
    assert_eq!(keys[0]["last_used_ms"], json!(NOW * 1000));
}

#[wasm_bindgen_test]
async fn ssh_key_list_reports_unverified() {
    let fx = fx().await;
    let key = Key::ed(1);
    let token = owner_with_key(&fx, 1, "alice", &key).await;
    assert_eq!(fx.add(&token, &Key::ed(2), "").await.status, 201);
    fx.store
        .tamper_ssh_key(&key.fingerprint(), |r| r.label = "x".into());
    fx.audit.clear();
    let r = fx.get("/v1/me/ssh-keys", &token).await;
    let d = ok_data(&r);
    assert_eq!(d["keys"].as_array().unwrap().len(), 1);
    assert_eq!(d["unverified"], json!([key.fingerprint()]));
    // A read: a metric, not a durable event.
    assert_eq!(fx.audit.only_metric()["op"], json!("ssh_key_list"));
    // The login reply counts only keys that verify.
    let r = fx.github_reply(1, "alice").await;
    assert_eq!(ok_data(&r)["ssh_keys"], json!(1));
}

#[wasm_bindgen_test]
async fn ssh_key_remove_is_scoped_to_the_caller() {
    let fx = fx().await;
    let key = Key::ed(1);
    let alice = owner_with_key(&fx, 1, "alice", &key).await;
    let bob = fx.github(2, "bob").await;
    let path = format!("/v1/me/ssh-keys/{}", key.id());
    assert_error(&fx.delete(&path, &bob).await, 404, "ssh key not found");
    assert!(fx.store.ssh_key_row(&key.fingerprint()).is_some());
    assert_error(
        &fx.delete("/v1/me/ssh-keys/abc", &alice).await,
        400,
        "invalid ssh key id",
    );
    // An unverified row can be removed.
    fx.store
        .tamper_ssh_key(&key.fingerprint(), |r| r.mac = vec![1; 32]);
    fx.audit.clear();
    assert_eq!(fx.delete(&path, &alice).await, Reply::no_content());
    assert_eq!(
        fx.last()["target_ssh_fingerprint"],
        json!(key.fingerprint())
    );
    assert_eq!(fx.last()["op"], json!("ssh_key_remove"));
    assert!(fx.store.ssh_key_row(&key.fingerprint()).is_none());
    assert_error(&fx.delete(&path, &alice).await, 404, "ssh key not found");
}

/// Review focus 3, the operator's kill switch.
#[wasm_bindgen_test]
async fn ops_revoke_removes_keys_and_logs_the_user_out() {
    let fx = fx().await;
    let key = Key::ed(1);
    let github = owner_with_key(&fx, 1, "alice", &key).await;
    assert_eq!(fx.add(&github, &Key::ed(2), "").await.status, 201);
    let ssh_token = fx.ssh(&key).await;
    let op = fx.github(OPERATOR, "op").await;
    assert_error(
        &fx.delete("/v1/ops/users/1/ssh-keys", &github).await,
        403,
        "permission denied",
    );
    assert_error(
        &fx.delete("/v1/ops/users/777/ssh-keys", &op).await,
        404,
        "user not found",
    );
    fx.now.set(NOW + 1);
    fx.audit.clear();
    let r = fx.delete("/v1/ops/users/1/ssh-keys", &op).await;
    assert_eq!(ok_data(&r)["removed"], json!(2));
    let ev = fx.last();
    assert_eq!(ev["op"], json!("ssh_keys_revoke"));
    assert_eq!(ev["target_github_id"], json!(1));
    assert_eq!(ev["ssh_keys_removed"], json!(2));
    assert_eq!(fx.audit.values()[0]["result"], json!("attempt"));
    assert_auth_failed(&fx.get("/v1/me", &github).await);
    assert_auth_failed(&fx.get("/v1/me", &ssh_token).await);
    assert_denied(&fx.ssh_reply(&key, ssh::NAMESPACE).await);
    assert_eq!(fx.get("/v1/me", &op).await.status, 200);
}
