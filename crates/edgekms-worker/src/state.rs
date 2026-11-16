//! Per-isolate state: the parsed config, pinned JWKS, and the imported root key. Built on the
//! first request an isolate serves and reused until the isolate is recycled.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_core::config::{Config, Mount};
use edgekms_core::jwt::Jwks;
use serde_json::Value;
use worker::Env;
use zeroize::Zeroizing;

use crate::master::MasterUnwrap;
use crate::vault::log_internal;
use crate::webcrypto::WebCryptoKeyOps;

/// Everything a request needs that doesn't change between requests.
pub struct State<K = WebCryptoKeyOps> {
    pub config: Config,
    pub ops: K,
    /// JWKS for mounts that pin their keys in config, parsed once.
    pub pinned_jwks: BTreeMap<String, Jwks>,
}

/// Why [`State::new`] refused a config. Names the mount only; no key material is involved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    #[error("mount {0:?} has a jwks that is not a JWKS document")]
    BadPinnedJwks(String),
}

impl<K> State<K> {
    /// Parses every pinned JWKS so a malformed one fails here, not at someone's login.
    ///
    /// # Errors
    /// [`StateError::BadPinnedJwks`] naming the mount whose `jwks` doesn't parse.
    pub fn new(config: Config, ops: K) -> Result<Self, StateError> {
        let mut pinned_jwks = BTreeMap::new();
        for (name, mount) in &config.mounts {
            if let Mount::Jwt {
                jwks: Some(jwks), ..
            } = mount
            {
                let parsed: Jwks = serde_json::from_value(jwks.clone())
                    .map_err(|_| StateError::BadPinnedJwks(name.clone()))?;
                pinned_jwks.insert(name.clone(), parsed);
            }
        }
        Ok(Self {
            config,
            ops,
            pinned_jwks,
        })
    }
}

/// How this Worker serves requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// One deployment, one config (`EDGEKMS_CONFIG`) and one root (`ROOT_KEY`): every
    /// self-hosted Worker.
    SingleTenant,
    /// The hosted tier: tenants by Host header under `apex`, each served at
    /// `origin_template` with its name in place of `{tenant}`.
    Hosted {
        apex: String,
        origin_template: String,
    },
}

/// The bindings [`mode_from`] decides on.
#[derive(Debug, Clone, Copy)]
pub struct ModeVars<'a> {
    /// `HOSTED_APEX`.
    pub hosted_apex: Option<&'a str>,
    /// `HOSTED_ORIGIN_TEMPLATE`.
    pub origin_template: Option<&'a str>,
    /// `GITHUB_API_BASE`.
    pub github_api_base: Option<&'a str>,
    /// Whether `EDGEKMS_CONFIG` or `ROOT_KEY` is bound, under any kind of binding.
    pub single_tenant_bound: bool,
    /// Whether some `MASTER_KEY_M<n>` is bound as anything but a Secrets Store binding (a
    /// Worker secret or a var).
    pub plain_master_bound: bool,
}

/// The Worker's [`Mode`]. Without `HOSTED_APEX` it is single-tenant whatever else is bound,
/// exactly as before the hosted tier.
///
/// # Errors
/// A fixed label, for a hosted Worker whose bindings are ambiguous or incomplete:
/// `hosted_and_single_tenant_bindings` (`EDGEKMS_CONFIG` or `ROOT_KEY` bound too),
/// `hosted_apex_invalid`, `hosted_origin_template_missing`, `hosted_origin_template_invalid`
/// (not exactly one `{tenant}`), `master_key_not_in_secrets_store` (a `MASTER_KEY_M<n>` that
/// isn't a Secrets Store binding, off `localhost`), or `github_api_base_refused` (see
/// [`crate::github::api_base`]).
pub fn mode_from(vars: &ModeVars) -> Result<Mode, &'static str> {
    let Some(apex) = vars.hosted_apex else {
        return Ok(Mode::SingleTenant);
    };
    if vars.single_tenant_bound {
        return Err("hosted_and_single_tenant_bindings");
    }
    let apex = apex.trim().to_ascii_lowercase();
    if apex.is_empty() {
        return Err("hosted_apex_invalid");
    }
    // The local end-to-end run adds later master versions as plain secrets; nowhere else may.
    if vars.plain_master_bound && apex != crate::master::PLAIN_MASTER_APEX {
        return Err("master_key_not_in_secrets_store");
    }
    let template = vars
        .origin_template
        .ok_or("hosted_origin_template_missing")?
        .trim();
    if template.matches("{tenant}").count() != 1 {
        return Err("hosted_origin_template_invalid");
    }
    crate::github::api_base(Some(&apex), vars.github_api_base)?;
    Ok(Mode::Hosted {
        apex,
        origin_template: template.to_owned(),
    })
}

/// [`mode_from`] over the Worker's bindings. A binding counts as bound whatever its kind (a
/// var, a JSON var, a secret or a Secrets Store binding), so a hosted Worker with a stray
/// `ROOT_KEY` of any kind fails closed.
///
/// # Errors
/// As [`mode_from`].
pub fn mode(env: &Env) -> Result<Mode, &'static str> {
    let bound = |name: &str| {
        js_sys::Reflect::get(env, &wasm_bindgen::JsValue::from_str(name))
            .is_ok_and(|v| !v.is_undefined())
    };
    let var = |name: &str| env.var(name).ok().map(|v| v.to_string());
    // A HOSTED_APEX bound as anything but a string is an empty apex, refused, not ignored.
    let hosted = bound("HOSTED_APEX").then(|| var("HOSTED_APEX").unwrap_or_default());
    let (apex, template, api) = (
        hosted,
        var("HOSTED_ORIGIN_TEMPLATE"),
        var("GITHUB_API_BASE"),
    );
    mode_from(&ModeVars {
        hosted_apex: apex.as_deref(),
        origin_template: template.as_deref(),
        github_api_base: api.as_deref(),
        single_tenant_bound: bound("EDGEKMS_CONFIG") || bound("ROOT_KEY"),
        plain_master_bound: crate::master::plain_master_bound(env),
    })
}

thread_local! {
    static STATE: RefCell<Option<Rc<State>>> = const { RefCell::new(None) };
    /// The isolate's unwrap-only master handles (hosted tier).
    static MASTER: RefCell<Option<Rc<MasterUnwrap>>> = const { RefCell::new(None) };
}

/// The isolate's one [`MasterUnwrap`], built on first use and shared by the data plane and the
/// control plane, so each master version is imported (lazily, inside it) once per isolate. A
/// failed build is not cached. Holding the `Env` it keeps across requests is fine for Secrets
/// Store, secrets, D1 and KV bindings.
///
/// # Errors
/// As [`MasterUnwrap::from_env`] (`master_key_missing` without `MASTER_KEY_CURRENT`).
pub async fn master_unwrap(env: &Env) -> worker::Result<Rc<MasterUnwrap>> {
    if let Some(m) = MASTER.with(|m| m.borrow().clone()) {
        return Ok(m);
    }
    let m = Rc::new(MasterUnwrap::from_env(env).await?);
    // Two first requests racing both build one; the first stored wins and both use it after.
    let m = MASTER.with(|slot| slot.borrow_mut().get_or_insert(m).clone());
    Ok(m)
}

/// The isolate's [`State`], built on first use. A failed build is not cached, so a fixed
/// binding takes effect on the next request without a redeploy.
///
/// # Errors
/// If `EDGEKMS_CONFIG` is missing or invalid, or `ROOT_KEY` is missing or not 32 bytes. Errors
/// name the binding and the reason only, never a value.
pub async fn state(env: &Env) -> worker::Result<Rc<State>> {
    if let Some(st) = STATE.with(|s| s.borrow().clone()) {
        return Ok(st);
    }
    let config = load_config(env)?;
    let ops = {
        let root = root_key(env).await?;
        WebCryptoKeyOps::import(&root, config.root_id.clone()).await?
        // `root` is zeroized here.
    };
    let st = Rc::new(State::new(config, ops).map_err(|e| {
        log_internal("EDGEKMS_CONFIG has a malformed pinned jwks");
        worker::Error::RustError(e.to_string())
    })?);
    STATE.with(|s| *s.borrow_mut() = Some(st.clone()));
    Ok(st)
}

/// `EDGEKMS_CONFIG` as either a JSON object var (wrangler `vars`) or a string holding JSON
/// (`wrangler dev --var EDGEKMS_CONFIG:<json>`, or a secret).
fn load_config(env: &Env) -> worker::Result<Config> {
    // `object_var` refuses a string binding and `var` refuses an object one, so try both.
    let text = match env.var("EDGEKMS_CONFIG") {
        Ok(v) => v.to_string(),
        Err(_) => env
            .object_var::<Value>("EDGEKMS_CONFIG")
            .map_err(|_| {
                log_internal("EDGEKMS_CONFIG binding is missing");
                worker::Error::RustError("EDGEKMS_CONFIG binding is missing".into())
            })?
            .to_string(),
    };
    Config::from_json(&text).map_err(|e| {
        log_internal("EDGEKMS_CONFIG is invalid");
        worker::Error::RustError(e.to_string())
    })
}

/// The root key from `ROOT_KEY`: a Secrets Store binding if there is one, else a Worker secret.
/// The base64 text and the decoded bytes are both zeroized when dropped.
///
/// # Errors
/// If neither binding yields a value, or it isn't base64 of exactly 32 bytes. The error never
/// contains the value.
pub async fn root_key(env: &Env) -> worker::Result<Zeroizing<[u8; 32]>> {
    let text: Zeroizing<String> = match env.secret_store("ROOT_KEY") {
        Ok(store) => Zeroizing::new(store.get().await?.ok_or_else(|| {
            log_internal("ROOT_KEY secrets store entry is empty");
            worker::Error::RustError("ROOT_KEY is empty".into())
        })?),
        Err(_) => Zeroizing::new(
            env.secret("ROOT_KEY")
                .map_err(|_| {
                    log_internal("ROOT_KEY binding is missing");
                    worker::Error::RustError("ROOT_KEY binding is missing".into())
                })?
                .to_string(),
        ),
    };
    decode_root_key(text.trim())
}

/// Base64 (standard alphabet) of exactly 32 bytes.
///
/// # Errors
/// A fixed message for bad base64 or a wrong length; never the input.
pub fn decode_root_key(b64: &str) -> worker::Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(STANDARD.decode(b64).map_err(|_| {
        log_internal("ROOT_KEY is not valid base64");
        worker::Error::RustError("ROOT_KEY is not valid base64".into())
    })?);
    let mut key = Zeroizing::new([0u8; 32]);
    if bytes.len() != key.len() {
        log_internal("ROOT_KEY does not decode to 32 bytes");
        return Err(worker::Error::RustError(
            "ROOT_KEY must decode to 32 bytes".into(),
        ));
    }
    key.copy_from_slice(&bytes);
    Ok(key)
}
