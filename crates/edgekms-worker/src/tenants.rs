//! The per-isolate tenant cache: tenant name to a ready [`State`] (config and root key handle),
//! revalidated against the tenant store at most every [`REVALIDATE_MS`].
//!
//! A load unwraps the root with the master key straight into a non-extractable HKDF handle,
//! verifies the config MAC under that root, parses and validates the config against the hosted
//! rules, and sets its `public_origins` to the tenant's origin. A config edit is seen within
//! one revalidation interval with no redeploy; a row that fails any check never loads.
//!
//! The cache holds at most [`MAX_TENANTS`] tenants (the least recently used is dropped) and
//! remembers up to [`MAX_UNKNOWN`] unknown or suspended names for [`NEGATIVE_MS`], so a scan of
//! random subdomains, or traffic to a suspended tenant, costs one store read per name per
//! isolate, not one per request.
//!
//! The config MAC covers the tenant name, so a row only loads under the name it was written
//! for. Per isolate, a config version lower than the one already served for the same tenant is
//! ignored (a lagging replica or a rolled-back row), and a slower concurrent load never
//! replaces a newer entry.
//!
//! A config edit reuses the cached root handle (no second unwrap); a change of tenant id, root
//! id or wrap key (a rewrap) unwraps again. When a changed row fails a check, the previous
//! entry keeps serving for at most one more [`REVALIDATE_MS`], so a bad write can't take a
//! working tenant down instantly; after that the tenant is refused until the row is fixed.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use edgekms_core::config::Config;
use edgekms_core::hosted::{HostedRules, config_mac_input, validate_hosted};
use edgekms_core::keyops::{KeyOps, MacPurpose};
use edgekms_core::tenant::TenantName;
use edgekms_core::transit::Id;
use web_sys::CryptoKey;

use crate::master::MasterUnwrap;
use crate::state::State;
use crate::store::{TenantRow, TenantStatus, TenantStore};
use crate::vault::log_internal;
use crate::webcrypto::WebCryptoKeyOps;

/// How long a cached tenant is served without asking the store whether it changed.
pub const REVALIDATE_MS: u64 = 30_000;

/// How long an unknown tenant name is answered from the cache.
pub const NEGATIVE_MS: u64 = 10_000;

/// Tenants cached per isolate; past this the least recently used is dropped.
pub const MAX_TENANTS: usize = 256;

/// Unknown names remembered per isolate.
pub const MAX_UNKNOWN: usize = 1024;

const UNWRAP_FAILED: &str = "tenant_unwrap_failed";
const MAC_BAD: &str = "tenant_config_mac_bad";
const CONFIG_INVALID: &str = "tenant_config_invalid";
const ROOT_ID_INVALID: &str = "tenant_root_id_invalid";
/// Logged when the store reports an older config version than this isolate already serves.
const ROLLBACK: &str = "tenant_config_version_went_back";

/// A tenant ready to serve.
pub struct Loaded {
    /// The tenant's immutable id (`t_<16 hex>`), which scopes revocations, audit and limits.
    pub tenant_id: String,
    pub state: Rc<State>,
}

/// Why a tenant couldn't be served. Labels are fixed strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LoadError {
    /// No tenant has this name: the bare `404`.
    #[error("unknown tenant")]
    Unknown,
    /// `403 permission denied`.
    #[error("tenant suspended")]
    Suspended,
    /// The row failed a check (`tenant_root_id_invalid`, `tenant_unwrap_failed`,
    /// `tenant_config_mac_bad`, `tenant_config_invalid`): `500`.
    #[error("tenant invalid: {0}")]
    Invalid(&'static str),
    /// The store or `WebCrypto` failed: `500`.
    #[error("tenant store: {0}")]
    Backend(&'static str),
}

struct Entry {
    tenant_id: String,
    config_version: u64,
    wrap_key: String,
    root_id: String,
    /// The unwrapped root, kept so a config edit doesn't unwrap again.
    root: CryptoKey,
    state: Rc<State>,
    checked_ms: u64,
    /// When a changed row first failed to load while this entry kept serving.
    failing_since: Option<u64>,
    /// LRU clock value of the last use.
    used: u64,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<String, Entry>,
    /// Names answered without the store until the time given: unknown names
    /// ([`LoadError::Unknown`]) and suspended tenants ([`LoadError::Suspended`]).
    negative: HashMap<String, (u64, LoadError)>,
    clock: u64,
}

impl Cache {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Caches `entry` under `name` and returns what to serve. An entry already cached for the
    /// same tenant at a higher config version stays (a slower concurrent load, or a rolled-back
    /// row, must not replace it), and is what's served.
    fn insert(&mut self, name: String, mut entry: Entry) -> Loaded {
        let used = self.tick();
        if let Some(existing) = self.entries.get_mut(&name)
            && existing.tenant_id == entry.tenant_id
            && existing.config_version > entry.config_version
        {
            existing.used = used;
            return existing.loaded();
        }
        entry.used = used;
        if !self.entries.contains_key(&name) && self.entries.len() >= MAX_TENANTS {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.used)
                .map(|(n, _)| n.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.negative.remove(&name);
        let loaded = entry.loaded();
        self.entries.insert(name, entry);
        loaded
    }

    /// Drops any entry for `name` and answers it with `err` for [`NEGATIVE_MS`]. At
    /// [`MAX_UNKNOWN`] names, expired ones go first, then the one expiring soonest.
    fn remember_negative(&mut self, name: &str, err: LoadError, now_ms: u64) {
        self.entries.remove(name);
        if !self.negative.contains_key(name) && self.negative.len() >= MAX_UNKNOWN {
            self.negative.retain(|_, (until, _)| *until > now_ms);
            if self.negative.len() >= MAX_UNKNOWN {
                let soonest = self
                    .negative
                    .iter()
                    .min_by_key(|(_, (until, _))| *until)
                    .map(|(n, _)| n.clone());
                if let Some(soonest) = soonest {
                    self.negative.remove(&soonest);
                }
            }
        }
        self.negative
            .insert(name.to_owned(), (now_ms.saturating_add(NEGATIVE_MS), err));
    }
}

impl Entry {
    fn loaded(&self) -> Loaded {
        Loaded {
            tenant_id: self.tenant_id.clone(),
            state: self.state.clone(),
        }
    }
}

thread_local! {
    static CACHE: RefCell<Cache> = RefCell::new(Cache::default());
}

/// The cached entry's identity, for deciding what a revalidation changed.
struct Previous {
    tenant_id: String,
    config_version: u64,
    wrap_key: String,
    root_id: String,
    root: CryptoKey,
}

/// What the cache knows about a name before asking the store. Every borrow of [`CACHE`] ends
/// before the next `.await`.
enum Cached {
    Fresh(Loaded),
    Negative(LoadError),
    /// Stale or absent.
    Revalidate(Option<Previous>),
}

fn lookup(name: &str, now_ms: u64) -> Cached {
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        let used = c.tick();
        if let Some(e) = c.entries.get_mut(name) {
            e.used = used;
            if now_ms.saturating_sub(e.checked_ms) < REVALIDATE_MS {
                return Cached::Fresh(e.loaded());
            }
            return Cached::Revalidate(Some(Previous {
                tenant_id: e.tenant_id.clone(),
                config_version: e.config_version,
                wrap_key: e.wrap_key.clone(),
                root_id: e.root_id.clone(),
                root: e.root.clone(),
            }));
        }
        match c.negative.get(name) {
            Some((until, err)) if *until > now_ms => Cached::Negative(*err),
            _ => Cached::Revalidate(None),
        }
    })
}

fn negative(name: &str, err: LoadError, now_ms: u64) -> LoadError {
    CACHE.with(|c| c.borrow_mut().remember_negative(name, err, now_ms));
    err
}

/// The tenant `name`, from the cache or loaded from `store` and unwrapped with `master`.
/// `origin` becomes the config's only public origin; `github_client_id` is the hosted
/// service's GitHub App, the only one a `github-user` mount may name. `now_ms` is Unix
/// milliseconds.
///
/// Pass a store built for this request (`D1Store::new`), so the version read and the row read
/// share one D1 session.
///
/// # Errors
/// See [`LoadError`].
pub async fn load(
    store: &impl TenantStore,
    master: &MasterUnwrap,
    name: &TenantName,
    origin: String,
    github_client_id: &str,
    now_ms: u64,
) -> Result<Loaded, LoadError> {
    let key = name.as_str();
    let previous = match lookup(key, now_ms) {
        Cached::Fresh(loaded) => return Ok(loaded),
        Cached::Negative(err) => return Err(err),
        Cached::Revalidate(previous) => previous,
    };

    let Some(version) = store.tenant_version(key).await.map_err(|e| backend(&e))? else {
        return Err(negative(key, LoadError::Unknown, now_ms));
    };
    if version.status == TenantStatus::Suspended {
        return Err(negative(key, LoadError::Suspended, now_ms));
    }
    if let Some(p) = &previous
        && p.tenant_id == version.id
    {
        let unchanged =
            p.config_version == version.config_version && p.wrap_key == version.wrap_key;
        // An older version than this isolate already served: a lagging replica or a rollback.
        let older = version.config_version < p.config_version;
        if older {
            log_internal(ROLLBACK);
        }
        if (unchanged || older)
            && let Some(loaded) = touch(key, now_ms)
        {
            return Ok(loaded);
        }
    }

    let Some(row) = store.tenant_by_name(key).await.map_err(|e| backend(&e))? else {
        return Err(negative(key, LoadError::Unknown, now_ms));
    };
    if row.status == TenantStatus::Suspended {
        return Err(negative(key, LoadError::Suspended, now_ms));
    }
    // A config edit keeps the root: same tenant, root id and wrap key.
    let reuse = previous.and_then(|p| {
        (p.tenant_id == row.id && p.wrap_key == row.wrap_key && p.root_id == row.root_id)
            .then_some(p.root)
    });
    match build(key, &row, reuse, master, origin, github_client_id).await {
        Ok((root, state)) => Ok(CACHE.with(|c| {
            c.borrow_mut().insert(
                key.to_owned(),
                Entry {
                    tenant_id: row.id.clone(),
                    config_version: row.config_version,
                    wrap_key: row.wrap_key.clone(),
                    root_id: row.root_id.clone(),
                    root,
                    state: Rc::new(state),
                    checked_ms: now_ms,
                    failing_since: None,
                    used: 0,
                },
            )
        })),
        Err(err) => {
            if let LoadError::Invalid(label) | LoadError::Backend(label) = err {
                log_internal(label);
            }
            keep_previous(key, &row.id, now_ms).ok_or(err)
        }
    }
}

/// Marks the cached entry checked at `now_ms` and returns it; `None` if a concurrent request
/// dropped it while this one awaited the store.
fn touch(name: &str, now_ms: u64) -> Option<Loaded> {
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        let e = c.entries.get_mut(name)?;
        e.checked_ms = now_ms;
        e.failing_since = None;
        Some(e.loaded())
    })
}

/// After a changed row of tenant `row_id` failed to load: the previous entry, if it is the
/// same tenant and hasn't been covering for a failing row for a full [`REVALIDATE_MS`]
/// already. Otherwise drops it: a broken row under another id (a name deleted and re-created,
/// or two names swapped) never keeps serving the old tenant.
fn keep_previous(name: &str, row_id: &str, now_ms: u64) -> Option<Loaded> {
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        let e = c.entries.get_mut(name)?;
        if e.tenant_id != row_id {
            c.entries.remove(name);
            return None;
        }
        let since = *e.failing_since.get_or_insert(now_ms);
        if now_ms.saturating_sub(since) >= REVALIDATE_MS {
            c.entries.remove(name);
            return None;
        }
        e.checked_ms = now_ms;
        Some(e.loaded())
    })
}

/// The service's apex from a tenant's origin: its host without the leading `<name>.` label
/// (`https://acme.edgekms.dev` gives `edgekms.dev`, `http://alice.localhost:8787` gives
/// `localhost`), or the whole host if the origin template put the name elsewhere.
fn apex_of(origin: &str, name: &str) -> String {
    let host = worker::Url::parse(origin)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    host.strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('.'))
        .map_or_else(|| host.clone(), str::to_owned)
}

fn backend(e: &crate::store::StoreError) -> LoadError {
    match e {
        crate::store::StoreError::Backend(label) => LoadError::Backend(label),
        _ => LoadError::Backend("tenant_store"),
    }
}

/// The checks of a load, in order: root id, unwrap (unless `reuse` holds the handle), config
/// MAC (bound to the requested `name`), config parse, hosted rules, pinned JWKS.
async fn build(
    name: &str,
    row: &TenantRow,
    reuse: Option<CryptoKey>,
    master: &MasterUnwrap,
    origin: String,
    github_client_id: &str,
) -> Result<(CryptoKey, State), LoadError> {
    let root_id = Id::new(&row.root_id).map_err(|_| LoadError::Invalid(ROOT_ID_INVALID))?;
    let root = match reuse {
        Some(root) => root,
        None => master
            .unwrap_root(&row.wrap_key, &row.wrapped_root, &row.id, &root_id)
            .await
            .map_err(|_| LoadError::Invalid(UNWRAP_FAILED))?,
    };
    let ops = WebCryptoKeyOps::from_hkdf_key(root.clone(), root_id.clone())
        .map_err(|_| LoadError::Backend("webcrypto"))?;
    let verified = ops
        .verify_mac(
            MacPurpose::Config,
            &config_mac_input(&row.id, name, row.config_version, &row.config),
            &row.config_mac,
        )
        .await
        .map_err(|_| LoadError::Backend("webcrypto"))?;
    if !verified {
        return Err(LoadError::Invalid(MAC_BAD));
    }
    let mut config =
        Config::from_json(&row.config).map_err(|_| LoadError::Invalid(CONFIG_INVALID))?;
    validate_hosted(
        &config,
        &HostedRules {
            root_id: &root_id,
            github_client_id,
            apex: &apex_of(&origin, name),
        },
    )
    .map_err(|_| LoadError::Invalid(CONFIG_INVALID))?;
    config.public_origins = vec![origin];
    let state = State::new(config, ops).map_err(|_| LoadError::Invalid(CONFIG_INVALID))?;
    Ok((root, state))
}
