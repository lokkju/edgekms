//! Request authentication: the bearer token, its MAC and expiry, the role's `not_before`, and
//! for long-lived tokens the KV revocation list. Every failure is `403 permission denied` with no
//! reason; the reason, when it is a server fault, goes to the internal log as a fixed label, and
//! the caller (`Deps::authenticate`) puts it in the audit event.

use edgekms_core::keyops::{KeyOps, MacPurpose};
use edgekms_core::token::{self, TokenClaims};
use edgekms_core::transit::{Ciphertext, Error, Id};
use worker::kv::KvStore;
use zeroize::Zeroizing;

use crate::handlers::ApiRequest;
use crate::state::State;
use crate::vault::log_internal;

/// Longest token header accepted. Real tokens are a few hundred bytes; anything past this is
/// refused before any MAC work.
pub const MAX_TOKEN_LEN: usize = 4096;

/// KV key prefix for revoked token ids.
const REVOKED_PREFIX: &str = "revoked:";

/// An authenticated caller.
#[derive(Debug, Clone)]
pub struct Caller {
    pub claims: TokenClaims,
}

/// Why authentication failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFailure {
    /// A fixed reason label for the audit event.
    pub label: &'static str,
    /// `(jti, role)` when the token's MAC and expiry checked out, so the claims are ours and
    /// safe to record, but the token was refused anyway (revoked, role gone or `not_before`).
    pub token: Option<(String, String)>,
}

impl AuthFailure {
    fn bare(label: &'static str) -> Self {
        Self { label, token: None }
    }

    fn of(label: &'static str, claims: &TokenClaims) -> Self {
        Self {
            label,
            token: Some((claims.jti.clone(), claims.role.clone())),
        }
    }
}

/// The revocation list for long-lived tokens.
#[allow(async_fn_in_trait)]
pub trait Revocations {
    /// # Errors
    /// If the store can't be read; the caller treats that as a refusal.
    async fn is_revoked(&self, jti: &str) -> worker::Result<bool>;

    /// Records `jti` as revoked for `ttl_secs`.
    ///
    /// # Errors
    /// If the store can't be written.
    async fn revoke(&self, jti: &str, ttl_secs: u64) -> worker::Result<()>;
}

/// The key-value store under the revocation list: Workers KV in production, a map in tests.
#[allow(async_fn_in_trait)]
pub trait RevocationStore {
    /// Whether `key` exists.
    ///
    /// # Errors
    /// If the store can't be read.
    async fn exists(&self, key: &str) -> worker::Result<bool>;

    /// Writes `key` so that it exists for `ttl_secs`.
    ///
    /// # Errors
    /// If the store can't be written.
    async fn put(&self, key: &str, ttl_secs: u64) -> worker::Result<()>;
}

impl RevocationStore for KvStore {
    async fn exists(&self, key: &str) -> worker::Result<bool> {
        Ok(self.get(key).text().await?.is_some())
    }

    async fn put(&self, key: &str, ttl_secs: u64) -> worker::Result<()> {
        KvStore::put(self, key, "1")?
            .expiration_ttl(ttl_secs)
            .execute()
            .await?;
        Ok(())
    }
}

impl<S: RevocationStore + ?Sized> RevocationStore for &S {
    async fn exists(&self, key: &str) -> worker::Result<bool> {
        (**self).exists(key).await
    }

    async fn put(&self, key: &str, ttl_secs: u64) -> worker::Result<()> {
        (**self).put(key, ttl_secs).await
    }
}

/// [`Revocations`] in Workers KV: `<prefix><jti>` exists while the token is revoked. The prefix
/// is `revoked:` for a single-tenant deployment and `revoked:<tenant id>:` for a hosted tenant,
/// so one tenant's revocation (or a revocation naming another tenant's token id) never touches
/// another tenant's tokens.
pub struct KvRevocations<S = KvStore> {
    pub kv: S,
    pub prefix: String,
}

impl<S> KvRevocations<S> {
    /// The single-tenant list: `revoked:<jti>`, as every deployment before the hosted tier.
    pub fn single_tenant(kv: S) -> Self {
        Self {
            kv,
            prefix: REVOKED_PREFIX.to_owned(),
        }
    }

    /// The hosted tenant `tenant_id`'s list: `revoked:<tenant id>:<jti>`.
    pub fn for_tenant(kv: S, tenant_id: &str) -> Self {
        Self {
            kv,
            prefix: format!("{REVOKED_PREFIX}{tenant_id}:"),
        }
    }

    /// The KV key that marks `jti` revoked.
    #[must_use]
    pub fn key(&self, jti: &str) -> String {
        format!("{}{jti}", self.prefix)
    }
}

impl<S: RevocationStore> Revocations for KvRevocations<S> {
    async fn is_revoked(&self, jti: &str) -> worker::Result<bool> {
        self.kv.exists(&self.key(jti)).await
    }

    async fn revoke(&self, jti: &str, ttl_secs: u64) -> worker::Result<()> {
        self.kv.put(&self.key(jti), ttl_secs).await
    }
}

/// The token from `X-Vault-Token`, else from `Authorization: Bearer`.
fn presented_token(req: &ApiRequest) -> Option<&str> {
    if let Some(t) = req.vault_token.as_deref() {
        return Some(t.trim());
    }
    let auth = req.authorization.as_deref()?.trim_start();
    let (scheme, rest) = auth.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(rest.trim())
}

/// Authenticates `req`.
///
/// # Errors
/// An [`AuthFailure`] (which the caller turns into `403 permission denied`) for a missing,
/// oversized, malformed, forged, expired or revoked token, a token whose role no longer exists
/// or was issued before the role's `not_before`, or a revocation list that can't be read.
pub async fn authenticate<K: KeyOps>(
    req: &ApiRequest,
    st: &State<K>,
    revoked: &impl Revocations,
    now: u64,
) -> Result<Caller, AuthFailure> {
    let Some(presented) = presented_token(req) else {
        return Err(AuthFailure::bare("missing_token"));
    };
    if presented.is_empty() || presented.len() > MAX_TOKEN_LEN {
        return Err(AuthFailure::bare("invalid_token"));
    }
    let claims = token::check(&Logged(&st.ops), presented, now)
        .await
        .map_err(|_| AuthFailure::bare("invalid_token"))?;
    let Some(role) = st.config.roles.get(&claims.role) else {
        return Err(AuthFailure::of("token_role_gone", &claims));
    };
    if claims.iat < role.not_before {
        return Err(AuthFailure::of("token_not_before", &claims));
    }
    if claims.long {
        match revoked.is_revoked(&claims.jti).await {
            Ok(false) => {}
            Ok(true) => return Err(AuthFailure::of("token_revoked", &claims)),
            Err(_) => {
                log_internal("revocation list lookup failed");
                return Err(AuthFailure::of("revocation_list_unavailable", &claims));
            }
        }
    }
    Ok(Caller { claims })
}

/// A [`KeyOps`] that logs the static label of every backend failure before passing the result
/// on. Callers that collapse errors into one client-facing answer (token checks, SSH challenges)
/// still leave a trace that the key backend, not the client, was at fault.
pub struct Logged<'a, K>(pub &'a K);

fn note<T>(r: Result<T, Error>) -> Result<T, Error> {
    if let Err(Error::Backend(label)) = &r {
        log_internal(label);
    }
    r
}

impl<K: KeyOps> KeyOps for Logged<'_, K> {
    async fn encrypt(&self, key_id: &Id, version: u32, plaintext: &[u8]) -> Result<String, Error> {
        note(self.0.encrypt(key_id, version, plaintext).await)
    }

    async fn decrypt(&self, key_id: &Id, ct: &Ciphertext) -> Result<Zeroizing<Vec<u8>>, Error> {
        note(self.0.decrypt(key_id, ct).await)
    }

    async fn mac(&self, purpose: MacPurpose, data: &[u8]) -> Result<[u8; 32], Error> {
        note(self.0.mac(purpose, data).await)
    }

    async fn verify_mac(
        &self,
        purpose: MacPurpose,
        data: &[u8],
        tag: &[u8],
    ) -> Result<bool, Error> {
        note(self.0.verify_mac(purpose, data, tag).await)
    }

    fn random(&self, out: &mut [u8]) {
        self.0.random(out);
    }
}
