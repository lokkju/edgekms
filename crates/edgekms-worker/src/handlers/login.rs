//! `auth/:mount/login` for JWT, SSH and GitHub user mounts, and `auth/:mount/challenge` for
//! SSH mounts.
//!
//! Every credential failure, whatever its cause, is the same `400 permission denied`, so the
//! response never tells a caller which check failed (wrong role, wrong key, expired challenge).
//! The cause goes to the internal log and the audit event as a stable code
//! (`jwt_expired`, `ssh_bad_signature`). A JWT that passes every check but carries a copied
//! claim too long for a token is refused with a `400` naming the claim.

use std::collections::BTreeMap;

use edgekms_core::config::{Mount, Role};
use edgekms_core::jwt::{self, Claims, JwtError};
use edgekms_core::keyops::KeyOps;
use edgekms_core::role::check_jwt_role;
use edgekms_core::ssh;
use serde_json::{Map, Value, json};

use super::{ApiRequest, Deps, LONG_TOKEN_SECS, issue, json_body};
use crate::audit::{AuditSink, RateLimit, allowed_meta};
use crate::auth::{Logged, Revocations};
use crate::github::{GithubError, plausible_token};
use crate::jwks::JwksSource;
use crate::vault::{Reply, log_internal};
use crate::webjws::WebJws;

/// JWT claims copied into the token's `meta` for audit, when present as strings.
const META_CLAIMS: [&str; 5] = ["sub", "repository", "ref", "workflow", "job_workflow_ref"];

/// The longest a copied claim may be, in bytes once JSON-escaped as the token holds it. All
/// five at this length still leave a token under [`MAX_TOKEN_LEN`](crate::auth::MAX_TOKEN_LEN).
/// A longer one refuses the login instead of being truncated, since two identities sharing a
/// prefix would look alike in the audit log.
const MAX_META_CLAIM_BYTES: usize = 256;

/// The one answer to every credential failure; `label` goes to the log and the audit event.
fn login_denied<K, R, J, A, L>(deps: &Deps<'_, K, R, J, A, L>, label: &'static str) -> Reply {
    log_internal(label);
    deps.deny(label);
    Reply::error(400, "permission denied")
}

fn field<'b>(body: &'b Map<String, Value>, name: &'static str) -> Result<&'b str, Reply> {
    match body.get(name) {
        Some(Value::String(s)) => Ok(s),
        _ => Err(Reply::error(400, &format!("missing {name}"))),
    }
}

/// The role named in the body, if it exists and belongs to `mount`. Only then does its name go
/// in the audit event.
fn find_role<'c, K, R, J, A, L>(
    deps: &Deps<'c, K, R, J, A, L>,
    name: &str,
    mount: &str,
) -> Option<&'c Role> {
    let role = deps
        .state
        .config
        .roles
        .get(name)
        .filter(|r| r.mount == mount)?;
    deps.event().role = Some(name.to_owned());
    Some(role)
}

/// Mints the login's token and records its id and allowlisted metadata in the audit event.
async fn issue_login<K: KeyOps, R, J, A, L>(
    deps: &Deps<'_, K, R, J, A, L>,
    role_name: &str,
    role: &Role,
    meta: BTreeMap<String, String>,
) -> Result<Reply, Reply> {
    let audit_meta = allowed_meta(&meta);
    let (reply, jti) = issue(
        deps,
        role_name,
        role.policies.clone(),
        role.token_ttl_secs,
        role.token_ttl_secs > LONG_TOKEN_SECS,
        meta,
    )
    .await?;
    let mut ev = deps.event();
    ev.jti = Some(jti);
    ev.meta = audit_meta;
    Ok(reply)
}

pub(super) async fn login<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
    mount_name: &str,
) -> Reply {
    let Some(mount) = deps.state.config.mounts.get(mount_name) else {
        // OpenBao, no token: login to a non-existent auth mount is
        // `403 {"errors":["permission denied"]}`. The metric still says `not_found`.
        deps.event().result = "error";
        deps.event().error = Some("not_found");
        return Reply::denied();
    };
    let result = match json_body(&req.body) {
        Err(r) => Err(r),
        Ok(body) => match mount {
            Mount::Jwt {
                issuer, jwks_url, ..
            } => jwt_login(deps, &body, mount_name, issuer, jwks_url.as_deref()).await,
            Mount::Ssh {} => ssh_login(deps, &body, mount_name, req).await,
            Mount::GithubUser { client_id } => {
                github_login(deps, &body, mount_name, client_id).await
            }
        },
    };
    match result {
        Ok(r) | Err(r) => r,
    }
}

async fn jwt_login<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    body: &Map<String, Value>,
    mount_name: &str,
    issuer: &str,
    jwks_url: Option<&str>,
) -> Result<Reply, Reply> {
    let role_name = field(body, "role")?;
    let token = field(body, "jwt")?;
    // The signature is verified whether or not the role exists on this mount, so the time a
    // refusal takes doesn't say which role names do.
    let role = find_role(deps, role_name, mount_name);
    let claims = verify_jwt(deps, mount_name, issuer, jwks_url, token).await?;
    let role = role.ok_or_else(|| login_denied(deps, "login_role_not_found"))?;
    check_jwt_role(role, &claims).map_err(|_| login_denied(deps, "jwt_claims_mismatch"))?;
    // The token is verified and its role matched, so naming the claim tells the caller nothing
    // about the deployment.
    let meta = jwt_meta(&claims).map_err(|claim| {
        log_internal("jwt_claim_too_long");
        deps.deny("jwt_claim_too_long");
        Reply::error(
            400,
            &format!("jwt claim {claim} is longer than {MAX_META_CLAIM_BYTES} bytes"),
        )
    })?;
    issue_login(deps, role_name, role, meta).await
}

/// The [`META_CLAIMS`] present as strings, or the name of the first one over
/// [`MAX_META_CLAIM_BYTES`].
fn jwt_meta(claims: &Claims) -> Result<BTreeMap<String, String>, &'static str> {
    let mut meta = BTreeMap::new();
    for claim in META_CLAIMS {
        if let Some(Value::String(v)) = claims.get(claim) {
            // Serializing a string can't fail; the two quotes aren't part of the value.
            let escaped = serde_json::to_string(v).map_or(usize::MAX, |s| s.len() - 2);
            if escaped > MAX_META_CLAIM_BYTES {
                return Err(claim);
            }
            meta.insert(claim.to_owned(), v.clone());
        }
    }
    Ok(meta)
}

/// Verifies against the pinned JWKS, or the fetched one with a single forced refetch when the
/// token names a `kid` the cached set lacks (the issuer may have rotated).
async fn verify_jwt<K, R, J: JwksSource, A, L>(
    deps: &Deps<'_, K, R, J, A, L>,
    mount_name: &str,
    issuer: &str,
    jwks_url: Option<&str>,
    token: &str,
) -> Result<Claims, Reply> {
    let now = deps.now;
    let result = if let Some(pinned) = deps.state.pinned_jwks.get(mount_name) {
        jwt::verify(token, pinned, &WebJws, issuer, now).await
    } else {
        let Some(url) = jwks_url else {
            // Config validation requires exactly one of jwks or jwks_url.
            log_internal("jwt_mount_without_keys");
            deps.fail("jwt_mount_without_keys");
            return Err(Reply::internal());
        };
        let fetched = fetch_jwks(deps, mount_name, url, false).await?;
        match jwt::verify(token, &fetched, &WebJws, issuer, now).await {
            Err(JwtError::UnknownKid(_)) => {
                let refreshed = fetch_jwks(deps, mount_name, url, true).await?;
                jwt::verify(token, &refreshed, &WebJws, issuer, now).await
            }
            other => other,
        }
    };
    result.map_err(|e| login_denied(deps, jwt_label(&e)))
}

async fn fetch_jwks<K, R, J: JwksSource, A, L>(
    deps: &Deps<'_, K, R, J, A, L>,
    mount: &str,
    url: &str,
    force: bool,
) -> Result<jwt::Jwks, Reply> {
    deps.jwks.jwks(mount, url, force).await.map_err(|_| {
        log_internal("jwks_unavailable");
        deps.fail("jwks_unavailable");
        Reply::internal()
    })
}

fn jwt_label(e: &JwtError) -> &'static str {
    match e {
        JwtError::Malformed => "jwt_malformed",
        JwtError::UnsupportedAlg(_) => "jwt_unsupported_alg",
        JwtError::MissingKid => "jwt_missing_kid",
        JwtError::UnknownKid(_) => "jwt_unknown_kid",
        JwtError::KeyMismatch => "jwt_key_mismatch",
        JwtError::BadSignature => "jwt_bad_signature",
        JwtError::WrongIssuer => "jwt_wrong_issuer",
        JwtError::Expired => "jwt_expired",
        JwtError::NotYetValid => "jwt_not_yet_valid",
        JwtError::MissingExp => "jwt_missing_exp",
    }
}

async fn ssh_login<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    body: &Map<String, Value>,
    mount_name: &str,
    req: &ApiRequest,
) -> Result<Reply, Reply> {
    let role_name = field(body, "role")?;
    let challenge = field(body, "challenge")?;
    let signature = field(body, "signature")?;
    // As in `jwt_login`, the challenge and the signature are checked whether or not the role
    // is on this mount, so the time a refusal takes doesn't say which role names are. Without
    // a role there are no keys to match, so a well-formed signature ends at `KeyNotAllowed`,
    // which is then the role's refusal; one that is malformed is the signature's.
    let role = find_role(deps, role_name, mount_name);
    // The signature is checked over the very string whose MAC and age were just checked.
    let origins = accepted_origins(deps, req);
    ssh::check_challenge(&Logged(&deps.state.ops), challenge, deps.now, &origins)
        .await
        .map_err(|e| login_denied(deps, ssh_label(&e)))?;
    let keys = role.map_or(&[][..], |r| r.ssh_keys.as_slice());
    let verified = ssh::verify(keys, challenge, signature);
    let (role, fingerprint) = match (role, verified) {
        (Some(role), Ok(fingerprint)) => (role, fingerprint),
        (None, Ok(_) | Err(ssh::SshError::KeyNotAllowed)) => {
            return Err(login_denied(deps, "login_role_not_found"));
        }
        (_, Err(e)) => return Err(login_denied(deps, ssh_label(&e))),
    };
    let meta = BTreeMap::from([("ssh_fingerprint".to_owned(), fingerprint)]);
    issue_login(deps, role_name, role, meta).await
}

pub(crate) fn ssh_label(e: &ssh::SshError) -> &'static str {
    use ssh::SshError as E;
    match e {
        E::MalformedChallenge => "ssh_challenge_malformed",
        E::WrongOrigin => "ssh_challenge_wrong_origin",
        E::WrongAccount => "ssh_challenge_wrong_account",
        E::BadAccount => "ssh_challenge_bad_account",
        E::BadOrigin | E::Backend => "ssh_challenge_check_failed",
        E::BadChallengeMac => "ssh_challenge_mac",
        E::ChallengeExpired => "ssh_challenge_expired",
        E::ChallengeFromFuture => "ssh_challenge_from_future",
        E::MalformedSignature => "ssh_signature_malformed",
        E::WrongNamespace => "ssh_wrong_namespace",
        E::KeyNotAllowed => "ssh_key_not_allowed",
        E::UnsupportedKeyType => "ssh_unsupported_key_type",
        E::BadSignature => "ssh_bad_signature",
        E::UserNotPresent => "ssh_user_not_present",
    }
}

/// A GitHub user token from the device flow: GitHub must confirm it belongs to the mount's
/// OAuth App, and the user it names must be one the role binds. GitHub being unreachable, or
/// refusing the App's own credentials, is a `500`; everything about the token is the usual
/// `400 permission denied`.
async fn github_login<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    body: &Map<String, Value>,
    mount_name: &str,
    client_id: &str,
) -> Result<Reply, Reply> {
    let role_name = field(body, "role")?;
    let token = field(body, "token")?;
    // As in `jwt_login`, GitHub checks the token whether or not the role is on this mount, so
    // the time a refusal takes doesn't say which role names are. Only the shape check, which
    // costs no GitHub quota, comes first.
    if !plausible_token(token) {
        return Err(login_denied(deps, "github_malformed_token"));
    }
    let role = find_role(deps, role_name, mount_name);
    let user = match deps.github.check_token(client_id, token).await {
        Ok(u) => u,
        Err(GithubError::Denied(label)) => return Err(login_denied(deps, label)),
        Err(GithubError::Unavailable(label)) => {
            log_internal(label);
            return Err(Reply::internal());
        }
    };
    // The token is GitHub-valid and has reached this deployment: burn it, so it is single-use
    // here and can't be relayed to another deployment that trusts the same App. A failure is
    // logged, not fatal; the login's own checks don't depend on it.
    if let Err(label) = deps.github.revoke_token(client_id, token).await {
        log_internal(label);
    }
    let role = role.ok_or_else(|| login_denied(deps, "login_role_not_found"))?;
    if !role.github_user_ids.contains(&user.id) {
        return Err(login_denied(deps, "github_user_not_bound"));
    }
    let meta = BTreeMap::from([("sub".to_owned(), format!("github-user:{}", user.id))]);
    issue_login(deps, role_name, role, meta).await
}

/// The origins a challenge may name: the configured `public_origins`, or, when there are none,
/// the request URL's origin, which only Cloudflare's routing (custom domain, no other origin)
/// keeps a client from choosing.
fn accepted_origins<'r, K, R, J, A, L>(
    deps: &'r Deps<'_, K, R, J, A, L>,
    req: &'r ApiRequest,
) -> Vec<&'r str> {
    let configured = &deps.state.config.public_origins;
    if configured.is_empty() {
        vec![req.origin.as_str()]
    } else {
        configured.iter().map(String::as_str).collect()
    }
}

/// `auth/:mount/challenge`: a fresh 60-second challenge for an SSH mount, bound to the origin
/// the request was sent to if that origin is accepted, else to the first configured one.
pub(super) async fn challenge<K: KeyOps, R, J, A, L>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
    mount_name: &str,
) -> Reply {
    if !matches!(
        deps.state.config.mounts.get(mount_name),
        Some(Mount::Ssh {})
    ) {
        // OpenBao, no token: login to a non-existent auth mount is
        // `403 {"errors":["permission denied"]}`. The metric still says `not_found`.
        deps.event().result = "error";
        deps.event().error = Some("not_found");
        return Reply::denied();
    }
    let origins = accepted_origins(deps, req);
    let origin = if origins.contains(&req.origin.as_str()) {
        req.origin.as_str()
    } else {
        origins[0]
    };
    match ssh::new_challenge(&Logged(&deps.state.ops), deps.now, origin).await {
        Ok(c) => Reply::data(json!({
            "challenge": c,
            "expires_in": ssh::CHALLENGE_TTL_SECS,
        })),
        Err(ssh::SshError::BadOrigin) => {
            log_internal("ssh challenge: request origin is not an http(s) origin");
            Reply::internal()
        }
        Err(_) => {
            log_internal("ssh challenge: key backend failure");
            Reply::internal()
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use edgekms_core::token::{PREFIX, TokenClaims};

    use super::*;
    use crate::auth::MAX_TOKEN_LEN;

    fn claims(value: &str) -> Claims {
        META_CLAIMS
            .iter()
            .map(|c| ((*c).to_owned(), json!(value)))
            .collect()
    }

    #[test]
    fn meta_claims_are_copied_up_to_the_cap() {
        let at_cap = "a".repeat(MAX_META_CLAIM_BYTES);
        let mut c = claims(&at_cap);
        c.insert("aud".to_owned(), json!("not copied"));
        c.insert("repository_id".to_owned(), json!(42));
        let meta = jwt_meta(&c).unwrap();
        assert_eq!(meta.len(), META_CLAIMS.len());
        assert!(meta.values().all(|v| *v == at_cap));
    }

    #[test]
    fn an_overlong_meta_claim_refuses_the_login() {
        let mut c = claims("short");
        c.insert(
            "workflow".to_owned(),
            json!("a".repeat(MAX_META_CLAIM_BYTES + 1)),
        );
        assert_eq!(jwt_meta(&c), Err("workflow"));
        // Measured as the token holds it: a quote is two bytes once escaped, a control
        // character six.
        let c = claims(&"\"".repeat(MAX_META_CLAIM_BYTES / 2 + 1));
        assert!(jwt_meta(&c).is_err());
        let c = claims(&"\u{1}".repeat(MAX_META_CLAIM_BYTES / 6 + 1));
        assert!(jwt_meta(&c).is_err());
    }

    /// Every copied claim at the cap still leaves a token under the Worker's limit, with room
    /// for a long role name and a list of policies.
    #[test]
    fn meta_at_the_cap_fits_in_a_token() {
        let meta = jwt_meta(&claims(&"a".repeat(MAX_META_CLAIM_BYTES))).unwrap();
        let worst = TokenClaims {
            v: 1,
            jti: "a".repeat(22),
            role: "r".repeat(64),
            policies: vec!["p".repeat(64); 8],
            iat: u64::MAX,
            exp: u64::MAX,
            long: true,
            meta,
        };
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&worst).unwrap());
        let len = PREFIX.len() + payload.len() + 1 + URL_SAFE_NO_PAD.encode([0; 32]).len();
        assert!(len <= MAX_TOKEN_LEN, "{len}");
    }
}
