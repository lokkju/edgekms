//! `auth/token/lookup-self`, `renew-self`, `create` and `revoke-accessor`.

use std::collections::BTreeMap;

use edgekms_core::config::AdminCapability;
use edgekms_core::keyops::KeyOps;
use edgekms_core::policy;
use serde_json::{Map, Value, json};

use super::{ApiRequest, Deps, issue, json_body};
use crate::audit::{AuditSink, RateLimit, civil_from_days};
use crate::auth::{Caller, Revocations};
use crate::jwks::JwksSource;
use crate::vault::{Reply, log_internal};

const MIN_TTL_SECS: u64 = 60;
/// 400 days: the longest token TTL, and how long a revocation entry is kept.
pub const MAX_TTL_SECS: u64 = 34_560_000;
const MAX_DISPLAY_NAME: usize = 128;
/// Vault token options whose meaning edgekms can't honour; ignoring them would hand out a token
/// unlike the one asked for.
const UNSUPPORTED: [&str; 4] = ["period", "num_uses", "renewable", "explicit_max_ttl"];

fn unwrap(r: Result<Reply, Reply>) -> Reply {
    match r {
        Ok(r) | Err(r) => r,
    }
}

/// `GET auth/token/lookup-self`. The token itself is never echoed back.
pub(super) async fn lookup_self<
    K: KeyOps,
    R: Revocations,
    J: JwksSource,
    A: AuditSink,
    L: RateLimit,
>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
) -> Reply {
    let Caller { claims } = match deps.authenticate(req).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    Reply::data(json!({
        "id": "<redacted>",
        "accessor": claims.jti,
        "policies": claims.policies,
        "ttl": claims.exp.saturating_sub(deps.now),
        "expire_time": rfc3339(claims.exp),
        "renewable": false,
        "meta": claims.meta,
    }))
}

/// `auth/token/renew-self`: stateless tokens can't be extended, so this always fails (after
/// authenticating, so an anonymous caller still sees 403). OpenBao's transit seal logs the
/// failure and carries on.
pub(super) async fn renew_self<
    K: KeyOps,
    R: Revocations,
    J: JwksSource,
    A: AuditSink,
    L: RateLimit,
>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
) -> Reply {
    match deps.authenticate(req).await {
        Ok(_) => Reply::error(400, "token is not renewable"),
        Err(r) => r,
    }
}

async fn admin<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
    cap: AdminCapability,
) -> Result<Caller, Reply> {
    let caller = deps.authenticate(req).await?;
    if policy::allows_admin(&deps.state.config, &caller.claims.policies, cap) {
        Ok(caller)
    } else {
        Err(Reply::denied())
    }
}

/// `auth/token/create`: an admin mints a token whose policies are a subset of its own, each
/// defined in config and granting key capabilities only, never admin. The new token is always
/// revocable by accessor, and is recorded under the caller's role, so raising that role's
/// `not_before` invalidates it too.
pub(super) async fn create<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
) -> Reply {
    unwrap(create_inner(deps, req).await)
}

async fn create_inner<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
) -> Result<Reply, Reply> {
    let caller = admin(deps, req, AdminCapability::TokenCreate).await?;
    let body = json_body(&req.body)?;
    if let Some(field) = UNSUPPORTED.iter().find(|f| body.contains_key(**f)) {
        return Err(Reply::error(
            400,
            &format!("{field} is not supported by edgekms"),
        ));
    }
    let policies = requested_policies(&body, deps, &caller)?;
    let ttl = match body.get("ttl") {
        None => return Err(Reply::error(400, "missing ttl")),
        Some(v) => ttl_secs(v).ok_or_else(|| {
            Reply::error(
                400,
                "ttl must be a duration (e.g. 8760h, 30m, 45s) or seconds, from 60s to 9600h",
            )
        })?,
    };
    let mut meta = BTreeMap::new();
    match body.get("display_name") {
        None | Some(Value::Null) => {}
        Some(Value::String(name))
            if name.len() <= MAX_DISPLAY_NAME && !name.chars().any(char::is_control) =>
        {
            meta.insert("display_name".to_owned(), name.clone());
        }
        Some(_) => {
            return Err(Reply::error(
                400,
                "display_name must be at most 128 printable characters",
            ));
        }
    }
    meta.insert("created_by".to_owned(), caller.claims.jti.clone());
    // Always long: revoke-accessor must be able to stop any created token.
    let (reply, jti) = issue(deps, &caller.claims.role, policies, ttl, true, meta).await?;
    deps.event().target_jti = Some(jti);
    Ok(reply)
}

fn requested_policies<K, R, J, A, L>(
    body: &Map<String, Value>,
    deps: &Deps<'_, K, R, J, A, L>,
    caller: &Caller,
) -> Result<Vec<String>, Reply> {
    let refuse = || {
        Reply::error(
            400,
            "policies must be a non-empty list of policies defined in config and held by the caller",
        )
    };
    let Some(Value::Array(items)) = body.get("policies") else {
        return Err(refuse());
    };
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(name) = item else {
            return Err(refuse());
        };
        let Some(policy) = deps.state.config.policies.get(name) else {
            return Err(refuse());
        };
        if !caller.claims.policies.contains(name) {
            return Err(refuse());
        }
        // A created token can be long-lived; granting admin through one would let a stolen
        // short operator token mint itself a persistent admin token.
        if !policy.admin.is_empty() {
            return Err(Reply::error(
                400,
                "token create may only grant key policies",
            ));
        }
        if !out.contains(name) {
            out.push(name.clone());
        }
    }
    if out.is_empty() {
        return Err(refuse());
    }
    Ok(out)
}

/// A TTL as integer seconds, a string of digits, a whole number of days (`365d`), or a
/// duration of `h`, `m` and `s` parts (`8760h`, `1h30m`, `45s`), within `60..=34_560_000`
/// seconds. That is Vault's `ParseDurationSecond`, restricted to integer parts.
fn ttl_secs(v: &Value) -> Option<u64> {
    let secs = match v {
        Value::Number(n) => n.as_u64()?,
        Value::String(s) => parse_duration(s)?,
        _ => return None,
    };
    (MIN_TTL_SECS..=MAX_TTL_SECS)
        .contains(&secs)
        .then_some(secs)
}

fn parse_duration(s: &str) -> Option<u64> {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse().ok();
    }
    // Vault takes `d` only as the sole unit, after an integer; anything else goes to Go's
    // `time.ParseDuration`, which has no `d`.
    if let Some(days) = s.strip_suffix('d') {
        if days.is_empty() || !days.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        return days.parse::<u64>().ok()?.checked_mul(86_400);
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut parts = 0;
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = match c {
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => return None,
        };
        if digits.is_empty() {
            return None;
        }
        let n: u64 = digits.parse().ok()?;
        total = total.checked_add(n.checked_mul(unit)?)?;
        digits.clear();
        parts += 1;
    }
    (parts > 0 && digits.is_empty()).then_some(total)
}

/// `auth/token/revoke-accessor`: records the token id as revoked for the longest token TTL, so
/// the entry outlives any token it could name. Only long tokens consult the list; every created
/// token is long, login tokens only when their role's TTL is over a day.
pub(super) async fn revoke_accessor<
    K: KeyOps,
    R: Revocations,
    J: JwksSource,
    A: AuditSink,
    L: RateLimit,
>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
) -> Reply {
    unwrap(revoke_inner(deps, req).await)
}

async fn revoke_inner<K: KeyOps, R: Revocations, J: JwksSource, A: AuditSink, L: RateLimit>(
    deps: &Deps<'_, K, R, J, A, L>,
    req: &ApiRequest,
) -> Result<Reply, Reply> {
    admin(deps, req, AdminCapability::TokenRevoke).await?;
    let body = json_body(&req.body)?;
    let Some(Value::String(accessor)) = body.get("accessor") else {
        return Err(Reply::error(400, "missing accessor"));
    };
    // Token ids are 16 random bytes in base64url: 22 characters.
    let well_formed = accessor.len() == 22
        && accessor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !well_formed {
        return Err(Reply::error(400, "invalid accessor"));
    }
    deps.event().target_jti = Some(accessor.clone());
    // The revocation is written before the audit event, and it stands even if that event then
    // fails to write and the caller gets `500 audit log unavailable`. That is the safe
    // direction, since the token stops working whether or not the log records it, and the
    // failed write still shows up as an `audit_unavailable` data point.
    deps.revocations
        .revoke(accessor, MAX_TTL_SECS)
        .await
        .map_err(|_| {
            log_internal("revocation list write failed");
            Reply::internal()
        })?;
    Ok(Reply::no_content())
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
fn rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(2_000_000_000), "2033-05-18T03:33:20Z");
        assert_eq!(rfc3339(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("8760h"), Some(31_536_000));
        assert_eq!(parse_duration("1h1m1s"), Some(3661));
        assert_eq!(parse_duration("90"), Some(90));
        assert_eq!(parse_duration("1d"), Some(86_400));
        assert_eq!(parse_duration("365d"), Some(31_536_000));
        // Go's ParseDuration sums repeated units, so OpenBao takes this too.
        assert_eq!(parse_duration("1h1h"), Some(7200));
        for bad in [
            "",
            "h",
            "1x",
            "1h2",
            "-1h",
            "1.5h",
            "1 h",
            "99999999999999999999h",
            // `d` only as a lone suffix on an integer, as in Vault's ParseDurationSecond.
            "1d1h",
            "1h1d",
            "1d1d",
            "d",
            "1.5d",
            "99999999999999999999d",
            "999999999999999d",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
    }
}
