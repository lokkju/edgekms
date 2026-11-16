//! Matching verified JWT claims against a configured role.

use crate::config::Role;
use crate::jwt::{self, Claims};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoleError {
    #[error("audience does not match the role")]
    AudienceMismatch,
    #[error("claim {0:?} does not match the role")]
    ClaimMismatch(String),
    #[error("token was issued before the role's not_before")]
    IssuedBeforeNotBefore,
}

fn audience_matches(aud: Option<&Value>, bound: &[String]) -> bool {
    match aud {
        Some(Value::String(a)) => bound.contains(a),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .any(|a| bound.iter().any(|b| b == a)),
        _ => false,
    }
}

/// Checks that `claims` (already signature-verified) satisfy `role`.
///
/// # Errors
/// Returns the first failing check: audience, each bound claim (in name order), then `iat`
/// against the role's `not_before`.
pub fn check_jwt_role(role: &Role, claims: &Claims) -> Result<(), RoleError> {
    if !audience_matches(claims.get("aud"), &role.bound_audiences) {
        return Err(RoleError::AudienceMismatch);
    }
    for (name, want) in &role.bound_claims {
        match claims.get(name) {
            Some(Value::String(got)) if want.matches(got) => {}
            _ => return Err(RoleError::ClaimMismatch(name.clone())),
        }
    }
    if role.not_before > 0 {
        // iat is read as exp and nbf are: fractions floor; negative, huge or absent fails closed.
        let ok = claims
            .get("iat")
            .and_then(jwt::numeric_date)
            .is_some_and(|i| i >= role.not_before);
        if !ok {
            return Err(RoleError::IssuedBeforeNotBefore);
        }
    }
    Ok(())
}
