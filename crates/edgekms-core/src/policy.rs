//! Capability checks against the config. A policy name the config does not define grants
//! nothing, so retiring a policy never breaks the check of a token that still names it.

use crate::config::{AdminCapability, Capability, Config};

/// True when any named policy grants `cap` on `key`.
#[must_use]
pub fn allows(config: &Config, policies: &[String], key: &str, cap: Capability) -> bool {
    policies
        .iter()
        .filter_map(|name| config.policies.get(name))
        .any(|policy| policy.keys.get(key).is_some_and(|caps| caps.contains(&cap)))
}

/// True when any named policy grants the admin capability `cap`.
#[must_use]
pub fn allows_admin(config: &Config, policies: &[String], cap: AdminCapability) -> bool {
    policies
        .iter()
        .filter_map(|name| config.policies.get(name))
        .any(|policy| policy.admin.contains(&cap))
}
