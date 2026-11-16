//! Instance configuration: keys, auth mounts, roles and policies, parsed from JSON and
//! validated as a whole before anything consumes it.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::Deserialize;

use crate::transit::Id;

const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 34_560_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("config is not valid JSON for the schema: {0}")]
    Json(String),
    #[error("invalid config: {0}")]
    Invalid(String),
}

fn invalid(path: &str, reason: &str) -> ConfigError {
    ConfigError::Invalid(format!("{path}: {reason}"))
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub root_id: Id,
    /// The origins (`https://host[:port]`) this deployment is reached at. SSH challenges are
    /// minted for and accepted from these only. When empty, the Worker uses the request URL's
    /// origin, which only Cloudflare's routing (a custom domain, no other origin) makes
    /// trustworthy; anywhere a client can choose the Host header, set this.
    #[serde(default)]
    pub public_origins: Vec<String>,
    pub keys: BTreeMap<String, KeyConfig>,
    pub mounts: BTreeMap<String, Mount>,
    pub roles: BTreeMap<String, Role>,
    pub policies: BTreeMap<String, Policy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub id: Id,
    pub latest_version: u32,
    pub min_decryption_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Mount {
    Jwt {
        issuer: String,
        #[serde(default)]
        jwks_url: Option<String>,
        #[serde(default)]
        jwks: Option<serde_json::Value>,
    },
    Ssh {},
    /// GitHub user tokens from the OAuth device flow of the OAuth App `client_id`. The Worker
    /// needs that App's client secret as the `GITHUB_CLIENT_SECRET` secret.
    GithubUser {
        client_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub mount: String,
    #[serde(default)]
    pub bound_audiences: Vec<String>,
    #[serde(default)]
    pub bound_claims: BTreeMap<String, ClaimMatch>,
    #[serde(default)]
    pub ssh_keys: Vec<String>,
    /// Numeric GitHub user ids, for a role on a `github-user` mount. Ids, not logins: a login
    /// can be renamed and taken by someone else.
    #[serde(default)]
    pub github_user_ids: Vec<u64>,
    pub policies: Vec<String>,
    pub token_ttl_secs: u64,
    #[serde(default)]
    pub not_before: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "RawClaimMatch")]
pub enum ClaimMatch {
    Exact(String),
    Glob { glob: String },
}

/// Wire form of [`ClaimMatch`]; the named struct is what lets `deny_unknown_fields` apply to the
/// glob object, which an untagged enum struct variant would not enforce.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawClaimMatch {
    Exact(String),
    Glob(RawGlob),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGlob {
    glob: String,
}

impl From<RawClaimMatch> for ClaimMatch {
    fn from(raw: RawClaimMatch) -> Self {
        match raw {
            RawClaimMatch::Exact(s) => Self::Exact(s),
            RawClaimMatch::Glob(RawGlob { glob }) => Self::Glob { glob },
        }
    }
}

impl ClaimMatch {
    /// Exact equality, or a glob in which only `*` is special (any run of characters, including
    /// none).
    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Self::Exact(s) => s == value,
            Self::Glob { glob } => glob_match(glob.as_bytes(), value.as_bytes()),
        }
    }
}

/// Iterative wildcard match, `*` only; O(n*m) worst case, no recursion.
fn glob_match(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub keys: BTreeMap<String, BTreeSet<Capability>>,
    /// Absent means none; an explicit `[]` is refused as a likely mistake.
    #[serde(default, deserialize_with = "non_empty_admin")]
    pub admin: BTreeSet<AdminCapability>,
}

/// Only runs when `admin` is present, so it separates an explicit `[]` from an absent field.
fn non_empty_admin<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BTreeSet<AdminCapability>, D::Error> {
    let set = BTreeSet::deserialize(d)?;
    if set.is_empty() {
        return Err(serde::de::Error::custom(
            "admin capabilities must not be empty; leave admin out instead",
        ));
    }
    Ok(set)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Encrypt,
    Decrypt,
    Rewrap,
    Read,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdminCapability {
    TokenCreate,
    TokenRevoke,
}

impl Config {
    /// # Errors
    /// [`ConfigError::Json`] when `s` does not fit the schema; [`ConfigError::Invalid`], naming
    /// the offending path, when a cross-field rule fails.
    pub fn from_json(s: &str) -> Result<Self, ConfigError> {
        let c: Self = serde_json::from_str(s).map_err(|e| ConfigError::Json(e.to_string()))?;
        c.validate()?;
        Ok(c)
    }

    #[must_use]
    pub fn key(&self, name: &str) -> Option<&KeyConfig> {
        self.keys.get(name)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for (i, origin) in self.public_origins.iter().enumerate() {
            if !crate::ssh::valid_origin(origin) {
                return Err(invalid(
                    &format!("public_origins[{i}]"),
                    "must be an origin, http(s)://host[:port] with no path",
                ));
            }
        }
        self.validate_keys()?;
        self.validate_mounts()?;
        self.validate_roles()?;
        self.validate_policies()
    }

    fn validate_keys(&self) -> Result<(), ConfigError> {
        let mut ids = HashSet::new();
        for (name, key) in &self.keys {
            let path = format!("keys.{name}");
            let name_ok = (1..=128).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
            if !name_ok {
                return Err(invalid(&path, "name must be 1 to 128 of [A-Za-z0-9_-]"));
            }
            if key.min_decryption_version < 1 || key.min_decryption_version > key.latest_version {
                return Err(invalid(
                    &path,
                    "min_decryption_version must be at least 1 and at most latest_version",
                ));
            }
            if !ids.insert(key.id.as_str()) {
                return Err(invalid(&format!("{path}.id"), "duplicate key id"));
            }
        }
        Ok(())
    }

    fn validate_mounts(&self) -> Result<(), ConfigError> {
        let mut github_app: Option<&str> = None;
        for (name, mount) in &self.mounts {
            let path = format!("mounts.{name}");
            if let Mount::GithubUser { client_id } = mount {
                // It goes into a GitHub API path.
                let ok = (1..=64).contains(&client_id.len())
                    && client_id.starts_with(|c: char| c.is_ascii_alphanumeric())
                    && client_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
                if !ok {
                    return Err(invalid(
                        &path,
                        "client_id must be 1 to 64 of [A-Za-z0-9._-], starting with a letter or digit",
                    ));
                }
                // The Worker holds one GITHUB_CLIENT_SECRET, which belongs to one OAuth App.
                if github_app.is_some_and(|a| a != client_id) {
                    return Err(invalid(
                        &path,
                        "every github-user mount must use the same OAuth App client_id",
                    ));
                }
                github_app = Some(client_id);
            }
            let Mount::Jwt {
                issuer,
                jwks_url,
                jwks,
            } = mount
            else {
                continue;
            };
            if !issuer.starts_with("https://") {
                return Err(invalid(&path, "issuer must start with https://"));
            }
            match (jwks_url, jwks) {
                (Some(url), None) if !url.starts_with("https://") => {
                    return Err(invalid(&path, "jwks_url must start with https://"));
                }
                (Some(_), None) | (None, Some(_)) => {}
                _ => return Err(invalid(&path, "set exactly one of jwks_url or jwks")),
            }
        }
        Ok(())
    }

    fn validate_roles(&self) -> Result<(), ConfigError> {
        for (name, role) in &self.roles {
            let path = format!("roles.{name}");
            let Some(mount) = self.mounts.get(&role.mount) else {
                return Err(invalid(
                    &path,
                    &format!("mount {:?} does not exist", role.mount),
                ));
            };
            if role.policies.is_empty() {
                return Err(invalid(&path, "policies must not be empty"));
            }
            if let Some(p) = role
                .policies
                .iter()
                .find(|p| !self.policies.contains_key(*p))
            {
                return Err(invalid(&path, &format!("policy {p:?} does not exist")));
            }
            if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&role.token_ttl_secs) {
                return Err(invalid(
                    &path,
                    "token_ttl_secs must be between 60 and 34560000",
                ));
            }
            match mount {
                Mount::Jwt { .. } => validate_jwt_role(&path, role)?,
                Mount::Ssh {} => validate_ssh_role(&path, role)?,
                Mount::GithubUser { .. } => validate_github_role(&path, role)?,
            }
            if !matches!(mount, Mount::GithubUser { .. }) && !role.github_user_ids.is_empty() {
                return Err(invalid(
                    &path,
                    "only a role on a github-user mount may set github_user_ids",
                ));
            }
        }
        Ok(())
    }

    fn validate_policies(&self) -> Result<(), ConfigError> {
        for (name, policy) in &self.policies {
            if let Some(k) = policy.keys.keys().find(|k| !self.keys.contains_key(*k)) {
                return Err(invalid(
                    &format!("policies.{name}"),
                    &format!("key {k:?} does not exist"),
                ));
            }
            // An empty list grants nothing; it is far more likely a typo than an intent.
            if let Some((k, _)) = policy.keys.iter().find(|(_, caps)| caps.is_empty()) {
                return Err(invalid(
                    &format!("policies.{name}.keys.{k}"),
                    "capabilities must not be empty",
                ));
            }
        }
        Ok(())
    }
}

fn validate_jwt_role(path: &str, role: &Role) -> Result<(), ConfigError> {
    if role.bound_audiences.is_empty() {
        return Err(invalid(path, "a JWT role needs bound_audiences"));
    }
    if role.bound_claims.is_empty() {
        return Err(invalid(path, "a JWT role needs bound_claims"));
    }
    if !role.ssh_keys.is_empty() {
        return Err(invalid(path, "a JWT role must not set ssh_keys"));
    }
    for (claim, m) in &role.bound_claims {
        if let ClaimMatch::Glob { glob } = m
            && !glob.contains('*')
        {
            return Err(invalid(
                &format!("{path}.bound_claims.{claim}"),
                "glob must contain at least one *",
            ));
        }
    }
    Ok(())
}

fn validate_ssh_role(path: &str, role: &Role) -> Result<(), ConfigError> {
    if role.ssh_keys.is_empty() {
        return Err(invalid(path, "an SSH role needs ssh_keys"));
    }
    for (i, line) in role.ssh_keys.iter().enumerate() {
        let parsed = ssh_key::PublicKey::from_openssh(line);
        if !parsed.is_ok_and(|k| crate::ssh::supported(&k.algorithm())) {
            return Err(invalid(
                &format!("{path}.ssh_keys[{i}]"),
                "must be an OpenSSH public key line of type ssh-ed25519, \
                 sk-ssh-ed25519@openssh.com or ecdsa-sha2-nistp256",
            ));
        }
    }
    if !role.bound_audiences.is_empty() || !role.bound_claims.is_empty() {
        return Err(invalid(
            path,
            "an SSH role must not set bound_audiences or bound_claims",
        ));
    }
    Ok(())
}

fn validate_github_role(path: &str, role: &Role) -> Result<(), ConfigError> {
    if role.github_user_ids.is_empty() {
        return Err(invalid(path, "a github-user role needs github_user_ids"));
    }
    if !role.bound_audiences.is_empty()
        || !role.bound_claims.is_empty()
        || !role.ssh_keys.is_empty()
    {
        return Err(invalid(
            path,
            "a github-user role must not set bound_audiences, bound_claims or ssh_keys",
        ));
    }
    Ok(())
}
