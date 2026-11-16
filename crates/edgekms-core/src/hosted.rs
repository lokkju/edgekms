//! Rules a tenant config must meet in the hosted tier on top of [`Config::from_json`], the
//! default config a new tenant starts with, and the byte layouts the Worker binds a tenant's
//! wrapped root key, config MAC, membership MACs and invite MACs to.

use crate::config::{Config, ConfigError, Mount};
use crate::transit::Id;

/// The largest tenant config the control plane accepts, checked before parsing. It sits under
/// the Worker's 64 KiB request body cap.
pub const MAX_CONFIG_BYTES: usize = 61_440;

/// Caps on a tenant config's sections, which bound what parsing one costs an isolate.
const MAX_KEYS: usize = 64;
const MAX_MOUNTS: usize = 32;
const MAX_ROLES: usize = 128;
const MAX_POLICIES: usize = 128;

/// The most versions of one key a hosted config may leave decryptable, `latest_version -
/// min_decryption_version + 1`. `GET transit/keys/:name` lists every one of them, and the
/// Worker derives and caches a key per version used, so this bounds both per key.
pub const MAX_DECRYPTABLE_VERSIONS: u32 = 256;

/// The highest `latest_version` a hosted config may set. A key rotated daily takes over two
/// thousand years to reach it; it exists so a version number is never large enough to matter.
pub const MAX_KEY_VERSION: u32 = 1_000_000;

/// What the hosted service decides for a tenant, which its config must agree with.
#[derive(Debug, Clone, Copy)]
pub struct HostedRules<'a> {
    /// The tenant row's root id.
    pub root_id: &'a Id,
    /// The client id of the hosted service's GitHub App, the only one a `github-user` mount
    /// may name.
    pub github_client_id: &'a str,
    /// The hosted service's apex (`HOSTED_APEX`, e.g. `edgekms.dev`). A `jwks_url` on it or under
    /// it would have the Worker fetch from itself.
    pub apex: &'a str,
}

fn invalid(path: &str, reason: &str) -> ConfigError {
    ConfigError::Invalid(format!("{path}: {reason}"))
}

/// Checks a parsed tenant config against the hosted rules: the root id is the service's, no
/// `public_origins`, every `github-user` mount uses the service's App, size caps on keys,
/// mounts, roles and policies, each key's `latest_version` at most [`MAX_KEY_VERSION`] with at
/// most [`MAX_DECRYPTABLE_VERSIONS`] of them decryptable, and no `jwks_url` on the service's
/// apex or under it.
///
/// # Errors
/// [`ConfigError::Invalid`] naming the path and the rule broken.
pub fn validate_hosted(config: &Config, rules: &HostedRules) -> Result<(), ConfigError> {
    if config.root_id != *rules.root_id {
        return Err(invalid("root_id", "the hosted service sets the root id"));
    }
    if !config.public_origins.is_empty() {
        return Err(invalid(
            "public_origins",
            "the hosted service sets the origin",
        ));
    }
    let caps = [
        ("keys", config.keys.len(), MAX_KEYS),
        ("mounts", config.mounts.len(), MAX_MOUNTS),
        ("roles", config.roles.len(), MAX_ROLES),
        ("policies", config.policies.len(), MAX_POLICIES),
    ];
    for (path, len, max) in caps {
        if len > max {
            return Err(invalid(path, &format!("at most {max} {path}")));
        }
    }
    for (name, key) in &config.keys {
        // `Config::from_json` already holds `1 <= min_decryption_version <= latest_version`.
        if key.latest_version > MAX_KEY_VERSION {
            return Err(invalid(
                &format!("keys.{name}.latest_version"),
                &format!("at most {MAX_KEY_VERSION}"),
            ));
        }
        if key
            .latest_version
            .saturating_sub(key.min_decryption_version)
            >= MAX_DECRYPTABLE_VERSIONS
        {
            return Err(invalid(
                &format!("keys.{name}"),
                &format!("at most {MAX_DECRYPTABLE_VERSIONS} decryptable versions"),
            ));
        }
    }
    for (name, mount) in &config.mounts {
        match mount {
            Mount::GithubUser { client_id } if client_id != rules.github_client_id => {
                return Err(invalid(
                    &format!("mounts.{name}.client_id"),
                    &format!(
                        "the hosted service's GitHub App is {}",
                        rules.github_client_id
                    ),
                ));
            }
            Mount::Jwt {
                jwks_url: Some(url),
                ..
            } => {
                let path = format!("mounts.{name}.jwks_url");
                let Ok(parsed) = url::Url::parse(url) else {
                    return Err(invalid(&path, "not a valid URL"));
                };
                let apex = normalize_host(rules.apex);
                if under_apex(parsed.host_str().unwrap_or_default(), &apex) {
                    return Err(invalid(&path, &format!("must not point at {apex}")));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Lowercase, without one trailing `.`.
fn normalize_host(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    host.strip_suffix('.').map(str::to_owned).unwrap_or(host)
}

/// Whether `host`, as a WHATWG URL parser resolves it (the same `url` crate the Worker's fetch
/// parses with, so percent-encoding, ideographic dots, tabs and backslashes are already
/// resolved), is `apex` or a name under it.
fn under_apex(host: &str, apex: &str) -> bool {
    let host = normalize_host(host);
    host == apex || host.strip_suffix(apex).is_some_and(|h| h.ends_with('.'))
}

/// The config a new tenant starts with, as compact JSON that passes both [`Config::from_json`]
/// and [`validate_hosted`]: one key `default`, the `github-user` mount, and an `owner` role for
/// `owner_github_id` with the `admin` and `default-all` policies.
#[must_use]
pub fn default_config(
    root_id: &Id,
    key_id: &Id,
    owner_github_id: u64,
    github_client_id: &str,
) -> String {
    serde_json::json!({
        "root_id": root_id.as_str(),
        "keys": {
            "default": { "id": key_id.as_str(), "latest_version": 1, "min_decryption_version": 1 }
        },
        "mounts": {
            "github-user": { "type": "github-user", "client_id": github_client_id }
        },
        "roles": {
            "owner": {
                "mount": "github-user",
                "github_user_ids": [owner_github_id],
                "policies": ["admin", "default-all"],
                "token_ttl_secs": 3600
            }
        },
        "policies": {
            "admin": { "admin": ["token-create", "token-revoke"] },
            "default-all": { "keys": { "default": ["encrypt", "decrypt", "rewrap", "read"] } }
        }
    })
    .to_string()
}

/// The AES-GCM additional data a tenant's wrapped root key is bound to:
/// `b"edgekms/wrap/v1/<tenant id>/<root id>"`.
#[must_use]
pub fn wrap_aad(tenant_id: &str, root_id: &Id) -> Vec<u8> {
    format!("edgekms/wrap/v1/{tenant_id}/{}", root_id.as_str()).into_bytes()
}

/// The bytes a tenant's config MAC (`MacPurpose::Config`) covers:
/// `tenant_id || 0x00 || name || 0x00 || version as u64 big-endian || config_json`.
///
/// The name is bound so a config only verifies under the hostname it was written for: swapping
/// two rows' names in the store makes both fail to load instead of serving one tenant's keys at
/// the other's hostname. A rename therefore has to re-MAC the config. Neither the id
/// (`t_<hex>`) nor a valid tenant name contains `0x00`, so the separators are unambiguous.
#[must_use]
pub fn config_mac_input(tenant_id: &str, name: &str, version: u64, config_json: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(tenant_id.len() + name.len() + 10 + config_json.len());
    out.extend_from_slice(tenant_id.as_bytes());
    out.push(0);
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(config_json.as_bytes());
    out
}

/// The bytes a membership row's MAC (`MacPurpose::Member`, under the control plane's root)
/// covers: `tenant_id || 0x00 || github_id as u64 big-endian || role || 0x00 || added_ms as
/// u64 big-endian`.
///
/// Binding the tenant id, the user and the role means a row copied to another tenant or user,
/// or with its role rewritten, doesn't verify. `added_ms` is when the row took its current
/// role. The tenant id and the role (`owner`, `member`) never contain `0x00`, and the integers
/// are fixed width, so the layout is unambiguous.
#[must_use]
pub fn member_mac_input(tenant_id: &str, github_id: u64, role: &str, added_ms: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(tenant_id.len() + role.len() + 18);
    out.extend_from_slice(tenant_id.as_bytes());
    out.push(0);
    out.extend_from_slice(&github_id.to_be_bytes());
    out.extend_from_slice(role.as_bytes());
    out.push(0);
    out.extend_from_slice(&added_ms.to_be_bytes());
    out
}

/// The bytes a pending invite row's MAC (`MacPurpose::Invite`, under the control plane's
/// root) covers: `tenant_id || 0x00 || github_id as u64 big-endian || role || 0x00 ||
/// invited_by as u64 big-endian || invited_ms as u64 big-endian`.
#[must_use]
pub fn invite_mac_input(
    tenant_id: &str,
    github_id: u64,
    role: &str,
    invited_by: u64,
    invited_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(tenant_id.len() + role.len() + 26);
    out.extend_from_slice(tenant_id.as_bytes());
    out.push(0);
    out.extend_from_slice(&github_id.to_be_bytes());
    out.extend_from_slice(role.as_bytes());
    out.push(0);
    out.extend_from_slice(&invited_by.to_be_bytes());
    out.extend_from_slice(&invited_ms.to_be_bytes());
    out
}

/// The bytes a signup allowlist row's MAC (`MacPurpose::Allow`, under the control plane's root)
/// covers: `github_id || added_by || added_ms`, each a u64 big-endian. The fields are fixed
/// width, so the layout is unambiguous, and the purpose's own key keeps the tag from verifying
/// as any other row's.
#[must_use]
pub fn allow_mac_input(github_id: u64, added_by: u64, added_ms: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&github_id.to_be_bytes());
    out.extend_from_slice(&added_by.to_be_bytes());
    out.extend_from_slice(&added_ms.to_be_bytes());
    out
}

/// The bytes an invite request row's MAC (`MacPurpose::InviteRequest`, under the control
/// plane's root) covers: `github_id || created_ms`, each a u64 big-endian, then the login and
/// the note, each as its length (u32 big-endian) and its bytes. The length prefixes keep the
/// two text fields unambiguous. The decision columns (status, decider, time) are outside it:
/// admission reads only the signup allowlist, so a forged status grants nothing.
#[must_use]
pub fn invite_request_mac_input(
    github_id: u64,
    created_ms: u64,
    login: &str,
    note: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + login.len() + note.len());
    out.extend_from_slice(&github_id.to_be_bytes());
    out.extend_from_slice(&created_ms.to_be_bytes());
    for field in [login, note] {
        // A login is at most 39 bytes and a stored note at most `MAX_NOTE_BYTES`, far below
        // what a u32 holds.
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// Whether `login` looks like a GitHub login: 1 to 39 ASCII letters, digits and hyphens. The
/// control plane issues request tokens and registration challenges only for one, so the login
/// they carry is safe to put on a terminal or a page, or in a shell command.
#[must_use]
pub fn plausible_login(login: &str) -> bool {
    (1..=39).contains(&login.len())
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The bytes a registered SSH key row's MAC (`MacPurpose::SshKey`, under the control plane's
/// root) covers: `github_id || added_ms`, each a u64 big-endian, then the fingerprint, the
/// public key, the label and `added_via`, each as its length (u32 big-endian) and its bytes.
/// Binding the account means a real row moved to another user doesn't verify; binding the
/// label and lineage means a D1 writer can't relabel a key or hide which key added it.
#[must_use]
pub fn ssh_key_mac_input(
    github_id: u64,
    added_ms: u64,
    fingerprint: &str,
    public_key: &str,
    label: &str,
    added_via: &str,
) -> Vec<u8> {
    let fields = [fingerprint, public_key, label, added_via];
    let mut out = Vec::with_capacity(16 + fields.iter().map(|f| 4 + f.len()).sum::<usize>());
    out.extend_from_slice(&github_id.to_be_bytes());
    out.extend_from_slice(&added_ms.to_be_bytes());
    for field in fields {
        // A public key is at most 8 KiB and the other fields far shorter.
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// The most Unicode scalar values an SSH key's label holds, after trimming.
pub const MAX_SSH_KEY_LABEL_CHARS: usize = 64;

/// Why [`ssh_key_label`] refused a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelError {
    TooLong,
    Control,
    Bidi,
    Invisible,
}

impl std::fmt::Display for LabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "the label must be at most 64 characters",
            Self::Control => "the label can't contain control characters or line breaks",
            Self::Bidi => "the label can't contain bidirectional formatting characters",
            Self::Invisible => "the label can't contain invisible characters",
        })
    }
}

impl std::error::Error for LabelError {}

/// An SSH key's label as the control plane stores it: `raw` trimmed, at most
/// [`MAX_SSH_KEY_LABEL_CHARS`] scalar values, one line with no control, bidirectional
/// formatting or invisible character, the same inert-text rules as an invite request's note
/// without its line breaks. Empty is allowed.
///
/// # Errors
/// The first rule the trimmed label breaks.
pub fn ssh_key_label(raw: &str) -> Result<&str, LabelError> {
    let label = raw.trim();
    if label.chars().count() > MAX_SSH_KEY_LABEL_CHARS {
        return Err(LabelError::TooLong);
    }
    if label.chars().any(char::is_control) {
        return Err(LabelError::Control);
    }
    if label.chars().any(is_bidi_control) {
        return Err(LabelError::Bidi);
    }
    if label.chars().any(is_invisible) {
        return Err(LabelError::Invisible);
    }
    Ok(label)
}

/// The most Unicode scalar values an invite request's note holds, after trimming.
pub const MAX_NOTE_CHARS: usize = 500;
/// The most bytes an invite request's note holds, after trimming.
pub const MAX_NOTE_BYTES: usize = 2000;

/// Why [`invite_note`] refused a note. Each message names the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteError {
    TooManyBytes,
    TooManyChars,
    Control,
    Bidi,
    Invisible,
}

impl std::fmt::Display for NoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooManyBytes => "the note must be at most 2000 bytes",
            Self::TooManyChars => "the note must be at most 500 characters",
            Self::Control => "the note can't contain control characters other than line breaks",
            Self::Bidi => "the note can't contain bidirectional formatting characters",
            Self::Invisible => "the note can't contain invisible characters",
        })
    }
}

impl std::error::Error for NoteError {}

/// Whether `c` is a bidirectional formatting character: the embedding, override and isolate
/// controls (U+202A to U+202E, U+2066 to U+2069) and the three marks (U+061C, U+200E, U+200F).
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

/// Whether `c` is invisible text an operator wouldn't see: zero-width space and word joiner,
/// the byte order mark, the line and paragraph separators, the soft hyphen, and the tag
/// characters (U+E0000 to U+E007F). Zero-width joiners stay allowed, for emoji and scripts that
/// need them.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{ad}' | '\u{200b}' | '\u{2060}' | '\u{2028}' | '\u{2029}' | '\u{feff}' | '\u{e0000}'
            ..='\u{e007f}'
    )
}

/// An invite request's note as the control plane stores it: `raw` with leading and trailing
/// whitespace trimmed, at most [`MAX_NOTE_BYTES`] bytes and [`MAX_NOTE_CHARS`] scalar values,
/// with no control character but `\n`, no bidirectional formatting character and no invisible
/// character ([`is_invisible`]), so it prints
/// inert in a terminal and can't reorder what an operator reads. Empty is allowed.
///
/// # Errors
/// The first rule the trimmed note breaks.
pub fn invite_note(raw: &str) -> Result<&str, NoteError> {
    let note = raw.trim();
    if note.len() > MAX_NOTE_BYTES {
        return Err(NoteError::TooManyBytes);
    }
    if note.chars().count() > MAX_NOTE_CHARS {
        return Err(NoteError::TooManyChars);
    }
    if note.chars().any(|c| c.is_control() && c != '\n') {
        return Err(NoteError::Control);
    }
    if note.chars().any(is_bidi_control) {
        return Err(NoteError::Bidi);
    }
    if note.chars().any(is_invisible) {
        return Err(NoteError::Invisible);
    }
    Ok(note)
}
