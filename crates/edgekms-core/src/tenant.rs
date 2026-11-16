//! Hosted-tier tenant names and Host header routing.
//!
//! A tenant is addressed as `https://<name>.<apex>` (`https://acme.edgekms.dev`). Its name is a
//! single DNS label under a strict charset, so a Host header maps to at most one tenant and no
//! homograph, punycode label or reserved service name can become one. [`route_host`] is the
//! only place a Host header turns into a tenant.

/// A validated tenant name: 3 to 32 characters of `[a-z0-9-]`, starting and ending with a
/// letter or digit, with no `--` anywhere, not in [`RESERVED`] and not starting with `edgekms`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantName(String);

/// Why [`TenantName::new`] refused a name. Each names the rule, never the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TenantNameError {
    #[error("tenant name must be 3 to 32 characters")]
    Length,
    #[error("tenant name may only contain a-z, 0-9 and -")]
    Charset,
    #[error("tenant name must start and end with a letter or digit")]
    Hyphen,
    #[error("tenant name must not contain --")]
    Punycode,
    #[error("tenant name is reserved")]
    Reserved,
}

impl TenantName {
    /// Validates `s` as a tenant name. Uppercase input is refused, not folded; [`route_host`]
    /// folds the Host header before calling this.
    ///
    /// # Errors
    /// The [`TenantNameError`] for the first rule `s` breaks, checked in the order length,
    /// charset, leading or trailing hyphen, `--`, reserved.
    pub fn new(s: &str) -> Result<Self, TenantNameError> {
        let b = s.as_bytes();
        if !(3..=32).contains(&b.len()) {
            return Err(TenantNameError::Length);
        }
        if !b
            .iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err(TenantNameError::Charset);
        }
        if b.first() == Some(&b'-') || b.last() == Some(&b'-') {
            return Err(TenantNameError::Hyphen);
        }
        // Also rules out every `xn--` punycode label, and with it IDN homographs.
        if s.contains("--") {
            return Err(TenantNameError::Punycode);
        }
        if RESERVED.contains(&s) || s.starts_with("edgekms") {
            return Err(TenantNameError::Reserved);
        }
        Ok(Self(s.to_owned()))
    }

    /// The name as validated.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Labels that are never tenant names: service hostnames under the apex and names that would
/// mislead (`admin`, `security`, `vault`).
pub const RESERVED: &[&str] = &[
    "www",
    "docs",
    "app",
    "api",
    "admin",
    "status",
    "blog",
    "help",
    "support",
    "billing",
    "pricing",
    "signup",
    "login",
    "logout",
    "auth",
    "oauth",
    "oidc",
    "sso",
    "id",
    "me",
    "account",
    "accounts",
    "dashboard",
    "console",
    "portal",
    "mail",
    "smtp",
    "imap",
    "pop",
    "mx",
    "ns1",
    "ns2",
    "ftp",
    "cdn",
    "static",
    "assets",
    "files",
    "autoconfig",
    "autodiscover",
    "security",
    "abuse",
    "postmaster",
    "hostmaster",
    "webmaster",
    "legal",
    "privacy",
    "terms",
    "about",
    "root",
    "system",
    "internal",
    "test",
    "staging",
    "dev",
    "demo",
    "edge",
    "km",
    "kms",
    "vault",
    "openbao",
    "bao",
    "www1",
    "www2",
];

/// Where a request's Host header sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRoute {
    /// `<name>.<apex>` for a valid tenant name.
    Tenant(TenantName),
    /// `api.<apex>`: the control plane.
    Control,
    /// `app.<apex>`: the web console.
    Console,
    /// A [`RESERVED`] label under the apex other than `api` and `app`.
    Reserved,
    /// Anything else: the apex itself, a deeper subdomain, another domain, an invalid label.
    Foreign,
}

/// Routes a Host header value (which may carry a `:port` and a trailing `.`) under `apex`.
///
/// Both are folded to lowercase; the port and one trailing `.` are dropped. The apex itself
/// is [`HostRoute::Foreign`] (it isn't routed to this Worker), as is any name that isn't
/// exactly one label under the apex, since no certificate covers a deeper one.
#[must_use]
pub fn route_host(host: &str, apex: &str) -> HostRoute {
    let host = host.to_ascii_lowercase();
    let host = host.split_once(':').map_or(host.as_str(), |(h, _)| h);
    let host = host.strip_suffix('.').unwrap_or(host);
    let apex = apex.to_ascii_lowercase();
    let apex = apex.strip_suffix('.').unwrap_or(&apex);
    let Some(label) = host
        .strip_suffix(apex)
        .and_then(|rest| rest.strip_suffix('.'))
    else {
        return HostRoute::Foreign;
    };
    if label.contains('.') {
        return HostRoute::Foreign;
    }
    if label == "api" {
        return HostRoute::Control;
    }
    if label == "app" {
        return HostRoute::Console;
    }
    if RESERVED.contains(&label) {
        return HostRoute::Reserved;
    }
    TenantName::new(label).map_or(HostRoute::Foreign, HostRoute::Tenant)
}

/// The tenant's public origin: `template` with its one `{tenant}` replaced by `name`
/// (`https://{tenant}.edgekms.dev`, or `http://{tenant}.localhost:8787` in e2e).
#[must_use]
pub fn tenant_origin(template: &str, name: &TenantName) -> String {
    template.replacen("{tenant}", name.as_str(), 1)
}
