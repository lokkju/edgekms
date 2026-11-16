//! The headers every response on `app.<apex>` carries, assets, sign-in and API alike.

/// The console's Content Security Policy: its own scripts and styles only, no inline code, no
/// framing, and `api.github.com` for the browser's login-to-id lookup.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.github.com; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
/// Two years, subdomains included.
pub const HSTS: &str = "max-age=63072000; includeSubDomains";
/// Denies every powerful feature.
pub const PERMISSIONS: &str = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

/// `Cache-Control` for API and sign-in responses, which carry tokens and per-user data.
pub const NO_STORE: &str = "no-store";
/// `Cache-Control` for Vite's content-hashed build output under `/assets/`.
pub const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// `Cache-Control` for everything else (`index.html`): revalidate every time.
pub const NO_CACHE: &str = "no-cache";

/// The security headers plus the `Cache-Control` for a response to `path`.
#[must_use]
pub fn security(path: &str) -> Vec<(&'static str, &'static str)> {
    vec![
        ("Content-Security-Policy", CSP),
        ("Strict-Transport-Security", HSTS),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Permissions-Policy", PERMISSIONS),
        ("Cache-Control", cache_control(path)),
    ]
}

/// The `Cache-Control` value for `path`.
#[must_use]
pub fn cache_control(path: &str) -> &'static str {
    let under = |prefix: &str| path == prefix || path.starts_with(&format!("{prefix}/"));
    if under("/api") || under("/auth") {
        NO_STORE
    } else if path.starts_with("/assets/") {
        IMMUTABLE
    } else {
        NO_CACHE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(h: &[(&'static str, &'static str)], name: &str) -> Option<&'static str> {
        h.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }

    #[test]
    fn cache_control_follows_the_path() {
        assert_eq!(
            get(&security("/api/v1/me"), "Cache-Control"),
            Some("no-store")
        );
        assert_eq!(
            get(&security("/auth/callback"), "Cache-Control"),
            Some("no-store")
        );
        assert_eq!(get(&security("/api"), "Cache-Control"), Some("no-store"));
        assert_eq!(
            get(&security("/assets/a.js"), "Cache-Control"),
            Some("public, max-age=31536000, immutable")
        );
        assert_eq!(get(&security("/"), "Cache-Control"), Some("no-cache"));
        assert_eq!(
            get(&security("/index.html"), "Cache-Control"),
            Some("no-cache")
        );
        assert_eq!(get(&security("/t/acme"), "Cache-Control"), Some("no-cache"));
        assert_eq!(get(&security("/apis"), "Cache-Control"), Some("no-cache"));
        assert_eq!(get(&security("/assets"), "Cache-Control"), Some("no-cache"));
    }

    #[test]
    fn every_response_gets_the_security_headers() {
        for path in ["/", "/api/v1/me", "/auth/login", "/assets/a.js", "/t/x"] {
            let h = security(path);
            assert_eq!(
                get(&h, "Content-Security-Policy"),
                Some(
                    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.github.com; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
                ),
                "{path}"
            );
            assert_eq!(
                get(&h, "Strict-Transport-Security"),
                Some("max-age=63072000; includeSubDomains")
            );
            assert_eq!(get(&h, "X-Content-Type-Options"), Some("nosniff"));
            assert_eq!(get(&h, "Referrer-Policy"), Some("no-referrer"));
            assert_eq!(get(&h, "Cross-Origin-Opener-Policy"), Some("same-origin"));
            assert_eq!(
                get(&h, "Permissions-Policy"),
                Some(
                    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
                )
            );
            assert_eq!(h.len(), 7);
        }
    }
}
