//! The console's three cookies. Each uses the `__Host-` prefix, so a browser only accepts them
//! from this exact host over HTTPS with `Path=/` and no `Domain`: a tenant host or any other
//! subdomain of the apex can't set or overwrite them.
//!
//! - [`AUTH_COOKIE`] carries a sign-in in progress (state, PKCE verifier, return path) for ten
//!   minutes. `SameSite=Lax`, because the callback is a top-level navigation from github.com,
//!   which never carries a `Strict` cookie.
//! - [`SESSION_COOKIE`] is the control token itself, `SameSite=Strict`.
//! - [`REQUEST_COOKIE`] is the request token a sign-in refused with `signup_closed` in `invite`
//!   mode carries (lokkju/edgekms#12), `SameSite=Strict`, for as long as the token lasts. The
//!   console sends it for the two invite request paths only.

/// A sign-in in progress (`crate::console::flow::pack`).
pub const AUTH_COOKIE: &str = "__Host-edgekms_auth";
/// The control token.
pub const SESSION_COOKIE: &str = "__Host-edgekms_session";
/// A refused user's request token.
pub const REQUEST_COOKIE: &str = "__Host-edgekms_request";

/// The cookie's `SameSite` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Lax,
    Strict,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
        }
    }
}

/// The value of the cookie `name` in a `Cookie` request header, if it's there. Names match
/// exactly (a cookie whose name merely starts with `name` is someone else's); the first match
/// wins.
#[must_use]
pub fn get<'a>(header: Option<&'a str>, name: &str) -> Option<&'a str> {
    header?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.trim())
}

/// Whether `v` can go into a cookie value as it is: RFC 6265 `cookie-octet`s only, so no
/// space, quote, comma, semicolon or backslash, and nothing outside printable ASCII.
#[must_use]
pub fn valid_value(v: &str) -> bool {
    v.bytes()
        .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b',' | b';' | b'\\'))
}

/// A `Set-Cookie` value for `name=value`, `HttpOnly`, `Secure`, host-only on `/`. The caller
/// passes a value [`valid_value`] accepts.
#[must_use]
pub fn set(name: &str, value: &str, same_site: SameSite, max_age: u32) -> String {
    format!(
        "{name}={value}; HttpOnly; Secure; Path=/; SameSite={}; Max-Age={max_age}",
        same_site.as_str()
    )
}

/// A `Set-Cookie` value that deletes `name`: empty, with `Max-Age=0` and the same attributes
/// it was set with.
#[must_use]
pub fn clear(name: &str, same_site: SameSite) -> String {
    set(name, "", same_site, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_picks_the_named_cookie_among_several() {
        let h = "a=1; __Host-edgekms_session2=wrong; __Host-edgekms_session=right; b=2";
        assert_eq!(get(Some(h), SESSION_COOKIE), Some("right"));
        assert_eq!(get(Some(h), "a"), Some("1"));
        assert_eq!(get(Some(h), "b"), Some("2"));
    }

    #[test]
    fn get_ignores_a_prefix_match_and_missing_cookies() {
        assert_eq!(get(Some("__Host-edgekms_session2=x"), SESSION_COOKIE), None);
        assert_eq!(get(Some("x__Host-edgekms_session=x"), SESSION_COOKIE), None);
        assert_eq!(get(Some(""), SESSION_COOKIE), None);
        assert_eq!(get(None, SESSION_COOKIE), None);
        assert_eq!(get(Some("novalue; other=1"), "novalue"), None);
    }

    #[test]
    fn get_returns_an_empty_value_as_empty() {
        assert_eq!(get(Some("__Host-edgekms_auth="), AUTH_COOKIE), Some(""));
    }

    #[test]
    fn set_writes_every_attribute() {
        assert_eq!(
            set(SESSION_COOKIE, "v", SameSite::Strict, 1800),
            "__Host-edgekms_session=v; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=1800"
        );
        assert_eq!(
            set(AUTH_COOKIE, "s.v.r", SameSite::Lax, 600),
            "__Host-edgekms_auth=s.v.r; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=600"
        );
    }

    #[test]
    fn clear_expires_the_cookie_with_the_same_attributes() {
        assert_eq!(
            clear(AUTH_COOKIE, SameSite::Lax),
            "__Host-edgekms_auth=; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=0"
        );
    }

    #[test]
    fn request_cookie_is_strict_and_host_only() {
        assert_eq!(
            set(REQUEST_COOKIE, "ekms.r", SameSite::Strict, 900),
            "__Host-edgekms_request=ekms.r; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=900"
        );
        assert_eq!(get(Some("__Host-edgekms_request=x"), SESSION_COOKIE), None);
        assert_eq!(get(Some("__Host-edgekms_session=x"), REQUEST_COOKIE), None);
    }

    #[test]
    fn valid_values_are_cookie_octets() {
        assert!(valid_value("ekms.abc-_DEF.123"));
        for bad in ["a b", "a;b", "a,b", "a\"b", "a\\b", "a\nb", "é"] {
            assert!(!valid_value(bad), "{bad:?}");
        }
    }
}
