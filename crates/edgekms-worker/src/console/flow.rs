//! The pure parts of the GitHub web-flow sign-in: state and PKCE (RFC 7636, `S256`), the
//! authorize URL, the sign-in cookie's contents and `return_to` sanitizing.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use crate::vault::{Reply, log_internal};
use crate::webcrypto::global_crypto;

/// GitHub's authorize endpoint, a browser navigation.
pub const AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
/// The longest `return_to` kept; anything longer becomes `/`.
pub const MAX_RETURN_TO: usize = 512;

/// A fresh sign-in: the `state` GitHub echoes back, the PKCE verifier kept in the auth cookie,
/// and its `S256` challenge sent to GitHub. The verifier is zeroized on drop.
pub struct AuthStart {
    pub state: String,
    pub verifier: Zeroizing<String>,
    pub challenge: String,
}

/// 32 random bytes, base64url without padding (43 characters).
fn random_token() -> Result<String, Reply> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| {
        log_internal("console: no randomness");
        Reply::internal()
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}

/// A new state and PKCE pair, from the platform's CSPRNG.
///
/// # Errors
/// `500` if there is no randomness or `WebCrypto`'s digest fails (logged).
pub async fn start() -> Result<AuthStart, Reply> {
    let state = random_token()?;
    let verifier = Zeroizing::new(random_token()?);
    let challenge = challenge(&verifier).await?;
    Ok(AuthStart {
        state,
        verifier,
        challenge,
    })
}

/// The `S256` code challenge for `verifier`: base64url (no padding) of its SHA-256.
///
/// # Errors
/// `500` if `WebCrypto`'s digest fails (logged).
pub async fn challenge(verifier: &str) -> Result<String, Reply> {
    let subtle = global_crypto().map_err(|_| Reply::internal())?.subtle();
    let digest = async {
        let promise = subtle.digest_with_str_and_u8_array("SHA-256", verifier.as_bytes())?;
        wasm_bindgen_futures::JsFuture::from(promise).await
    }
    .await
    .map_err(|_| {
        log_internal("console: SHA-256 failed");
        Reply::internal()
    })?;
    Ok(URL_SAFE_NO_PAD.encode(js_sys::Uint8Array::new(&digest).to_vec()))
}

/// Whether `a` and `b` are equal, in time that depends only on their lengths.
#[must_use]
pub fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// Percent-decodes `s`; `None` for a `%` not followed by two hex digits. `plus_space` decodes
/// `+` as a space, as a query string's form encoding does.
#[must_use]
pub fn percent_decode(s: &str, plus_space: bool) -> Option<Vec<u8>> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = hex(*bytes.get(i + 1)?)?;
                let lo = hex(*bytes.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' if plus_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

/// The first value of `name` in the query string `query` (without its `?`), form-decoded.
/// `None` when it's absent or its encoding is broken.
#[must_use]
pub fn query_param(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k, true)? == name.as_bytes()).then_some(v)
        })
        .and_then(|v| String::from_utf8(percent_decode(v, true)?).ok())
}

/// `raw` if it's a safe place to send the browser after sign-in, else `/`.
///
/// Safe means a same-origin absolute path: at most [`MAX_RETURN_TO`] bytes, printable ASCII
/// with no space or backslash both as given and once percent-decoded, starting with `/` and
/// not with `//` (decoded or not, which a browser reads as another host). Paths under
/// `/auth/` are refused too, so a sign-in can't land on another sign-in.
#[must_use]
pub fn safe_return_to(raw: Option<&str>) -> String {
    fn clean(bytes: &[u8]) -> bool {
        bytes.first() == Some(&b'/')
            && bytes.get(1) != Some(&b'/')
            && bytes.iter().all(|&b| b.is_ascii_graphic() && b != b'\\')
            && !bytes.starts_with(b"/auth/")
    }
    let Some(raw) = raw else {
        return "/".to_owned();
    };
    let ok = raw.len() <= MAX_RETURN_TO
        && clean(raw.as_bytes())
        && percent_decode(raw, false).is_some_and(|d| clean(&d));
    if ok { raw.to_owned() } else { "/".to_owned() }
}

/// `path` (from [`safe_return_to`]) with `signed_in=1` added to its query, before any fragment:
/// the mark that tells the SPA a sign-in just completed. The result is still a same-origin
/// path, since only the query changes.
#[must_use]
pub fn mark_signed_in(path: &str) -> String {
    let (before, fragment) = match path.find('#') {
        Some(i) => path.split_at(i),
        None => (path, ""),
    };
    let sep = match before.find('?') {
        None => "?",
        Some(_) if before.ends_with('?') || before.ends_with('&') => "",
        Some(_) => "&",
    };
    format!("{before}{sep}signed_in=1{fragment}")
}

/// Percent-encodes everything but RFC 3986's unreserved characters.
#[must_use]
pub fn encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            // Writing to a String can't fail.
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Where `GET /auth/login` sends the browser: GitHub's authorize page for the App, with the
/// state and the `S256` challenge.
#[must_use]
pub fn authorize_url(client_id: &str, redirect_uri: &str, state: &str, challenge: &str) -> String {
    format!(
        "{AUTHORIZE_URL}?client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256",
        encode(client_id),
        encode(redirect_uri),
        encode(state),
        encode(challenge),
    )
}

/// The auth cookie's value: the three fields, each base64url without padding, joined by `.`.
#[must_use]
pub fn pack(state: &str, verifier: &str, return_to: &str) -> String {
    [state, verifier, return_to]
        .map(|f| URL_SAFE_NO_PAD.encode(f))
        .join(".")
}

/// The `(state, verifier, return_to)` [`pack`] wrote; `None` for anything else.
#[must_use]
pub fn unpack(cookie: &str) -> Option<(String, String, String)> {
    let field = |f: &str| {
        let bytes = URL_SAFE_NO_PAD.decode(f).ok()?;
        String::from_utf8(bytes).ok()
    };
    let mut parts = cookie.split('.');
    let (Some(s), Some(v), Some(r), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    Some((field(s)?, field(v)?, field(r)?))
}

/// The console's origin: `HOSTED_ORIGIN_TEMPLATE` with `{tenant}` as `app`
/// (`https://app.edgekms.dev`, `http://app.localhost:8787` under `wrangler dev`).
#[must_use]
pub fn console_origin(origin_template: &str) -> String {
    origin_template.replacen("{tenant}", "app", 1)
}

/// The control plane's origin: `origin_template` with `{tenant}` as `api`. The console's proxy
/// presents its requests to the control plane under it, so an SSH challenge fetched through
/// the console names the control origin, as one the CLI fetches does.
#[must_use]
pub fn control_origin(origin_template: &str) -> String {
    origin_template.replacen("{tenant}", "api", 1)
}

/// The OAuth redirect URI registered on the App: the console origin's `/auth/callback`.
#[must_use]
pub fn redirect_uri(origin_template: &str) -> String {
    format!("{}/auth/callback", console_origin(origin_template))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_keeps_same_origin_paths() {
        assert_eq!(safe_return_to(None), "/");
        assert_eq!(safe_return_to(Some("/")), "/");
        assert_eq!(safe_return_to(Some("/t/x")), "/t/x");
        assert_eq!(safe_return_to(Some("/t/x/export")), "/t/x/export");
        assert_eq!(safe_return_to(Some("/t/a%2Db?tab=1")), "/t/a%2Db?tab=1");
    }

    #[test]
    fn return_to_refuses_everything_else() {
        let long = format!("/{}", "a".repeat(4096));
        for bad in [
            "//evil.com",
            "/\\evil.com",
            "\\/evil.com",
            "https://evil.com",
            "/%2F%2Fevil.com",
            "/%2fevil.com",
            "/%5Cevil.com",
            "",
            "t/x",
            "/t/x\n",
            "/t/\u{7f}",
            "/t/%0a",
            "/t/%00",
            "/t/%",
            "/t/%zz",
            "/t/ x",
            "/t/%20x",
            "/t/é",
            "/t/%C3%A9",
            "/auth/login",
            "/auth/callback?code=x",
            "/%61uth/login",
            long.as_str(),
        ] {
            assert_eq!(safe_return_to(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(
            safe_return_to(Some(&format!("/{}", "a".repeat(511)))).len(),
            512
        );
        assert_eq!(safe_return_to(Some(&format!("/{}", "a".repeat(512)))), "/");
    }

    #[test]
    fn pack_round_trips() {
        let packed = pack("st", "ver", "/t/x?y=1.2");
        assert_eq!(packed.split('.').count(), 3);
        assert_eq!(
            unpack(&packed),
            Some(("st".into(), "ver".into(), "/t/x?y=1.2".into()))
        );
    }

    #[test]
    fn unpack_refuses_malformed_cookies() {
        let packed = pack("st", "ver", "/");
        let two: Vec<&str> = packed.split('.').take(2).collect();
        assert_eq!(unpack(&two.join(".")), None);
        assert_eq!(unpack(&format!("{packed}.eA")), None);
        assert_eq!(unpack("c3Q.dmVy.L*"), None);
        assert_eq!(unpack("c3Q=.dmVy.Lw"), None);
        assert_eq!(unpack(""), None);
        // Valid base64 of bytes that aren't UTF-8.
        assert_eq!(unpack("_w.dmVy.Lw"), None);
    }

    #[test]
    fn authorize_url_carries_the_challenge_and_an_encoded_redirect() {
        let url = authorize_url(
            "Iv1.abc",
            "https://app.edgekms.dev/auth/callback",
            "st-_",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        );
        assert!(
            url.starts_with("https://github.com/login/oauth/authorize?"),
            "{url}"
        );
        assert!(url.contains("client_id=Iv1.abc&"), "{url}");
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Fapp.edgekms.dev%2Fauth%2Fcallback&"),
            "{url}"
        );
        assert!(url.contains("state=st-_&"), "{url}");
        assert!(
            url.contains("code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&"),
            "{url}"
        );
        assert!(url.ends_with("&code_challenge_method=S256"), "{url}");
    }

    #[test]
    fn same_compares_whole_strings() {
        assert!(same("abc", "abc"));
        assert!(same("", ""));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "ab"));
        assert!(!same("abc", ""));
    }

    #[test]
    fn query_params_are_form_decoded() {
        let q = "code=a%2Bb&state=x+y&return_to=%2Ft%2Fx&code=second&flag";
        assert_eq!(query_param(q, "code").as_deref(), Some("a+b"));
        assert_eq!(query_param(q, "state").as_deref(), Some("x y"));
        assert_eq!(query_param(q, "return_to").as_deref(), Some("/t/x"));
        assert_eq!(query_param(q, "flag").as_deref(), Some(""));
        assert_eq!(query_param(q, "missing"), None);
        assert_eq!(query_param("", "code"), None);
        assert_eq!(query_param("code=%zz", "code"), None);
        assert_eq!(query_param("code=%FF", "code"), None);
    }

    #[test]
    fn console_origin_fills_the_template_with_app() {
        assert_eq!(
            console_origin("https://{tenant}.edgekms.dev"),
            "https://app.edgekms.dev"
        );
        assert_eq!(
            redirect_uri("http://{tenant}.localhost:8787"),
            "http://app.localhost:8787/auth/callback"
        );
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    /// RFC 7636, appendix B.
    #[wasm_bindgen_test]
    async fn challenge_matches_the_rfc_example() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                .await
                .unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[wasm_bindgen_test]
    async fn start_makes_fresh_43_character_values() {
        let a = start().await.unwrap();
        let b = start().await.unwrap();
        assert_eq!(a.state.len(), 43);
        assert_eq!(a.verifier.len(), 43);
        assert_ne!(a.state, b.state);
        assert_ne!(*a.verifier, *b.verifier);
        assert_ne!(a.state, *a.verifier);
        assert_eq!(a.challenge, challenge(&a.verifier).await.unwrap());
    }
}
