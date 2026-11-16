//! Vault's response envelopes: `{"data": ...}` and `{"auth": ...}` on success, and
//! `{"errors": [...]}` with an HTTP status on failure.
//!
//! Handlers return a [`Reply`], a plain status and JSON body, so they can be tested without a
//! Workers runtime; [`Reply::into_response`] is the only step that touches `worker::Response`.
//! The bytes and headers it sends ([`Reply::body_bytes`], [`Reply::headers`]) match what
//! OpenBao 2 sends for the same answer.
//!
//! A reply may carry plaintext (decrypt) or a token (login, token create), so its body is
//! zeroized when the reply is dropped, and the bytes it is serialized to are kept in zeroizing
//! buffers up to the hand-off to the runtime (see [`Reply::into_response`]).

use std::io;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use worker::Response;
use zeroize::{Zeroize as _, Zeroizing};

/// An HTTP status and an optional JSON body.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub status: u16,
    pub body: Option<Value>,
}

impl Reply {
    /// `200 {"data": v}`.
    #[must_use]
    pub fn data(v: Value) -> Self {
        Self::envelope("data", v)
    }

    /// `200 {"data": {"plaintext": "<base64 of pt>"}}`, the decrypt answer. The base64 string
    /// goes into the body as is, with no intermediate copy left behind.
    #[must_use]
    pub fn plaintext(pt: &[u8]) -> Self {
        let mut data = Map::with_capacity(1);
        data.insert("plaintext".to_owned(), Value::String(STANDARD.encode(pt)));
        Self::data(Value::Object(data))
    }

    /// `200 {"auth": v}`.
    #[must_use]
    pub fn auth(v: Value) -> Self {
        Self::envelope("auth", v)
    }

    /// `status {"errors": [msg]}`.
    #[must_use]
    pub fn error(status: u16, msg: &str) -> Self {
        Self {
            status,
            body: Some(json!({ "errors": [msg] })),
        }
    }

    /// `200` with `v` as the whole body, for the few endpoints Vault doesn't wrap.
    #[must_use]
    pub fn raw(v: Value) -> Self {
        Self {
            status: 200,
            body: Some(v),
        }
    }

    /// `204` with no body.
    #[must_use]
    pub fn no_content() -> Self {
        Self {
            status: 204,
            body: None,
        }
    }

    /// `403 permission denied`, Vault's answer to any token or policy problem.
    #[must_use]
    pub fn denied() -> Self {
        Self::error(403, "permission denied")
    }

    /// `404` with no body and no content type, for paths outside `/v1/`.
    #[must_use]
    pub fn bare_404() -> Self {
        Self {
            status: 404,
            body: None,
        }
    }

    /// `405 {"errors":[]}`, which is what OpenBao answers to `DELETE /v1/sys/health`.
    #[must_use]
    pub fn method_not_allowed() -> Self {
        Self {
            status: 405,
            body: Some(json!({ "errors": [] })),
        }
    }

    /// `413 {"errors":["http: request body too large"]}`, OpenBao's answer (Go's
    /// `http.MaxBytesReader` error) to a body over its cap.
    #[must_use]
    pub fn too_large() -> Self {
        Self::error(413, "http: request body too large")
    }

    /// `400` for a body whose stream broke off. OpenBao answers a body that ends early with
    /// Go's JSON decoder error, so this is the same text; the client has usually gone already.
    #[must_use]
    pub fn truncated_body() -> Self {
        Self::error(400, "failed to decode JSON input: unexpected EOF")
    }

    /// `500 internal error`. The cause is logged separately, never sent.
    #[must_use]
    pub fn internal() -> Self {
        Self::error(500, "internal error")
    }

    fn envelope(key: &str, v: Value) -> Self {
        let mut body = Map::with_capacity(1);
        body.insert(key.to_owned(), v);
        Self {
            status: 200,
            body: Some(Value::Object(body)),
        }
    }

    /// `200` with no body, for `HEAD /v1/sys/health`: GET's status and headers, as OpenBao
    /// answers it.
    #[must_use]
    pub fn head_ok() -> Self {
        Self {
            status: 200,
            body: None,
        }
    }

    /// Whether this is the bare `404` for a path outside `/v1/`, which has no body and no
    /// headers of its own.
    fn is_bare(&self) -> bool {
        self.status == 404 && self.body.is_none()
    }

    /// The body as OpenBao writes it: Go's `json.Encoder` output, which escapes `<`, `>`, `&`,
    /// U+2028 and U+2029 and ends with a newline. `None` when there is no body.
    ///
    /// Every buffer the body passes through is zeroized, including the ones growing leaves
    /// behind: the escaped output is sized exactly before it is written.
    #[must_use]
    pub fn body_bytes(&self) -> Option<Zeroizing<Vec<u8>>> {
        let v = self.body.as_ref()?;
        let mut json = ZeroizingWriter::default();
        // Serializing a `Value` into memory can't fail: its map keys are always strings, and
        // the writer never errors.
        let _ = serde_json::to_writer(&mut json, v);
        // serde_json writes valid UTF-8.
        let text = std::str::from_utf8(&json.0).unwrap_or_default();
        let escaped = |c: char| match c {
            '<' => Some("\\u003c"),
            '>' => Some("\\u003e"),
            '&' => Some("\\u0026"),
            '\u{2028}' => Some("\\u2028"),
            '\u{2029}' => Some("\\u2029"),
            _ => None,
        };
        let len = text
            .chars()
            .map(|c| escaped(c).map_or(c.len_utf8(), str::len))
            .sum::<usize>()
            + 1;
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        // These characters only ever occur inside JSON strings, where the escapes mean the
        // same thing.
        let mut start = 0;
        for (i, c) in text.char_indices() {
            if let Some(esc) = escaped(c) {
                out.extend_from_slice(&text.as_bytes()[start..i]);
                out.extend_from_slice(esc.as_bytes());
                start = i + c.len_utf8();
            }
        }
        out.extend_from_slice(&text.as_bytes()[start..]);
        out.push(b'\n');
        Some(out)
    }

    /// The headers OpenBao sends on every API response (`Date` and `Content-Length` aside):
    /// `Cache-Control: no-store`, its default HSTS header and, except on the bare `404`,
    /// `Content-Type: application/json`, even with no body (`204`, `HEAD`).
    #[must_use]
    pub fn headers(&self) -> Vec<(&'static str, &'static str)> {
        let mut h = vec![
            ("Cache-Control", "no-store"),
            (
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            ),
        ];
        if !self.is_bare() {
            h.insert(0, ("Content-Type", "application/json"));
        }
        h
    }

    /// The body bytes move into workers-rs without another copy; it copies them into a
    /// JavaScript `Uint8Array` and frees its `Vec` without zeroizing it, and the JavaScript
    /// copies are the runtime's. That one buffer is the only copy on the Rust side this can't
    /// zeroize.
    ///
    /// # Errors
    /// If the runtime refuses to build the response.
    pub fn into_response(self) -> worker::Result<Response> {
        let resp = match self.body_bytes() {
            Some(mut bytes) => Response::from_bytes(std::mem::take(&mut *bytes))?,
            None => Response::empty()?,
        };
        let headers = resp.headers();
        for (name, value) in self.headers() {
            headers.set(name, value)?;
        }
        Ok(resp.with_status(self.status))
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        if let Some(body) = &mut self.body {
            zeroize_value(body);
        }
    }
}

/// Zeroizes every string in `v` (leaving it empty), wherever it is nested. Map keys are left
/// alone: they are field names, never secrets.
pub fn zeroize_value(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_value),
        Value::Object(map) => map.values_mut().for_each(zeroize_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Appends `data` to `buf`. When `buf` must grow, its contents move to a new allocation and
/// the old one is zeroized, where `Vec`'s own growth would free it with the bytes still in it.
pub fn extend_zeroizing(buf: &mut Zeroizing<Vec<u8>>, data: &[u8]) {
    let needed = buf.len() + data.len();
    if needed > buf.capacity() {
        let mut grown = Vec::with_capacity(needed.max(buf.capacity().saturating_mul(2)));
        grown.extend_from_slice(buf);
        // Dropping the `Zeroizing` zeroizes the old allocation, spare capacity included.
        drop(Zeroizing::new(std::mem::replace(&mut **buf, grown)));
    }
    buf.extend_from_slice(data);
}

/// An `io::Write` into a zeroizing buffer that grows with [`extend_zeroizing`].
#[derive(Default)]
struct ZeroizingWriter(Zeroizing<Vec<u8>>);

impl io::Write for ZeroizingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        extend_zeroizing(&mut self.0, data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Logs a fixed label to the Worker's error log. Taking only `&'static str` means no request
/// data, token, key or plaintext can reach the log through this function.
pub fn log_internal(label: &'static str) {
    worker::console_error!("edgekms: {label}");
}

/// Logs a fixed label at `console.info`, for events worth seeing that aren't failures. `info`,
/// not `log`, so it shows under `wrangler dev --log-level info` (what `scripts/e2e.sh` runs).
/// Like [`log_internal`], it takes only `&'static str`.
pub fn log_notice(label: &'static str) {
    web_sys::console::info_1(&format!("edgekms: {label}").into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_value_clears_every_string_and_keeps_the_shape() {
        let mut v = json!({
            "data": { "plaintext": "c2VjcmV0", "nested": ["a", { "b": "c" }] },
            "n": 1,
            "t": true,
        });
        zeroize_value(&mut v);
        assert_eq!(
            v,
            json!({
                "data": { "plaintext": "", "nested": ["", { "b": "" }] },
                "n": 1,
                "t": true,
            })
        );
    }

    #[test]
    fn extend_zeroizing_appends_across_growth() {
        let mut buf = Zeroizing::new(Vec::new());
        let mut want = Vec::new();
        for i in 0..200u8 {
            let chunk = vec![i; usize::from(i % 7) + 1];
            extend_zeroizing(&mut buf, &chunk);
            want.extend_from_slice(&chunk);
        }
        assert_eq!(*buf, want);
    }

    #[test]
    fn extend_zeroizing_does_not_reallocate_within_capacity() {
        let mut buf = Zeroizing::new(Vec::with_capacity(16));
        extend_zeroizing(&mut buf, b"0123");
        let ptr = buf.as_ptr();
        extend_zeroizing(&mut buf, b"456789abcdef");
        assert_eq!(buf.as_ptr(), ptr);
        assert_eq!(&buf[..], b"0123456789abcdef");
    }

    #[test]
    fn body_bytes_escapes_as_go_does_past_the_first_allocation() {
        // Long enough that serializing grows the buffer several times.
        let long = "x<y>&z\u{2028}\u{2029}".repeat(500);
        let r = Reply::data(json!({ "plaintext": long }));
        let want = format!(
            "{{\"data\":{{\"plaintext\":\"{}\"}}}}\n",
            r"x\u003cy\u003e\u0026z\u2028\u2029".repeat(500)
        );
        assert_eq!(std::str::from_utf8(&r.body_bytes().unwrap()).unwrap(), want);
        assert_eq!(Reply::no_content().body_bytes(), None);
    }

    #[test]
    fn decrypt_reply_carries_the_plaintext_as_a_string() {
        let r = Reply::plaintext(b"secret");
        assert_eq!(r, Reply::data(json!({ "plaintext": "c2VjcmV0" })));
    }
}
