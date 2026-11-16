//! A path-routed stub HTTP server for the login tests.
#![allow(dead_code)] // each test crate uses a different subset

use std::thread;
use std::time::Duration;

use serde_json::Value;

/// One request the stub saw.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    /// Path and query.
    pub url: String,
    pub body: String,
}

impl Seen {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }

    /// The value of `key` in a form-encoded body.
    pub fn form(&self, key: &str) -> Option<String> {
        url::form_urlencoded::parse(self.body.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }
}

/// Serves requests with `route(base_url, request)` until `max` have been seen or none arrives
/// for two seconds; the handle yields every request seen.
pub fn routed(
    max: usize,
    route: impl Fn(&str, &Seen) -> (u16, Value) + Send + 'static,
) -> (String, thread::JoinHandle<Vec<Seen>>) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let base = format!("http://{}", server.server_addr().to_ip().unwrap());
    let url = base.clone();
    let h = thread::spawn(move || {
        let mut seen = Vec::new();
        while seen.len() < max {
            let Ok(Some(mut req)) = server.recv_timeout(Duration::from_secs(2)) else {
                break;
            };
            let mut body = String::new();
            req.as_reader().read_to_string(&mut body).unwrap();
            let s = Seen {
                method: req.method().to_string(),
                url: req.url().to_owned(),
                body,
            };
            let (status, reply) = route(&base, &s);
            seen.push(s);
            let resp = tiny_http::Response::from_string(reply.to_string())
                .with_status_code(status)
                .with_header(
                    "Content-Type: application/json"
                        .parse::<tiny_http::Header>()
                        .unwrap(),
                );
            req.respond(resp).unwrap();
        }
        seen
    });
    (url, h)
}
