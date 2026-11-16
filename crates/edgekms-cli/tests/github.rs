//! `login github` against a stub that plays both GitHub's device flow and the Worker.

mod common;

use std::cell::RefCell;
use std::time::Duration;

use common::{Seen, routed};
use edgekms_cli::login::{self, DeviceFlow, DevicePrompt, LoginError, UreqTransport};
use serde_json::{Value, json};

const GH_TOKEN: &str = "gho_secret_user_token";

fn flow(base: &str) -> (String, String) {
    (
        format!("{base}/login/device/code"),
        format!("{base}/login/oauth/access_token"),
    )
}

fn device_code_reply(expires_in: u64) -> Value {
    json!({
        "device_code": "dev-123",
        "user_code": "ABCD-1234",
        "verification_uri": "https://github.com/login/device",
        "expires_in": expires_in,
        "interval": 5
    })
}

/// Replies to the token endpoint in order from `polls`, then answers the Worker login.
fn github_stub(polls: Vec<Value>, expires_in: u64) -> (String, std::thread::JoinHandle<Vec<Seen>>) {
    let polls = std::sync::Mutex::new(polls.into_iter());
    routed(20, move |_, s| match s.url.as_str() {
        "/login/device/code" => (200, device_code_reply(expires_in)),
        "/login/oauth/access_token" => (200, polls.lock().unwrap().next().unwrap()),
        "/v1/auth/github-user/login" => (200, json!({"auth": {"client_token": "ekms.tok"}})),
        other => panic!("unexpected {other}"),
    })
}

#[test]
fn device_flow_polls_through_pending_and_slow_down_then_logs_in() {
    let (base, h) = github_stub(
        vec![
            json!({"error": "authorization_pending"}),
            json!({"error": "slow_down", "interval": 10}),
            json!({"access_token": GH_TOKEN, "token_type": "bearer", "scope": ""}),
        ],
        900,
    );
    let (device, token) = flow(&base);
    let f = DeviceFlow {
        client_id: "Iv1.test",
        device_code_url: &device,
        token_url: &token,
    };
    let prompted = RefCell::new(None);
    let slept = RefCell::new(Vec::new());
    let tok = login::login_github(
        &UreqTransport::new(),
        &f,
        |p: &DevicePrompt| *prompted.borrow_mut() = Some(p.clone()),
        |d| slept.borrow_mut().push(d),
        &base,
        "github-user",
        "op",
    )
    .unwrap();
    assert_eq!(tok, "ekms.tok");
    let p = prompted.into_inner().unwrap();
    assert_eq!(p.user_code, "ABCD-1234");
    assert_eq!(p.verification_uri, "https://github.com/login/device");
    assert_eq!(
        slept.into_inner(),
        [5, 5, 10].map(Duration::from_secs).to_vec()
    );

    let seen = h.join().unwrap();
    assert_eq!(seen[0].form("client_id").as_deref(), Some("Iv1.test"));
    for poll in &seen[1..4] {
        assert_eq!(poll.form("device_code").as_deref(), Some("dev-123"));
        assert_eq!(
            poll.form("grant_type").as_deref(),
            Some("urn:ietf:params:oauth:grant-type:device_code")
        );
    }
    assert_eq!(seen[4].url, "/v1/auth/github-user/login");
    assert_eq!(seen[4].json(), json!({"role": "op", "token": GH_TOKEN}));
}

#[test]
fn declined_authorization_never_reaches_the_worker() {
    let (base, h) = github_stub(
        vec![
            json!({"error": "access_denied", "error_description": "The user has denied your application access."}),
        ],
        900,
    );
    let (device, token) = flow(&base);
    let f = DeviceFlow {
        client_id: "Iv1.test",
        device_code_url: &device,
        token_url: &token,
    };
    let err = login::login_github(
        &UreqTransport::new(),
        &f,
        |_| {},
        |_| {},
        &base,
        "github-user",
        "op",
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::Authorization(_)), "{err}");
    assert!(err.to_string().contains("access_denied"), "{err}");
    let seen = h.join().unwrap();
    assert!(seen.iter().all(|s| !s.url.starts_with("/v1/")), "{seen:?}");
}

#[test]
fn device_code_expiry_stops_polling() {
    let (base, h) = github_stub(
        vec![
            json!({"error": "authorization_pending"}),
            json!({"error": "authorization_pending"}),
        ],
        12,
    );
    let (device, token) = flow(&base);
    let f = DeviceFlow {
        client_id: "Iv1.test",
        device_code_url: &device,
        token_url: &token,
    };
    let err = login::login_github(
        &UreqTransport::new(),
        &f,
        |_| {},
        |_| {},
        &base,
        "github-user",
        "op",
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::Timeout(_)), "{err}");
    // 12 seconds at 5-second intervals: two polls, then the third would pass the expiry.
    assert_eq!(h.join().unwrap().len(), 3);
}

#[test]
fn rejected_worker_login_never_echoes_the_github_token() {
    let (base, h) = routed(10, |_, s| match s.url.as_str() {
        "/login/device/code" => (200, device_code_reply(900)),
        "/login/oauth/access_token" => (200, json!({"access_token": GH_TOKEN})),
        _ => (400, json!({"errors": ["permission denied"]})),
    });
    let (device, token) = flow(&base);
    let f = DeviceFlow {
        client_id: "Iv1.test",
        device_code_url: &device,
        token_url: &token,
    };
    let err = login::login_github(
        &UreqTransport::new(),
        &f,
        |_| {},
        |_| {},
        &base,
        "github-user",
        "op",
    )
    .unwrap_err();
    h.join().unwrap();
    assert!(err.to_string().contains("permission denied"), "{err}");
    assert!(!format!("{err} {err:?}").contains(GH_TOKEN));
}

#[test]
fn insecure_worker_address_is_refused_before_github_is_contacted() {
    let (base, h) = routed(5, |_, s| panic!("contacted: {}", s.url));
    let (device, token) = flow(&base);
    let f = DeviceFlow {
        client_id: "Iv1.test",
        device_code_url: &device,
        token_url: &token,
    };
    let err = login::login_github(
        &UreqTransport::new(),
        &f,
        |_| {},
        |_| {},
        "http://kms.example.com",
        "github-user",
        "op",
    )
    .unwrap_err();
    assert!(matches!(err, LoginError::Insecure(_)), "{err}");
    assert!(h.join().unwrap().is_empty());
}

#[test]
fn github_endpoints_default_to_github_com() {
    let f = DeviceFlow::github("Iv1.x");
    assert_eq!(f.device_code_url, "https://github.com/login/device/code");
    assert_eq!(f.token_url, "https://github.com/login/oauth/access_token");
}

#[test]
fn a_zero_polling_interval_is_raised_to_one_second() {
    let (base, h) = routed(10, |_, s| match s.url.as_str() {
        "/login/device/code" => (
            200,
            json!({"device_code": "d", "user_code": "U", "verification_uri": "https://x",
                   "expires_in": 60, "interval": 0}),
        ),
        "/login/oauth/access_token" => (200, json!({"access_token": GH_TOKEN})),
        _ => (200, json!({"auth": {"client_token": "ekms.tok"}})),
    });
    let (device, token) = flow(&base);
    let f = DeviceFlow {
        client_id: "Iv1.test",
        device_code_url: &device,
        token_url: &token,
    };
    let slept = RefCell::new(Vec::new());
    login::login_github(
        &UreqTransport::new(),
        &f,
        |_| {},
        |d| slept.borrow_mut().push(d),
        &base,
        "github-user",
        "op",
    )
    .unwrap();
    h.join().unwrap();
    assert_eq!(slept.into_inner(), vec![Duration::from_secs(1)]);
}
