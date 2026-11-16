//! `edgekms account login` and `edgekms tenant` against a `tiny_http` stub of the control plane,
//! as `tests/login.rs` stubs the Worker. The library functions are tested directly; the rules
//! that live in the binary (the token from the environment only, the root key from stdin only,
//! nothing but the key on stdout) run the built `edgekms` binary against the same stub.

use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::cell::RefCell;

use edgekms_cli::control::{
    self, AccountLogin, AgentKeys, Client, ControlError, ControlTransport, Grant, Import, Info,
    InviteLogin, InviteRequest, Method, Request, RequestState, Requester, Role, SshKey,
    TenantStatus, UreqControl,
};
use edgekms_cli::login::{DeviceFlow, HttpReply, LoginError, Signer, UreqTransport};
use edgekms_core::keyops::SoftKeyOps;
use edgekms_core::ssh;
use edgekms_core::transit::{Id, RootKey};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const GH_TOKEN: &str = "gho_secret_user_token";
const CONTROL_TOKEN: &str = "ekms.control-token-secret";
const CLIENT_ID: &str = "Iv_hosted_test";
const ROOT: [u8; 32] = [7; 32];

/// One request the stub saw, headers included (lowercased names).
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn form(&self, key: &str) -> Option<String> {
        url::form_urlencoded::parse(self.body.as_bytes())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }
}

/// A reply: status, JSON body (or `Value::Null` for an empty body), extra headers.
type Reply = (u16, Value, Vec<(&'static str, String)>);

fn ok(body: Value) -> Reply {
    (200, body, vec![])
}

/// Serves requests with `route(base_url, request)` until `max` have been seen or none arrives
/// for two seconds; the handle yields every request seen.
fn stub(
    max: usize,
    route: impl Fn(&str, &Seen) -> Reply + Send + 'static,
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
                headers: req
                    .headers()
                    .iter()
                    .map(|h| {
                        (
                            h.field.as_str().as_str().to_ascii_lowercase(),
                            h.value.as_str().to_owned(),
                        )
                    })
                    .collect(),
                body,
            };
            let (status, reply, extra) = route(&base, &s);
            seen.push(s);
            let text = if reply.is_null() {
                String::new()
            } else {
                reply.to_string()
            };
            let mut resp = tiny_http::Response::from_string(text)
                .with_status_code(status)
                .with_header(
                    "Content-Type: application/json"
                        .parse::<tiny_http::Header>()
                        .unwrap(),
                );
            for (k, v) in extra {
                resp = resp.with_header(tiny_http::Header::from_bytes(k, v).unwrap());
            }
            req.respond(resp).unwrap();
        }
        seen
    });
    (url, h)
}

fn flow(base: &str) -> (String, String) {
    (
        format!("{base}/login/device/code"),
        format!("{base}/login/oauth/access_token"),
    )
}

fn device_routes(s: &Seen) -> Option<Reply> {
    match s.url.as_str() {
        "/login/device/code" => Some(ok(json!({
            "device_code": "dev-123", "user_code": "ABCD-1234",
            "verification_uri": "https://github.com/login/device", "expires_in": 900, "interval": 5
        }))),
        "/login/oauth/access_token" => Some(ok(json!({"access_token": GH_TOKEN}))),
        _ => None,
    }
}

fn account_login(base: &str, explicit: bool) -> Result<AccountLogin, ControlError> {
    let (device, token) = flow(base);
    let f = DeviceFlow {
        client_id: CLIENT_ID,
        device_code_url: &device,
        token_url: &token,
    };
    control::account_login(
        &UreqTransport::new(),
        &UreqControl::new(),
        &f,
        explicit,
        |_| {},
        |_| {},
        base,
    )
}

fn hosted_config(root_id: &str) -> String {
    json!({
        "root_id": root_id,
        "keys": {"default": {"id": "k_one", "latest_version": 1, "min_decryption_version": 1}},
        "mounts": {"github-user": {"type": "github-user", "client_id": CLIENT_ID}},
        "roles": {"owner": {"mount": "github-user", "github_user_ids": [42],
                            "policies": ["default-all"], "token_ttl_secs": 3600}},
        "policies": {"default-all": {"keys": {"default": ["encrypt", "decrypt"]}}}
    })
    .to_string()
}

/// `GET /v1/tenants/alice` as the control plane answers it: `config` is an object.
fn tenant_data(version: u64) -> Value {
    json!({"data": {
        "name": "alice", "id": "t_0123456789abcdef", "root_id": "r_alice", "status": "active",
        "config": serde_json::from_str::<Value>(&hosted_config("r_alice")).unwrap(),
        "config_version": version,
        "members": [{"github_id": 42, "role": "owner"}],
        "invites": [{"github_id": 77, "role": "member"}]
    }})
}

/// `GET /v1/info`: top level, no `data` envelope.
fn info_reply() -> Reply {
    ok(json!({"github_client_id": CLIENT_ID, "apex": "edgekms.dev"}))
}

/// The stub's answer to `/v1/info`, or `None` for another path.
fn info_route(s: &Seen) -> Option<Reply> {
    (s.url == "/v1/info").then(info_reply)
}

/// A [`ControlTransport`] that answers from a list and records each request, for URLs no stub
/// can serve (`https://api.edgekms.dev`).
struct Mock {
    replies: RefCell<Vec<HttpReply>>,
    seen: RefCell<Vec<(Method, String, bool)>>,
}

impl Mock {
    fn new(replies: Vec<HttpReply>) -> Self {
        Self {
            replies: RefCell::new(replies.into_iter().rev().collect()),
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl ControlTransport for Mock {
    fn send(&self, req: &Request<'_>) -> Result<HttpReply, LoginError> {
        self.seen
            .borrow_mut()
            .push((req.method, req.url.to_owned(), req.bearer.is_some()));
        self.replies
            .borrow_mut()
            .pop()
            .ok_or_else(|| LoginError::Http(format!("unexpected {}", req.url)))
    }
}

fn client<'a>(t: &'a UreqControl, base: &str) -> Client<'a, UreqControl> {
    Client::new(t, base, CONTROL_TOKEN).unwrap()
}

fn bearer() -> String {
    format!("Bearer {CONTROL_TOKEN}")
}

// ---- Account login ----

#[test]
fn account_login_posts_the_github_token_and_prints_only_the_control_token() {
    let (base, h) = stub(10, |_, s| {
        device_routes(s).unwrap_or_else(|| match s.url.as_str() {
            "/v1/login/github" => ok(json!({"data": {
                "token": CONTROL_TOKEN, "expires_in": control::CONTROL_TOKEN_SECS, "github_id": 42,
                "login": "Alice", "created_tenant": "alice", "auth": "github", "ssh_keys": 1
            }})),
            other => panic!("unexpected {other}"),
        })
    });
    let out = account_login(&base, true).unwrap();
    assert_eq!(out.token.as_str(), CONTROL_TOKEN);
    assert_eq!(out.github_id, Some(42));
    assert_eq!(out.login.as_deref(), Some("Alice"));
    assert_eq!(out.created_tenant.as_deref(), Some("alice"));
    assert_eq!(out.ssh_keys, Some(1));
    assert_eq!(out.ssh_fingerprint, None);
    // The summary for stderr names the user and the tenant, never a token.
    let summary = out.summary();
    assert!(
        summary.contains("Alice") && summary.contains("alice") && summary.contains("30 minutes"),
        "{summary}"
    );
    assert!(!summary.contains("SSH key"), "{summary}");
    assert_eq!(
        out.ssh_keys_line().as_deref(),
        Some("1 SSH key can log in to this account; see `edgekms account ssh-keys list`.")
    );
    assert!(!summary.contains(CONTROL_TOKEN) && !summary.contains(GH_TOKEN));

    let seen = h.join().unwrap();
    assert_eq!(seen[0].form("client_id").as_deref(), Some(CLIENT_ID));
    let login = seen.iter().find(|s| s.url == "/v1/login/github").unwrap();
    assert_eq!(login.method, "POST");
    assert_eq!(login.json(), json!({"token": GH_TOKEN}));
    assert_eq!(login.header("authorization"), None);
}

#[test]
fn hosted_client_id_is_not_sent_to_another_host() {
    let (base, h) = stub(5, |_, s| panic!("contacted: {}", s.url));
    let err = account_login(&base, false).unwrap_err();
    assert!(
        matches!(err, ControlError::HostedClientIdElsewhere(_)),
        "{err}"
    );
    assert!(err.to_string().contains("--client-id"), "{err}");
    assert!(h.join().unwrap().is_empty());

    // The rule itself: only https://api.edgekms.dev takes the hosted App's token.
    for api in [
        "https://api.edgekms.dev",
        "https://api.edgekms.dev/",
        "https://API.edgekms.dev",
    ] {
        control::check_api(api, false).unwrap_or_else(|e| panic!("{api}: {e}"));
    }
    for api in [
        "https://api.edgekms.dev.evil.com",
        "https://evil.com",
        "https://api.edgekms.dev:8443",
        "https://user@api.edgekms.dev",
        "https://alice.edgekms.dev",
        "http://localhost:8787",
        // edge.km is not the official apex (it may become an alias later, by adding its API
        // host to HOSTED_API_HOSTS).
        "https://api.edge.km",
    ] {
        assert!(control::check_api(api, false).is_err(), "{api}");
    }
    // The default --api is official, and every official host is https-only and exact.
    control::check_api(control::DEFAULT_API, false).unwrap();
    assert_eq!(control::DEFAULT_API, "https://api.edgekms.dev");
    for host in control::HOSTED_API_HOSTS {
        control::check_api(&format!("https://{host}"), false).unwrap();
        assert!(
            control::check_api(&format!("http://{host}"), false).is_err(),
            "{host}"
        );
    }
    // An explicit --client-id may go anywhere check_addr allows.
    control::check_api("http://localhost:8787", true).unwrap();
    assert!(control::check_api("http://kms.example.com", true).is_err());
}

#[test]
fn redirects_are_not_followed() {
    let (base, h) = stub(5, |base, s| match s.url.as_str() {
        "/v1/me" => (
            302,
            Value::Null,
            vec![("Location", format!("{base}/elsewhere"))],
        ),
        other => panic!("followed the redirect to {other}"),
    });
    let t = UreqControl::new();
    let err = client(&t, &base).me().unwrap_err();
    assert!(
        matches!(err, ControlError::Rejected { status: 302, .. }),
        "{err}"
    );
    assert_eq!(h.join().unwrap().len(), 1);
}

#[test]
fn rejected_control_login_never_echoes_the_github_token() {
    let (base, h) = stub(10, |_, s| {
        device_routes(s).unwrap_or_else(|| (400, json!({"errors": ["invalid token"]}), vec![]))
    });
    let err = account_login(&base, true).unwrap_err();
    h.join().unwrap();
    assert!(err.to_string().contains("invalid token"), "{err}");
    assert!(!format!("{err} {err:?}").contains(GH_TOKEN));
}

#[test]
fn login_client_id_comes_from_the_flag_the_env_or_v1_info() {
    let info = || HttpReply {
        status: 200,
        body: json!({"github_client_id": "Iv_from_info", "apex": "edgekms.dev"}),
    };
    // --client-id: explicit, may go to any address check_addr allows; nothing is fetched.
    let m = Mock::new(vec![]);
    let got = control::login_client_id(&m, "http://127.0.0.1:8787", Some("Iv_mine"), None).unwrap();
    assert_eq!(got, ("Iv_mine".to_owned(), true));
    // The environment names the hosted id: not explicit, nothing fetched.
    let got = control::login_client_id(&m, control::DEFAULT_API, None, Some(" Iv_env ")).unwrap();
    assert_eq!(got, ("Iv_env".to_owned(), false));
    assert!(m.seen.borrow().is_empty());
    // Neither: GET /v1/info, without a token, from api.edgekms.dev only. An empty variable is unset.
    let m = Mock::new(vec![info()]);
    let got = control::login_client_id(&m, "https://api.edgekms.dev/", None, Some("")).unwrap();
    assert_eq!(got, ("Iv_from_info".to_owned(), false));
    assert_eq!(
        m.seen.borrow().as_slice(),
        &[(
            Method::Get,
            "https://api.edgekms.dev/v1/info".to_owned(),
            false
        )]
    );
}

#[test]
fn login_client_id_never_asks_another_host() {
    // Elsewhere, the hosted id (from the env or from that host's own /v1/info) is refused
    // before any request: a server could otherwise name the hosted App and collect its tokens.
    for env in [None, Some("Iv_env")] {
        let m = Mock::new(vec![]);
        let err = control::login_client_id(&m, "http://127.0.0.1:8787", None, env).unwrap_err();
        assert!(
            matches!(err, ControlError::HostedClientIdElsewhere(_)),
            "{err}"
        );
        assert!(m.seen.borrow().is_empty());
    }
}

#[test]
fn hosted_client_id_given_as_the_flag_stays_pinned() {
    // --client-id naming the hosted App, by the constant or by the environment's value, is not
    // an explicit id of the caller's own: it goes to api.edgekms.dev only.
    for (flag, env) in [
        (control::HOSTED_CLIENT_ID, None),
        (" Iv_env ", Some("Iv_env")),
    ] {
        let m = Mock::new(vec![]);
        let err =
            control::login_client_id(&m, "http://127.0.0.1:8787", Some(flag), env).unwrap_err();
        assert!(
            matches!(err, ControlError::HostedClientIdElsewhere(_)),
            "{flag}: {err}"
        );
        let got = control::login_client_id(&m, control::DEFAULT_API, Some(flag), env).unwrap();
        assert_eq!(got, (flag.trim().to_owned(), false));
        assert!(m.seen.borrow().is_empty());
    }
}

#[test]
fn info_needs_both_fields_at_the_top_level() {
    // Wrapped in `data`, as other routes are, is not what /v1/info sends.
    let m = Mock::new(vec![HttpReply {
        status: 200,
        body: json!({"data": {"github_client_id": "Iv_x", "apex": "edgekms.dev"}}),
    }]);
    let err = control::fetch_info(&m, control::DEFAULT_API).unwrap_err();
    assert!(matches!(err, ControlError::Response(_)), "{err}");
    let m = Mock::new(vec![HttpReply {
        status: 404,
        body: json!({"errors": ["unsupported path"]}),
    }]);
    let err = control::login_client_id(&m, control::DEFAULT_API, None, None).unwrap_err();
    assert!(
        matches!(err, ControlError::Rejected { status: 404, .. }),
        "{err}"
    );
    let (base, h) = stub(1, |_, s| info_route(s).unwrap());
    let info = control::fetch_info(&UreqControl::new(), &base).unwrap();
    assert_eq!(
        info,
        Info {
            github_client_id: CLIENT_ID.to_owned(),
            apex: "edgekms.dev".to_owned()
        }
    );
    let seen = h.join().unwrap();
    assert_eq!(seen[0].header("authorization"), None);
}

// ---- Tenant commands, each request against the stub ----

fn me_reply() -> Reply {
    ok(json!({"data": {"github_id": 42, "login": "alice",
                       "tenants": [{"name": "alice", "role": "owner"}, {"name": "team", "role": "member"}],
                       "invites": [{"name": "ops", "role": "owner"}]}}))
}

#[test]
fn list_reads_me() {
    let (base, h) = stub(1, |_, _| me_reply());
    let t = UreqControl::new();
    let me = client(&t, &base).me().unwrap();
    assert_eq!(me.login, "alice");
    assert_eq!(
        me.tenants,
        vec![
            ("alice".to_owned(), "owner".to_owned()),
            ("team".to_owned(), "member".to_owned())
        ]
    );
    assert_eq!(me.invites, vec![("ops".to_owned(), "owner".to_owned())]);
    let seen = h.join().unwrap();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("GET", "/v1/me")
    );
    assert_eq!(seen[0].header("authorization"), Some(bearer().as_str()));
}

#[test]
fn show_gets_the_tenant() {
    let (base, h) = stub(1, |_, _| ok(tenant_data(3)));
    let t = UreqControl::new();
    let data = client(&t, &base).show("alice").unwrap();
    assert_eq!(data["config_version"], 3);
    let seen = h.join().unwrap();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("GET", "/v1/tenants/alice")
    );
    assert_eq!(seen[0].header("authorization"), Some(bearer().as_str()));
}

#[test]
fn tenant_names_are_checked_before_any_request() {
    let (base, h) = stub(5, |_, s| panic!("contacted: {}", s.url));
    let t = UreqControl::new();
    let c = client(&t, &base);
    for bad in ["../ops", "a/b", "Alice", "api", "x"] {
        let err = c.show(bad).unwrap_err();
        assert!(
            matches!(err, ControlError::TenantName { .. }),
            "{bad}: {err}"
        );
    }
    assert!(h.join().unwrap().is_empty());
}

fn created(name: &str, root_id: &str) -> Reply {
    ok(json!({"data": {"name": name, "id": "t_1", "root_id": root_id, "config_version": 1}}))
}

#[test]
fn create_posts_name_and_optional_config() {
    let (base, h) = stub(3, |_, s| {
        info_route(s).unwrap_or_else(|| created("team", "r_x"))
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    let data = c.create("team", None, None).unwrap();
    assert_eq!(data["root_id"], "r_x");
    let config = hosted_config("r_whatever");
    c.create("team", Some(&config), None).unwrap();
    let seen = h.join().unwrap();
    // Without a config, nothing to check: the POST alone.
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("POST", "/v1/tenants")
    );
    assert_eq!(seen[0].header("authorization"), Some(bearer().as_str()));
    assert_eq!(seen[0].json(), json!({"name": "team"}));
    // With one, the rules come from /v1/info first.
    assert_eq!(
        (seen[1].method.as_str(), seen[1].url.as_str()),
        ("GET", "/v1/info")
    );
    assert_eq!(
        seen[2].json(),
        json!({"name": "team", "config": serde_json::from_str::<Value>(&config).unwrap()})
    );
}

#[test]
fn create_without_import_takes_a_config_whatever_its_root_id() {
    // The control plane overwrites root_id with the root it generates, so a config naming
    // another root, or none, is fine locally.
    let (base, h) = stub(4, |_, s| {
        info_route(s).unwrap_or_else(|| created("team", "r_x"))
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    let mut rootless: Value = serde_json::from_str(&hosted_config("r_x")).unwrap();
    rootless.as_object_mut().unwrap().remove("root_id");
    c.create("team", Some(&rootless.to_string()), None).unwrap();
    // Pretty-printed past the cap is fine: POST measures the compacted JSON it stores.
    let config: Value = serde_json::from_str(&hosted_config("r_x")).unwrap();
    let pretty = serde_json::to_string_pretty(&config).unwrap();
    let padded = pretty.replace('\n', &format!("\n{}", " ".repeat(4000)));
    assert!(padded.len() > edgekms_core::hosted::MAX_CONFIG_BYTES);
    c.create("team", Some(&padded), None).unwrap();
    let seen = h.join().unwrap();
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[3].json()["config"], config);
}

#[test]
fn create_checks_configs_against_the_servers_info() {
    // The client id and apex come from /v1/info, not the --api host.
    let (base, h) = stub(5, |_, s| {
        info_route(s).unwrap_or_else(|| panic!("sent {}", s.url))
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    let foreign = hosted_config("r1").replace(CLIENT_ID, "Iv_someone_else");
    let err = c.create("team", Some(&foreign), None).unwrap_err();
    assert!(err.to_string().contains("client_id"), "{err}");
    let mut v: Value = serde_json::from_str(&hosted_config("r1")).unwrap();
    v["mounts"]["oidc"] = json!({"type": "jwt", "issuer": "https://x.example",
                                 "jwks_url": "https://kms.edgekms.dev/jwks"});
    let err = c.create("team", Some(&v.to_string()), None).unwrap_err();
    assert!(err.to_string().contains("edgekms.dev"), "{err}");
    let seen = h.join().unwrap();
    assert!(seen.iter().all(|s| s.url == "/v1/info"), "{seen:?}");
}

#[test]
fn create_with_import_sends_root_id_and_key() {
    let (base, h) = stub(2, |_, s| {
        info_route(s).unwrap_or_else(|| created("bob", "r1"))
    });
    let t = UreqControl::new();
    let config = hosted_config("r1");
    let root_id = Id::new("r1").unwrap();
    client(&t, &base)
        .create(
            "bob",
            Some(&config),
            Some(Import {
                root_id: &root_id,
                root_key: &ROOT,
            }),
        )
        .unwrap();
    let seen = h.join().unwrap();
    assert_eq!(seen[0].url, "/v1/info");
    let body = seen[1].json();
    assert_eq!(
        body["import"],
        json!({"root_id": "r1", "root_key": STANDARD.encode(ROOT)})
    );
    assert_eq!(body["config"]["root_id"], "r1");
}

#[test]
fn create_with_import_validates_locally_first() {
    // Only the rules are read; nothing is created.
    let (base, h) = stub(5, |_, s| {
        info_route(s).unwrap_or_else(|| panic!("sent: {}", s.url))
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    let root_id = Id::new("r1").unwrap();
    let import = || {
        Some(Import {
            root_id: &root_id,
            root_key: &ROOT,
        })
    };
    // An import needs the config naming the tenant's existing keys.
    let err = c.create("bob", None, import()).unwrap_err();
    assert!(err.to_string().contains("--config"), "{err}");
    // Its root_id must be the imported one.
    let err = c
        .create("bob", Some(&hosted_config("r2")), import())
        .unwrap_err();
    assert!(err.to_string().contains("root_id"), "{err}");
    // A github-user mount must use the hosted App.
    let foreign = hosted_config("r1").replace(CLIENT_ID, "Iv_someone_else");
    let err = c.create("bob", Some(&foreign), import()).unwrap_err();
    assert!(err.to_string().contains("client_id"), "{err}");
    let seen = h.join().unwrap();
    assert!(seen.iter().all(|s| s.url == "/v1/info"), "{seen:?}");
}

#[test]
fn config_get_returns_the_config_and_version() {
    let (base, h) = stub(1, |_, _| ok(tenant_data(7)));
    let t = UreqControl::new();
    let (config, version) = client(&t, &base).config_get("alice").unwrap();
    assert_eq!(version, 7);
    assert_eq!(config, hosted_config("r_alice"));
    let seen = h.join().unwrap();
    assert_eq!(seen[0].url, "/v1/tenants/alice");
}

#[test]
fn config_get_wants_a_config_object() {
    // The control plane sends config as an object, never as a string of JSON.
    let (base, h) = stub(1, |_, _| {
        let mut d = tenant_data(2);
        d["data"]["config"] = json!(hosted_config("r_alice"));
        ok(d)
    });
    let t = UreqControl::new();
    let err = client(&t, &base).config_get("alice").unwrap_err();
    assert!(matches!(err, ControlError::Response(_)), "{err}");
    h.join().unwrap();
}

#[test]
fn config_set_reads_the_version_then_puts_with_if_match() {
    let (base, h) = stub(3, |_, s| match s.method.as_str() {
        "GET" => info_route(s).unwrap_or_else(|| ok(tenant_data(4))),
        "PUT" => ok(json!({"data": {"config_version": 5}})),
        m => panic!("unexpected {m}"),
    });
    let t = UreqControl::new();
    let config = hosted_config("r_alice");
    let mut noticed = None;
    let v = client(&t, &base)
        .config_set("alice", &config, None, |v| noticed = Some(v))
        .unwrap();
    assert_eq!(v, 5);
    assert_eq!(noticed, Some(4));
    let seen = h.join().unwrap();
    let urls: Vec<_> = seen.iter().map(|s| s.url.as_str()).collect();
    assert_eq!(
        urls,
        ["/v1/tenants/alice", "/v1/info", "/v1/tenants/alice/config"]
    );
    assert_eq!(seen[2].method, "PUT");
    assert_eq!(seen[2].header("if-match"), Some("\"4\""));
    assert_eq!(seen[2].header("authorization"), Some(bearer().as_str()));
    assert_eq!(seen[2].body, config);
}

#[test]
fn config_set_with_if_version_uses_it() {
    let (base, h) = stub(3, |_, s| match s.method.as_str() {
        "GET" => info_route(s).unwrap_or_else(|| ok(tenant_data(9))),
        _ => ok(json!({"data": {"config_version": 3}})),
    });
    let t = UreqControl::new();
    let mut noticed = None;
    client(&t, &base)
        .config_set("alice", &hosted_config("r_alice"), Some(2), |v| {
            noticed = Some(v);
        })
        .unwrap();
    assert_eq!(noticed, None);
    let seen = h.join().unwrap();
    assert_eq!(seen.last().unwrap().header("if-match"), Some("\"2\""));
}

#[test]
fn config_set_stale_version_is_reported() {
    let (base, h) = stub(3, |_, s| match s.method.as_str() {
        "GET" => info_route(s).unwrap_or_else(|| ok(tenant_data(4))),
        _ => (409, json!({"errors": ["config version mismatch"]}), vec![]),
    });
    let t = UreqControl::new();
    let err = client(&t, &base)
        .config_set("alice", &hosted_config("r_alice"), Some(3), |_| {})
        .unwrap_err();
    assert!(matches!(err, ControlError::Stale(3)), "{err}");
    h.join().unwrap();
}

#[test]
fn config_set_validates_locally_before_sending() {
    let (base, h) = stub(5, |_, s| match s.method.as_str() {
        "GET" => info_route(s).unwrap_or_else(|| ok(tenant_data(4))),
        m => panic!("sent a {m}"),
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    // Not a config at all: refused before any request.
    let err = c
        .config_set("alice", "{not json", None, |_| {})
        .unwrap_err();
    assert!(matches!(err, ControlError::Config(_)), "{err}");
    // Valid JSON, but public_origins breaks the hosted rules.
    let mut v: Value = serde_json::from_str(&hosted_config("r_alice")).unwrap();
    v["public_origins"] = json!(["https://alice.edgekms.dev"]);
    let err = c
        .config_set("alice", &v.to_string(), None, |_| {})
        .unwrap_err();
    assert!(err.to_string().contains("public_origins"), "{err}");
    // The tenant's root id comes from the control plane; a config naming another is refused.
    let err = c
        .config_set("alice", &hosted_config("r_other"), None, |_| {})
        .unwrap_err();
    assert!(err.to_string().contains("root_id"), "{err}");
    // Over the size cap: refused before parsing or sending.
    let huge = " ".repeat(edgekms_core::hosted::MAX_CONFIG_BYTES + 1);
    let err = c.config_set("alice", &huge, None, |_| {}).unwrap_err();
    assert!(err.to_string().contains("bytes"), "{err}");
    let seen = h.join().unwrap();
    assert!(seen.iter().all(|s| s.method == "GET"), "{seen:?}");
}

#[test]
fn member_add_is_an_invite_and_says_which() {
    // PUT and DELETE are 204 with no body; the tenant read afterwards tells invite from change.
    let (base, h) = stub(7, |_, s| match s.method.as_str() {
        "GET" => ok(tenant_data(1)),
        _ => (204, Value::Null, vec![]),
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    // 77 shows up among the invites: an invite, nothing granted yet.
    assert_eq!(
        c.set_member("alice", 77, Role::Member).unwrap(),
        Grant::Invited
    );
    // 42 holds owner already (or was just lowered to it): applied.
    assert_eq!(
        c.set_member("alice", 42, Role::Owner).unwrap(),
        Grant::Applied
    );
    // Neither list shows it: unconfirmed.
    assert_eq!(
        c.set_member("alice", 78, Role::Owner).unwrap(),
        Grant::Unconfirmed
    );
    c.remove_member("alice", 77).unwrap();
    let seen = h.join().unwrap();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("PUT", "/v1/tenants/alice/members/77")
    );
    assert_eq!(seen[0].json(), json!({"role": "member"}));
    assert_eq!(
        (seen[1].method.as_str(), seen[1].url.as_str()),
        ("GET", "/v1/tenants/alice")
    );
    assert_eq!(seen[2].json(), json!({"role": "owner"}));
    assert_eq!(
        (seen[6].method.as_str(), seen[6].url.as_str()),
        ("DELETE", "/v1/tenants/alice/members/77")
    );
    for s in &seen {
        assert_eq!(s.header("authorization"), Some(bearer().as_str()));
    }
}

#[test]
fn member_add_refused_while_suspended_surfaces_the_error() {
    let (base, h) = stub(1, |_, _| {
        (403, json!({"errors": ["tenant is suspended"]}), vec![])
    });
    let t = UreqControl::new();
    let err = client(&t, &base)
        .set_member("alice", 77, Role::Member)
        .unwrap_err();
    assert!(
        matches!(err, ControlError::Rejected { status: 403, ref message } if message == "tenant is suspended"),
        "{err}"
    );
    h.join().unwrap();
}

#[test]
fn accept_and_decline_post_empty_bodies() {
    let (base, h) = stub(2, |_, s| match s.url.as_str() {
        "/v1/tenants/ops/accept" => ok(json!({"data": {"name": "ops", "role": "owner"}})),
        "/v1/tenants/team/decline" => (204, Value::Null, vec![]),
        other => panic!("unexpected {other}"),
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    assert_eq!(c.accept("ops").unwrap(), "owner");
    c.decline("team").unwrap();
    let seen = h.join().unwrap();
    for s in &seen {
        assert_eq!(s.method, "POST");
        assert_eq!(s.json(), json!({}));
        assert_eq!(s.header("authorization"), Some(bearer().as_str()));
    }
}

#[test]
fn accept_without_an_invite_is_the_servers_404() {
    let (base, h) = stub(1, |_, _| {
        (404, json!({"errors": ["tenant not found"]}), vec![])
    });
    let t = UreqControl::new();
    let err = client(&t, &base).accept("ops").unwrap_err();
    assert!(
        matches!(err, ControlError::Rejected { status: 404, .. }),
        "{err}"
    );
    h.join().unwrap();
}

#[test]
fn logout_posts_with_the_token() {
    let (base, h) = stub(1, |_, _| (204, Value::Null, vec![]));
    let t = UreqControl::new();
    client(&t, &base).logout().unwrap();
    let seen = h.join().unwrap();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("POST", "/v1/logout")
    );
    assert_eq!(seen[0].header("authorization"), Some(bearer().as_str()));
}

#[test]
fn a_204_marked_gzip_is_not_decoded() {
    // workerd sends the Worker's empty 204s with `Content-Encoding: gzip` to a client that
    // accepts gzip (found by scripts/e2e-hosted.sh); decoding the empty body would fail.
    let (base, h) = stub(2, |_, _| {
        (204, Value::Null, vec![("Content-Encoding", "gzip".into())])
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    c.remove_member("alice", 42).unwrap();
    c.logout().unwrap();
    assert_eq!(h.join().unwrap().len(), 2);
}

#[test]
fn removing_the_last_owner_surfaces_the_servers_error() {
    let (base, h) = stub(1, |_, _| {
        (400, json!({"errors": ["tenant needs an owner"]}), vec![])
    });
    let t = UreqControl::new();
    let err = client(&t, &base).remove_member("alice", 42).unwrap_err();
    assert!(err.to_string().contains("tenant needs an owner"), "{err}");
    h.join().unwrap();
}

#[test]
fn export_posts_and_returns_the_key() {
    let (base, h) = stub(1, |_, _| {
        ok(json!({"data": {"root_id": "r_alice", "root_key": STANDARD.encode(ROOT)}}))
    });
    let t = UreqControl::new();
    let out = client(&t, &base).export("alice").unwrap();
    assert_eq!(out.root_id, "r_alice");
    assert_eq!(out.root_key.as_str(), STANDARD.encode(ROOT));
    let seen = h.join().unwrap();
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("POST", "/v1/tenants/alice/export")
    );
    assert_eq!(seen[0].header("authorization"), Some(bearer().as_str()));
}

#[test]
fn export_needing_a_fresh_login_says_so() {
    let (base, h) = stub(2, |_, s| {
        let msg = if s.url.contains("alice") {
            "fresh login required"
        } else {
            "a fresh login required elsewhere"
        };
        (403, json!({"errors": [msg]}), vec![])
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    let err = c.export("alice").unwrap_err();
    assert!(matches!(err, ControlError::StaleLogin), "{err}");
    assert!(err.to_string().contains("account login"), "{err}");
    // Only the exact string: any other 403 is the server's own refusal.
    let err = c.export("bob1").unwrap_err();
    assert!(
        matches!(err, ControlError::Rejected { status: 403, .. }),
        "{err}"
    );
    let seen = h.join().unwrap();
    assert!(seen.iter().all(|s| s.json() == json!({})), "{seen:?}");
}

#[test]
fn export_refuses_a_reply_that_is_not_a_root_key() {
    let (base, h) = stub(1, |_, _| {
        ok(json!({"data": {"root_id": "r_alice", "root_key": "not base64!"}}))
    });
    let t = UreqControl::new();
    let err = client(&t, &base).export("alice").unwrap_err();
    assert!(matches!(err, ControlError::Response(_)), "{err}");
    h.join().unwrap();
}

#[test]
fn errors_never_carry_the_control_token() {
    let (base, h) = stub(1, |_, _| {
        (403, json!({"errors": ["permission denied"]}), vec![])
    });
    let t = UreqControl::new();
    let err = client(&t, &base).me().unwrap_err();
    h.join().unwrap();
    assert!(!format!("{err} {err:?}").contains(CONTROL_TOKEN));
}

#[test]
fn insecure_api_is_refused() {
    let t = UreqControl::new();
    let err = Client::new(&t, "http://kms.example.com", CONTROL_TOKEN)
        .err()
        .unwrap();
    assert!(
        matches!(err, ControlError::Login(LoginError::Insecure(_))),
        "{err}"
    );
}

#[test]
fn transport_sends_no_authorization_without_a_bearer() {
    let (base, h) = stub(1, |_, _| ok(json!({})));
    UreqControl::new()
        .send(&Request {
            method: Method::Get,
            url: &format!("{base}/x"),
            bearer: None,
            if_match: None,
            body: None,
        })
        .unwrap();
    assert_eq!(h.join().unwrap()[0].header("authorization"), None);
}

// ---- The binary: token, root key and stdout rules ----

fn edgekms(args: &[&str], token: Option<&str>, stdin: Option<&str>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_edgekms"));
    cmd.args(args)
        .env_remove(control::CONTROL_TOKEN_ENV)
        .env_remove(control::HOSTED_CLIENT_ID_ENV)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(t) = token {
        cmd.env(control::CONTROL_TOKEN_ENV, t);
    }
    let mut child = cmd.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn token_comes_from_env_never_argv() {
    let (base, h) = stub(1, |_, _| {
        ok(json!({"data": {"github_id": 42, "login": "alice", "tenants": [], "invites": []}}))
    });
    // There is no flag for it.
    for flag in ["--token", "--control-token"] {
        let out = edgekms(
            &["tenant", "list", "--api", &base, flag, CONTROL_TOKEN],
            None,
            None,
        );
        assert!(!out.status.success());
        assert!(text(&out.stderr).contains("unexpected argument"), "{flag}");
    }
    // Without the variable, nothing is sent.
    let out = edgekms(&["tenant", "list", "--api", &base], None, None);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains(control::CONTROL_TOKEN_ENV),
        "{}",
        text(&out.stderr)
    );
    // With it, it goes in the Authorization header.
    let out = edgekms(
        &["tenant", "list", "--api", &base],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let seen = h.join().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].header("authorization"), Some(bearer().as_str()));
    assert!(!text(&out.stdout).contains(CONTROL_TOKEN));
    assert!(!text(&out.stderr).contains(CONTROL_TOKEN));
}

#[test]
fn create_with_import_reads_root_from_stdin_only() {
    let (base, h) = stub(2, |_, s| {
        info_route(s).unwrap_or_else(|| created("bob", "r1"))
    });
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.json");
    std::fs::write(&config, hosted_config("r1")).unwrap();
    let config = config.to_str().unwrap();
    let key = STANDARD.encode(ROOT);

    // No flag takes the key.
    let out = edgekms(
        &[
            "tenant",
            "create",
            "bob",
            "--api",
            &base,
            "--config",
            config,
            "--import-root-id",
            "r1",
            "--root-key",
            &key,
        ],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("unexpected argument"));

    // An empty stdin is not a key; nothing is sent.
    let args = [
        "tenant",
        "create",
        "bob",
        "--api",
        &base,
        "--config",
        config,
        "--import-root-id",
        "r1",
    ];
    let out = edgekms(&args, Some(CONTROL_TOKEN), Some(""));
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("root key"),
        "{}",
        text(&out.stderr)
    );

    let out = edgekms(&args, Some(CONTROL_TOKEN), Some(&format!("{key}\n")));
    assert!(out.status.success(), "{}", text(&out.stderr));
    let seen = h.join().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].json()["import"]["root_key"], key);
    assert!(!text(&out.stdout).contains(&key) && !text(&out.stderr).contains(&key));
}

#[test]
fn export_prints_only_the_key_on_stdout() {
    let key = STANDARD.encode(ROOT);
    let reply_key = key.clone();
    let (base, h) = stub(1, move |_, _| {
        ok(json!({"data": {"root_id": "r_alice", "root_key": reply_key}}))
    });
    let out = edgekms(
        &["tenant", "export", "alice", "--api", &base],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    h.join().unwrap();
    assert_eq!(text(&out.stdout), format!("{key}\n"));
    let err = text(&out.stderr);
    assert!(err.contains("r_alice"), "{err}");
    assert!(err.contains("warning"), "{err}");
    assert!(!err.contains(&key));
}

#[test]
fn config_get_prints_config_on_stdout_and_version_on_stderr() {
    let (base, h) = stub(1, |_, _| ok(tenant_data(6)));
    let out = edgekms(
        &["tenant", "config", "get", "alice", "--api", &base],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    h.join().unwrap();
    assert_eq!(text(&out.stdout), format!("{}\n", hosted_config("r_alice")));
    assert!(text(&out.stderr).contains('6'));
}

#[test]
fn account_login_binary_refuses_the_hosted_id_elsewhere_before_github() {
    // No server at all: the refusal comes before any connection.
    let out = edgekms(
        &["account", "login", "--api", "http://127.0.0.1:9"],
        None,
        None,
    );
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("--client-id"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn invites_lists_pending_invites_apart_from_tenants() {
    let (base, h) = stub(2, |_, _| me_reply());
    let out = edgekms(
        &["tenant", "invites", "--api", &base],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ops\towner\n");
    assert!(text(&out.stderr).contains("tenant accept"));
    // `list` shows accepted tenants only, and points at the invites.
    let out = edgekms(
        &["tenant", "list", "--api", &base],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "alice\towner\nteam\tmember\n");
    assert!(text(&out.stderr).contains("1 pending invite"));
    h.join().unwrap();
}

#[test]
fn accept_decline_and_member_add_say_what_happened() {
    let (base, h) = stub(4, |_, s| match (s.method.as_str(), s.url.as_str()) {
        ("POST", "/v1/tenants/ops/accept") => ok(json!({"data": {"name": "ops", "role": "owner"}})),
        ("GET", "/v1/tenants/alice") => ok(tenant_data(1)),
        _ => (204, Value::Null, vec![]),
    });
    let run = |args: &[&str]| {
        let mut all = args.to_vec();
        all.extend(["--api", &base]);
        let out = edgekms(&all, Some(CONTROL_TOKEN), None);
        assert!(out.status.success(), "{args:?}: {}", text(&out.stderr));
        assert_eq!(text(&out.stdout), "");
        text(&out.stderr)
    };
    let err = run(&["tenant", "accept", "ops"]);
    assert!(err.contains("an owner of ops"), "{err}");
    let err = run(&["tenant", "decline", "team"]);
    assert!(err.contains("Declined"), "{err}");
    let err = run(&["tenant", "member", "add", "alice", "--github-id", "77"]);
    assert!(
        err.contains("Invited GitHub id 77") && err.contains("tenant accept alice"),
        "{err}"
    );
    h.join().unwrap();
}

#[test]
fn account_logout_posts_with_the_env_token() {
    let (base, h) = stub(1, |_, _| (204, Value::Null, vec![]));
    let out = edgekms(&["account", "logout", "--api", &base], None, None);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains(control::CONTROL_TOKEN_ENV));
    let out = edgekms(
        &["account", "logout", "--api", &base],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let seen = h.join().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].url.as_str()),
        ("POST", "/v1/logout")
    );
    assert_eq!(seen[0].header("authorization"), Some(bearer().as_str()));
}

#[test]
fn a_refused_token_points_at_its_1800_second_life() {
    let (base, h) = stub(1, |_, _| {
        (403, json!({"errors": ["permission denied"]}), vec![])
    });
    let out = edgekms(
        &["tenant", "list", "--api", &base],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(!out.status.success());
    let err = text(&out.stderr);
    assert!(
        err.contains("1800") && err.contains("account login"),
        "{err}"
    );
    h.join().unwrap();
}

#[test]
fn help_mentions_the_token_life() {
    let out = edgekms(&["account", "login", "--help"], None, None);
    assert!(text(&out.stdout).contains("1800 seconds"));
}

// ---- The signup gate, the naming rule and the operator allowlist ----

#[test]
fn signup_closed_login_says_invite_only() {
    let (base, h) = stub(10, |_, s| {
        device_routes(s).unwrap_or_else(|| {
            (
                403,
                json!({"errors": ["signups are closed"], "code": "signup_closed"}),
                vec![],
            )
        })
    });
    let err = account_login(&base, true).unwrap_err();
    h.join().unwrap();
    assert!(matches!(err, ControlError::SignupClosed), "{err}");
    let text = err.to_string();
    assert!(text.contains("invite-only"), "{text}");
    assert!(text.contains("edgekms account request-invite"), "{text}");
    assert!(text.contains(control::INVITE_URL), "{text}");
    assert!(!format!("{err} {err:?}").contains(GH_TOKEN));
}

#[test]
fn other_login_refusals_are_not_the_signup_message() {
    // A 403 without the code is the server's own refusal, passed through.
    let (base, h) = stub(10, |_, s| {
        device_routes(s).unwrap_or_else(|| (403, json!({"errors": ["signups are closed"]}), vec![]))
    });
    let err = account_login(&base, true).unwrap_err();
    h.join().unwrap();
    assert!(
        matches!(err, ControlError::Rejected { status: 403, .. }),
        "{err}"
    );
}

#[test]
fn create_refused_by_the_naming_rule_explains_it() {
    let (base, h) = stub(1, |_, _| {
        (
            403,
            json!({"errors": ["tenant name must start with alice-"], "code": "tenant_name_prefix"}),
            vec![],
        )
    });
    let t = UreqControl::new();
    let err = client(&t, &base).create("team", None, None).unwrap_err();
    h.join().unwrap();
    assert!(matches!(err, ControlError::TenantNamePrefix(_)), "{err}");
    let text = err.to_string();
    assert!(
        text.contains("tenant name must start with alice-"),
        "{text}"
    );
    assert!(text.contains("personal tenant"), "{text}");
    assert!(text.contains("alice-team"), "{text}");
}

#[test]
fn allowlist_commands_call_the_operator_routes() {
    let (base, h) = stub(3, |_, s| match s.method.as_str() {
        "GET" => ok(json!({"data": {
            "allowlist": [{"github_id": 42, "added_by": 9, "added_ms": 1_800_000_000_000_u64}],
            "unverified": [77]
        }})),
        _ => (204, Value::Null, vec![]),
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    c.allowlist_add(42).unwrap();
    c.allowlist_remove(42).unwrap();
    let list = c.allowlist().unwrap();
    assert_eq!(list.entries, vec![(42, 9, 1_800_000_000_000)]);
    assert_eq!(list.unverified, vec![77]);
    let seen = h.join().unwrap();
    let calls: Vec<_> = seen
        .iter()
        .map(|s| (s.method.as_str(), s.url.as_str()))
        .collect();
    assert_eq!(
        calls,
        [
            ("PUT", "/v1/ops/allowlist/42"),
            ("DELETE", "/v1/ops/allowlist/42"),
            ("GET", "/v1/ops/allowlist"),
        ]
    );
    assert_eq!(seen[0].json(), json!({}));
    assert!(
        seen.iter()
            .all(|s| s.header("authorization") == Some(bearer().as_str()))
    );
}

#[test]
fn allowlist_remove_of_an_absent_id_surfaces_the_404() {
    let (base, h) = stub(1, |_, _| {
        (404, json!({"errors": ["not on the allowlist"]}), vec![])
    });
    let t = UreqControl::new();
    let err = client(&t, &base).allowlist_remove(42).unwrap_err();
    h.join().unwrap();
    assert!(err.to_string().contains("not on the allowlist"), "{err}");
}

#[test]
fn ops_allowlist_binary_prints_the_list_and_says_what_it_did() {
    let (base, h) = stub(3, |_, s| match s.method.as_str() {
        "GET" => ok(json!({"data": {
            "allowlist": [{"github_id": 42, "added_by": 9, "added_ms": 1_800_000_000_000_u64},
                          {"github_id": 43, "added_by": 9, "added_ms": 1_800_000_000_001_u64}],
            "unverified": [77]
        }})),
        _ => (204, Value::Null, vec![]),
    });
    let run = |args: &[&str]| {
        let mut all = args.to_vec();
        all.extend(["--api", &base]);
        let out = edgekms(&all, Some(CONTROL_TOKEN), None);
        assert!(out.status.success(), "{args:?}: {}", text(&out.stderr));
        (text(&out.stdout), text(&out.stderr))
    };
    let (out, err) = run(&["ops", "allowlist", "add", "42"]);
    assert_eq!(out, "");
    assert!(
        err.contains("GitHub id 42") && err.contains("allowlist"),
        "{err}"
    );
    let (out, err) = run(&["ops", "allowlist", "remove", "42"]);
    assert_eq!(out, "");
    assert!(err.contains("Removed GitHub id 42"), "{err}");
    let (out, err) = run(&["ops", "allowlist", "list"]);
    assert_eq!(out, "42\t9\t1800000000000\n43\t9\t1800000000001\n");
    assert!(err.contains("77"), "{err}");
    h.join().unwrap();
}

#[test]
fn tenant_status_calls_the_operator_route() {
    let (base, h) = stub(2, |_, _| (204, Value::Null, vec![]));
    let t = UreqControl::new();
    let c = client(&t, &base);
    c.set_tenant_status("acme", TenantStatus::Suspended)
        .unwrap();
    c.set_tenant_status("acme", TenantStatus::Active).unwrap();
    let seen = h.join().unwrap();
    let calls: Vec<_> = seen
        .iter()
        .map(|s| (s.method.as_str(), s.url.as_str(), s.json()))
        .collect();
    assert_eq!(
        calls,
        [
            (
                "PUT",
                "/v1/ops/tenants/acme/status",
                json!({"status": "suspended"})
            ),
            (
                "PUT",
                "/v1/ops/tenants/acme/status",
                json!({"status": "active"})
            ),
        ]
    );
    assert!(
        seen.iter()
            .all(|s| s.header("authorization") == Some(bearer().as_str()))
    );
}

#[test]
fn tenant_status_refuses_a_bad_name_without_a_request() {
    let t = UreqControl::new();
    let c = client(&t, "http://127.0.0.1:9");
    let err = c
        .set_tenant_status("Not A Name", TenantStatus::Suspended)
        .unwrap_err();
    assert!(matches!(err, ControlError::TenantName { .. }), "{err}");
}

#[test]
fn tenant_status_surfaces_the_404() {
    let (base, h) = stub(1, |_, _| {
        (404, json!({"errors": ["tenant not found"]}), vec![])
    });
    let t = UreqControl::new();
    let err = client(&t, &base)
        .set_tenant_status("acme", TenantStatus::Active)
        .unwrap_err();
    h.join().unwrap();
    assert!(err.to_string().contains("tenant not found"), "{err}");
}

#[test]
fn ops_tenant_binary_suspends_and_resumes() {
    let (base, h) = stub(2, |_, _| (204, Value::Null, vec![]));
    let run = |args: &[&str]| {
        let mut all = args.to_vec();
        all.extend(["--api", &base]);
        let out = edgekms(&all, Some(CONTROL_TOKEN), None);
        assert!(out.status.success(), "{args:?}: {}", text(&out.stderr));
        (text(&out.stdout), text(&out.stderr))
    };
    let (out, err) = run(&["ops", "tenant", "suspend", "acme"]);
    assert_eq!(out, "");
    assert!(err.contains("acme is suspended"), "{err}");
    let (out, err) = run(&["ops", "tenant", "resume", "acme"]);
    assert_eq!(out, "");
    assert!(err.contains("acme is active"), "{err}");
    let seen = h.join().unwrap();
    assert_eq!(seen[0].json(), json!({"status": "suspended"}));
    assert_eq!(seen[1].json(), json!({"status": "active"}));
}

#[test]
fn ops_allowlist_needs_the_control_token() {
    let out = edgekms(
        &["ops", "allowlist", "list", "--api", "http://127.0.0.1:9"],
        None,
        None,
    );
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains(control::CONTROL_TOKEN_ENV));
}

// ---- #54: invite requests ----

const REQUEST_TOKEN: &str = "ekms.request-token-secret";

/// The control plane's refusal of a login in invite mode, with a request token.
fn refused_with_token() -> Reply {
    (
        403,
        json!({"errors": ["signups are closed"], "code": "signup_closed",
               "request_token": REQUEST_TOKEN, "request_expires_in": 900}),
        vec![],
    )
}

fn request_invite_login(base: &str) -> Result<InviteLogin, ControlError> {
    let (device, token) = flow(base);
    let f = DeviceFlow {
        client_id: CLIENT_ID,
        device_code_url: &device,
        token_url: &token,
    };
    control::request_invite_login(
        &UreqTransport::new(),
        &UreqControl::new(),
        &f,
        true,
        |_| {},
        |_| {},
        base,
    )
}

fn mine_reply(request: &Value, accepting: bool) -> Reply {
    ok(
        json!({"data": {"github_id": 77, "login": "carol", "accepting": accepting,
                       "request": request}}),
    )
}

#[test]
fn invite_url_is_the_console_page() {
    assert_eq!(
        control::INVITE_URL,
        "https://app.edgekms.dev/request-invite"
    );
}

#[test]
fn request_invite_login_hands_back_the_request_token() {
    let (base, h) = stub(10, |_, s| {
        device_routes(s).unwrap_or_else(refused_with_token)
    });
    let out = request_invite_login(&base).unwrap();
    let seen = h.join().unwrap();
    assert_eq!(seen.last().unwrap().url, "/v1/login/github");
    match &out {
        InviteLogin::Refused(token) => assert_eq!(token.as_str(), REQUEST_TOKEN),
        other => panic!("{other:?}"),
    }
    // Its Debug never shows the token.
    assert!(!format!("{out:?}").contains(REQUEST_TOKEN));
}

#[test]
fn request_invite_when_admitted_says_so_and_keeps_no_token() {
    let (base, h) = stub(10, |_, s| {
        device_routes(s).unwrap_or_else(|| {
            ok(json!({"data": {"token": CONTROL_TOKEN, "expires_in": 1800,
                               "github_id": 77, "login": "carol"}}))
        })
    });
    let out = request_invite_login(&base).unwrap();
    h.join().unwrap();
    assert!(matches!(out, InviteLogin::Admitted), "{out:?}");
    assert!(!format!("{out:?}").contains(CONTROL_TOKEN));
}

#[test]
fn request_invite_without_a_token_says_not_taking_requests() {
    let (base, h) = stub(10, |_, s| {
        device_routes(s).unwrap_or_else(|| {
            (
                403,
                json!({"errors": ["signups are closed"], "code": "signup_closed"}),
                vec![],
            )
        })
    });
    let out = request_invite_login(&base).unwrap();
    h.join().unwrap();
    assert!(matches!(out, InviteLogin::Closed), "{out:?}");
}

#[test]
fn requester_reads_and_files_with_the_request_token() {
    let (base, h) = stub(2, |_, s| match (s.method.as_str(), s.url.as_str()) {
        ("GET", "/v1/invite-requests/mine") => mine_reply(&Value::Null, true),
        ("POST", "/v1/invite-requests") => (
            201,
            json!({"data": {"status": "pending", "created_ms": 1_762_819_200_000_u64}}),
            vec![],
        ),
        _ => (404, json!({"errors": ["unsupported path"]}), vec![]),
    });
    let t = UreqControl::new();
    let r = Requester::new(&t, &base, REQUEST_TOKEN).unwrap();
    let mine = r.mine().unwrap();
    assert_eq!((mine.github_id, mine.login.as_str()), (77, "carol"));
    assert!(mine.accepting);
    assert_eq!(mine.request, None);
    assert_eq!(r.file("  CI signing\n").unwrap(), 1_762_819_200_000);
    let seen = h.join().unwrap();
    for s in &seen {
        assert_eq!(
            s.header("authorization"),
            Some(format!("Bearer {REQUEST_TOKEN}").as_str())
        );
    }
    // Sent trimmed, as the control plane stores it.
    assert_eq!(seen[1].json(), json!({"note": "CI signing"}));
}

#[test]
fn requester_reads_an_existing_request() {
    let (base, h) = stub(1, |_, _| {
        mine_reply(
            &json!({"status": "declined", "created_ms": 1_762_819_200_000_u64,
                   "decided_ms": 1_762_905_600_000_u64}),
            true,
        )
    });
    let t = UreqControl::new();
    let mine = Requester::new(&t, &base, REQUEST_TOKEN)
        .unwrap()
        .mine()
        .unwrap();
    h.join().unwrap();
    assert_eq!(
        mine.request,
        Some(RequestState {
            status: "declined".into(),
            created_ms: 1_762_819_200_000,
            decided_ms: Some(1_762_905_600_000),
        })
    );
}

#[test]
fn request_invite_checks_the_note_before_sending() {
    let mock = Mock::new(vec![]);
    let r = Requester::new(&mock, "https://api.edgekms.dev", REQUEST_TOKEN).unwrap();
    for bad in ["a\u{1b}[2Jb", "a\rb", "a\u{202e}b", &"x".repeat(501)] {
        let err = r.file(bad).unwrap_err();
        assert!(matches!(err, ControlError::Note(_)), "{err}");
    }
    assert!(mock.seen.borrow().is_empty(), "nothing was sent");
}

#[test]
fn filing_refusals_say_what_they_mean() {
    for (status, code, want) in [
        (409, "already_admitted", "edgekms account login"),
        (409, "already_requested", "already asked"),
        (409, "request_declined", "wasn't approved"),
        (
            403,
            "invite_requests_closed",
            "isn't taking invite requests",
        ),
        (503, "invite_requests_full", "try again later"),
        (
            400,
            "note_invalid",
            "the note must be at most 500 characters",
        ),
    ] {
        let msg = if code == "note_invalid" {
            "the note must be at most 500 characters"
        } else {
            "refused"
        };
        let mock = Mock::new(vec![HttpReply {
            status,
            body: json!({"errors": [msg], "code": code}),
        }]);
        let err = Requester::new(&mock, "https://api.edgekms.dev", REQUEST_TOKEN)
            .unwrap()
            .file("hello")
            .unwrap_err();
        assert!(err.to_string().contains(want), "{code}: {err}");
        assert!(!format!("{err} {err:?}").contains(REQUEST_TOKEN));
    }
}

#[test]
fn utc_dates_are_calendar_days() {
    assert_eq!(control::utc_date(0), "1970-01-01");
    assert_eq!(control::utc_date(1_762_819_200_000), "2025-11-11");
    assert_eq!(control::utc_date(1_762_905_599_999), "2025-11-11");
    assert_eq!(control::utc_date(951_782_400_000), "2000-02-29");
    assert_eq!(control::utc_date(4_107_542_400_000), "2100-03-01");
}

fn invite_requests_reply() -> Reply {
    ok(json!({"data": {
        "requests": [
            {"github_id": 77, "login": "carol", "note": "CI signing\nfor a small project",
             "created_ms": 1_762_819_200_000_u64, "status": "pending",
             "decided_by": null, "decided_ms": null},
            {"github_id": 78, "login": "dave", "note": "",
             "created_ms": 1_762_732_800_000_u64, "status": "declined",
             "decided_by": 9, "decided_ms": 1_762_905_600_000_u64}
        ],
        "unverified": [79],
        "pending": 1
    }}))
}

#[test]
fn invite_request_commands_call_the_operator_routes() {
    let (base, h) = stub(4, |_, s| match s.method.as_str() {
        "GET" => invite_requests_reply(),
        _ => (204, Value::Null, vec![]),
    });
    let t = UreqControl::new();
    let c = client(&t, &base);
    let list = c.invite_requests().unwrap();
    assert_eq!(list.pending, 1);
    assert_eq!(list.unverified, vec![79]);
    assert_eq!(list.requests.len(), 2);
    assert_eq!(
        list.requests[0],
        InviteRequest {
            github_id: 77,
            login: "carol".into(),
            note: "CI signing\nfor a small project".into(),
            created_ms: 1_762_819_200_000,
            status: "pending".into(),
            decided_by: None,
            decided_ms: None,
        }
    );
    assert_eq!(list.requests[1].decided_by, Some(9));
    c.invite_request_approve(77).unwrap();
    c.invite_request_decline(78).unwrap();
    c.invite_request_delete(79).unwrap();
    let seen = h.join().unwrap();
    let calls: Vec<_> = seen
        .iter()
        .map(|s| (s.method.as_str(), s.url.as_str()))
        .collect();
    assert_eq!(
        calls,
        [
            ("GET", "/v1/ops/invite-requests"),
            ("POST", "/v1/ops/invite-requests/77/approve"),
            ("POST", "/v1/ops/invite-requests/78/decline"),
            ("DELETE", "/v1/ops/invite-requests/79"),
        ]
    );
    assert_eq!(seen[1].json(), json!({}));
    assert!(
        seen.iter()
            .all(|s| s.header("authorization") == Some(bearer().as_str()))
    );
}

#[test]
fn ops_invite_requests_binary_lists_and_acts() {
    let (base, h) = stub(4, |_, s| match (s.method.as_str(), s.url.as_str()) {
        ("GET", _) => invite_requests_reply(),
        ("POST", "/v1/ops/invite-requests/77/approve") => (204, Value::Null, vec![]),
        _ => (
            409,
            json!({"errors": ["that request was already decided"], "code": "request_not_pending"}),
            vec![],
        ),
    });
    let run = |args: &[&str]| {
        let mut all = args.to_vec();
        all.extend(["--api", &base]);
        edgekms(&all, Some(CONTROL_TOKEN), None)
    };
    let out = run(&["ops", "invite-requests", "list"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "77  carol  pending  2025-11-11\n    CI signing\n    for a small project\n\
         78  dave  declined  2025-11-10  (decided 2025-11-12 by 9)\n"
    );
    assert!(text(&out.stderr).contains("79"), "{}", text(&out.stderr));
    let out = run(&["ops", "invite-requests", "approve", "77"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "");
    assert!(
        text(&out.stderr).contains("Approved"),
        "{}",
        text(&out.stderr)
    );
    let out = run(&["ops", "invite-requests", "decline", "77"]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("already decided"),
        "{}",
        text(&out.stderr)
    );
    h.join().unwrap();
}

#[test]
fn account_request_invite_binary_files_the_note() {
    let (base, h) = stub(10, |_, s| {
        if s.url == "/login/device/code" {
            return ok(json!({
                "device_code": "dev-123", "user_code": "ABCD-1234",
                "verification_uri": "https://github.com/login/device", "expires_in": 900,
                "interval": 1
            }));
        }
        device_routes(s).unwrap_or_else(|| match (s.method.as_str(), s.url.as_str()) {
            ("POST", "/v1/login/github") => refused_with_token(),
            ("GET", "/v1/invite-requests/mine") => mine_reply(&Value::Null, true),
            ("POST", "/v1/invite-requests") => (
                201,
                json!({"data": {"status": "pending", "created_ms": 1_762_819_200_000_u64}}),
                vec![],
            ),
            _ => (404, json!({"errors": ["unsupported path"]}), vec![]),
        })
    });
    let out = Command::new(env!("CARGO_BIN_EXE_edgekms"))
        .args([
            "account",
            "request-invite",
            "--api",
            &base,
            "--client-id",
            CLIENT_ID,
            "--note",
            "CI signing",
        ])
        .env_remove(control::CONTROL_TOKEN_ENV)
        .env("EDGEKMS_GITHUB_OAUTH_BASE", &base)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let seen = h.join().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "", "nothing on stdout");
    let err = text(&out.stderr);
    assert!(err.contains("2025-11-11"), "{err}");
    assert!(
        !err.contains(REQUEST_TOKEN) && !err.contains(GH_TOKEN),
        "{err}"
    );
    let filed = seen
        .iter()
        .find(|s| s.url == "/v1/invite-requests")
        .unwrap();
    assert_eq!(filed.json(), json!({"note": "CI signing"}));
}

// ---- SSH-key login and key management (lokkju/edgekms#16) ----

/// A control plane no stub can serve, so a challenge can be minted for it before the request.
const API: &str = "https://api.example.test";
const SIG: &str = "-----BEGIN SSH SIGNATURE-----\nAAA\n-----END SSH SIGNATURE-----\n";
const ED_LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLF9QjiOrSbBZxOB0++MjcQ7YR7DdHG5whZgLIctenx alice@laptop";
const ED_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLF9QjiOrSbBZxOB0++MjcQ7YR7DdHG5whZgLIctenx";
const ED_FP: &str = "SHA256:wyzNiTWBGtOPQwOsLq0o9IOIkd6rJucpzYZO0DRw/fU";
const ED_ID: &str = "wyzNiTWBGtOPQwOsLq0o9IOIkd6rJucpzYZO0DRw_fU";
const ED2_LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG3UsV5S/PjvAY7uyJX4iJYFh2aoB3rbMCBi8qzNb9cv work";
const ED2_FP: &str = "SHA256:TVwKM0Mnsehdg8oOcjzYffOdPd0n6ekF+WfQtdbg1bM";
const EC_LINE: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDKWaOaSGtdW/C//Yye0kwrDCJRTvfmDykbTb2CeBmF2BrAHX4HOv1FIQ24Dn46VqJzQ6lIDJgeWrxSMo/6IGiQ= ecdsa@host";
const EC_FP: &str = "SHA256:9PYJ5VMtmHIhgQZ6kCo7U9V5QYbXsUczdsJrwdFW3k4";
const P384_LINE: &str = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBMhMGd9KijqVgUcw6pgXinTLSyQNk6SG2KQLKOzYDlyw6zCxZx/4cT9KkKLddt8f5xHyhSk5Peqd2fUgjTfZFSs/KyTlgrG3UD1B3vGq0hT8LQJJ1EFtNjsPEWaPYCMGJA== p384";
const RSA_LINE: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDRfv4nyrxyvGZuCpQLy6XavA+lCJ9wMgEZbTQQZ9SeTxW2/uUTTgO1OFBXMD8cZaLu5gLB6LTJ6N6O58wkYREE+4YpvztPnN0RyLJqVSDbaRFGm5EWPqFcqICK1ONbWaJA1KIxahVtig+DCkHSbCXoOFO8WNCw26DvU0Bd+QCAHw== rsa@host";

/// A genuine challenge, as a control plane at `origin` would mint it.
fn challenge_for(origin: &str) -> String {
    let ops = SoftKeyOps::new(RootKey::new(Id::new("r1").unwrap(), [1; 32]), rand::rng());
    pollster::block_on(ssh::new_challenge(&ops, 1_000, origin)).unwrap()
}

/// The GitHub id of the account the add tests are signed in as.
const ALICE_ID: u64 = 42;

/// A genuine registration challenge for `github_id` named `login`, as a control plane at
/// `origin` would mint it.
fn register_challenge_for(origin: &str, github_id: u64, login: &str) -> String {
    let ops = SoftKeyOps::new(RootKey::new(Id::new("r1").unwrap(), [1; 32]), rand::rng());
    let account = ssh::RegisterAccount {
        github_id,
        login: login.to_owned(),
    };
    pollster::block_on(ssh::new_register_challenge(&ops, 1_000, origin, &account)).unwrap()
}

/// A registration challenge for alice (`ALICE_ID`) from the control plane at `API`.
fn alice_challenge() -> String {
    register_challenge_for(API, ALICE_ID, "alice")
}

fn reply(status: u16, body: Value) -> HttpReply {
    HttpReply { status, body }
}

/// One request a [`Canned`] transport saw: method, URL, bearer and JSON body.
type Sent = (Method, String, Option<String>, Value);

/// A [`ControlTransport`] answering with `route(method, url)` and recording every request.
struct Canned<F> {
    route: F,
    seen: RefCell<Vec<Sent>>,
}

fn canned<F: Fn(Method, &str) -> HttpReply>(route: F) -> Canned<F> {
    Canned {
        route,
        seen: RefCell::new(Vec::new()),
    }
}

impl<F: Fn(Method, &str) -> HttpReply> ControlTransport for Canned<F> {
    fn send(&self, req: &Request<'_>) -> Result<HttpReply, LoginError> {
        let body = req
            .body
            .map_or(Value::Null, |b| serde_json::from_slice(b).unwrap());
        self.seen.borrow_mut().push((
            req.method,
            req.url.to_owned(),
            req.bearer.map(str::to_owned),
            body,
        ));
        Ok((self.route)(req.method, req.url))
    }
}

/// Records every (namespace, challenge) it is asked to sign.
#[derive(Default)]
struct Recorder {
    calls: RefCell<Vec<(String, String)>>,
}

impl Signer for Recorder {
    fn sign(&self, namespace: &str, challenge: &str) -> Result<String, LoginError> {
        self.calls
            .borrow_mut()
            .push((namespace.to_owned(), challenge.to_owned()));
        Ok(SIG.to_owned())
    }
}

struct NeverSign;

impl Signer for NeverSign {
    fn sign(&self, _: &str, challenge: &str) -> Result<String, LoginError> {
        panic!("asked to sign {challenge}");
    }
}

fn ssh_login_data() -> Value {
    json!({"data": {
        "token": CONTROL_TOKEN, "expires_in": 1800, "github_id": 42, "login": "alice",
        "auth": "ssh", "ssh_fingerprint": ED_FP, "ssh_keys": 2
    }})
}

fn url(path: &str) -> String {
    format!("{API}{path}")
}

#[test]
fn ssh_login_signs_the_challenge_byte_exact_under_edgekms_and_returns_the_token() {
    let chal = challenge_for(API);
    let t = canned(|m, u| match (m, u.strip_prefix(API)) {
        (Method::Post, Some("/v1/login/ssh/challenge")) => {
            reply(200, json!({"data": {"challenge": chal, "expires_in": 60}}))
        }
        (Method::Post, Some("/v1/login/ssh")) => reply(200, ssh_login_data()),
        other => panic!("unexpected {other:?}"),
    });
    let signer = Recorder::default();
    let out = control::ssh_login(&t, &signer, API).unwrap();
    assert_eq!(out.token.as_str(), CONTROL_TOKEN);
    assert_eq!(out.github_id, Some(42));
    assert_eq!(out.ssh_fingerprint.as_deref(), Some(ED_FP));
    assert_eq!(out.ssh_keys, Some(2));
    assert_eq!(
        *signer.calls.borrow(),
        vec![("edgekms".to_owned(), chal.clone())]
    );
    let seen = t.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].1, url("/v1/login/ssh/challenge"));
    assert_eq!(seen[0].2, None, "a login sends no bearer");
    assert_eq!(seen[0].3, json!({}));
    assert_eq!(seen[1].2, None);
    assert_eq!(seen[1].3, json!({"challenge": chal, "signature": SIG}));

    let summary = out.summary();
    assert!(
        summary.contains(&format!("alice (GitHub id 42) with SSH key {ED_FP}"))
            && summary.contains("30 minutes"),
        "{summary}"
    );
    assert!(!summary.contains(CONTROL_TOKEN), "{summary}");
    assert_eq!(
        out.ssh_keys_line().as_deref(),
        Some("2 SSH keys can log in to this account; see `edgekms account ssh-keys list`.")
    );
}

#[test]
fn ssh_login_refuses_a_foreign_or_malformed_challenge_before_signing() {
    // A hostile server relays a genuine challenge it fetched from another deployment.
    let foreign = challenge_for("https://kms.victim.example");
    for (chal, wrong_origin) in [(foreign.as_str(), true), ("ekmsc.abc", false)] {
        let t = canned(|_, _| reply(200, json!({"data": {"challenge": chal}})));
        let err = control::ssh_login(&t, &NeverSign, API).unwrap_err();
        if wrong_origin {
            assert!(
                matches!(err, ControlError::Login(LoginError::WrongOrigin { .. })),
                "{err}"
            );
            assert!(err.to_string().contains("kms.victim.example"), "{err}");
        } else {
            assert!(
                matches!(err, ControlError::Login(LoginError::Response(_))),
                "{err}"
            );
        }
        assert_eq!(t.seen.borrow().len(), 1, "no login request may follow");
    }
}

#[test]
fn ssh_login_permission_denied_says_how_to_register_a_key() {
    let chal = challenge_for(API);
    let t = canned(|_, u| {
        if u.ends_with("/challenge") {
            reply(200, json!({"data": {"challenge": chal}}))
        } else {
            reply(400, json!({"errors": ["permission denied"]}))
        }
    });
    let err = control::ssh_login(&t, &Recorder::default(), API).unwrap_err();
    assert!(matches!(err, ControlError::SshLoginRefused), "{err}");
    assert!(
        err.to_string().contains(
            "the key isn't registered to an edgekms account that can log in, or the signature \
             was refused; register keys with `edgekms account ssh-keys add` from a GitHub login"
        ),
        "{err}"
    );
    // Any other refusal is the control plane's own message.
    let t = canned(|_, u| {
        if u.ends_with("/challenge") {
            reply(200, json!({"data": {"challenge": chal}}))
        } else {
            reply(429, json!({"errors": ["rate limit quota exceeded"]}))
        }
    });
    let err = control::ssh_login(&t, &Recorder::default(), API).unwrap_err();
    assert!(
        matches!(err, ControlError::Rejected { status: 429, .. }),
        "{err}"
    );
}

#[test]
fn ssh_login_checks_the_address_but_not_the_hosted_host() {
    // Plain http to anything but loopback: refused before any request.
    let t = canned(|_, u| panic!("contacted {u}"));
    let err = control::ssh_login(&t, &NeverSign, "http://api.example.test").unwrap_err();
    assert!(
        matches!(err, ControlError::Login(LoginError::Insecure(_))),
        "{err}"
    );
    // A loopback control plane (the e2e run's) is fine: the GitHub host pin doesn't apply.
    let (base, h) = stub(2, |base, s| match s.url.as_str() {
        "/v1/login/ssh/challenge" => ok(json!({"data": {"challenge": challenge_for(base)}})),
        "/v1/login/ssh" => ok(ssh_login_data()),
        other => panic!("unexpected {other}"),
    });
    let out = control::ssh_login(&UreqControl::new(), &Recorder::default(), &base).unwrap();
    assert_eq!(out.token.as_str(), CONTROL_TOKEN);
    let seen = h.join().unwrap();
    assert_eq!(seen[1].header("content-type"), Some("application/json"));
}

fn login_with_keys(ssh_keys: Option<u64>) -> AccountLogin {
    AccountLogin {
        token: Zeroizing::new(CONTROL_TOKEN.to_owned()),
        expires_in: Some(1800),
        github_id: Some(42),
        login: Some("alice".into()),
        created_tenant: None,
        ssh_fingerprint: None,
        ssh_keys,
    }
}

/// A hostile `--api` (which `account login --ssh` doesn't pin to the hosted host) can't put
/// terminal escapes on stderr through the login or fingerprint it reports.
#[test]
fn server_strings_are_escaped_before_printing() {
    let mut login = login_with_keys(Some(1));
    login.login = Some("ev\u{1b}[2Jil".into());
    login.ssh_fingerprint = Some("SHA256:x\u{202e}y".into());
    let s = login.summary();
    assert!(!s.contains('\u{1b}') && !s.contains('\u{202e}'), "{s}");
    assert!(s.contains("ev\\u{1b}[2Jil"), "{s}");
    assert_eq!(control::printable_ascii("SHA256:abc"), "SHA256:abc");
    assert_eq!(control::printable_ascii("a\tb\nc"), "a\\tb\\nc");
}

#[test]
fn the_key_count_line_reads_naturally() {
    assert_eq!(login_with_keys(None).ssh_keys_line(), None);
    let none = login_with_keys(Some(0)).ssh_keys_line().unwrap();
    assert!(
        none.starts_with("No SSH keys can log in to this account")
            && none.contains("edgekms account ssh-keys add"),
        "{none}"
    );
    assert_eq!(
        login_with_keys(Some(3)).ssh_keys_line().as_deref(),
        Some("3 SSH keys can log in to this account; see `edgekms account ssh-keys list`.")
    );
}

/// `ssh-add -L` as a canned listing.
struct Agent(String);

impl AgentKeys for Agent {
    fn list(&self) -> Result<String, ControlError> {
        Ok(self.0.clone())
    }
}

fn agent(lines: &[&str]) -> Agent {
    Agent(lines.iter().flat_map(|l| [*l, "\n"]).collect())
}

struct NoAgent;

impl AgentKeys for NoAgent {
    fn list(&self) -> Result<String, ControlError> {
        panic!("ssh-add asked with --key given");
    }
}

#[test]
fn the_agents_one_supported_key_is_chosen_and_its_directory_removed() {
    let chosen = control::choose_key(None, &agent(&[RSA_LINE, ED_LINE, P384_LINE])).unwrap();
    assert_eq!(chosen.key.fingerprint, ED_FP);
    assert_eq!(chosen.key.comment, "alice@laptop");

    for fail in [false, true] {
        let seen_path = RefCell::new(None);
        let result = chosen.sign_with(
            |p: &std::path::Path| {
                *seen_path.borrow_mut() = Some(p.to_owned());
                p.to_owned()
            },
            |p: &std::path::PathBuf| {
                assert_eq!(p.extension().unwrap(), "pub");
                let text = std::fs::read_to_string(p).unwrap();
                assert_eq!(text.trim(), ED_KEY, "a public key and nothing else");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = std::fs::metadata(p.parent().unwrap())
                        .unwrap()
                        .permissions()
                        .mode();
                    assert_eq!(mode & 0o777, 0o700);
                }
                if fail {
                    Err(ControlError::Login(LoginError::Sign(
                        "agent refused".into(),
                    )))
                } else {
                    Ok(7)
                }
            },
        );
        if fail {
            assert!(result.unwrap_err().to_string().contains("agent refused"));
        } else {
            assert_eq!(result.unwrap(), 7);
        }
        let path = seen_path.into_inner().unwrap();
        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists(), "the directory is removed");
    }
}

#[test]
fn an_agent_without_a_supported_key_is_an_error() {
    for listing in [agent(&[]), agent(&[RSA_LINE, P384_LINE])] {
        let err = control::choose_key(None, &listing).unwrap_err();
        assert!(matches!(err, ControlError::AgentNoKeys), "{err}");
        let m = err.to_string();
        assert!(
            m.contains("Ed25519")
                && m.contains("sk-ssh-ed25519")
                && m.contains("ECDSA P-256")
                && m.contains("--key"),
            "{m}"
        );
    }
}

#[test]
fn an_agent_with_several_supported_keys_is_never_guessed_from() {
    let listing = agent(&[ED_LINE, RSA_LINE, ED2_LINE, EC_LINE]);
    let err = control::choose_key(None, &listing).unwrap_err();
    let m = err.to_string();
    for want in [
        ED_FP,
        "alice@laptop",
        ED2_FP,
        "work",
        EC_FP,
        "ecdsa@host",
        "--key",
    ] {
        assert!(m.contains(want), "{want} missing from {m}");
    }
    assert!(!m.contains("rsa@host"), "{m}");
}

#[test]
fn a_key_file_is_read_and_signed_with_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let pubfile = dir.path().join("id.pub");
    std::fs::write(&pubfile, format!("{ED_LINE}\n")).unwrap();
    let chosen = control::choose_key(Some(&pubfile), &NoAgent).unwrap();
    assert_eq!(chosen.key.fingerprint, ED_FP);
    let path = chosen
        .sign_with(std::path::Path::to_owned, |p| Ok(p.clone()))
        .unwrap();
    assert_eq!(path, pubfile);
    assert!(pubfile.exists(), "the caller's key file is left alone");

    // Not a .pub file: refused without reading it.
    let err = control::choose_key(Some(&dir.path().join("id")), &NoAgent).unwrap_err();
    assert!(err.to_string().contains(".pub"), "{err}");
    // An unsupported key.
    let rsa = dir.path().join("rsa.pub");
    std::fs::write(&rsa, RSA_LINE).unwrap();
    let err = control::choose_key(Some(&rsa), &NoAgent).unwrap_err();
    assert!(err.to_string().contains("ssh-ed25519"), "{err}");
    // A missing one.
    let err = control::choose_key(Some(&dir.path().join("gone.pub")), &NoAgent).unwrap_err();
    assert!(err.to_string().contains("gone.pub"), "{err}");
}

fn key_json() -> Value {
    json!({
        "id": ED_ID, "fingerprint": ED_FP, "key_type": "ssh-ed25519", "public_key": ED_KEY,
        "label": "alice@laptop", "added_ms": 1_762_900_000_000_u64, "added_via": "github",
        "last_used_ms": null
    })
}

/// A control plane that answers the registration challenge with `chal`, then the add with `add`.
fn add_routes(chal: &str, add: HttpReply) -> impl Fn(Method, &str) -> HttpReply + '_ {
    move |m, u| match (m, u.strip_prefix(API)) {
        (Method::Post, Some("/v1/me/ssh-keys/challenge")) => reply(
            200,
            json!({"data": {"challenge": chal, "expires_in": 300, "namespace": "edgekms-register"}}),
        ),
        (Method::Post, Some("/v1/me/ssh-keys")) => add.clone(),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn ssh_key_add_proves_with_edgekms_register_and_posts_the_key() {
    let chal = alice_challenge();
    let t = canned(add_routes(&chal, reply(201, json!({"data": key_json()}))));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let signer = Recorder::default();
    let key = c
        .ssh_key_add(&signer, ED_LINE, None, ALICE_ID, |_| {})
        .unwrap();
    assert_eq!(
        key,
        SshKey {
            id: ED_ID.into(),
            fingerprint: ED_FP.into(),
            key_type: "ssh-ed25519".into(),
            public_key: ED_KEY.into(),
            label: "alice@laptop".into(),
            added_ms: 1_762_900_000_000,
            added_via: "github".into(),
            last_used_ms: None,
        }
    );
    assert_eq!(
        *signer.calls.borrow(),
        vec![("edgekms-register".to_owned(), chal.clone())]
    );
    let seen = t.seen.borrow();
    assert_eq!(seen[0].1, url("/v1/me/ssh-keys/challenge"));
    assert_eq!(seen[0].2.as_deref(), Some(CONTROL_TOKEN));
    assert_eq!(seen[0].3, json!({}));
    assert_eq!(seen[1].1, url("/v1/me/ssh-keys"));
    assert_eq!(seen[1].2.as_deref(), Some(CONTROL_TOKEN));
    // The label defaults to the key's comment.
    assert_eq!(
        seen[1].3,
        json!({"public_key": ED_KEY, "label": "alice@laptop", "challenge": chal, "signature": SIG})
    );
}

#[test]
fn ssh_key_add_labels_follow_the_rules_locally() {
    let chal = alice_challenge();
    let sent_label = |line: &str, label: Option<&str>| {
        let t = canned(add_routes(&chal, reply(201, json!({"data": key_json()}))));
        let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
        c.ssh_key_add(&Recorder::default(), line, label, ALICE_ID, |_| {})
            .unwrap();
        let seen = t.seen.borrow();
        seen[1].3["label"].as_str().unwrap().to_owned()
    };
    assert_eq!(sent_label(ED_LINE, Some("  yubikey-5c  ")), "yubikey-5c");
    // A comment that breaks the rules isn't used; the key goes in without a label.
    let long = format!("{ED_KEY} {}", "c".repeat(65));
    assert_eq!(sent_label(&long, None), "");
    assert_eq!(sent_label(ED_KEY, None), "");

    // An explicit label that breaks them is refused before any request.
    let t = canned(|_, u| panic!("contacted {u}"));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    for bad in ["evil\u{202e}gpj".to_owned(), "x".repeat(65)] {
        let err = c
            .ssh_key_add(&NeverSign, ED_LINE, Some(&bad), ALICE_ID, |_| {})
            .unwrap_err();
        assert!(matches!(err, ControlError::Label(_)), "{err}");
    }
    // So is a key the control plane wouldn't take.
    for bad in [RSA_LINE, "not a key"] {
        let err = c
            .ssh_key_add(&NeverSign, bad, None, ALICE_ID, |_| {})
            .unwrap_err();
        assert!(matches!(err, ControlError::PublicKey(_)), "{err}");
    }
}

#[test]
fn ssh_key_add_refuses_a_foreign_challenge_before_signing() {
    let foreign = register_challenge_for("https://console.evil.example", ALICE_ID, "alice");
    let t = canned(add_routes(
        &foreign,
        reply(201, json!({"data": key_json()})),
    ));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let err = c
        .ssh_key_add(&NeverSign, ED_LINE, None, ALICE_ID, |_| {})
        .unwrap_err();
    assert!(
        matches!(err, ControlError::Login(LoginError::WrongOrigin { .. })),
        "{err}"
    );
    assert_eq!(t.seen.borrow().len(), 1, "nothing is posted");
}

/// lokkju/edgekms#17: the account a registration challenge names is announced before signing,
/// and a challenge for any account but the expected one is never signed.
#[test]
fn ssh_key_add_announces_the_account_and_refuses_another() {
    let chal = alice_challenge();
    let t = canned(add_routes(&chal, reply(201, json!({"data": key_json()}))));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let signer = Recorder::default();
    let announced = RefCell::new(None);
    c.ssh_key_add(&signer, ED_LINE, None, ALICE_ID, |a| {
        assert!(signer.calls.borrow().is_empty(), "announced before signing");
        *announced.borrow_mut() = Some(a.clone());
    })
    .unwrap();
    assert_eq!(
        announced.into_inner(),
        Some(ssh::RegisterAccount {
            github_id: ALICE_ID,
            login: "alice".into()
        })
    );

    // A challenge naming mallory's account, from a control plane alice is signed in to.
    let mallory = register_challenge_for(API, 7, "mallory");
    let t = canned(add_routes(
        &mallory,
        reply(201, json!({"data": key_json()})),
    ));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let err = c
        .ssh_key_add(&NeverSign, ED_LINE, None, ALICE_ID, |a| {
            panic!("announced {a:?}")
        })
        .unwrap_err();
    assert!(
        matches!(
            &err,
            ControlError::SshKeyWrongAccount { expected: ALICE_ID, got } if got.github_id == 7
        ),
        "{err}"
    );
    let m = err.to_string();
    assert!(m.contains("mallory (7)") && m.contains("42"), "{m}");
    assert_eq!(t.seen.borrow().len(), 1, "nothing is posted");

    // A challenge in the format from before the account was bound isn't signed either.
    let old = challenge_for(API);
    let t = canned(add_routes(&old, reply(201, json!({"data": key_json()}))));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let err = c
        .ssh_key_add(&NeverSign, ED_LINE, None, ALICE_ID, |_| {})
        .unwrap_err();
    assert!(
        matches!(err, ControlError::Login(LoginError::Response(_))),
        "{err}"
    );
    assert_eq!(t.seen.borrow().len(), 1, "nothing is posted");
}

#[test]
fn token_account_reads_the_control_tokens_claims() {
    let claims = json!({
        "v": 1, "jti": "j", "role": "control", "policies": [], "iat": 1, "exp": 2,
        "long": false, "meta": {"github_id": "42", "login": "alice", "auth": "github"}
    });
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&claims).unwrap());
    let token = format!("ekms.{payload}.dGFn");
    assert_eq!(
        control::token_account(&token),
        Some(ssh::RegisterAccount {
            github_id: 42,
            login: "alice".into()
        })
    );
    for opaque in [CONTROL_TOKEN, "", "ekms..", "ekms.e30.dGFn", "not-a-token"] {
        assert_eq!(control::token_account(opaque), None, "{opaque}");
    }
}

const FRESH: &str = "run `edgekms account login` (GitHub or `--ssh`) again; adding a key needs a \
                     login under five minutes old";

#[test]
fn ssh_key_add_needing_a_fresh_login_says_so() {
    let fresh = reply(
        403,
        json!({"errors": ["fresh login required"], "code": "fresh_login_required"}),
    );
    // At the challenge.
    let t = canned(|_, _| fresh.clone());
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let err = c
        .ssh_key_add(&NeverSign, ED_LINE, None, ALICE_ID, |_| {})
        .unwrap_err();
    assert!(matches!(err, ControlError::SshKeyFreshLogin), "{err}");
    assert_eq!(err.to_string(), FRESH);
    assert_eq!(t.seen.borrow().len(), 1);
    // And at the add, when the login aged in between.
    let chal = alice_challenge();
    let t = canned(add_routes(&chal, fresh.clone()));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let err = c
        .ssh_key_add(&Recorder::default(), ED_LINE, None, ALICE_ID, |_| {})
        .unwrap_err();
    assert_eq!(err.to_string(), FRESH);
}

#[test]
fn ssh_key_add_refusals_say_what_they_mean() {
    let chal = alice_challenge();
    for (status, code, want) in [
        (409, "ssh_key_in_use", "already registered"),
        (409, "ssh_key_limit", "10 SSH keys"),
        (400, "ssh_key_proof_failed", "signature"),
        (400, "label_invalid", "label"),
        (400, "ssh_key_invalid", "OpenSSH public key"),
        (400, "ssh_key_unsupported", "sk-ssh-ed25519@openssh.com"),
    ] {
        let t = canned(add_routes(
            &chal,
            reply(status, json!({"errors": ["refused"], "code": code})),
        ));
        let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
        let err = c
            .ssh_key_add(&Recorder::default(), ED_LINE, None, ALICE_ID, |_| {})
            .unwrap_err();
        assert!(
            matches!(err, ControlError::SshKeyRefused(_)),
            "{code}: {err}"
        );
        let m = err.to_string();
        assert!(m.contains(want), "{code}: {m}");
        assert!(!m.contains('\u{2014}'), "{code}: {m}");
    }
    // An uncoded refusal is the control plane's own message.
    let t = canned(add_routes(
        &chal,
        reply(403, json!({"errors": ["permission denied"]})),
    ));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let err = c
        .ssh_key_add(&Recorder::default(), ED_LINE, None, ALICE_ID, |_| {})
        .unwrap_err();
    assert!(
        matches!(err, ControlError::Rejected { status: 403, .. }),
        "{err}"
    );
}

#[test]
fn ssh_key_remove_takes_the_id_or_the_fingerprint() {
    for given in [ED_ID, ED_FP] {
        let t = canned(|_, _| reply(204, Value::Null));
        let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
        c.ssh_key_remove(given).unwrap();
        let seen = t.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, Method::Delete);
        assert_eq!(seen[0].1, url(&format!("/v1/me/ssh-keys/{ED_ID}")));
        assert_eq!(seen[0].2.as_deref(), Some(CONTROL_TOKEN));
    }
}

#[test]
fn ssh_key_remove_refuses_junk_without_a_request() {
    let t = canned(|_, u| panic!("contacted {u}"));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let raw_b64 = ED_FP.strip_prefix("SHA256:").unwrap();
    let short = &ED_ID[1..];
    for bad in [
        "",
        raw_b64,
        short,
        "SHA256:abc",
        "MD5:00:11",
        "../../v1/me",
        "wyzNiTWBGtOPQwOsLq0o9IOIkd6rJucpzYZO0DRw_f?",
    ] {
        let err = c.ssh_key_remove(bad).unwrap_err();
        assert!(matches!(err, ControlError::SshKeyId(_)), "{bad}: {err}");
    }
}

#[test]
fn ssh_key_remove_of_an_absent_key_says_so() {
    let t = canned(|_, _| reply(404, json!({"errors": ["ssh key not found"]})));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let err = c.ssh_key_remove(ED_FP).unwrap_err();
    assert!(matches!(err, ControlError::NoSuchSshKey), "{err}");
    assert_eq!(err.to_string(), "no such key on this account");
}

fn ssh_keys_reply() -> Value {
    let mut used = key_json();
    used["id"] = json!("TVwKM0Mnsehdg8oOcjzYffOdPd0n6ekF-WfQtdbg1bM");
    used["fingerprint"] = json!(ED2_FP);
    used["label"] = json!("work");
    used["added_via"] = json!(format!("ssh:{ED_FP}"));
    used["last_used_ms"] = json!(1_762_900_500_000_u64);
    json!({"data": {"keys": [key_json(), used], "unverified": [EC_FP]}})
}

#[test]
fn ssh_keys_lists_keys_and_unverified_rows() {
    let t = canned(|m, u| {
        assert_eq!((m, u), (Method::Get, url("/v1/me/ssh-keys").as_str()));
        reply(200, ssh_keys_reply())
    });
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    let list = c.ssh_keys().unwrap();
    assert_eq!(list.keys.len(), 2);
    assert_eq!(list.keys[0].last_used_ms, None);
    assert_eq!(list.keys[1].last_used_ms, Some(1_762_900_500_000));
    assert_eq!(list.keys[1].added_via, format!("ssh:{ED_FP}"));
    assert_eq!(list.unverified, vec![EC_FP.to_owned()]);
    // A key missing a field is a malformed reply, not a silent gap.
    let t = canned(|_, _| reply(200, json!({"data": {"keys": [{"id": ED_ID}]}})));
    let c = Client::new(&t, API, CONTROL_TOKEN).unwrap();
    assert!(matches!(
        c.ssh_keys().unwrap_err(),
        ControlError::Response(_)
    ));
}

#[test]
fn ssh_keys_binary_lists_tab_separated_and_removes() {
    let (base, h) = stub(2, |_, s| match (s.method.as_str(), s.url.as_str()) {
        ("GET", "/v1/me/ssh-keys") => ok(ssh_keys_reply()),
        ("DELETE", path) if path == format!("/v1/me/ssh-keys/{ED_ID}") => {
            (204, Value::Null, vec![])
        }
        other => panic!("unexpected {other:?}"),
    });
    let out = edgekms(
        &["account", "ssh-keys", "list", "--api", &base],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!(
            "{ED_ID}\t{ED_FP}\tssh-ed25519\talice@laptop\t1762900000000\tgithub\t\n\
             TVwKM0Mnsehdg8oOcjzYffOdPd0n6ekF-WfQtdbg1bM\t{ED2_FP}\tssh-ed25519\twork\t\
             1762900000000\tssh:{ED_FP}\t1762900500000\n\
             unverified\t{EC_FP}\n"
        )
    );
    let out = edgekms(
        &["account", "ssh-keys", "remove", ED_FP, "--api", &base],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "");
    assert!(text(&out.stderr).contains(ED_FP), "{}", text(&out.stderr));
    let seen = h.join().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter()
            .all(|s| s.header("authorization") == Some(bearer().as_str()))
    );
    // Without the token, nothing is sent.
    let out = edgekms(&["account", "ssh-keys", "list", "--api", &base], None, None);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains(control::CONTROL_TOKEN_ENV));
}

#[test]
fn account_login_ssh_flags_conflict_where_they_should() {
    let out = edgekms(
        &["account", "login", "--ssh", "--client-id", CLIENT_ID],
        None,
        None,
    );
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("cannot be used with"),
        "{}",
        text(&out.stderr)
    );
    let out = edgekms(&["account", "login", "--key", "id.pub"], None, None);
    assert!(!out.status.success());
    assert!(text(&out.stderr).contains("--ssh"), "{}", text(&out.stderr));
}

/// lokkju/edgekms#17, in the binary: without an account to expect (the test token carries no
/// claims) nothing is sent, and with `--expect-github-id` a challenge for another account is
/// refused before ssh-keygen is asked anything.
#[test]
fn ssh_keys_add_binary_pins_the_account() {
    let dir = tempfile::tempdir().unwrap();
    let pub_file = dir.path().join("id.pub");
    std::fs::write(&pub_file, ED_LINE).unwrap();
    let key = pub_file.to_str().unwrap();

    let out = edgekms(
        &["account", "ssh-keys", "add", "--key", key, "--api", API],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("--expect-github-id"),
        "{}",
        text(&out.stderr)
    );

    let (base, h) = stub(1, |base, s| match (s.method.as_str(), s.url.as_str()) {
        ("POST", "/v1/me/ssh-keys/challenge") => ok(json!({"data": {
            "challenge": register_challenge_for(base, 7, "mallory"),
            "expires_in": 300, "namespace": "edgekms-register",
            "github_id": 7, "login": "mallory"
        }})),
        other => panic!("unexpected {other:?}"),
    });
    let out = edgekms(
        &[
            "account",
            "ssh-keys",
            "add",
            "--key",
            key,
            "--expect-github-id",
            "42",
            "--api",
            &base,
        ],
        Some(CONTROL_TOKEN),
        None,
    );
    assert!(!out.status.success());
    let err = text(&out.stderr);
    assert!(err.contains("mallory (7)") && err.contains("42"), "{err}");
    assert_eq!(
        h.join().unwrap().len(),
        1,
        "only the challenge was asked for"
    );
}

#[test]
fn ssh_keys_add_help_recommends_touch_or_confirm_keys() {
    let out = edgekms(&["account", "ssh-keys", "add", "--help"], None, None);
    let help = text(&out.stdout);
    assert!(
        help.contains("sk-ssh-ed25519") && help.contains("ssh-add -c"),
        "{help}"
    );
}

#[test]
fn account_login_ssh_binary_prints_only_the_token() {
    // A real key and a real ssh-keygen: with no agent, ssh-keygen signs with the private key
    // beside the .pub file, which stands in for the agent here.
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id");
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "ci@runner", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let pubfile = dir.path().join("id.pub");
    let fp = ssh::parse_public_key(&std::fs::read_to_string(&pubfile).unwrap())
        .unwrap()
        .fingerprint;
    let reply_fp = fp.clone();
    let (base, h) = stub(2, move |base, s| match s.url.as_str() {
        "/v1/login/ssh/challenge" => ok(json!({"data": {"challenge": challenge_for(base)}})),
        "/v1/login/ssh" => ok(json!({"data": {
            "token": CONTROL_TOKEN, "expires_in": 1800, "github_id": 42, "login": "alice",
            "auth": "ssh", "ssh_fingerprint": reply_fp, "ssh_keys": 1
        }})),
        other => panic!("unexpected {other}"),
    });
    let out = Command::new(env!("CARGO_BIN_EXE_edgekms"))
        .args(["account", "login", "--ssh", "--api", &base, "--key"])
        .arg(&pubfile)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove(control::CONTROL_TOKEN_ENV)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let err = text(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert_eq!(text(&out.stdout), format!("{CONTROL_TOKEN}\n"));
    assert!(
        err.contains(&format!("alice (GitHub id 42) with SSH key {fp}")),
        "{err}"
    );
    assert!(err.contains("five minutes"), "{err}");
    assert!(err.contains("1 SSH key can log in"), "{err}");
    assert!(err.contains(control::CONTROL_TOKEN_ENV), "{err}");
    assert!(!err.contains(CONTROL_TOKEN), "{err}");
    // The signature is a real one, by this key, under `edgekms`, over the challenge as sent.
    let seen = h.join().unwrap();
    let login = seen[1].json();
    let v = ssh::verify_embedded(
        login["challenge"].as_str().unwrap(),
        login["signature"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(v.fingerprint, fp);
}
