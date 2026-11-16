//! Hosted config rules, the default tenant config and the wrap and config MAC byte layouts
//! (`edgekms_core::hosted`).

use edgekms_core::config::{Config, ConfigError, Mount};
use edgekms_core::hosted::{
    HostedRules, LabelError, MAX_CONFIG_BYTES, MAX_DECRYPTABLE_VERSIONS, MAX_KEY_VERSION,
    MAX_NOTE_BYTES, MAX_NOTE_CHARS, MAX_SSH_KEY_LABEL_CHARS, NoteError, allow_mac_input,
    config_mac_input, default_config, invite_mac_input, invite_note, invite_request_mac_input,
    member_mac_input, ssh_key_label, ssh_key_mac_input, validate_hosted, wrap_aad,
};
use edgekms_core::transit::Id;
use serde_json::{Value, json};

const HOSTED: &str = include_str!("fixtures/config.hosted.json");
const CLIENT_ID: &str = "Iv_hosted_test";

fn fixture() -> Value {
    serde_json::from_str(HOSTED).unwrap()
}

/// Parses `v` with `Config::from_json`, then runs `validate_hosted` with the fixture's root id
/// and the test client id.
fn check(v: &Value) -> Result<(), ConfigError> {
    let config = Config::from_json(&v.to_string()).unwrap();
    let root_id = Id::new("r_fc3585fd964c55ea").unwrap();
    validate_hosted(
        &config,
        &HostedRules {
            root_id: &root_id,
            github_client_id: CLIENT_ID,
            apex: "edge.km",
        },
    )
}

fn invalid(s: &str) -> Result<(), ConfigError> {
    Err(ConfigError::Invalid(s.to_owned()))
}

#[test]
fn hosted_fixture_passes() {
    assert_eq!(check(&fixture()), Ok(()));
}

#[test]
fn root_id_mismatch_is_refused() {
    let mut v = fixture();
    v["root_id"] = json!("r_other");
    assert_eq!(
        check(&v),
        invalid("root_id: the hosted service sets the root id")
    );
}

#[test]
fn public_origins_is_refused() {
    let mut v = fixture();
    v["public_origins"] = json!(["https://acme.edge.km"]);
    assert_eq!(
        check(&v),
        invalid("public_origins: the hosted service sets the origin")
    );
    // An explicitly empty list is the same as leaving it out.
    v["public_origins"] = json!([]);
    assert_eq!(check(&v), Ok(()));
}

#[test]
fn foreign_github_client_id_is_refused() {
    let mut v = fixture();
    v["mounts"]["github-user"]["client_id"] = json!("Iv_someone_else");
    assert_eq!(
        check(&v),
        invalid("mounts.github-user.client_id: the hosted service's GitHub App is Iv_hosted_test")
    );
}

/// Adds `n` more entries to `v[section]`, each a copy of the entry `template` under a new name.
fn pad(v: &mut Value, section: &str, template: &str, n: usize) {
    let entry = v[section][template].clone();
    let map = v[section].as_object_mut().unwrap();
    for i in 0..n {
        let mut e = entry.clone();
        if section == "keys" {
            e["id"] = json!(format!("k_pad_{i}"));
        }
        map.insert(format!("pad-{i}"), e);
    }
}

#[test]
fn too_many_roles_is_refused() {
    let mut v = fixture();
    let have = v["roles"].as_object().unwrap().len();
    pad(&mut v, "roles", "operator", 128 - have);
    assert_eq!(check(&v), Ok(()));
    pad(&mut v, "roles", "operator", 129 - have);
    assert_eq!(check(&v), invalid("roles: at most 128 roles"));
}

#[test]
fn too_many_keys_mounts_and_policies_are_refused() {
    let mut v = fixture();
    let have = v["keys"].as_object().unwrap().len();
    pad(&mut v, "keys", "smoke", 65 - have);
    assert_eq!(check(&v), invalid("keys: at most 64 keys"));

    let mut v = fixture();
    let have = v["mounts"].as_object().unwrap().len();
    pad(&mut v, "mounts", "ssh", 33 - have);
    assert_eq!(check(&v), invalid("mounts: at most 32 mounts"));

    let mut v = fixture();
    let have = v["policies"].as_object().unwrap().len();
    pad(&mut v, "policies", "smoke", 129 - have);
    assert_eq!(check(&v), invalid("policies: at most 128 policies"));
}

#[test]
fn decryptable_window_is_capped() {
    let mut v = fixture();
    v["keys"]["smoke"]["latest_version"] = json!(MAX_DECRYPTABLE_VERSIONS);
    assert_eq!(check(&v), Ok(()));
    v["keys"]["smoke"]["latest_version"] = json!(MAX_DECRYPTABLE_VERSIONS + 1);
    assert_eq!(
        check(&v),
        invalid("keys.smoke: at most 256 decryptable versions")
    );
    // Raising min_decryption_version slides the window up.
    v["keys"]["smoke"]["min_decryption_version"] = json!(2);
    assert_eq!(check(&v), Ok(()));
}

#[test]
fn latest_version_is_capped() {
    let mut v = fixture();
    v["keys"]["smoke"]["latest_version"] = json!(MAX_KEY_VERSION);
    v["keys"]["smoke"]["min_decryption_version"] = json!(MAX_KEY_VERSION);
    assert_eq!(check(&v), Ok(()));
    v["keys"]["smoke"]["latest_version"] = json!(MAX_KEY_VERSION + 1);
    v["keys"]["smoke"]["min_decryption_version"] = json!(MAX_KEY_VERSION + 1);
    assert_eq!(
        check(&v),
        invalid("keys.smoke.latest_version: at most 1000000")
    );
    // The isolate-killing case from the review: one version, but four billion of them.
    v["keys"]["smoke"]["latest_version"] = json!(4_000_000_000_u32);
    v["keys"]["smoke"]["min_decryption_version"] = json!(1);
    assert!(check(&v).is_err());
}

#[test]
fn jwks_url_on_edge_km_is_refused() {
    let refused = [
        "https://edge.km/jwks",
        "https://acme.edge.km/.well-known/jwks",
        "https://API.EDGE.KM/jwks",
        "https://api.edge.km./jwks",
        "https://api.edge.km:443/jwks",
        "https://edge.km",
        "https://edge.km?x=1",
        "https://github.com@api.edge.km/jwks",
    ];
    for url in refused {
        let mut v = fixture();
        v["mounts"]["github"]["jwks_url"] = json!(url);
        assert_eq!(
            check(&v),
            invalid("mounts.github.jwks_url: must not point at edge.km"),
            "{url}"
        );
    }
    for url in [
        "https://notedge.km/jwks",
        "https://edge.km.example.com/jwks",
        "https://api.edge.km@example.com/jwks",
    ] {
        let mut v = fixture();
        v["mounts"]["github"]["jwks_url"] = json!(url);
        assert_eq!(check(&v), Ok(()), "{url}");
    }
}

/// Hosts a WHATWG URL parser (the one the Worker's fetch uses) resolves to the apex or under
/// it, though splitting the string by hand doesn't.
#[test]
fn jwks_url_parser_bypasses_are_refused() {
    for url in [
        "https://edge.km\\.evil.com/jwks",
        "https://EDGE%2Ekm/jwks",
        "https://edge\t.km/jwks",
        "https://api.ed\nge.km/jwks",
        "https://api.edge\u{3002}km/x",
        "https://api.edge\u{ff0e}km/x",
        "https://acme.edge.km\\@evil.com/jwks",
    ] {
        let mut v = fixture();
        v["mounts"]["github"]["jwks_url"] = json!(url);
        assert_eq!(
            check(&v),
            invalid("mounts.github.jwks_url: must not point at edge.km"),
            "{url:?}"
        );
    }
}

#[test]
fn unparsable_jwks_url_is_refused() {
    let mut v = fixture();
    v["mounts"]["github"]["jwks_url"] = json!("https://exa mple.com/jwks");
    assert_eq!(
        check(&v),
        invalid("mounts.github.jwks_url: not a valid URL")
    );
}

#[test]
fn jwks_url_check_follows_the_configured_apex() {
    let mut v = fixture();
    v["mounts"]["github"]["jwks_url"] = json!("https://issuer.localhost/jwks");
    let config = Config::from_json(&v.to_string()).unwrap();
    let root_id = Id::new("r_fc3585fd964c55ea").unwrap();
    let rules = |apex| HostedRules {
        root_id: &root_id,
        github_client_id: CLIENT_ID,
        apex,
    };
    assert_eq!(
        validate_hosted(&config, &rules("localhost")),
        invalid("mounts.github.jwks_url: must not point at localhost")
    );
    assert_eq!(validate_hosted(&config, &rules("edge.km")), Ok(()));
    // The apex may arrive in any case or with a trailing dot.
    assert!(validate_hosted(&config, &rules("LocalHost.")).is_err());
}

#[test]
fn default_config_passes_both_validations() {
    let root_id = Id::new("r_0123456789abcdef").unwrap();
    let key_id = Id::new("k_0123456789abcdef").unwrap();
    let json = default_config(&root_id, &key_id, 583_231, CLIENT_ID);
    assert!(!json.contains('\n'), "compact JSON");
    assert!(json.len() < MAX_CONFIG_BYTES);
    let config = Config::from_json(&json).unwrap();
    assert_eq!(
        validate_hosted(
            &config,
            &HostedRules {
                root_id: &root_id,
                github_client_id: CLIENT_ID,
                apex: "edge.km",
            },
        ),
        Ok(())
    );
}

#[test]
fn default_config_binds_the_owner() {
    let root_id = Id::new("r_0123456789abcdef").unwrap();
    let key_id = Id::new("k_fedcba9876543210").unwrap();
    let config = Config::from_json(&default_config(&root_id, &key_id, 42, CLIENT_ID)).unwrap();
    assert_eq!(config.root_id, root_id);
    assert_eq!(config.public_origins, Vec::<String>::new());
    let key = config.key("default").unwrap();
    assert_eq!(
        (&key.id, key.latest_version, key.min_decryption_version),
        (&key_id, 1, 1)
    );
    assert_eq!(
        config.mounts["github-user"],
        Mount::GithubUser {
            client_id: CLIENT_ID.to_owned()
        }
    );
    assert_eq!(config.mounts.len(), 1);
    let owner = &config.roles["owner"];
    assert_eq!(owner.mount, "github-user");
    assert_eq!(owner.github_user_ids, [42]);
    assert_eq!(owner.policies, ["admin", "default-all"]);
    assert_eq!(owner.token_ttl_secs, 3600);
    assert_eq!(config.roles.len(), 1);
    assert_eq!(config.policies["admin"].admin.len(), 2);
    assert_eq!(config.policies["default-all"].keys["default"].len(), 4);
}

#[test]
fn wrap_aad_layout() {
    assert_eq!(
        wrap_aad("t_1", &Id::new("r1").unwrap()),
        b"edgekms/wrap/v1/t_1/r1"
    );
    assert_eq!(
        wrap_aad("t_test", &Id::new("r1").unwrap()),
        b"edgekms/wrap/v1/t_test/r1"
    );
}

#[test]
fn config_mac_input_layout() {
    let mut want = b"t_1".to_vec();
    want.push(0);
    want.extend_from_slice(b"acme");
    want.push(0);
    want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x01, 0x02]);
    want.extend_from_slice(br#"{"a":1}"#);
    assert_eq!(config_mac_input("t_1", "acme", 0x0102, r#"{"a":1}"#), want);
    assert_eq!(
        config_mac_input("t", "abc", u64::MAX, ""),
        [
            b't', 0, b'a', b'b', b'c', 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        ]
    );
}

/// The name is bound: the same tenant, version and config under another name is another
/// input, so a config MAC doesn't verify after the row's name changes.
#[test]
fn config_mac_input_binds_the_name() {
    assert_ne!(
        config_mac_input("t_1", "alice", 1, "{}"),
        config_mac_input("t_1", "bob", 1, "{}")
    );
    // The separators keep the id and the name from sliding into each other.
    assert_ne!(
        config_mac_input("t_1", "abc", 1, "{}"),
        config_mac_input("t_1a", "bc", 1, "{}")
    );
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The layouts the member and invite MAC vectors in `tests/keyops.rs` were computed over,
/// built independently in Python with `struct.pack(">Q", ...)`.
#[test]
fn member_mac_input_layout() {
    assert_eq!(
        member_mac_input("t_1", 583_231, "owner", 1_800_000_000_000),
        unhex("745f3100000000000008e63f6f776e657200000001a3185c5000")
    );
}

#[test]
fn invite_mac_input_layout() {
    assert_eq!(
        invite_mac_input("t_1", 583_231, "member", 42, 1_800_000_000_000),
        unhex("745f3100000000000008e63f6d656d62657200000000000000002a000001a3185c5000")
    );
}

/// The layout the allowlist MAC vector in `tests/keyops.rs` was computed over, built
/// independently in Python with `struct.pack(">QQQ", ...)`.
#[test]
fn allow_mac_input_layout() {
    assert_eq!(
        allow_mac_input(583_231, 42, 1_800_000_000_000),
        unhex("000000000008e63f000000000000002a000001a3185c5000")
    );
    let base = allow_mac_input(7, 1, 100);
    for other in [
        allow_mac_input(8, 1, 100),
        allow_mac_input(7, 2, 100),
        allow_mac_input(7, 1, 101),
    ] {
        assert_ne!(base, other);
    }
}

/// Every field is bound: changing any one of them is another input, so a row whose tenant,
/// user, role, inviter or time was rewritten doesn't verify.
#[test]
fn member_and_invite_inputs_bind_every_field() {
    let base = member_mac_input("t_1", 7, "member", 100);
    for other in [
        member_mac_input("t_2", 7, "member", 100),
        member_mac_input("t_1", 8, "member", 100),
        member_mac_input("t_1", 7, "owner", 100),
        member_mac_input("t_1", 7, "member", 101),
    ] {
        assert_ne!(base, other);
    }
    let base = invite_mac_input("t_1", 7, "member", 1, 100);
    for other in [
        invite_mac_input("t_2", 7, "member", 1, 100),
        invite_mac_input("t_1", 8, "member", 1, 100),
        invite_mac_input("t_1", 7, "owner", 1, 100),
        invite_mac_input("t_1", 7, "member", 2, 100),
        invite_mac_input("t_1", 7, "member", 1, 101),
    ] {
        assert_ne!(base, other);
    }
}

/// The layout the invite request MAC vector in `tests/keyops.rs` was computed over, built
/// independently in Python with `struct.pack('>QQ', ...)` and `struct.pack('>I', len)` before
/// each of the login and the note.
#[test]
fn invite_request_mac_input_layout() {
    assert_eq!(
        invite_request_mac_input(
            583_231,
            1_800_000_000_000,
            "octocat",
            "CI signing\nfor an OSS project"
        ),
        unhex(
            "000000000008e63f000001a3185c5000000000076f63746f6361740000001d4349207369676e696e67\
             0a666f7220616e204f53532070726f6a656374"
        )
    );
    // The length prefixes keep the two text fields apart: moving the boundary between login
    // and note is another input.
    assert_ne!(
        invite_request_mac_input(7, 100, "ab", "c"),
        invite_request_mac_input(7, 100, "a", "bc")
    );
    let base = invite_request_mac_input(7, 100, "a", "b");
    for other in [
        invite_request_mac_input(8, 100, "a", "b"),
        invite_request_mac_input(7, 101, "a", "b"),
        invite_request_mac_input(7, 100, "A", "b"),
        invite_request_mac_input(7, 100, "a", "B"),
    ] {
        assert_ne!(base, other);
    }
}

/// The note rules the control plane applies to an invite request: trimmed, at most 2000 bytes
/// and 500 scalar values, and nothing that isn't inert in a terminal or on a page.
#[test]
fn invite_notes_follow_the_rules() {
    assert_eq!(invite_note(""), Ok(""));
    assert_eq!(invite_note("   \n\t "), Ok(""));
    assert_eq!(invite_note("  CI signing  "), Ok("CI signing"));
    assert_eq!(invite_note("line one\nline two"), Ok("line one\nline two"));
    assert_eq!(
        invite_note("caf\u{e9} \u{1f510}"),
        Ok("caf\u{e9} \u{1f510}")
    );
    for bad in [
        "a\rb",
        "a\tb",
        "a\u{1b}[31mb",
        "a\0b",
        "a\u{7f}b",
        "a\u{85}b",
        "a\u{9b}b",
    ] {
        assert_eq!(invite_note(bad), Err(NoteError::Control), "{bad:?}");
    }
    for bad in [
        "a\u{202e}b",
        "a\u{202a}b",
        "a\u{2066}b",
        "a\u{2069}b",
        "a\u{200e}b",
        "a\u{200f}b",
        "a\u{61c}b",
    ] {
        assert_eq!(invite_note(bad), Err(NoteError::Bidi), "{bad:?}");
    }
    for bad in [
        "a\u{200b}b",
        "a\u{feff}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a\u{2060}b",
        "a\u{ad}b",
        "a\u{e0041}b",
    ] {
        assert_eq!(invite_note(bad), Err(NoteError::Invisible), "{bad:?}");
    }
    // A zero-width joiner holds emoji sequences together, so it stays.
    assert!(invite_note("\u{1f469}\u{200d}\u{1f4bb}").is_ok());
    let most = "a".repeat(MAX_NOTE_CHARS);
    assert_eq!(invite_note(&most), Ok(most.as_str()));
    assert_eq!(
        invite_note(&format!("{most}b")),
        Err(NoteError::TooManyChars)
    );
    // Trimming comes first: the limits are on what is stored.
    assert_eq!(invite_note(&format!("  {most}\n ")), Ok(most.as_str()));
    // 500 four-byte characters are exactly 2000 bytes.
    let wide = "\u{1f510}".repeat(MAX_NOTE_CHARS);
    assert_eq!(wide.len(), MAX_NOTE_BYTES);
    assert_eq!(invite_note(&wide), Ok(wide.as_str()));
    // 2001 bytes is refused for its size before its characters are counted.
    assert_eq!(
        invite_note(&"a".repeat(MAX_NOTE_BYTES + 1)),
        Err(NoteError::TooManyBytes)
    );
    // Each rule's message names it.
    assert!(
        NoteError::TooManyChars
            .to_string()
            .contains("500 characters")
    );
    assert!(NoteError::TooManyBytes.to_string().contains("2000 bytes"));
    assert!(
        NoteError::Control
            .to_string()
            .contains("control characters")
    );
    assert!(NoteError::Bidi.to_string().contains("bidirectional"));
    assert!(NoteError::Invisible.to_string().contains("invisible"));
}

/// `ssh_key_mac_input`: two u64s big-endian, then four length-prefixed strings.
#[test]
fn ssh_key_mac_input_layout() {
    let got = ssh_key_mac_input(7, 256, "SHA256:a", "k", "", "github");
    let mut want = Vec::new();
    want.extend_from_slice(&7u64.to_be_bytes());
    want.extend_from_slice(&256u64.to_be_bytes());
    for s in ["SHA256:a", "k", "", "github"] {
        want.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
        want.extend_from_slice(s.as_bytes());
    }
    assert_eq!(got, want);
    // Moving a boundary between two strings is another input.
    assert_ne!(
        ssh_key_mac_input(7, 1, "a", "bc", "d", "github"),
        ssh_key_mac_input(7, 1, "ab", "c", "d", "github")
    );
    assert_ne!(
        ssh_key_mac_input(7, 1, "a", "b", "lab", "elgithub"),
        ssh_key_mac_input(7, 1, "a", "b", "label", "github")
    );
    let base = ssh_key_mac_input(7, 1, "f", "k", "l", "github");
    for other in [
        ssh_key_mac_input(8, 1, "f", "k", "l", "github"),
        ssh_key_mac_input(7, 2, "f", "k", "l", "github"),
        ssh_key_mac_input(7, 1, "F", "k", "l", "github"),
        ssh_key_mac_input(7, 1, "f", "K", "l", "github"),
        ssh_key_mac_input(7, 1, "f", "k", "L", "github"),
        ssh_key_mac_input(7, 1, "f", "k", "l", "ssh:SHA256:x"),
    ] {
        assert_ne!(base, other);
    }
}

/// An SSH key's label: trimmed, at most 64 scalar values, one line of inert text.
#[test]
fn ssh_key_labels_follow_the_rules() {
    assert_eq!(ssh_key_label(""), Ok(""));
    assert_eq!(ssh_key_label("  yubikey-5c  "), Ok("yubikey-5c"));
    assert_eq!(ssh_key_label("nick@laptop"), Ok("nick@laptop"));
    let max = "\u{e9}".repeat(MAX_SSH_KEY_LABEL_CHARS);
    assert_eq!(ssh_key_label(&max), Ok(max.as_str()));
    let long = format!("{max}a");
    assert_eq!(ssh_key_label(&long), Err(LabelError::TooLong));
    for bad in ["a\nb", "a\tb", "a\u{1b}b", "a\0b", "a\u{85}b"] {
        assert_eq!(ssh_key_label(bad), Err(LabelError::Control), "{bad:?}");
    }
    for bad in ["a\u{202e}b", "a\u{2066}b", "a\u{200f}b"] {
        assert_eq!(ssh_key_label(bad), Err(LabelError::Bidi), "{bad:?}");
    }
    for bad in ["a\u{200b}b", "a\u{feff}b", "a\u{e0041}b"] {
        assert_eq!(ssh_key_label(bad), Err(LabelError::Invisible), "{bad:?}");
    }
    assert!(LabelError::TooLong.to_string().contains("64"));
}
