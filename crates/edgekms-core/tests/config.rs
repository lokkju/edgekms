use edgekms_core::config::{Capability, ClaimMatch, Config, ConfigError};

const VALID: &str = include_str!("fixtures/config.valid.json");

fn mutate(f: impl FnOnce(&mut serde_json::Value)) -> Result<Config, ConfigError> {
    let mut v: serde_json::Value = serde_json::from_str(VALID).unwrap();
    f(&mut v);
    Config::from_json(&v.to_string())
}

/// Asserts `r` is `Invalid` at exactly `path`, for the rule whose message contains `reason`, so a
/// test fails if a different rule fires first.
fn invalid(r: Result<Config, ConfigError>, path: &str, reason: &str) {
    match r {
        Err(ConfigError::Invalid(msg)) => {
            let (got_path, got_reason) = msg
                .split_once(": ")
                .unwrap_or_else(|| panic!("{msg} has no path"));
            assert_eq!(got_path, path, "{msg}");
            assert!(
                got_reason.contains(reason),
                "{msg} should mention {reason:?}"
            );
        }
        other => panic!(
            "expected Invalid({path}: {reason}), got {:?}",
            other.map(|_| ())
        ),
    }
}

#[test]
fn valid_config_loads() {
    let c = Config::from_json(VALID).unwrap();
    assert_eq!(c.root_id.as_str(), "r1");
    assert_eq!(c.key("infra-prod").unwrap().latest_version, 2);
    assert!(c.policies["infra-prod-admin"].keys["infra-prod"].contains(&Capability::Rewrap));
}

#[test]
fn unknown_field_is_rejected() {
    assert!(matches!(
        mutate(|v| v["roles"]["infra-ci"]["bound_claim"] = serde_json::json!({})),
        Err(ConfigError::Json(_))
    ));
}

#[test]
fn jwt_role_without_bound_claims_is_rejected() {
    invalid(
        mutate(|v| v["roles"]["infra-ci"]["bound_claims"] = serde_json::json!({})),
        "roles.infra-ci",
        "needs bound_claims",
    );
}

#[test]
fn jwt_role_without_bound_audiences_is_rejected() {
    invalid(
        mutate(|v| v["roles"]["infra-ci"]["bound_audiences"] = serde_json::json!([])),
        "roles.infra-ci",
        "needs bound_audiences",
    );
}

#[test]
fn jwt_role_with_ssh_keys_is_rejected() {
    invalid(
        mutate(|v| {
            v["roles"]["infra-ci"]["ssh_keys"] =
                serde_json::json!([include_str!("fixtures/ssh/ed25519.pub").trim()]);
        }),
        "roles.infra-ci",
        "must not set ssh_keys",
    );
}

#[test]
fn ssh_role_without_keys_is_rejected() {
    invalid(
        mutate(|v| v["roles"]["operator"]["ssh_keys"] = serde_json::json!([])),
        "roles.operator",
        "needs ssh_keys",
    );
}

#[test]
fn ssh_role_with_audiences_or_claims_is_rejected() {
    invalid(
        mutate(|v| v["roles"]["operator"]["bound_audiences"] = serde_json::json!(["https://x"])),
        "roles.operator",
        "must not set bound_audiences or bound_claims",
    );
    invalid(
        mutate(|v| v["roles"]["operator"]["bound_claims"] = serde_json::json!({"sub": "x"})),
        "roles.operator",
        "must not set bound_audiences or bound_claims",
    );
}

#[test]
fn role_with_empty_policies_is_rejected() {
    for role in ["infra-ci", "operator"] {
        invalid(
            mutate(|v| v["roles"][role]["policies"] = serde_json::json!([])),
            &format!("roles.{role}"),
            "policies must not be empty",
        );
    }
}

#[test]
fn policy_granting_nothing_loads() {
    // An empty policy is legal config; it grants no capability (see tests/policy.rs).
    let c = mutate(|v| v["policies"]["admin"] = serde_json::json!({})).unwrap();
    assert!(c.policies["admin"].keys.is_empty());
    assert!(c.policies["admin"].admin.is_empty());
}

#[test]
fn policy_key_with_no_capabilities_is_rejected() {
    // An empty list grants nothing, so it is almost certainly a typo for a real grant.
    invalid(
        mutate(|v| {
            v["policies"]["infra-prod-decrypt"]["keys"]["infra-prod"] = serde_json::json!([]);
        }),
        "policies.infra-prod-decrypt.keys.infra-prod",
        "capabilities must not be empty",
    );
}

#[test]
fn policy_with_an_explicit_empty_admin_list_is_rejected() {
    let r = mutate(|v| v["policies"]["admin"]["admin"] = serde_json::json!([]));
    match r {
        Err(ConfigError::Json(msg)) => assert!(
            msg.contains("admin capabilities must not be empty"),
            "{msg}"
        ),
        other => panic!("expected a Json error, got {:?}", other.map(|_| ())),
    }
}

const SSH_KEY_RULE: &str = "must be an OpenSSH public key line";

#[test]
fn ssh_role_with_rsa_key_is_rejected() {
    invalid(
        mutate(|v| {
            v["roles"]["operator"]["ssh_keys"] = serde_json::json!(["ssh-rsa AAAAB3Nza op"]);
        }),
        "roles.operator.ssh_keys[0]",
        SSH_KEY_RULE,
    );
}

fn with_ssh_keys(keys: &[&str]) -> Result<Config, ConfigError> {
    mutate(|v| v["roles"]["operator"]["ssh_keys"] = serde_json::json!(keys))
}

#[test]
fn ssh_role_with_unparseable_key_is_rejected() {
    let ecdsa_body = include_str!("fixtures/ssh/ecdsa.pub")
        .split_whitespace()
        .nth(1)
        .unwrap();
    for bad in [
        "ssh-ed25519 AAAAgarbage op".to_owned(),
        "ssh-ed25519 not base64 at all".to_owned(),
        "ssh-ed25519".to_owned(),
        // The algorithm name must match the key data.
        format!("ssh-ed25519 {ecdsa_body} op"),
    ] {
        invalid(
            with_ssh_keys(&[&bad]),
            "roles.operator.ssh_keys[0]",
            SSH_KEY_RULE,
        );
    }
}

#[test]
fn ssh_role_with_unsupported_algorithm_is_rejected() {
    let p384 = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBMti7i3s7orU0htsLnKEgPO90qYsTFffs6t//9tFK7icXr9K0u+GoFP81Y72svVd/KHt+nODeMZtR8Tt0QGaUG5vMAxrb7mHM3yDksO5234ciyh1wEgqx1TmUYiuLcb6mw== p384";
    let rsa = include_str!("fixtures/ssh/rsa.pub").trim();
    for bad in [p384, rsa] {
        invalid(
            with_ssh_keys(&[include_str!("fixtures/ssh/ed25519.pub").trim(), bad]),
            "roles.operator.ssh_keys[1]",
            SSH_KEY_RULE,
        );
    }
}

#[test]
fn ssh_role_with_other_key_prefixes_is_rejected() {
    // Valid Ed25519 key data under a prefix that isn't its own algorithm name.
    let ed25519_body = include_str!("fixtures/ssh/ed25519.pub")
        .split_whitespace()
        .nth(1)
        .unwrap();
    for prefix in [
        "ssh-dss",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "sk-ssh-ed25519@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256",
        "SSH-ED25519",
    ] {
        invalid(
            with_ssh_keys(&[&format!("{prefix} {ed25519_body} op")]),
            "roles.operator.ssh_keys[0]",
            SSH_KEY_RULE,
        );
    }
}

#[test]
fn ssh_role_with_supported_keys_loads() {
    // An sk-ssh-ed25519 key line built from the ed25519 fixture's key with application `ssh:`.
    let sk = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIJE0GVkXJCpxL5JWYnwGJv8f4VpNFckoFtC/6rejoXzsAAAABHNzaDo= fixture-sk";
    let keys = [
        include_str!("fixtures/ssh/ed25519.pub").trim(),
        include_str!("fixtures/ssh/ecdsa.pub").trim(),
        include_str!("fixtures/ssh/other.pub").trim(),
        sk,
    ];
    let c = with_ssh_keys(&keys).unwrap();
    assert_eq!(c.roles["operator"].ssh_keys.len(), 4);
}

#[test]
fn role_naming_missing_mount_or_policy_is_rejected() {
    invalid(
        mutate(|v| v["roles"]["infra-ci"]["mount"] = "nope".into()),
        "roles.infra-ci",
        r#"mount "nope" does not exist"#,
    );
    invalid(
        mutate(|v| v["roles"]["infra-ci"]["policies"] = serde_json::json!(["nope"])),
        "roles.infra-ci",
        r#"policy "nope" does not exist"#,
    );
}

#[test]
fn policy_naming_missing_key_is_rejected() {
    invalid(
        mutate(|v| v["policies"]["admin"]["keys"] = serde_json::json!({"nope": ["decrypt"]})),
        "policies.admin",
        r#"key "nope" does not exist"#,
    );
}

#[test]
fn key_versions_are_checked() {
    for min in [0, 3] {
        invalid(
            mutate(|v| v["keys"]["infra-prod"]["min_decryption_version"] = min.into()),
            "keys.infra-prod",
            "min_decryption_version must be at least 1 and at most latest_version",
        );
    }
}

#[test]
fn duplicate_key_ids_are_rejected() {
    // Keys validate in name order, so the second holder of the id is the one named.
    invalid(
        mutate(|v| v["keys"]["infra-prod"]["id"] = "k_02be44d0".into()),
        "keys.openbao-unseal.id",
        "duplicate key id",
    );
}

#[test]
fn bad_key_name_and_bad_id_are_rejected() {
    let long = "k".repeat(129);
    for name in ["bad/name", "", "has space", long.as_str()] {
        invalid(
            mutate(|v| {
                let k = v["keys"]
                    .as_object_mut()
                    .unwrap()
                    .remove("infra-prod")
                    .unwrap();
                v["keys"][name] = k;
                // Drop the policies that name the key, so only the key-name rule can fire.
                v["policies"]["infra-prod-decrypt"]["keys"] = serde_json::json!({});
                v["policies"]["infra-prod-admin"]["keys"] = serde_json::json!({});
            }),
            &format!("keys.{name}"),
            "name must be 1 to 128",
        );
    }
    assert!(mutate(|v| v["keys"]["infra-prod"]["id"] = "K/1".into()).is_err());
}

#[test]
fn jwt_mount_needs_exactly_one_key_source_and_https() {
    invalid(
        mutate(|v| v["mounts"]["github"]["jwks"] = serde_json::json!({"keys": []})),
        "mounts.github",
        "set exactly one of jwks_url or jwks",
    );
    invalid(
        mutate(|v| {
            v["mounts"]["github"]["jwks_url"].take();
        }),
        "mounts.github",
        "set exactly one of jwks_url or jwks",
    );
    invalid(
        mutate(|v| v["mounts"]["github"]["issuer"] = "http://x".into()),
        "mounts.github",
        "issuer must start with https://",
    );
}

#[test]
fn jwt_mount_with_non_https_jwks_url_is_rejected() {
    for url in [
        "http://token.actions.githubusercontent.com/.well-known/jwks",
        "HTTPS://token.actions.githubusercontent.com/.well-known/jwks",
        "file:///etc/jwks.json",
        "",
    ] {
        invalid(
            mutate(|v| v["mounts"]["github"]["jwks_url"] = url.into()),
            "mounts.github",
            "jwks_url must start with https://",
        );
    }
}

#[test]
fn ttl_bounds_are_enforced() {
    for ttl in [59, 34_560_001] {
        invalid(
            mutate(|v| v["roles"]["infra-ci"]["token_ttl_secs"] = ttl.into()),
            "roles.infra-ci",
            "token_ttl_secs must be between 60 and 34560000",
        );
    }
    for ttl in [60, 34_560_000] {
        mutate(|v| v["roles"]["infra-ci"]["token_ttl_secs"] = ttl.into()).unwrap();
    }
}

fn glob(g: &str) -> ClaimMatch {
    ClaimMatch::Glob { glob: g.into() }
}

#[test]
fn glob_matching_is_literal_except_star() {
    let g = glob("refs/tags/v*");
    assert!(g.matches("refs/tags/v1.2.3"));
    assert!(g.matches("refs/tags/v"));
    assert!(!g.matches("refs/heads/main"));
    let q = glob("a?b*");
    assert!(q.matches("a?bc"));
    assert!(!q.matches("axbc"));
    assert!(ClaimMatch::Exact("refs/tags/v*".into()).matches("refs/tags/v*"));
    assert!(!ClaimMatch::Exact("refs/tags/v*".into()).matches("refs/tags/v1"));
}

#[test]
fn glob_edge_cases() {
    for (pattern, value, want) in [
        // `**` is two single stars: any run, including none; there is no path semantics.
        ("*", "", true),
        ("*", "anything/at/all", true),
        ("**", "", true),
        ("**", "a/b", true),
        ("a**b", "ab", true),
        ("a**b", "a/x/b", true),
        ("a**b", "a/x/c", false),
        // A star on each side: the literal anywhere, including at either end.
        ("*a*", "a", true),
        ("*a*", "xax", true),
        ("*a*", "ba", true),
        ("*a*", "xyz", false),
        ("*a*", "", false),
        // A star in the middle still anchors both ends.
        ("refs/*/main", "refs/heads/main", true),
        ("refs/*/main", "refs//main", true),
        ("refs/*/main", "refs/heads/main2", false),
        ("refs/*/main", "xrefs/heads/main", false),
        ("a*b*c", "abc", true),
        ("a*b*c", "aXbYc", true),
        ("a*b*c", "acb", false),
        // Backtracking past a partial match.
        ("*ab", "aab", true),
        ("*ab", "abab", true),
        ("*ab", "aba", false),
        // An empty pattern matches only the empty value.
        ("", "", true),
        ("", "a", false),
    ] {
        assert_eq!(
            glob(pattern).matches(value),
            want,
            "{pattern:?} vs {value:?}"
        );
    }
    assert!(ClaimMatch::Exact(String::new()).matches(""));
    assert!(!ClaimMatch::Exact(String::new()).matches("a"));
}

#[test]
fn glob_without_star_is_rejected() {
    for g in ["refs/heads/main", ""] {
        invalid(
            mutate(|v| {
                v["roles"]["infra-ci"]["bound_claims"]["ref"] = serde_json::json!({"glob": g});
            }),
            "roles.infra-ci.bound_claims.ref",
            "glob must contain at least one *",
        );
    }
}

#[test]
fn glob_claim_with_extra_field_is_rejected() {
    let r = mutate(|v| {
        v["roles"]["infra-ci"]["bound_claims"]["ref"] =
            serde_json::json!({"glob": "refs/tags/v*", "exact": "x"});
    });
    assert!(matches!(
        r,
        Err(ConfigError::Json(_) | ConfigError::Invalid(_))
    ));
}

#[test]
fn ssh_mount_with_extra_field_is_rejected() {
    let r = mutate(|v| v["mounts"]["ssh"] = serde_json::json!({"type": "ssh", "x": 1}));
    assert!(matches!(
        r,
        Err(ConfigError::Json(_) | ConfigError::Invalid(_))
    ));
}

/// The valid config plus a `github-user` mount and a role on it.
fn with_github(f: impl FnOnce(&mut serde_json::Value)) -> Result<Config, ConfigError> {
    mutate(|v| {
        v["mounts"]["github-user"] =
            serde_json::json!({ "type": "github-user", "client_id": "Iv1.0123abcd" });
        v["roles"]["gh-op"] = serde_json::json!({
            "mount": "github-user",
            "github_user_ids": [583_231],
            "policies": ["infra-prod-admin"],
            "token_ttl_secs": 3600
        });
        f(v);
    })
}

#[test]
fn github_user_mount_and_role_load() {
    let c = with_github(|_| {}).unwrap();
    assert_eq!(
        c.mounts["github-user"],
        edgekms_core::config::Mount::GithubUser {
            client_id: "Iv1.0123abcd".into()
        }
    );
    assert_eq!(c.roles["gh-op"].github_user_ids, vec![583_231]);
}

#[test]
fn github_user_mount_needs_a_sane_client_id() {
    for bad in ["", "a/b", "Iv1 x", &"a".repeat(65)] {
        invalid(
            with_github(|v| v["mounts"]["github-user"]["client_id"] = serde_json::json!(bad)),
            "mounts.github-user",
            "client_id must be 1 to 64",
        );
    }
    assert!(matches!(
        with_github(|v| v["mounts"]["github-user"]["extra"] = serde_json::json!(1)),
        Err(ConfigError::Json(_))
    ));
}

#[test]
fn github_user_role_needs_user_ids_and_nothing_else() {
    invalid(
        with_github(|v| v["roles"]["gh-op"]["github_user_ids"] = serde_json::json!([])),
        "roles.gh-op",
        "needs github_user_ids",
    );
    invalid(
        with_github(|v| v["roles"]["gh-op"]["bound_audiences"] = serde_json::json!(["x"])),
        "roles.gh-op",
        "must not set bound_audiences, bound_claims or ssh_keys",
    );
    invalid(
        with_github(|v| v["roles"]["gh-op"]["bound_claims"] = serde_json::json!({"a": "b"})),
        "roles.gh-op",
        "must not set bound_audiences, bound_claims or ssh_keys",
    );
    invalid(
        with_github(|v| {
            v["roles"]["gh-op"]["ssh_keys"] = v["roles"]["operator"]["ssh_keys"].clone();
        }),
        "roles.gh-op",
        "must not set bound_audiences, bound_claims or ssh_keys",
    );
}

#[test]
fn github_user_ids_are_refused_on_other_roles() {
    invalid(
        mutate(|v| v["roles"]["infra-ci"]["github_user_ids"] = serde_json::json!([1])),
        "roles.infra-ci",
        "only a role on a github-user mount",
    );
    invalid(
        mutate(|v| v["roles"]["operator"]["github_user_ids"] = serde_json::json!([1])),
        "roles.operator",
        "only a role on a github-user mount",
    );
}

#[test]
fn public_origins_default_to_none_and_must_be_origins() {
    assert_eq!(
        Config::from_json(VALID).unwrap().public_origins,
        Vec::<String>::new()
    );
    let c = mutate(|v| {
        v["public_origins"] = serde_json::json!(["https://kms.example.com", "http://[::1]:8787"]);
    })
    .unwrap();
    assert_eq!(c.public_origins.len(), 2);
    for bad in [
        "https://kms.example.com/",
        "kms.example.com",
        "https://kms.example.com/path",
    ] {
        invalid(
            mutate(|v| v["public_origins"] = serde_json::json!([bad])),
            "public_origins[0]",
            "must be an origin",
        );
    }
}

#[test]
fn github_client_id_must_start_with_a_letter_or_digit() {
    for bad in [".", "..", "-x", "_x"] {
        invalid(
            with_github(|v| v["mounts"]["github-user"]["client_id"] = serde_json::json!(bad)),
            "mounts.github-user",
            "starting with a letter or digit",
        );
    }
}

#[test]
fn github_user_mounts_share_one_oauth_app() {
    // The Worker holds one GITHUB_CLIENT_SECRET, so two apps can't both work.
    assert!(
        with_github(|v| {
            v["mounts"]["zz-github"] =
                serde_json::json!({ "type": "github-user", "client_id": "Iv1.0123abcd" });
        })
        .is_ok()
    );
    invalid(
        with_github(|v| {
            v["mounts"]["zz-github"] =
                serde_json::json!({ "type": "github-user", "client_id": "Iv1.other" });
        }),
        "mounts.zz-github",
        "same OAuth App client_id",
    );
}
