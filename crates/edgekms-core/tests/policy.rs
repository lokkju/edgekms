use edgekms_core::config::{AdminCapability, Capability, Config};
use edgekms_core::policy;

fn cfg() -> Config {
    Config::from_json(include_str!("fixtures/config.valid.json")).unwrap()
}
fn p(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn grants_listed_capability() {
    assert!(policy::allows(
        &cfg(),
        &p(&["infra-prod-decrypt"]),
        "infra-prod",
        Capability::Decrypt
    ));
}
#[test]
fn denies_unlisted_capability() {
    assert!(!policy::allows(
        &cfg(),
        &p(&["infra-prod-decrypt"]),
        "infra-prod",
        Capability::Encrypt
    ));
}
#[test]
fn denies_other_key() {
    assert!(!policy::allows(
        &cfg(),
        &p(&["infra-prod-decrypt"]),
        "openbao-unseal",
        Capability::Decrypt
    ));
}
#[test]
fn unions_policies() {
    assert!(policy::allows(
        &cfg(),
        &p(&["infra-prod-decrypt", "infra-prod-admin"]),
        "infra-prod",
        Capability::Rewrap
    ));
}
#[test]
fn unknown_policy_grants_nothing() {
    assert!(!policy::allows(
        &cfg(),
        &p(&["retired"]),
        "infra-prod",
        Capability::Decrypt
    ));
}
#[test]
fn empty_policy_list_grants_nothing() {
    let c = cfg();
    for key in ["infra-prod", "openbao-unseal"] {
        for cap in [
            Capability::Encrypt,
            Capability::Decrypt,
            Capability::Rewrap,
            Capability::Read,
        ] {
            assert!(!policy::allows(&c, &[], key, cap), "{key} {cap:?}");
        }
    }
    for cap in [AdminCapability::TokenCreate, AdminCapability::TokenRevoke] {
        assert!(!policy::allows_admin(&c, &[], cap), "{cap:?}");
    }
}
#[test]
fn key_policies_and_admin_policies_do_not_cross() {
    let c = cfg();
    // Every key capability on infra-prod is still no admin capability.
    for cap in [AdminCapability::TokenCreate, AdminCapability::TokenRevoke] {
        assert!(
            !policy::allows_admin(&c, &p(&["infra-prod-admin", "infra-prod-decrypt"]), cap),
            "{cap:?}"
        );
    }
    // And both admin capabilities are no key capability.
    assert!(!policy::allows(
        &c,
        &p(&["admin"]),
        "infra-prod",
        Capability::Decrypt
    ));
}
#[test]
fn admin_capabilities() {
    assert!(policy::allows_admin(
        &cfg(),
        &p(&["admin"]),
        AdminCapability::TokenCreate
    ));
    assert!(!policy::allows_admin(
        &cfg(),
        &p(&["infra-prod-admin"]),
        AdminCapability::TokenRevoke
    ));
}
