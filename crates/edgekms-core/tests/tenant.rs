//! Tenant names and Host header routing (`edgekms_core::tenant`).

use std::collections::BTreeSet;

use edgekms_core::tenant::{
    HostRoute, RESERVED, TenantName, TenantNameError, route_host, tenant_origin,
};

fn tenant(s: &str) -> HostRoute {
    HostRoute::Tenant(TenantName::new(s).unwrap())
}

#[test]
fn reserved_names_are_lowercase_labels_without_duplicates() {
    let unique: BTreeSet<_> = RESERVED.iter().collect();
    assert_eq!(unique.len(), RESERVED.len(), "duplicate reserved name");
    for name in RESERVED {
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "{name}"
        );
    }
    for name in ["api", "www", "admin", "vault", "edge", "km"] {
        assert!(RESERVED.contains(&name), "{name}");
    }
}

#[test]
fn valid_names_load() {
    let long = "a".repeat(32);
    for name in ["acme", "a1b", "x-y-z", "123", long.as_str()] {
        assert_eq!(TenantName::new(name).unwrap().as_str(), name);
    }
}

#[test]
fn length_is_3_to_32() {
    assert_eq!(TenantName::new(""), Err(TenantNameError::Length));
    assert_eq!(TenantName::new("ab"), Err(TenantNameError::Length));
    assert!(TenantName::new("abc").is_ok());
    assert!(TenantName::new(&"a".repeat(32)).is_ok());
    assert_eq!(
        TenantName::new(&"a".repeat(33)),
        Err(TenantNameError::Length)
    );
    // Length counts bytes, and multibyte input fails the charset either way.
    assert_eq!(TenantName::new("ééé"), Err(TenantNameError::Charset));
}

#[test]
fn charset_and_hyphens() {
    let cases = [
        ("-ab", TenantNameError::Hyphen),
        ("ab-", TenantNameError::Hyphen),
        ("a--b", TenantNameError::Punycode),
        ("xn--80ak6aa92e", TenantNameError::Punycode),
        ("Abc", TenantNameError::Charset),
        ("a_b", TenantNameError::Charset),
        ("a.b", TenantNameError::Charset),
        ("a b", TenantNameError::Charset),
        ("abc\0", TenantNameError::Charset),
    ];
    for (name, want) in cases {
        assert_eq!(TenantName::new(name), Err(want), "{name:?}");
    }
}

#[test]
fn reserved_names_are_refused() {
    for name in RESERVED {
        // Two-letter entries (`id`, `me`, `mx`, `km`) already fail the length rule.
        let want = if name.len() < 3 {
            TenantNameError::Length
        } else {
            TenantNameError::Reserved
        };
        assert_eq!(TenantName::new(name), Err(want), "{name}");
    }
    for name in ["edgekms", "edgekms-foo", "edgekms1"] {
        assert_eq!(
            TenantName::new(name),
            Err(TenantNameError::Reserved),
            "{name}"
        );
    }
    // A reserved word inside a longer name is fine.
    assert!(TenantName::new("my-vault").is_ok());
    assert!(TenantName::new("apis").is_ok());
}

#[test]
fn route_host_cases() {
    let apex = "edge.km";
    let cases = [
        ("acme.edge.km", tenant("acme")),
        ("ACME.EDGE.KM", tenant("acme")),
        ("acme.edge.km:443", tenant("acme")),
        ("acme.edge.km.", tenant("acme")),
        ("acme.edge.km.:8443", tenant("acme")),
        ("api.edge.km", HostRoute::Control),
        ("API.edge.km", HostRoute::Control),
        ("api.edge.km:443", HostRoute::Control),
        ("app.edge.km", HostRoute::Console),
        ("APP.edge.km:443", HostRoute::Console),
        ("app.edge.km.", HostRoute::Console),
        ("app.acme.edge.km", HostRoute::Foreign),
        ("acme.app.edge.km", HostRoute::Foreign),
        ("www.edge.km", HostRoute::Reserved),
        ("me.edge.km", HostRoute::Reserved),
        ("admin.edge.km", HostRoute::Reserved),
        ("a.b.edge.km", HostRoute::Foreign),
        ("api.api.edge.km", HostRoute::Foreign),
        ("edge.km", HostRoute::Foreign),
        ("edge.km.", HostRoute::Foreign),
        (".edge.km", HostRoute::Foreign),
        ("acme.edge.km..", HostRoute::Foreign),
        ("acme.edge.km.evil.com", HostRoute::Foreign),
        ("evil-edge.km", HostRoute::Foreign),
        ("xn--80ak6aa92e.edge.km", HostRoute::Foreign),
        ("edgekms.edge.km", HostRoute::Foreign),
        ("ab.edge.km", HostRoute::Foreign),
        ("a_b.edge.km", HostRoute::Foreign),
        ("", HostRoute::Foreign),
        ("km", HostRoute::Foreign),
    ];
    for (host, want) in cases {
        assert_eq!(route_host(host, apex), want, "{host:?}");
    }
    assert_eq!(
        route_host("acme.localhost:8787", "localhost"),
        tenant("acme")
    );
    assert_eq!(
        route_host("api.localhost:8787", "localhost"),
        HostRoute::Control
    );
    assert_eq!(
        route_host("app.localhost:8787", "localhost"),
        HostRoute::Console
    );
    // The apex is compared case-insensitively too.
    assert_eq!(route_host("acme.edge.km", "EDGE.KM"), tenant("acme"));
}

#[test]
fn origin_template_is_filled() {
    let name = TenantName::new("acme").unwrap();
    assert_eq!(
        tenant_origin("https://{tenant}.edge.km", &name),
        "https://acme.edge.km"
    );
    assert_eq!(
        tenant_origin("http://{tenant}.localhost:8787", &name),
        "http://acme.localhost:8787"
    );
}
