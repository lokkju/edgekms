//! The per-IP rate-limit key and `CF-Worker` handling (`edgekms_core::clientip`). The
//! config MAC vector (`config_mac_matches_vector`) is in `tests/keyops.rs`.

use edgekms_core::clientip::limit_key;

#[test]
fn plain_ip_is_its_own_key() {
    assert_eq!(
        limit_key(Some("203.0.113.9"), None).as_deref(),
        Some("203.0.113.9")
    );
    assert_eq!(
        limit_key(Some("2001:db8::1"), None).as_deref(),
        Some("2001:db8::1")
    );
    // A Cloudflare address without CF-Worker is still just the address.
    assert_eq!(
        limit_key(Some("104.16.0.1"), None).as_deref(),
        Some("104.16.0.1")
    );
}

#[test]
fn missing_ip_is_no_key() {
    assert_eq!(limit_key(None, None), None);
    assert_eq!(limit_key(None, Some("tenant.example")), None);
}

#[test]
fn cf_worker_from_cloudflare_range_is_keyed_with_zone() {
    assert_eq!(
        limit_key(Some("104.16.0.1"), Some("tenant.example")).as_deref(),
        Some("cfw:tenant.example|104.16.0.1")
    );
    assert_eq!(
        limit_key(Some("2606:4700::1"), Some("tenant.example")).as_deref(),
        Some("cfw:tenant.example|2606:4700::1")
    );
    // Range edges of 173.245.48.0/20 (173.245.48.0 to 173.245.63.255) and 2a06:98c0::/29.
    for (ip, inside) in [
        ("173.245.47.255", false),
        ("173.245.48.0", true),
        ("173.245.63.255", true),
        ("173.245.64.0", false),
        ("2a06:98bf:ffff::1", false),
        ("2a06:98c0::", true),
        ("2a06:98c7:ffff:ffff:ffff:ffff:ffff:ffff", true),
        ("2a06:98c8::", false),
    ] {
        let want = if inside {
            format!("cfw:z.example|{ip}")
        } else {
            ip.to_owned()
        };
        assert_eq!(limit_key(Some(ip), Some("z.example")), Some(want), "{ip}");
    }
}

#[test]
fn forged_cf_worker_from_outside_cloudflare_is_ignored() {
    assert_eq!(
        limit_key(Some("203.0.113.9"), Some("evil.example")).as_deref(),
        Some("203.0.113.9")
    );
    assert_eq!(
        limit_key(Some("2001:db8::1"), Some("evil.example")).as_deref(),
        Some("2001:db8::1")
    );
}

#[test]
fn overlong_cf_worker_is_ignored() {
    let at_cap = "a".repeat(253);
    assert_eq!(
        limit_key(Some("104.16.0.1"), Some(&at_cap)),
        Some(format!("cfw:{at_cap}|104.16.0.1"))
    );
    let over = "a".repeat(254);
    assert_eq!(
        limit_key(Some("104.16.0.1"), Some(&over)).as_deref(),
        Some("104.16.0.1")
    );
    // An empty header names no zone.
    assert_eq!(
        limit_key(Some("104.16.0.1"), Some("")).as_deref(),
        Some("104.16.0.1")
    );
}

#[test]
fn unparsable_ip_is_verbatim() {
    assert_eq!(
        limit_key(Some("not an ip"), Some("tenant.example")).as_deref(),
        Some("not an ip")
    );
    // A Cloudflare address with a port or brackets doesn't parse, so it isn't matched.
    assert_eq!(
        limit_key(Some("104.16.0.1:443"), Some("tenant.example")).as_deref(),
        Some("104.16.0.1:443")
    );
    assert_eq!(
        limit_key(Some("[2606:4700::1]"), Some("tenant.example")).as_deref(),
        Some("[2606:4700::1]")
    );
}
