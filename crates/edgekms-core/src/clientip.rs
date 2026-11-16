//! The key a per-IP rate limit counts a request against.
//!
//! A `fetch` from another Worker arrives with Cloudflare's shared egress address in
//! `CF-Connecting-IP` and the calling zone in `CF-Worker`. Keyed on the IP alone, every such
//! caller would share one bucket, so a request from inside Cloudflare's published ranges that
//! names a `CF-Worker` is keyed on both. A `CF-Worker` header from anywhere else is ignored, so
//! a client can't buy a fresh bucket per invented zone name.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The longest `CF-Worker` value used: a DNS name is at most 253 bytes.
const MAX_CF_WORKER: usize = 253;

// Cloudflare's published ranges, from `scripts/cloudflare-ranges.sh` (which prints these two
// constants; diff its output against them to refresh the list).
const CLOUDFLARE_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(173, 245, 48, 0), 20),
    (Ipv4Addr::new(103, 21, 244, 0), 22),
    (Ipv4Addr::new(103, 22, 200, 0), 22),
    (Ipv4Addr::new(103, 31, 4, 0), 22),
    (Ipv4Addr::new(141, 101, 64, 0), 18),
    (Ipv4Addr::new(108, 162, 192, 0), 18),
    (Ipv4Addr::new(190, 93, 240, 0), 20),
    (Ipv4Addr::new(188, 114, 96, 0), 20),
    (Ipv4Addr::new(197, 234, 240, 0), 22),
    (Ipv4Addr::new(198, 41, 128, 0), 17),
    (Ipv4Addr::new(162, 158, 0, 0), 15),
    (Ipv4Addr::new(104, 16, 0, 0), 13),
    (Ipv4Addr::new(104, 24, 0, 0), 14),
    (Ipv4Addr::new(172, 64, 0, 0), 13),
    (Ipv4Addr::new(131, 0, 72, 0), 22),
];
const CLOUDFLARE_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x2400, 0xcb00, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2803, 0xf800, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0xb500, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0x8100, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2a06, 0x98c0, 0, 0, 0, 0, 0, 0), 29),
    (Ipv6Addr::new(0x2c0f, 0xf248, 0, 0, 0, 0, 0, 0), 32),
];

/// Whether `ip` is in one of Cloudflare's published ranges.
fn in_cloudflare(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let ip = ip.to_bits();
            CLOUDFLARE_V4.iter().any(|&(net, len)| {
                let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
                ip & mask == net.to_bits() & mask
            })
        }
        IpAddr::V6(ip) => {
            let ip = ip.to_bits();
            CLOUDFLARE_V6.iter().any(|&(net, len)| {
                let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
                ip & mask == net.to_bits() & mask
            })
        }
    }
}

/// The rate-limit key for a request with `CF-Connecting-IP` `ip` and `CF-Worker` `cf_worker`:
/// `None` without an IP; `cfw:<cf_worker>|<ip>` when the IP is in Cloudflare's ranges and the
/// header is 1 to 253 bytes; otherwise the IP as given. An IP that doesn't parse is used
/// verbatim and never matched against the ranges.
#[must_use]
pub fn limit_key(ip: Option<&str>, cf_worker: Option<&str>) -> Option<String> {
    let ip = ip?;
    let from_cloudflare = ip.parse::<IpAddr>().is_ok_and(in_cloudflare);
    match cf_worker {
        Some(zone) if from_cloudflare && (1..=MAX_CF_WORKER).contains(&zone.len()) => {
            Some(format!("cfw:{zone}|{ip}"))
        }
        _ => Some(ip.to_owned()),
    }
}
