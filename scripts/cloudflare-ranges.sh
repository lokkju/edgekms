#!/usr/bin/env bash
# Prints Cloudflare's published IP ranges (https://www.cloudflare.com/ips-v4 and ips-v6) as the
# Rust constants in crates/edgekms-core/src/clientip.rs, so the compiled-in list can be
# refreshed and diffed:
#
#   scripts/cloudflare-ranges.sh > /tmp/ranges.rs
#   diff /tmp/ranges.rs <(sed -n '/^const CLOUDFLARE_V4/,/^];$/p;/^const CLOUDFLARE_V6/,/^];$/p' \
#     crates/edgekms-core/src/clientip.rs)
set -euo pipefail
v4="$(curl -fsS https://www.cloudflare.com/ips-v4)"
v6="$(curl -fsS https://www.cloudflare.com/ips-v6)"
uv run --no-project python -I -c '
import ipaddress, sys
v4, v6 = sys.argv[1].split(), sys.argv[2].split()
print("const CLOUDFLARE_V4: &[(Ipv4Addr, u8)] = &[")
for cidr in v4:
    n = ipaddress.IPv4Network(cidr)
    octets = ", ".join(str(b) for b in n.network_address.packed)
    print(f"    (Ipv4Addr::new({octets}), {n.prefixlen}),")
print("];")
print("const CLOUDFLARE_V6: &[(Ipv6Addr, u8)] = &[")
for cidr in v6:
    n = ipaddress.IPv6Network(cidr)
    p = n.network_address.packed
    words = (int.from_bytes(p[i:i + 2], "big") for i in range(0, 16, 2))
    groups = ", ".join(hex(w) if w else "0" for w in words)
    print(f"    (Ipv6Addr::new({groups}), {n.prefixlen}),")
print("];")
' "$v4" "$v6"
