#!/usr/bin/env bash
# Writes crates/edgekms-core/tests/fixtures/ssh/: keys of each type and signatures over a fixed challenge.
# Rerunning it replaces every key, so tests that embed a fixture key (the sk line in
# tests/config.rs) need updating after a full run.
set -euo pipefail
out="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)/crates/edgekms-core/tests/fixtures/ssh"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out"
msg="ekmsc.fixture-challenge"
printf %s "$msg" >"$out/challenge.txt"
for t in ed25519 ecdsa rsa; do
  ssh-keygen -q -t "$t" -N '' -C "fixture-$t" -f "$tmp/$t" $([ "$t" = ecdsa ] && echo -b 256)
  cp "$tmp/$t.pub" "$out/$t.pub"
  ssh-keygen -Y sign -n edgekms -f "$tmp/$t" <"$out/challenge.txt" >"$out/$t.sig"
done
ssh-keygen -Y sign -n git -f "$tmp/ed25519" <"$out/challenge.txt" >"$out/ed25519.wrong-namespace.sig"
ssh-keygen -q -t ed25519 -N '' -C other -f "$tmp/other"
cp "$tmp/other.pub" "$out/other.pub"
ssh-keygen -q -t ecdsa -b 256 -N '' -C other-ecdsa -f "$tmp/other-ecdsa"
cp "$tmp/other-ecdsa.pub" "$out/other-ecdsa.pub"
# ssh-keygen signs with SHA-512 by default; SSHSIG also allows SHA-256. A key of its own, so these
# two files can be added without regenerating the rest.
ssh-keygen -q -t ed25519 -N '' -C fixture-sha256 -f "$tmp/sha256"
cp "$tmp/sha256.pub" "$out/sha256.pub"
ssh-keygen -Y sign -n edgekms -O hashalg=sha256 -f "$tmp/sha256" <"$out/challenge.txt" >"$out/sha256.sig"
echo "wrote $out"
