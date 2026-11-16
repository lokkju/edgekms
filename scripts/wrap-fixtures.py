# /// script
# dependencies = ["cryptography"]
# ///
"""Writes crates/edgekms-worker/tests/fixtures/wrap.json: one hosted-tier wrapped root.

The wrap is AES-256-GCM under the master key, IV prepended and the 16-byte tag appended
(iv[12] || ct[32] || tag[16]), with AAD edgekms/wrap/v1/<tenant id>/<root id>. Every input
is fixed, so the output is deterministic; a real wrap uses a fresh random IV.

Run: uv run scripts/wrap-fixtures.py
"""
import json, pathlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

master = bytes(range(0x40, 0x60))
root = bytes(range(32))  # the existing KAT root
iv = bytes.fromhex("000102030405060708090a0b")
tenant_id, root_id = "t_test", "r1"
aad = f"edgekms/wrap/v1/{tenant_id}/{root_id}".encode()

wrapped = iv + AESGCM(master).encrypt(iv, root, aad)
assert len(wrapped) == 60

# Self-check against the existing KAT: the unwrapped root derives k_test v1's DataKey.
data_key = HKDF(hashes.SHA256(), 32, f"edgekms/v1/{root_id}".encode(), b"transit/k_test/1").derive(root)
assert data_key.hex() == "f8c344d0aa08dc23f094d482c48f51c008ba7465db443e2973a62ee14fadf707"

out = {
    "master": master.hex(),
    "root": root.hex(),
    "tenant_id": tenant_id,
    "root_id": root_id,
    "aad": aad.decode(),
    "iv": iv.hex(),
    "wrapped": wrapped.hex(),
    "k_test_v1_data_key": data_key.hex(),
}
path = pathlib.Path(__file__).resolve().parent.parent / "crates/edgekms-worker/tests/fixtures/wrap.json"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(out, indent=2) + "\n")
print(path)
