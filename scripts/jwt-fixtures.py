# /// script
# dependencies = ["cryptography", "pyjwt"]
# ///
"""Writes crates/edgekms-core/tests/fixtures/jwt.json: a JWKS and tokens covering each verify() outcome."""
import base64, json, pathlib, jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

ISS = "https://issuer.test"
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
other_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)

def jwk(pub, kid):
    d = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(pub) if isinstance(pub, rsa.RSAPublicKey) else jwt.algorithms.ECAlgorithm.to_jwk(pub))
    d["kid"] = kid
    return d

jwks = {"keys": [jwk(rsa_key.public_key(), "rsa1"), jwk(ec_key.public_key(), "ec1")]}
base = {"iss": ISS, "aud": "https://kms.test", "sub": "repo:o/r:ref:refs/heads/main", "repository_id": "42",
        "ref": "refs/heads/main", "iat": 1_000_000_000, "nbf": 1_000_000_000, "exp": 4_102_444_800}

def sign(claims, key, alg, kid, **hdr):
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid, **hdr})

def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

valid_rs = sign(base, rsa_key, "RS256", "rsa1")
h, p, s = valid_rs.split(".")
pub_pem = rsa_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
cases = {
    "valid_rs256": valid_rs,
    "valid_es256": sign(base, ec_key, "ES256", "ec1"),
    "expired": sign({**base, "exp": 1_000_000_100}, rsa_key, "RS256", "rsa1"),
    "not_yet_valid": sign({**base, "nbf": 4_000_000_000}, rsa_key, "RS256", "rsa1"),
    "no_exp": sign({k: v for k, v in base.items() if k != "exp"}, rsa_key, "RS256", "rsa1"),
    "wrong_issuer": sign({**base, "iss": "https://evil.test"}, rsa_key, "RS256", "rsa1"),
    "unknown_kid": sign(base, other_rsa, "RS256", "rsa2"),
    "missing_kid": jwt.encode(base, rsa_key, algorithm="RS256"),
    "bad_signature": f"{h}.{p}.{s[:-4]}AAAA",
    "signed_by_other_key": sign(base, other_rsa, "RS256", "rsa1"),
    "rs256_header_ec_key": f"{b64({'alg': 'RS256', 'kid': 'ec1', 'typ': 'JWT'})}.{p}.{s}",
    "alg_none": f"{b64({'alg': 'none', 'kid': 'rsa1'})}.{p}.",
    "hs256_with_public_key": f"{b64({'alg': 'HS256', 'kid': 'rsa1'})}.{p}.{s}",
    "aud_list": sign({**base, "aud": ["x", "https://kms.test"]}, rsa_key, "RS256", "rsa1"),
    "numeric_repository_id": sign({**base, "repository_id": 42}, rsa_key, "RS256", "rsa1"),
    "two_parts": f"{h}.{p}",
}
out = pathlib.Path(__file__).resolve().parent.parent / "crates/edgekms-core/tests/fixtures/jwt.json"
out.write_text(json.dumps({"issuer": ISS, "jwks": jwks, "cases": cases}, indent=2) + "\n")
print(f"wrote {out}")
