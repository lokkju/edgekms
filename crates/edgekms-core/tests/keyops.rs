use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_core::hosted::{
    allow_mac_input, invite_mac_input, invite_request_mac_input, member_mac_input,
};
use edgekms_core::keyops::{KeyOps, MacPurpose, SoftKeyOps};
use edgekms_core::transit::{self, Ciphertext, DataKey, Id, RootKey};
use pollster::block_on;
use rand::rngs::StdRng;
use rand::{Rng as _, SeedableRng as _};

fn ops() -> SoftKeyOps<rand::rngs::ThreadRng> {
    let bytes: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).unwrap());
    SoftKeyOps::new(RootKey::new(Id::new("r1").unwrap(), bytes), rand::rng())
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        write!(s, "{x:02x}").unwrap();
        s
    })
}

#[test]
fn mac_matches_independent_hkdf_hmac_vectors() {
    // Python cryptography: HKDF(salt "edgekms/v1/r1", info "mac/<p>/v1") then HMAC-SHA256("probe").
    let cases = [
        (
            MacPurpose::Token,
            "1a0052537fb94790d605802454d8be1cb1e896411390953baa1296b18e7ee3b1",
        ),
        (
            MacPurpose::Challenge,
            "ef43c64c2107cf81465d1b8e9b0fa0cf80b8c161529e38802d779dd038adfe0d",
        ),
        (
            MacPurpose::Audit,
            "42c36a7be01ddb4dc75db3c3609721ef6496cb547fb4a9b08bde8be656e1989d",
        ),
    ];
    for (p, want) in cases {
        assert_eq!(
            hex(&block_on(ops().mac(p, b"probe")).unwrap()),
            want,
            "{p:?}"
        );
    }
}

#[test]
fn config_mac_matches_vector() {
    // The same independent computation as the three vectors above, for the hosted tier's
    // config MAC:
    // uv run --no-project --with cryptography python -I -c "
    // from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    // from cryptography.hazmat.primitives import hashes, hmac
    // k=HKDF(algorithm=hashes.SHA256(),length=32,salt=b'edgekms/v1/r1',info=b'mac/config/v1').derive(bytes(range(32)))
    // h=hmac.HMAC(k,hashes.SHA256()); h.update(b'probe'); print(h.finalize().hex())"
    assert_eq!(
        hex(&block_on(ops().mac(MacPurpose::Config, b"probe")).unwrap()),
        "cd5ce29599ea8bc9b4860c1125e764300708388b5faf937199874b4dee1f7d8e"
    );
}

#[test]
fn member_and_invite_macs_match_vectors() {
    // The same independent computation for the hosted control plane's membership and invite
    // row MACs: info "mac/member/v1" and "mac/invite/v1", over "probe" and over the row layouts
    // `tests/hosted.rs` pins (Python builds those bytes with `struct.pack(">Q", ...)`).
    assert_eq!(
        hex(&block_on(ops().mac(MacPurpose::Member, b"probe")).unwrap()),
        "5ae599aed569217c770194b71a602d69f99460bc75c03a1c2cad2cd483671cb5"
    );
    assert_eq!(
        hex(&block_on(ops().mac(MacPurpose::Invite, b"probe")).unwrap()),
        "97a2844856cc86b35dd51fd790c208f28ed3927313bb8cce9863a1a7e91e3985"
    );
    let member = member_mac_input("t_1", 583_231, "owner", 1_800_000_000_000);
    assert_eq!(
        hex(&block_on(ops().mac(MacPurpose::Member, &member)).unwrap()),
        "e85762d22f8f3a9c3747436b8da4c1b4340127da502036e63b3e17aa42f0a1d8"
    );
    let invite = invite_mac_input("t_1", 583_231, "member", 42, 1_800_000_000_000);
    assert_eq!(
        hex(&block_on(ops().mac(MacPurpose::Invite, &invite)).unwrap()),
        "3211e974701b0f0214ba1c03e3f25956c049cbdcf5daae19d3af30d63f37747c"
    );
}

#[test]
fn allowlist_mac_matches_vectors() {
    // The signup allowlist row MAC: info "mac/allow/v1", over "probe" and over the row
    // layout `tests/hosted.rs` pins, computed independently as above:
    // uv run --no-project --with cryptography python -I -c "
    // import struct
    // from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    // from cryptography.hazmat.primitives import hashes, hmac
    // k=HKDF(algorithm=hashes.SHA256(),length=32,salt=b'edgekms/v1/r1',info=b'mac/allow/v1').derive(bytes(range(32)))
    // h=hmac.HMAC(k,hashes.SHA256()); h.update(struct.pack('>QQQ', 583231, 42, 1800000000000))
    // print(h.finalize().hex())"
    assert_eq!(
        hex(&block_on(ops().mac(MacPurpose::Allow, b"probe")).unwrap()),
        "266e8a4f60c92e8687e283d7853c7bd3b355ad2478ef3cb7f47d3d25c4814271"
    );
    let row = allow_mac_input(583_231, 42, 1_800_000_000_000);
    assert_eq!(
        hex(&block_on(ops().mac(MacPurpose::Allow, &row)).unwrap()),
        "bc9f9940738441dcc760cc8f5af32f99f27e923a59ca3d57d7e1ef0455b362a0"
    );
}

#[test]
fn invite_request_mac_matches_vectors() {
    // The invite request row MAC (#54): info "mac/invite-request/v1", over "probe" and over the
    // row layout `tests/hosted.rs` pins, computed independently as above:
    // uv run --no-project --with cryptography python -I -c "
    // import struct
    // from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    // from cryptography.hazmat.primitives import hashes, hmac
    // k=HKDF(algorithm=hashes.SHA256(),length=32,salt=b'edgekms/v1/r1',info=b'mac/invite-request/v1').derive(bytes(range(32)))
    // l=b'octocat'; n='CI signing\nfor an OSS project'.encode()
    // row=struct.pack('>QQ',583231,1800000000000)+struct.pack('>I',len(l))+l+struct.pack('>I',len(n))+n
    // h=hmac.HMAC(k,hashes.SHA256()); h.update(row); print(h.finalize().hex())"
    assert_eq!(MacPurpose::InviteRequest.info(), "mac/invite-request/v1");
    assert_eq!(
        hex(&block_on(ops().mac(MacPurpose::InviteRequest, b"probe")).unwrap()),
        "bbaae71e162fd00f01ad68dd41ffbd985d0053119c3adaff9df7982b2c6835ad"
    );
    let row = invite_request_mac_input(
        583_231,
        1_800_000_000_000,
        "octocat",
        "CI signing\nfor an OSS project",
    );
    assert_eq!(
        hex(&block_on(ops().mac(MacPurpose::InviteRequest, &row)).unwrap()),
        "437d25ad6b7e677217666750ff7597ae1066554f879016933a69b0a8274350f7"
    );
}

#[test]
fn verify_mac_accepts_good_and_rejects_bad_tags() {
    let o = ops();
    let tag = block_on(o.mac(MacPurpose::Token, b"data")).unwrap();
    assert!(block_on(o.verify_mac(MacPurpose::Token, b"data", &tag)).unwrap());
    assert!(!block_on(o.verify_mac(MacPurpose::Challenge, b"data", &tag)).unwrap());
    assert!(!block_on(o.verify_mac(MacPurpose::Token, b"datA", &tag)).unwrap());
    assert!(!block_on(o.verify_mac(MacPurpose::Token, b"data", &tag[..31])).unwrap());
    let mut long = tag.to_vec();
    long.push(0);
    assert!(!block_on(o.verify_mac(MacPurpose::Token, b"data", &long)).unwrap());
    long.extend_from_slice(&tag);
    assert!(!block_on(o.verify_mac(MacPurpose::Token, b"data", &long)).unwrap());
    assert!(!block_on(o.verify_mac(MacPurpose::Token, b"data", &[])).unwrap());
}

fn seeded(seed: u64) -> SoftKeyOps<StdRng> {
    SoftKeyOps::new(
        RootKey::new(Id::new("r1").unwrap(), [1; 32]),
        StdRng::seed_from_u64(seed),
    )
}

#[test]
fn random_draws_from_the_injected_rng() {
    let mut want = [0u8; 48];
    StdRng::seed_from_u64(7).fill_bytes(&mut want);
    let o = seeded(7);
    let (mut a, mut b) = ([0u8; 16], [0u8; 32]);
    o.random(&mut a);
    o.random(&mut b);
    assert_eq!(a, want[..16]);
    assert_eq!(b, want[16..]);
}

#[test]
fn encrypt_takes_its_nonce_from_the_injected_rng() {
    let mut want = [0u8; 12];
    StdRng::seed_from_u64(9).fill_bytes(&mut want);
    let ct = block_on(seeded(9).encrypt(&Id::new("k_test").unwrap(), 1, b"probe")).unwrap();
    let payload = STANDARD
        .decode(ct.strip_prefix("vault:v1:").unwrap())
        .unwrap();
    assert_eq!(payload[..12], want);
    // The same seed reproduces the ciphertext byte for byte; another seed does not.
    let k = Id::new("k_test").unwrap();
    assert_eq!(ct, block_on(seeded(9).encrypt(&k, 1, b"probe")).unwrap());
    assert_ne!(ct, block_on(seeded(10).encrypt(&k, 1, b"probe")).unwrap());
}

#[test]
fn encrypt_matches_transit_derivation() {
    let o = ops();
    let k = Id::new("k_test").unwrap();
    let ct = block_on(o.encrypt(&k, 1, b"probe")).unwrap();
    // Same KAT as tests/transit.rs: r1/k_test/v1.
    let expected = DataKey::from_bytes(decode_hex(
        "f8c344d0aa08dc23f094d482c48f51c008ba7465db443e2973a62ee14fadf707",
    ));
    let parsed: Ciphertext = ct.parse().unwrap();
    assert_eq!(&*transit::decrypt(&expected, &parsed).unwrap(), b"probe");
    assert_eq!(&*block_on(o.decrypt(&k, &parsed)).unwrap(), b"probe");
}

#[test]
fn decrypt_under_another_key_id_fails() {
    let o = ops();
    let ct: Ciphertext = block_on(o.encrypt(&Id::new("k_a").unwrap(), 1, b"x"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(block_on(o.decrypt(&Id::new("k_b").unwrap(), &ct)).is_err());
}

#[test]
fn random_fills_and_differs() {
    let o = ops();
    let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
    o.random(&mut a);
    o.random(&mut b);
    assert_ne!(a, b);
}

fn decode_hex(s: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

/// `Hmac<Sha256>` keeps the key as two SHA-256 states (after the inner and outer pad blocks) plus a
/// block buffer. `hmac` 0.13 doesn't mark `Hmac` itself `ZeroizeOnDrop`, so this checks the parts:
/// with the `zeroize` features of `hmac` and `sha2` both wipe themselves on drop, and without them
/// this test doesn't compile.
#[test]
fn hmac_state_zeroizes_on_drop() {
    fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    zeroizes_on_drop::<<sha2::Sha256 as hmac::EagerHash>::Core>();
    zeroizes_on_drop::<sha2::Sha256>();
}

#[test]
fn encrypt_output_is_pinned_byte_for_byte() {
    // Root [1; 32] with id r1, key k_test v1, nonce from StdRng seed 9. The derivation, the nonce
    // placement and the vault:v<N>: framing all feed this string; existing ciphertexts need all three.
    let ct = block_on(seeded(9).encrypt(&Id::new("k_test").unwrap(), 1, b"probe")).unwrap();
    assert_eq!(ct, "vault:v1:h6l3l0iIjaXZa7vOBMmlG7c6LhX1/gv0fqXsoQjuaEep");
}

#[test]
fn encrypt_rejects_key_version_zero() {
    // WebCryptoKeyOps refuses version 0 with this error (through Ciphertext::from_parts).
    let r = block_on(ops().encrypt(&Id::new("k_test").unwrap(), 0, b"x"));
    assert!(matches!(r, Err(transit::Error::Malformed(_))), "{r:?}");
}
