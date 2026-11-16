//! Prints a Transit ciphertext for stdin under a raw base64 key, so `scripts/openbao-vectors.sh`
//! can check that OpenBao decrypts what edgekms writes.
//!
//! Usage: `vault_encrypt <base64 key> <version> < plaintext`

use std::io::Read as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use edgekms_core::transit::{self, DataKey};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, key, version] = args.as_slice() else {
        panic!("usage: vault_encrypt <base64 key> <version> < plaintext");
    };
    let key: [u8; 32] = STANDARD.decode(key).unwrap().try_into().unwrap();
    let mut plaintext = Vec::new();
    std::io::stdin().read_to_end(&mut plaintext).unwrap();
    let ct = transit::encrypt(
        &DataKey::from_bytes(key),
        version.parse().unwrap(),
        &plaintext,
        &mut rand::rng(),
    )
    .unwrap();
    println!("{ct}");
}
