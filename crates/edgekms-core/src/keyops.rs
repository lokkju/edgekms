//! Secret-key operations behind one trait, so the Worker can use `WebCrypto` and tests and tools
//! can use `RustCrypto` while producing identical bytes. Key material never leaves the implementation.

use std::cell::RefCell;

use hmac::{Hmac, KeyInit, Mac};
use rand_core::Rng as _;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::transit::{self, Ciphertext, Error, Id, RootKey};

/// What a MAC is for. Each purpose gets its own key, derived from the root with the HKDF info
/// string [`MacPurpose::info`], so a tag for one purpose never verifies for another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacPurpose {
    Token,
    Challenge,
    Audit,
    /// A hosted tenant's config row, so a config written straight to the tenant store without
    /// the tenant's root doesn't load.
    Config,
    /// A hosted tenant's membership row, under the control plane's own root, so a membership
    /// written straight to the tenant store without the master grants nothing.
    Member,
    /// A hosted tenant's pending invite row, under the control plane's own root.
    Invite,
    /// A signup allowlist row, under the control plane's own root, so an allowlist entry
    /// written straight to the tenant store without the master admits no one.
    Allow,
    /// An invite request row, under the control plane's own root, so a request written straight
    /// to the tenant store can't put a misleading login or note beside someone's GitHub id.
    InviteRequest,
    /// A control-plane login challenge (`POST /v1/login/ssh/challenge`), under the control
    /// plane's own root. Kept apart from [`MacPurpose::Challenge`], the data plane's, and from
    /// registration challenges.
    ControlChallenge,
    /// A registration challenge an SSH key signs to prove its holder registered it
    /// (`POST /v1/me/ssh-keys/challenge`), under the control plane's own root.
    SshKeyProof,
    /// A registered SSH key row, under the control plane's own root, so a key written straight
    /// to the tenant store without the master logs no one in.
    SshKey,
}

impl MacPurpose {
    #[must_use]
    pub fn info(self) -> &'static str {
        match self {
            Self::Token => "mac/token/v1",
            Self::Challenge => "mac/challenge/v1",
            Self::Audit => "mac/audit/v1",
            Self::Config => "mac/config/v1",
            Self::Member => "mac/member/v1",
            Self::Invite => "mac/invite/v1",
            Self::Allow => "mac/allow/v1",
            Self::InviteRequest => "mac/invite-request/v1",
            Self::ControlChallenge => "mac/control-challenge/v1",
            Self::SshKeyProof => "mac/ssh-key-proof/v1",
            Self::SshKey => "mac/ssh-key/v1",
        }
    }
}

/// Transit encryption under derived keys, HMACs for tokens, challenges and audit, and randomness.
///
/// `decrypt` derives the key from `ct.version()`; checking that version against configuration is
/// the caller's job. Futures are not `Send`: the Worker is single-threaded.
#[allow(async_fn_in_trait)]
pub trait KeyOps {
    /// # Errors
    /// [`Error::Malformed`] if `version` is 0; [`Error::Backend`] if the key backend fails.
    async fn encrypt(&self, key_id: &Id, version: u32, plaintext: &[u8]) -> Result<String, Error>;

    /// # Errors
    /// [`Error::Decrypt`] if the key is wrong or the ciphertext was altered; [`Error::Backend`] if
    /// the key backend fails.
    async fn decrypt(&self, key_id: &Id, ct: &Ciphertext) -> Result<Zeroizing<Vec<u8>>, Error>;

    /// `HMAC-SHA256(HKDF(root, salt = "edgekms/v1/" + root id, info = purpose.info()), data)`.
    ///
    /// # Errors
    /// [`Error::Backend`] if the key backend fails; [`SoftKeyOps`] never fails.
    async fn mac(&self, purpose: MacPurpose, data: &[u8]) -> Result<[u8; 32], Error>;

    /// Constant-time check of `tag` against [`KeyOps::mac`]; a tag of the wrong length is `false`.
    ///
    /// # Errors
    /// [`Error::Backend`] if the key backend fails; [`SoftKeyOps`] never fails.
    async fn verify_mac(&self, purpose: MacPurpose, data: &[u8], tag: &[u8])
    -> Result<bool, Error>;

    fn random(&self, out: &mut [u8]);
}

/// [`KeyOps`] on `RustCrypto`, holding the root key in memory.
pub struct SoftKeyOps<R> {
    root: RootKey,
    rng: RefCell<R>,
}

impl<R: rand_core::CryptoRng> SoftKeyOps<R> {
    #[must_use]
    pub fn new(root: RootKey, rng: R) -> Self {
        Self {
            root,
            rng: RefCell::new(rng),
        }
    }

    fn hmac(&self, purpose: MacPurpose, data: &[u8]) -> Hmac<Sha256> {
        let key = self.root.derive(purpose.info());
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&*key)
            .expect("any key length is valid for HMAC");
        m.update(data);
        m
    }
}

#[allow(clippy::unused_async_trait_impl)] // the trait is async for WebCrypto; RustCrypto never awaits
impl<R: rand_core::CryptoRng> KeyOps for SoftKeyOps<R> {
    async fn encrypt(&self, key_id: &Id, version: u32, plaintext: &[u8]) -> Result<String, Error> {
        transit::encrypt(
            &self.root.transit_key(key_id, version),
            version,
            plaintext,
            &mut *self.rng.borrow_mut(),
        )
    }

    async fn decrypt(&self, key_id: &Id, ct: &Ciphertext) -> Result<Zeroizing<Vec<u8>>, Error> {
        transit::decrypt(&self.root.transit_key(key_id, ct.version()), ct)
    }

    async fn mac(&self, purpose: MacPurpose, data: &[u8]) -> Result<[u8; 32], Error> {
        Ok(self.hmac(purpose, data).finalize().into_bytes().into())
    }

    async fn verify_mac(
        &self,
        purpose: MacPurpose,
        data: &[u8],
        tag: &[u8],
    ) -> Result<bool, Error> {
        Ok(self.hmac(purpose, data).verify_slice(tag).is_ok())
    }

    fn random(&self, out: &mut [u8]) {
        self.rng.borrow_mut().fill_bytes(out);
    }
}
