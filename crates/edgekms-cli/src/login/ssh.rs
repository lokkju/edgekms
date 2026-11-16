//! `login ssh`: a challenge from the Worker, signed by `ssh-keygen` (so ssh-agent, FIDO keys
//! included, does the signing), swapped for a token. This module never reads a private key.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::json;

use super::{
    LoginError, Transport, check_addr, check_mount, origin_of, str_at, take_client_token,
    vault_post,
};

/// The namespace a login signature is checked against, on a Worker and on the control plane.
pub const NAMESPACE: &str = edgekms_core::ssh::NAMESPACE;
/// The namespace of the proof that registers a key on the control plane.
pub const REGISTER_NAMESPACE: &str = edgekms_core::ssh::REGISTER_NAMESPACE;

/// Signs a challenge under an `SSHSIG` namespace, returning the armored `SSHSIG`.
pub trait Signer {
    /// # Errors
    /// [`LoginError::Sign`].
    fn sign(&self, namespace: &str, challenge: &str) -> Result<String, LoginError>;
}

/// Signs through `ssh-keygen -Y sign -n <namespace> -f <key>`, with the challenge on stdin.
pub struct SshKeygen {
    key: PathBuf,
}

impl SshKeygen {
    /// `key` is the public key file; ssh-keygen then asks ssh-agent for the signature.
    #[must_use]
    pub fn new(key: &Path) -> Self {
        Self {
            key: key.to_owned(),
        }
    }
}

impl Signer for SshKeygen {
    fn sign(&self, namespace: &str, challenge: &str) -> Result<String, LoginError> {
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", namespace, "-f"])
            .arg(&self.key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| LoginError::Sign(format!("cannot run ssh-keygen: {e}")))?;
        // A write error means ssh-keygen exited early; its stderr says why.
        let _ = child
            .stdin
            .take()
            .map(|mut s| s.write_all(challenge.as_bytes()));
        let out = child
            .wait_with_output()
            .map_err(|e| LoginError::Sign(format!("ssh-keygen: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let msg = stderr.trim();
            return Err(LoginError::Sign(if msg.is_empty() {
                format!("ssh-keygen exited with {}", out.status)
            } else {
                msg.to_owned()
            }));
        }
        String::from_utf8(out.stdout)
            .map_err(|_| LoginError::Sign("ssh-keygen wrote a non-UTF-8 signature".into()))
    }
}

/// The whole login: challenge, signature, token. Returns the client token.
///
/// # Errors
/// A [`LoginError`] from address checks, transport, signer, or a malformed reply.
pub fn login_ssh(
    transport: &impl Transport,
    signer: &impl Signer,
    addr: &str,
    mount: &str,
    role: &str,
) -> Result<String, LoginError> {
    let addr = check_addr(addr)?;
    check_mount(mount)?;
    let reply = vault_post(
        transport,
        &format!("{addr}/v1/auth/{mount}/challenge"),
        &json!({ "role": role }),
    )?;
    let challenge = str_at(&reply, &["data", "challenge"], "no challenge in the reply")?;
    // Only a well-formed challenge for this very server is signed: anything else would make
    // the operator's key an oracle for whatever the server sends (lokkju/edgekms#1).
    let got = edgekms_core::ssh::challenge_origin(challenge)
        .map_err(|_| LoginError::Response("the challenge is malformed"))?;
    let expected = origin_of(addr)?;
    if got != expected {
        return Err(LoginError::WrongOrigin { expected, got });
    }
    let signature = signer.sign(NAMESPACE, challenge)?;
    let reply = vault_post(
        transport,
        &format!("{addr}/v1/auth/{mount}/login"),
        &json!({ "role": role, "challenge": challenge, "signature": signature }),
    )?;
    take_client_token(reply)
}
