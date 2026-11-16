//! SSH keys on the control plane (lokkju/edgekms#16): `edgekms account login --ssh`, which turns
//! an ssh-agent signature over a control-plane challenge into a control token without GitHub,
//! and `edgekms account ssh-keys`, which lists, registers and removes the keys that can do that.
//!
//! Signing goes through [`Signer`] (`ssh-keygen -Y sign`, which asks ssh-agent); nothing here
//! reads a private key. A challenge is signed only when it names the origin of the control plane
//! it came from, and only under the namespace its purpose calls for: `edgekms` to log in,
//! `edgekms-register` to prove a key being registered. The namespace is never taken from the
//! server's reply. A registration challenge is signed only when it also names the account the
//! user expects (lokkju/edgekms#17).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use edgekms_core::hosted::{plausible_login, ssh_key_label};
use edgekms_core::ssh::{
    ParsedKey, RegisterAccount, challenge_origin, fingerprint_from_id, key_id, parse_public_key,
    register_challenge_parts,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    AccountLogin, Client, ControlError, ControlTransport, Method, Request, error_message,
    expect_ok, json_bytes, refused_with, take_login,
};
use crate::login::{
    HttpReply, LoginError, NAMESPACE, REGISTER_NAMESPACE, Signer, check_addr, origin_of,
    zeroize_json,
};

/// The `code` of a refusal that needs a login under five minutes old.
pub const FRESH_LOGIN_CODE: &str = "fresh_login_required";

/// Refuses to sign `challenge` unless it is well formed and names the origin of `api`, so a
/// server relaying another deployment's challenge (a tenant's, or the control plane's to a CLI
/// pointed elsewhere) never gets a signature over it.
fn check_origin(challenge: &str, api: &str) -> Result<(), ControlError> {
    let got = challenge_origin(challenge)
        .map_err(|_| LoginError::Response("the challenge is malformed"))?;
    let expected = origin_of(api)?;
    if got != expected {
        return Err(LoginError::WrongOrigin { expected, got }.into());
    }
    Ok(())
}

/// Refuses to sign a registration challenge unless it is well formed, names the origin of
/// `api`, and names the account `expected` (lokkju/edgekms#17): a key signed over a challenge
/// for someone else's account would be registered to theirs. Returns the account it names.
fn check_register(
    challenge: &str,
    api: &str,
    expected: u64,
) -> Result<RegisterAccount, ControlError> {
    let (account, got) = register_challenge_parts(challenge)
        .map_err(|_| LoginError::Response("the registration challenge is malformed"))?;
    let want = origin_of(api)?;
    if got != want {
        return Err(LoginError::WrongOrigin {
            expected: want,
            got,
        }
        .into());
    }
    if account.github_id != expected {
        return Err(ControlError::SshKeyWrongAccount {
            expected,
            got: account,
        });
    }
    Ok(account)
}

/// The account a control token says it is for, read from its claims without checking its MAC
/// (only the control plane can): `None` for a token that isn't `ekms.<payload>.<mac>` with a
/// numeric `github_id` and a GitHub-shaped `login`. The CLI checks a registration challenge
/// against it, so the challenge must name the account the user logged in as.
#[must_use]
pub fn token_account(token: &str) -> Option<RegisterAccount> {
    let mut parts = token.strip_prefix("ekms.")?.split('.');
    let (Some(payload), Some(_mac), None) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(payload).ok()?);
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    let meta = &claims["meta"];
    let github_id = meta["github_id"].as_str()?.parse().ok()?;
    let login = meta["login"].as_str().filter(|l| plausible_login(l))?;
    Some(RegisterAccount {
        github_id,
        login: login.to_owned(),
    })
}

fn challenge_in(reply: &Value) -> Result<&str, ControlError> {
    reply["data"]["challenge"]
        .as_str()
        .ok_or(ControlError::Response("no challenge in the reply"))
}

/// `POST url` with a JSON body and no control token, as both login requests are.
fn post_unauthenticated(
    c: &impl ControlTransport,
    url: &str,
    body: &Value,
) -> Result<HttpReply, ControlError> {
    let bytes = json_bytes(body);
    Ok(c.send(&Request {
        method: Method::Post,
        url,
        bearer: None,
        if_match: None,
        body: Some(&bytes),
    })?)
}

/// `edgekms account login --ssh`: `POST <api>/v1/login/ssh/challenge`, the challenge's origin
/// checked against `api`, a signature by `signer` under `edgekms`, then `POST <api>/v1/login/ssh`.
/// Returns the control token and who it's for. `api` must pass [`check_addr`]; the hosted-App
/// host pin of [`super::check_api`] is for GitHub tokens and doesn't apply, since the origin
/// check does that job for a challenge.
///
/// # Errors
/// A [`LoginError`] from the address check, the origin check (before anything is signed) or the
/// signer; [`ControlError::SshLoginRefused`] for the control plane's uniform
/// `400 permission denied`; another refusal or a malformed reply.
pub fn ssh_login(
    c: &impl ControlTransport,
    signer: &impl Signer,
    api: &str,
) -> Result<AccountLogin, ControlError> {
    let api = check_addr(api)?;
    let reply = expect_ok(post_unauthenticated(
        c,
        &format!("{api}/v1/login/ssh/challenge"),
        &json!({}),
    )?)?;
    let challenge = challenge_in(&reply)?;
    check_origin(challenge, api)?;
    let signature = signer.sign(NAMESPACE, challenge)?;
    let mut body = json!({ "challenge": challenge, "signature": signature });
    let reply = post_unauthenticated(c, &format!("{api}/v1/login/ssh"), &body);
    zeroize_json(&mut body);
    let reply = reply?;
    if reply.status == 400 && error_message(&reply.body) == "permission denied" {
        return Err(ControlError::SshLoginRefused);
    }
    take_login(reply)
}

/// One SSH key that can log in to the caller's account, as `GET /v1/me/ssh-keys` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKey {
    /// The fingerprint's base64 in base64url, 43 characters: how routes name the key.
    pub id: String,
    /// `SHA256:` and the unpadded base64 of the key blob's SHA-256, as `ssh-keygen -l` prints.
    pub fingerprint: String,
    pub key_type: String,
    /// `<type> <base64>`, without a comment.
    pub public_key: String,
    pub label: String,
    pub added_ms: u64,
    /// `github`, or `ssh:<fingerprint>` naming the key whose session added this one.
    pub added_via: String,
    /// The last SSH login with the key; `None` if it has never logged in.
    pub last_used_ms: Option<u64>,
}

impl SshKey {
    fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v[k].as_str().map(str::to_owned);
        Some(Self {
            id: s("id")?,
            fingerprint: s("fingerprint")?,
            key_type: s("key_type")?,
            public_key: s("public_key")?,
            label: s("label")?,
            added_ms: v["added_ms"].as_u64()?,
            added_via: s("added_via")?,
            last_used_ms: v["last_used_ms"].as_u64(),
        })
    }
}

/// `GET /v1/me/ssh-keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeys {
    pub keys: Vec<SshKey>,
    /// Fingerprints of the caller's key rows whose MAC doesn't verify: written to D1 without the
    /// control plane. They log no one in; remove them.
    pub unverified: Vec<String>,
}

/// The label a key is registered with: `explicit` if given, which must keep the control plane's
/// rules; else the key's comment when it keeps them, else none.
fn key_label(explicit: Option<&str>, comment: &str) -> Result<String, ControlError> {
    match explicit {
        Some(l) => ssh_key_label(l)
            .map(str::to_owned)
            .map_err(|e| ControlError::Label(e.to_string())),
        None => Ok(ssh_key_label(comment).unwrap_or_default().to_owned()),
    }
}

/// The error for a coded refusal of the registration challenge or the add, if it is one.
fn add_refusal(reply: &HttpReply) -> Option<ControlError> {
    if refused_with(reply, FRESH_LOGIN_CODE) {
        return Some(ControlError::SshKeyFreshLogin);
    }
    if reply.ok() {
        return None;
    }
    let message = match reply.body["code"].as_str()? {
        "ssh_key_in_use" => {
            "this key is already registered to an edgekms account, this one or another; \
             `edgekms account ssh-keys list` shows the keys on this one"
        }
        "ssh_key_limit" => {
            "this account already has 10 SSH keys, the most it can hold; remove one with \
             `edgekms account ssh-keys remove` first"
        }
        "ssh_key_proof_failed" => {
            "the control plane didn't accept the key's signature over its challenge, which may \
             have expired or been used already; run the command again"
        }
        "label_invalid" => {
            "the control plane refused the label: it takes at most 64 characters, with no \
             control, bidirectional or invisible formatting characters"
        }
        "ssh_key_invalid" => {
            "the control plane couldn't read the key as one OpenSSH public key line"
        }
        "ssh_key_unsupported" => {
            "the control plane takes only ssh-ed25519, sk-ssh-ed25519@openssh.com and \
             ecdsa-sha2-nistp256 keys"
        }
        _ => return None,
    };
    Some(ControlError::SshKeyRefused(message))
}

impl<T: ControlTransport> Client<'_, T> {
    /// `GET /v1/me/ssh-keys`: the keys that can log in to the caller's account.
    ///
    /// # Errors
    /// A transport error, the refusal, or a reply missing a field.
    pub fn ssh_keys(&self) -> Result<SshKeys, ControlError> {
        let reply = self.call(Method::Get, "/v1/me/ssh-keys", None)?;
        let d = &reply["data"];
        let keys = d["keys"]
            .as_array()
            .ok_or(ControlError::Response("no keys in the reply"))?
            .iter()
            .map(SshKey::from_json)
            .collect::<Option<Vec<_>>>()
            .ok_or(ControlError::Response("a key without its fields"))?;
        let unverified = d["unverified"]
            .as_array()
            .map(|v| {
                v.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(SshKeys { keys, unverified })
    }

    /// Registers `public_key` (one OpenSSH public key line) on the caller's account:
    /// `POST /v1/me/ssh-keys/challenge`, the challenge's origin checked against the control
    /// plane's and its account against `expected_github_id`, `announce` called with that
    /// account, a signature by `signer` under `edgekms-register` as proof of holding the key,
    /// then `POST /v1/me/ssh-keys`. The key and the label are checked here first by the control
    /// plane's rules; without `label`, the key's comment is the label when it keeps them.
    ///
    /// # Errors
    /// [`ControlError::PublicKey`] or [`ControlError::Label`] before any request; a
    /// [`LoginError`] from the origin check or [`ControlError::SshKeyWrongAccount`] from the
    /// account check (both before anything is signed), or from the signer;
    /// [`ControlError::SshKeyFreshLogin`] for a login five minutes old or more;
    /// [`ControlError::SshKeyRefused`] for the control plane's other coded refusals; a
    /// transport error, another refusal or a malformed reply.
    pub fn ssh_key_add(
        &self,
        signer: &impl Signer,
        public_key: &str,
        label: Option<&str>,
        expected_github_id: u64,
        announce: impl FnOnce(&RegisterAccount),
    ) -> Result<SshKey, ControlError> {
        let key =
            parse_public_key(public_key).map_err(|e| ControlError::PublicKey(e.to_string()))?;
        let label = key_label(label, &key.comment)?;
        let reply = self.send(Method::Post, "/v1/me/ssh-keys/challenge", None, Some(b"{}"))?;
        if let Some(e) = add_refusal(&reply) {
            return Err(e);
        }
        let reply = expect_ok(reply)?;
        let challenge = challenge_in(&reply)?;
        let account = check_register(challenge, &self.api, expected_github_id)?;
        announce(&account);
        let signature = signer.sign(REGISTER_NAMESPACE, challenge)?;
        let body = json!({
            "public_key": key.public_key,
            "label": label,
            "challenge": challenge,
            "signature": signature,
        });
        let bytes = json_bytes(&body);
        let reply = self.send(Method::Post, "/v1/me/ssh-keys", None, Some(&bytes))?;
        if let Some(e) = add_refusal(&reply) {
            return Err(e);
        }
        let reply = expect_ok(reply)?;
        SshKey::from_json(&reply["data"]).ok_or(ControlError::Response("no key in the reply"))
    }

    /// `DELETE /v1/me/ssh-keys/<id>` (`204`), naming the key by its 43-character id or its
    /// `SHA256:` fingerprint. Every control token the key minted stops working.
    ///
    /// # Errors
    /// [`ControlError::SshKeyId`] for anything else, before any request;
    /// [`ControlError::NoSuchSshKey`] on a `404`; a transport error or another refusal.
    pub fn ssh_key_remove(&self, key: &str) -> Result<(), ControlError> {
        let id = if key.starts_with("SHA256:") {
            key_id(key)
        } else {
            fingerprint_from_id(key).map(|_| key.to_owned())
        }
        .ok_or_else(|| ControlError::SshKeyId(key.to_owned()))?;
        let reply = self.send(Method::Delete, &format!("/v1/me/ssh-keys/{id}"), None, None)?;
        if reply.status == 404 {
            return Err(ControlError::NoSuchSshKey);
        }
        expect_ok(reply).map(drop)
    }
}

/// The public keys ssh-agent holds, one OpenSSH line each, as `ssh-add -L` prints them.
/// Injectable, so tests need no agent.
pub trait AgentKeys {
    /// The listing; empty when the agent holds no keys.
    ///
    /// # Errors
    /// [`ControlError::Agent`] when the agent can't be asked.
    fn list(&self) -> Result<String, ControlError>;
}

/// Asks ssh-agent through `ssh-add -L`.
pub struct SshAdd;

impl AgentKeys for SshAdd {
    fn list(&self) -> Result<String, ControlError> {
        let out = Command::new("ssh-add")
            .arg("-L")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| ControlError::Agent(format!("cannot run ssh-add: {e}")))?;
        let stdout = String::from_utf8(out.stdout)
            .map_err(|_| ControlError::Agent("ssh-add wrote non-UTF-8 output".into()))?;
        if out.status.success() {
            return Ok(stdout);
        }
        // `ssh-add -L` exits 1 for an agent without keys, saying so on stdout, and for errors
        // fetching them; 2 when there is no agent to ask.
        if out.status.code() == Some(1) && stdout.contains("no identities") {
            return Ok(String::new());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let msg = stderr.trim();
        Err(ControlError::Agent(if msg.is_empty() {
            format!("ssh-add exited with {}", out.status)
        } else {
            msg.to_owned()
        }))
    }
}

/// The key a control-plane signature is made with, picked by [`choose_key`].
#[derive(Debug, Clone)]
pub struct ChosenKey {
    pub key: ParsedKey,
    /// The caller's `--key` file; `None` for the agent's key, which [`ChosenKey::sign_with`]
    /// writes to a temporary file.
    file: Option<PathBuf>,
}

/// A server-supplied value that should be printable ASCII (an id, a fingerprint, a key type,
/// `added_via`, a GitHub login) as it can go to a terminal or a TSV line: as it is when it is,
/// with every other character escaped (`\u{..}`, `\t`, `\n`) when it isn't.
#[must_use]
pub fn printable_ascii(value: &str) -> String {
    if value.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        value.to_owned()
    } else {
        value.escape_default().to_string()
    }
}

/// A comment as it can go to a terminal: as it is, unless it holds a control character.
fn printable(comment: &str) -> String {
    if comment.chars().any(char::is_control) {
        comment.escape_debug().to_string()
    } else {
        comment.to_owned()
    }
}

/// Picks the key to sign with. With `key_file` (which must end in `.pub`), the public key in
/// it. Without, ssh-agent's keys of a supported type ([`parse_public_key`] accepts them), of
/// which there must be exactly one: keys are never tried in turn, since each failed login counts
/// against the control plane's failure limit and each security key would ask for a touch.
///
/// # Errors
/// [`ControlError::KeyFile`] for a `key_file` that isn't a readable `.pub` file of a supported
/// key; [`ControlError::Agent`], [`ControlError::AgentNoKeys`] or
/// [`ControlError::AgentManyKeys`] without one.
pub fn choose_key(
    key_file: Option<&Path>,
    agent: &impl AgentKeys,
) -> Result<ChosenKey, ControlError> {
    if let Some(path) = key_file {
        if path.extension().is_none_or(|e| e != "pub") {
            return Err(ControlError::KeyFile(format!(
                "{} must be the public key file (ending in .pub); ssh-keygen finds the private \
                 key in ssh-agent",
                path.display()
            )));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| ControlError::KeyFile(format!("cannot read {}: {e}", path.display())))?;
        let key = parse_public_key(&text)
            .map_err(|e| ControlError::KeyFile(format!("{}: {e}", path.display())))?;
        return Ok(ChosenKey {
            key,
            file: Some(path.to_owned()),
        });
    }
    let mut keys: Vec<ParsedKey> = agent
        .list()?
        .lines()
        .filter_map(|l| parse_public_key(l).ok())
        .collect();
    match keys.len() {
        0 => Err(ControlError::AgentNoKeys),
        1 => Ok(ChosenKey {
            key: keys.remove(0),
            file: None,
        }),
        _ => Err(ControlError::AgentManyKeys(
            keys.iter()
                .map(|k| {
                    format!("  {} {}", k.fingerprint, printable(&k.comment))
                        .trim_end()
                        .to_owned()
                })
                .collect::<Vec<_>>()
                .join("\n"),
        )),
    }
}

/// A fresh directory only the user can enter, for the agent key's public half.
fn private_temp_dir() -> std::io::Result<tempfile::TempDir> {
    let mut b = tempfile::Builder::new();
    b.prefix("edgekms-ssh-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        b.permissions(std::fs::Permissions::from_mode(0o700));
    }
    b.tempdir()
}

impl ChosenKey {
    /// Runs `f` with the signer `signer` builds from the key's `.pub` path: the caller's
    /// `--key` file, or, for the agent's key, a file in a fresh temporary directory (a public
    /// key, nothing secret) that is removed afterwards, whether `f` succeeded or not.
    ///
    /// # Errors
    /// [`ControlError::TempKey`] when the temporary file can't be written, or `f`'s error.
    pub fn sign_with<S, R>(
        &self,
        signer: impl FnOnce(&Path) -> S,
        f: impl FnOnce(&S) -> Result<R, ControlError>,
    ) -> Result<R, ControlError> {
        if let Some(path) = &self.file {
            return f(&signer(path));
        }
        let dir = private_temp_dir().map_err(|e| ControlError::TempKey(e.to_string()))?;
        let path = dir.path().join("agent-key.pub");
        std::fs::write(&path, format!("{}\n", self.key.public_key))
            .map_err(|e| ControlError::TempKey(e.to_string()))?;
        let out = f(&signer(&path));
        // Dropping the directory removes it too (also on a panic); closing says nothing more
        // worth failing a login over.
        let _ = dir.close();
        out
    }

    /// The key as one OpenSSH line, with its comment, for registering it.
    #[must_use]
    pub fn line(&self) -> String {
        if self.key.comment.is_empty() {
            self.key.public_key.clone()
        } else {
            format!("{} {}", self.key.public_key, self.key.comment)
        }
    }
}
