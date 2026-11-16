use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use edgekms_cli::cli::{
    AccountCommand, AllowlistCommand, Cli, Command, ConfigCommand, InviteRequestsCommand,
    LoginMethod, MemberCommand, OpsCommand, OpsTenantCommand, SshKeysCommand, TenantCommand,
};
use edgekms_cli::control::{
    self, AccountLogin, Client, ControlError, Grant, Import, InviteLogin, InviteRequest, Requester,
    Role, SshAdd, TenantStatus, UreqControl,
};
use edgekms_cli::login::{
    self, DeviceFlow, DevicePrompt, OidcClient, SshKeygen, SystemBrowser, UreqTransport,
};
use edgekms_cli::offline;
use edgekms_core::config::Config;
use edgekms_core::transit::Id;
use zeroize::Zeroizing;

/// How long `login oidc` waits for the browser to come back.
const OIDC_TIMEOUT: Duration = Duration::from_secs(300);

fn load_config(path: &PathBuf) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Config::from_json(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The root key from stdin, refused when stdin is a terminal: typing it would echo it.
fn root_key_from_stdin() -> Result<Zeroizing<[u8; 32]>, String> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(
            "the root key is read from stdin, which is a terminal here and would echo it; \
             pipe it in instead, for example \
             sops decrypt --extract '[\"root_key\"]' <file> | edgekms ..."
                .into(),
        );
    }
    offline::read_root_key(unbuffered_stdin()?).map_err(|e| e.to_string())
}

/// Stdin without std's process-wide 8 KiB buffer, which would keep a copy of the root key in
/// memory nobody zeroizes: a second handle on the same descriptor, read directly.
fn unbuffered_stdin() -> Result<std::fs::File, String> {
    #[cfg(unix)]
    let owned = {
        use std::os::fd::AsFd;
        io::stdin().as_fd().try_clone_to_owned()
    };
    #[cfg(windows)]
    let owned = {
        use std::os::windows::io::AsHandle;
        io::stdin().as_handle().try_clone_to_owned()
    };
    owned
        .map(std::fs::File::from)
        .map_err(|e| format!("cannot read stdin: {e}"))
}

/// The device flow's endpoints: github.com's, or the loopback stub's named by
/// [`login::GITHUB_OAUTH_BASE_ENV`] (the hosted e2e run's).
struct Endpoints(Option<(String, String)>);

impl Endpoints {
    fn from_env() -> Result<Self, String> {
        match std::env::var(login::GITHUB_OAUTH_BASE_ENV) {
            Ok(base) if !base.is_empty() => login::stub_endpoints(&base)
                .map(|e| Self(Some(e)))
                .map_err(|e| format!("{}: {e}", login::GITHUB_OAUTH_BASE_ENV)),
            _ => Ok(Self(None)),
        }
    }

    fn flow<'a>(&'a self, client_id: &'a str) -> DeviceFlow<'a> {
        match &self.0 {
            Some((device_code_url, token_url)) => DeviceFlow {
                client_id,
                device_code_url,
                token_url,
            },
            None => DeviceFlow::github(client_id),
        }
    }
}

fn login(method: LoginMethod) -> Result<String, String> {
    let t = UreqTransport::new();
    let result = match method {
        LoginMethod::Ssh {
            addr,
            role,
            key,
            mount,
        } => {
            if key.extension().is_none_or(|e| e != "pub") {
                return Err("--key must be the public key file (ending in .pub); \
                            ssh-keygen finds the private key in ssh-agent"
                    .into());
            }
            login::login_ssh(&t, &SshKeygen::new(&key), &addr, &mount, &role)
        }
        LoginMethod::Github {
            addr,
            role,
            client_id,
            mount,
        } => login::login_github(
            &t,
            &Endpoints::from_env()?.flow(&client_id),
            |p: &DevicePrompt| {
                eprintln!(
                    "To log in, open {} and enter the code {} (valid for {} minutes).",
                    p.verification_uri,
                    p.user_code,
                    p.expires_in / 60
                );
            },
            std::thread::sleep,
            &addr,
            &mount,
            &role,
        ),
        LoginMethod::Oidc {
            addr,
            role,
            mount,
            issuer,
            client_id,
            scope,
            port,
            no_browser,
        } => {
            let secret = std::env::var("EDGEKMS_OIDC_CLIENT_SECRET")
                .ok()
                .map(Zeroizing::new);
            let client = OidcClient {
                issuer: &issuer,
                client_id: &client_id,
                client_secret: secret.as_deref().map(String::as_str),
                scopes: &scope,
                port,
                timeout: OIDC_TIMEOUT,
            };
            let browser = SystemBrowser {
                launch: !no_browser,
            };
            login::login_oidc(&t, &browser, &client, &addr, &mount, &role)
        }
    };
    result.map_err(|e| e.to_string())
}

/// The control token from [`control::CONTROL_TOKEN_ENV`], never a flag.
fn control_token() -> Result<Zeroizing<String>, String> {
    std::env::var(control::CONTROL_TOKEN_ENV)
        .ok()
        .filter(|t| !t.is_empty())
        .map(Zeroizing::new)
        .ok_or_else(|| msg(ControlError::NoToken))
}

/// `account request-invite`: the login, then the request's state or a new request.
fn request_invite(api: &str, client_id: Option<&str>, note: Option<&str>) -> Result<(), String> {
    let endpoints = Endpoints::from_env()?;
    let c = UreqControl::new();
    let env = std::env::var(control::HOSTED_CLIENT_ID_ENV).ok();
    let (client_id, explicit) =
        control::login_client_id(&c, api, client_id, env.as_deref()).map_err(msg)?;
    let login = control::request_invite_login(
        &UreqTransport::new(),
        &c,
        &endpoints.flow(&client_id),
        explicit,
        |p: &DevicePrompt| {
            eprintln!(
                "To sign in, open {} and enter the code {} (valid for {} minutes).",
                p.verification_uri,
                p.user_code,
                p.expires_in / 60
            );
        },
        std::thread::sleep,
        api,
    )
    .map_err(msg)?;
    let token = match login {
        InviteLogin::Refused(token) => token,
        InviteLogin::Admitted => {
            eprintln!("Your GitHub account can already sign in: run `edgekms account login`.");
            return Ok(());
        }
        InviteLogin::Closed => return Err(msg(ControlError::RequestsClosed)),
    };
    let r = Requester::new(&c, api, &token).map_err(msg)?;
    let mine = r.mine().map_err(msg)?;
    if let Some(req) = &mine.request {
        let asked = control::utc_date(req.created_ms);
        match req.status.as_str() {
            "pending" => eprintln!(
                "You asked for an invite on {asked}; an operator will review it. edgekms doesn't \
                 email you: run `edgekms account login` later, and once you're approved it \
                 creates your tenant."
            ),
            "approved" => {
                eprintln!("Your request of {asked} was approved: run `edgekms account login`.");
            }
            _ => eprintln!("Your request of {asked} wasn't approved."),
        }
        return Ok(());
    }
    if !mine.accepting {
        return Err(msg(ControlError::RequestsClosed));
    }
    let note = match note {
        Some(n) => Zeroizing::new(n.to_owned()),
        None if io::stdin().is_terminal() => {
            eprint!("What will you use edgekms for? (optional, one line) ");
            let _ = io::stderr().flush();
            let mut line = Zeroizing::new(String::new());
            io::stdin()
                .read_line(&mut line)
                .map_err(|e| format!("cannot read the note: {e}"))?;
            line
        }
        None => Zeroizing::new(String::new()),
    };
    let created = r.file(&note).map_err(msg)?;
    eprintln!(
        "Asked for an invite as {} on {}. An operator will review it; edgekms doesn't email you, \
         so run `edgekms account login` later.",
        mine.login,
        control::utc_date(created)
    );
    Ok(())
}

/// What every `account login` prints on stderr, after the login and before the token.
fn print_login(out: &AccountLogin) {
    eprintln!("{}", out.summary());
    eprintln!(
        "For its first five minutes the token can also export root keys (`edgekms tenant \
         export`) and add SSH keys (`edgekms account ssh-keys add`)."
    );
    if let Some(line) = out.ssh_keys_line() {
        eprintln!("{line}");
    }
    eprintln!(
        "Export the token below as {} for `edgekms tenant`; it isn't saved anywhere.",
        control::CONTROL_TOKEN_ENV
    );
}

/// `account login --ssh`: the key from `--key` or the agent, then the login.
fn ssh_account_login(api: &str, key: Option<&Path>) -> Result<Zeroizing<String>, String> {
    // A bad --api is refused before the agent is asked anything.
    login::check_addr(api).map_err(|e| e.to_string())?;
    let chosen = control::choose_key(key, &SshAdd).map_err(msg)?;
    let c = UreqControl::new();
    let out = chosen
        .sign_with(SshKeygen::new, |s| control::ssh_login(&c, s, api))
        .map_err(msg)?;
    print_login(&out);
    Ok(out.token)
}

/// A label as it can safely go to a terminal or a TSV line: as it is when it keeps the control
/// plane's rules, escaped otherwise.
fn printable_label(label: &str) -> String {
    if edgekms_core::hosted::ssh_key_label(label).is_ok_and(|l| l == label) {
        label.to_owned()
    } else {
        label.escape_debug().to_string()
    }
}

/// The `edgekms account ssh-keys` commands; `None` when nothing goes to stdout.
fn ssh_keys(api: &str, command: SshKeysCommand) -> Result<Option<Zeroizing<String>>, String> {
    let token = control_token()?;
    let t = UreqControl::new();
    let c = Client::new(&t, api, &token).map_err(msg)?;
    match command {
        SshKeysCommand::List => {
            let list = c.ssh_keys().map_err(msg)?;
            if !list.unverified.is_empty() {
                eprintln!(
                    "edgekms: warning: SSH key records that fail their integrity check (written \
                     to D1 without the control plane; they log no one in): {}. Remove them with \
                     `edgekms account ssh-keys remove`.",
                    list.unverified
                        .iter()
                        .map(|f| control::printable_ascii(f))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if list.keys.is_empty() && list.unverified.is_empty() {
                eprintln!(
                    "No SSH keys can log in to this account; add one with \
                     `edgekms account ssh-keys add`."
                );
                return Ok(None);
            }
            let keys = list.keys.iter().map(|k| {
                format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    control::printable_ascii(&k.id),
                    control::printable_ascii(&k.fingerprint),
                    control::printable_ascii(&k.key_type),
                    printable_label(&k.label),
                    k.added_ms,
                    control::printable_ascii(&k.added_via),
                    k.last_used_ms.map(|v| v.to_string()).unwrap_or_default()
                )
            });
            let unverified = list
                .unverified
                .iter()
                .map(|f| format!("unverified\t{}", control::printable_ascii(f)));
            let out = keys.chain(unverified).collect::<Vec<_>>().join("\n");
            Ok(Some(Zeroizing::new(out)))
        }
        SshKeysCommand::Add {
            key,
            label,
            expect_github_id,
        } => {
            let expected = expect_github_id
                .or_else(|| control::token_account(&token).map(|a| a.github_id))
                .ok_or_else(|| msg(ControlError::SshKeyNoAccount))?;
            let chosen = control::choose_key(key.as_deref(), &SshAdd).map_err(msg)?;
            let fingerprint = control::printable_ascii(&chosen.key.fingerprint);
            let added = chosen
                .sign_with(SshKeygen::new, |s| {
                    c.ssh_key_add(s, &chosen.line(), label.as_deref(), expected, |a| {
                        // The login has a GitHub login's shape: the challenge parser checked.
                        eprintln!(
                            "Registering SSH key {fingerprint} to GitHub account {} ({}).",
                            a.login, a.github_id
                        );
                    })
                })
                .map_err(msg)?;
            let labelled = if added.label.is_empty() {
                String::new()
            } else {
                format!(" ({})", printable_label(&added.label))
            };
            eprintln!(
                "Added SSH key {}{labelled}, id {}. It can log in with \
                 `edgekms account login --ssh`.",
                control::printable_ascii(&added.fingerprint),
                control::printable_ascii(&added.id)
            );
            Ok(None)
        }
        SshKeysCommand::Remove { key } => {
            c.ssh_key_remove(&key).map_err(msg)?;
            eprintln!("Removed SSH key {key}; every control token it minted has stopped working.");
            Ok(None)
        }
    }
}

/// The `edgekms account` commands; `None` when nothing goes to stdout.
fn account(command: AccountCommand) -> Result<Option<Zeroizing<String>>, String> {
    let (api, client_id) = match command {
        AccountCommand::Login {
            api,
            ssh: true,
            key,
            ..
        } => return ssh_account_login(&api, key.as_deref()).map(Some),
        AccountCommand::Login { api, client_id, .. } => (api, client_id),
        AccountCommand::SshKeys { api, command } => return ssh_keys(&api.api, command),
        AccountCommand::RequestInvite {
            api,
            client_id,
            note,
        } => {
            request_invite(&api, client_id.as_deref(), note.as_deref())?;
            return Ok(None);
        }
        AccountCommand::Logout { api } => {
            let token = control_token()?;
            let t = UreqControl::new();
            Client::new(&t, &api, &token)
                .and_then(|c| c.logout())
                .map_err(msg)?;
            eprintln!(
                "Logged out: every control token you held has stopped working. Unset {}.",
                control::CONTROL_TOKEN_ENV
            );
            return Ok(None);
        }
    };
    let endpoints = Endpoints::from_env()?;
    let c = UreqControl::new();
    let env = std::env::var(control::HOSTED_CLIENT_ID_ENV).ok();
    let (client_id, explicit) =
        control::login_client_id(&c, &api, client_id.as_deref(), env.as_deref()).map_err(msg)?;
    let out = control::account_login(
        &UreqTransport::new(),
        &c,
        &endpoints.flow(&client_id),
        explicit,
        |p: &DevicePrompt| {
            eprintln!(
                "To log in, open {} and enter the code {} (valid for {} minutes).",
                p.verification_uri,
                p.user_code,
                p.expires_in / 60
            );
        },
        std::thread::sleep,
        &api,
    )
    .map_err(msg)?;
    print_login(&out);
    Ok(Some(out.token))
}

fn read_file(path: &PathBuf) -> Result<Zeroizing<String>, String> {
    std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// The error for stderr. A bare `403 permission denied` is also what an expired or logged-out
/// control token gets, so it says so.
#[allow(clippy::needless_pass_by_value)] // used as a map_err callback
fn msg(e: ControlError) -> String {
    match &e {
        ControlError::Rejected {
            status: 403,
            message,
        } if message == "permission denied" => {
            format!(
                "{e} (an owner- or operator-only action, or a control token that expired \
                 after {} seconds or was logged out; run `edgekms account login` for a new one)",
                control::CONTROL_TOKEN_SECS
            )
        }
        _ => e.to_string(),
    }
}

/// `tenant create`: the config file and the import's root id are checked, and the root key read
/// from stdin, before anything is sent.
fn tenant_create(
    c: &Client<'_, UreqControl>,
    name: &str,
    config: Option<&PathBuf>,
    import_root_id: Option<&str>,
) -> Result<(), String> {
    let config = config.map(read_file).transpose()?;
    let root_id = import_root_id
        .map(|r| Id::new(r).map_err(|e| format!("--import-root-id: {e}")))
        .transpose()?;
    if root_id.is_some() && config.is_none() {
        return Err("an import needs --config with the tenant's existing keys, \
                    or its old ciphertexts won't decrypt"
            .into());
    }
    let root = root_id
        .as_ref()
        .map(|_| root_key_from_stdin())
        .transpose()?;
    let import = root_id
        .as_ref()
        .zip(root.as_deref())
        .map(|(root_id, root_key)| Import { root_id, root_key });
    let data = c
        .create(name, config.as_deref().map(String::as_str), import)
        .map_err(msg)?;
    eprintln!(
        "Created tenant {} (root id {}).",
        data["name"].as_str().unwrap_or(name),
        data["root_id"].as_str().unwrap_or("unknown")
    );
    if config.is_some() && root_id.is_none() {
        eprintln!(
            "The control plane set the config's root_id to the new root; \
             `edgekms tenant config get` shows the stored config."
        );
    }
    Ok(())
}

/// `tenant export`: the root id and warnings on stderr; the key alone is returned for stdout.
fn tenant_export(c: &Client<'_, UreqControl>, name: &str) -> Result<Zeroizing<String>, String> {
    let out = c.export(name).map_err(msg)?;
    eprintln!("edgekms: root id: {}", out.root_id);
    eprintln!(
        "edgekms: warning: stdout is {name}'s root key. Anyone holding it can decrypt every \
         ciphertext the tenant has issued and mint tokens for it; keep it only in an encrypted \
         store such as sops."
    );
    if io::stdout().is_terminal() {
        eprintln!(
            "edgekms: warning: stdout is a terminal, so the key is now in your scrollback; \
             clear it, and pipe the output next time."
        );
    }
    Ok(out.root_key)
}

/// `tenant member add`: the grant, and on stderr whether it was an invite or applied at once.
fn tenant_member_add(
    c: &Client<'_, UreqControl>,
    name: &str,
    github_id: u64,
    owner: bool,
) -> Result<(), String> {
    let role = if owner { Role::Owner } else { Role::Member };
    let what = article(role.as_str());
    match c.set_member(name, github_id, role).map_err(msg)? {
        Grant::Invited => eprintln!(
            "Invited GitHub id {github_id} to be {what} of {name}. Nothing changes until they \
             run `edgekms tenant accept {name}`."
        ),
        Grant::Applied => eprintln!("GitHub id {github_id} is now {what} of {name}."),
        Grant::Unconfirmed => eprintln!(
            "Sent: GitHub id {github_id} is invited to be {what} of {name} and must run \
             `edgekms tenant accept {name}`, unless this lowered an owner to member, which \
             applies at once. `edgekms tenant show {name}` tells which."
        ),
    }
    Ok(())
}

/// The `edgekms ops` commands; `None` when nothing goes to stdout.
fn ops(api: &str, command: OpsCommand) -> Result<Option<Zeroizing<String>>, String> {
    let token = control_token()?;
    let t = UreqControl::new();
    let c = Client::new(&t, api, &token).map_err(msg)?;
    let command = match command {
        OpsCommand::Allowlist { command } => command,
        OpsCommand::InviteRequests { command } => return invite_requests(&c, &command),
        OpsCommand::Tenant { command } => {
            let (name, status) = match command {
                OpsTenantCommand::Suspend { name } => (name, TenantStatus::Suspended),
                OpsTenantCommand::Resume { name } => (name, TenantStatus::Active),
            };
            c.set_tenant_status(&name, status).map_err(msg)?;
            eprintln!("Tenant {name} is {}.", status.as_str());
            return Ok(None);
        }
    };
    match command {
        AllowlistCommand::Add { github_id } => {
            c.allowlist_add(github_id).map_err(msg)?;
            eprintln!("GitHub id {github_id} is on the signup allowlist.");
            Ok(None)
        }
        AllowlistCommand::Remove { github_id } => {
            c.allowlist_remove(github_id).map_err(msg)?;
            eprintln!("Removed GitHub id {github_id} from the signup allowlist.");
            Ok(None)
        }
        AllowlistCommand::List => {
            let list = c.allowlist().map_err(msg)?;
            if !list.unverified.is_empty() {
                let ids: Vec<String> = list.unverified.iter().map(u64::to_string).collect();
                eprintln!(
                    "edgekms: warning: allowlist rows that don't verify (written to D1 without \
                     the control plane; they admit no one): {}. Remove them with \
                     `edgekms ops allowlist remove`.",
                    ids.join(", ")
                );
            }
            if list.entries.is_empty() {
                eprintln!("The signup allowlist is empty.");
                return Ok(None);
            }
            let out = list
                .entries
                .iter()
                .map(|(id, by, ms)| format!("{id}\t{by}\t{ms}"))
                .collect::<Vec<_>>()
                .join("\n");
            Ok(Some(Zeroizing::new(out)))
        }
    }
}

/// A note as it can safely go to a terminal: as it is when it keeps the control plane's rules
/// (only plain text and newlines), escaped otherwise.
fn printable_note(note: &str) -> String {
    if edgekms_core::hosted::invite_note(note).is_ok_and(|n| n == note) {
        note.to_owned()
    } else {
        note.escape_debug().to_string()
    }
}

/// One `ops invite-requests list` entry: the summary line, then the note indented.
fn request_lines(r: &InviteRequest) -> String {
    let mut out = format!(
        "{}  {}  {}  {}",
        r.github_id,
        printable_note(&r.login),
        r.status,
        control::utc_date(r.created_ms)
    );
    if let (Some(by), Some(ms)) = (r.decided_by, r.decided_ms) {
        let _ = write!(out, "  (decided {} by {by})", control::utc_date(ms));
    }
    for line in printable_note(&r.note).lines() {
        out.push_str("\n    ");
        out.push_str(line);
    }
    out
}

/// The `edgekms ops invite-requests` commands.
fn invite_requests(
    c: &Client<'_, UreqControl>,
    command: &InviteRequestsCommand,
) -> Result<Option<Zeroizing<String>>, String> {
    match *command {
        InviteRequestsCommand::List => {
            let list = c.invite_requests().map_err(msg)?;
            if !list.unverified.is_empty() {
                let ids: Vec<String> = list.unverified.iter().map(u64::to_string).collect();
                eprintln!(
                    "edgekms: warning: invite requests that don't verify (written to D1 without \
                     the control plane; they can't be approved): {}. Remove them with \
                     `edgekms ops invite-requests delete`.",
                    ids.join(", ")
                );
            }
            if list.requests.is_empty() {
                eprintln!("There are no invite requests.");
                return Ok(None);
            }
            eprintln!("{} pending.", list.pending);
            let out = list
                .requests
                .iter()
                .map(request_lines)
                .collect::<Vec<_>>()
                .join("\n");
            Ok(Some(Zeroizing::new(out)))
        }
        InviteRequestsCommand::Approve { github_id } => {
            c.invite_request_approve(github_id).map_err(msg)?;
            eprintln!(
                "Approved GitHub id {github_id}: they're on the signup allowlist, and their next \
                 sign-in creates their tenant."
            );
            Ok(None)
        }
        InviteRequestsCommand::Decline { github_id } => {
            c.invite_request_decline(github_id).map_err(msg)?;
            eprintln!("Declined the request of GitHub id {github_id}.");
            Ok(None)
        }
        InviteRequestsCommand::Delete { github_id } => {
            c.invite_request_delete(github_id).map_err(msg)?;
            eprintln!("Deleted the request of GitHub id {github_id}.");
            Ok(None)
        }
    }
}

/// The `edgekms tenant` commands; `None` when nothing goes to stdout.
fn tenant(api: &str, command: TenantCommand) -> Result<Option<Zeroizing<String>>, String> {
    let token = control_token()?;
    let t = UreqControl::new();
    let c = Client::new(&t, api, &token).map_err(msg)?;
    let out = match command {
        TenantCommand::List => {
            let me = c.me().map_err(msg)?;
            eprintln!("{} (GitHub id {})", me.login, me.github_id);
            if !me.invites.is_empty() {
                eprintln!(
                    "{} pending invite(s); see `edgekms tenant invites`.",
                    me.invites.len()
                );
            }
            pairs(&me.tenants)
        }
        TenantCommand::Invites => {
            let me = c.me().map_err(msg)?;
            if me.invites.is_empty() {
                eprintln!("No pending invites.");
                return Ok(None);
            }
            eprintln!("Accept with `edgekms tenant accept <name>`, or decline.");
            pairs(&me.invites)
        }
        TenantCommand::Accept { name } => {
            let role = c.accept(&name).map_err(msg)?;
            eprintln!("You are now {} of {name}.", article(&role));
            return Ok(None);
        }
        TenantCommand::Decline { name } => {
            c.decline(&name).map_err(msg)?;
            eprintln!("Declined the invite to {name}.");
            return Ok(None);
        }
        TenantCommand::Show { name } => {
            serde_json::to_string_pretty(&c.show(&name).map_err(msg)?).unwrap_or_default()
        }
        TenantCommand::Create {
            name,
            config,
            import_root_id,
        } => {
            tenant_create(&c, &name, config.as_ref(), import_root_id.as_deref())?;
            return Ok(None);
        }
        TenantCommand::Config {
            command: ConfigCommand::Get { name },
        } => {
            let (config, version) = c.config_get(&name).map_err(msg)?;
            eprintln!("config version {version}");
            config
        }
        TenantCommand::Config {
            command:
                ConfigCommand::Set {
                    name,
                    file,
                    if_version,
                },
        } => {
            let config = read_file(&file)?;
            let version = c
                .config_set(&name, &config, if_version, |v| {
                    eprintln!("No --if-version given; replacing the current config version {v}.");
                })
                .map_err(|err| format!("{}: {err}", file.display()))?;
            eprintln!("{name} is now at config version {version}.");
            return Ok(None);
        }
        TenantCommand::Member {
            command:
                MemberCommand::Add {
                    name,
                    github_id,
                    owner,
                },
        } => {
            tenant_member_add(&c, &name, github_id, owner)?;
            return Ok(None);
        }
        TenantCommand::Member {
            command: MemberCommand::Remove { name, github_id },
        } => {
            c.remove_member(&name, github_id).map_err(msg)?;
            eprintln!("Removed GitHub id {github_id} from {name}, or withdrew their invite.");
            return Ok(None);
        }
        TenantCommand::Export { name } => return tenant_export(&c, &name).map(Some),
    };
    Ok(Some(Zeroizing::new(out)))
}

/// `name<TAB>role` lines.
fn pairs(list: &[(String, String)]) -> String {
    list.iter()
        .map(|(name, role)| format!("{name}\t{role}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// "an owner", "a member".
fn article(role: &str) -> String {
    if role.starts_with(['a', 'e', 'i', 'o', 'u']) {
        format!("an {role}")
    } else {
        format!("a {role}")
    }
}

fn run(cli: Cli) -> Result<Option<Zeroizing<String>>, String> {
    match cli.command {
        Command::Login { method } => login(method).map(Zeroizing::new).map(Some),
        Command::Account { command } => account(command),
        Command::Tenant { api, command } => tenant(&api.api, command),
        Command::Ops { api, command } => ops(&api.api, command),
        Command::Decrypt {
            config,
            key,
            ciphertext,
        } => {
            let config = load_config(&config)?;
            let root = root_key_from_stdin()?;
            let out =
                offline::decrypt(&config, &root, &key, &ciphertext).map_err(|e| e.to_string())?;
            if let Some(notice) = out.notice {
                eprintln!("edgekms: notice: {notice}");
            }
            Ok(Some(out.plaintext))
        }
        Command::Export {
            config,
            key,
            version,
        } => {
            let config = load_config(&config)?;
            let root = root_key_from_stdin()?;
            offline::export(&config, &root, &key, version)
                .map(Some)
                .map_err(|e| e.to_string())
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(out) => {
            if let Some(out) = out {
                // A closed stdout is not worth a panic.
                let _ = writeln!(io::stdout(), "{}", out.as_str());
            }
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("edgekms: {msg}");
            ExitCode::FAILURE
        }
    }
}
