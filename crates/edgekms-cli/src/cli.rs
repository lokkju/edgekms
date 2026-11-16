//! The `edgekms` command line's clap definitions. They live in the library, not `main.rs`, so
//! the site's reference generator (`edgekms-site-prep`) can walk `Cli::command()`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::control;

#[derive(Parser)]
#[command(name = "edgekms", version, about = "edgekms command line")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Log in to a Worker and print the token on stdout.
    Login {
        #[command(subcommand)]
        method: LoginMethod,
    },
    /// Offline: decrypt a ciphertext with the root key read as base64 from stdin.
    Decrypt {
        /// The tenant or instance config (JSON) the ciphertext's key is in.
        #[arg(long)]
        config: PathBuf,
        /// The key's name in the config.
        #[arg(long)]
        key: String,
        /// The ciphertext, `vault:v<version>:...`.
        ciphertext: String,
    },
    /// Offline: print the raw base64 key for one version, root key read as base64 from stdin.
    Export {
        /// The tenant or instance config (JSON) the key is in.
        #[arg(long)]
        config: PathBuf,
        /// The key's name in the config.
        #[arg(long)]
        key: String,
        /// The key version to export.
        #[arg(long)]
        version: u32,
    },
    /// The hosted edgekms service at edgekms.dev: log in to its control plane.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// The hosted edgekms service: manage your tenants. Reads the control token from
    /// `EDGEKMS_CONTROL_TOKEN` (see `edgekms account login`); a token lasts 1800 seconds.
    Tenant {
        #[command(flatten)]
        api: ApiArg,
        #[command(subcommand)]
        command: TenantCommand,
    },
    /// The hosted edgekms service, for its operators (`OPERATOR_GITHUB_IDS`) only. Reads the
    /// control token from `EDGEKMS_CONTROL_TOKEN`.
    Ops {
        #[command(flatten)]
        api: ApiArg,
        #[command(subcommand)]
        command: OpsCommand,
    },
}

#[derive(Subcommand)]
pub enum OpsCommand {
    /// The signup allowlist: the GitHub users who may sign up while `SIGNUP_MODE` is `invite`.
    Allowlist {
        #[command(subcommand)]
        command: AllowlistCommand,
    },
    /// Suspend or resume any tenant, by name.
    Tenant {
        #[command(subcommand)]
        command: OpsTenantCommand,
    },
    /// Requests for an invite from GitHub users refused while `SIGNUP_MODE` is `invite`.
    InviteRequests {
        #[command(subcommand)]
        command: InviteRequestsCommand,
    },
}

#[derive(Subcommand)]
pub enum InviteRequestsCommand {
    /// Print each request as `github_id  login  status  date` with its note indented below:
    /// every pending one, oldest first, then the 100 most recently decided.
    List,
    /// Put the user on the signup allowlist and mark the request approved; their next sign-in
    /// creates their personal tenant.
    Approve { github_id: u64 },
    /// Mark the request declined. They can't ask again until the request is deleted.
    Decline { github_id: u64 },
    /// Delete the request, whatever its status. A declined user can then ask again; an approved
    /// one stays on the allowlist.
    Delete { github_id: u64 },
}

#[derive(Subcommand)]
pub enum OpsTenantCommand {
    /// Suspend a tenant: within about 30 seconds its host refuses every request, and its config
    /// and members can't change. Its owners can still export the root key.
    Suspend { name: String },
    /// Make a suspended tenant active again.
    Resume { name: String },
}

#[derive(Subcommand)]
pub enum AllowlistCommand {
    /// Let a GitHub user, by numeric id, sign up.
    Add { github_id: u64 },
    /// Take a GitHub user off the allowlist. Once they have signed up, they keep logging in
    /// while they belong to a tenant.
    Remove { github_id: u64 },
    /// Print `github_id<TAB>added_by<TAB>added_ms` for each entry.
    List,
}

#[derive(Args)]
pub struct ApiArg {
    /// The control plane URL; https, or http for loopback only.
    #[arg(long, global = true, default_value = control::DEFAULT_API)]
    pub api: String,
}

#[derive(Subcommand)]
pub enum AccountCommand {
    /// GitHub's device flow with the hosted edgekms App, or with --ssh a key registered on your
    /// account, then print a control token on stdout for `export EDGEKMS_CONTROL_TOKEN=...`.
    /// The token lasts 1800 seconds (30 minutes); `tenant export` and `account ssh-keys add`
    /// need one under five minutes old. Nothing is saved to disk.
    Login {
        /// The control plane URL; https, or http for loopback only.
        #[arg(long, default_value = control::DEFAULT_API)]
        api: String,
        /// Your own GitHub App's client id, for a control plane other than api.edgekms.dev. Without
        /// it the hosted App's id is used, from `EDGEKMS_HOSTED_CLIENT_ID` or else from the
        /// control plane's `/v1/info`, and its tokens go only to <https://api.edgekms.dev>.
        #[arg(long)]
        client_id: Option<String>,
        /// Log in without GitHub, with an SSH key registered on your account (see `edgekms
        /// account ssh-keys`): the control plane's challenge is signed through ssh-agent with
        /// `ssh-keygen -Y sign`. Without --key, ssh-agent must hold exactly one Ed25519,
        /// sk-ssh-ed25519 or ECDSA P-256 key.
        #[arg(long, conflicts_with = "client_id")]
        ssh: bool,
        /// With --ssh, the public key file (ending in .pub) to sign with. ssh-keygen finds the
        /// private half in ssh-agent, or falls back to the private key file beside it (the same
        /// path without .pub) and may prompt for its passphrase.
        #[arg(long, requires = "ssh")]
        key: Option<PathBuf>,
    },
    /// The SSH keys that can log in to your account with `edgekms account login --ssh`, for
    /// when GitHub is unavailable. Reads the control token from `EDGEKMS_CONTROL_TOKEN`.
    SshKeys {
        #[command(flatten)]
        api: ApiArg,
        #[command(subcommand)]
        command: SshKeysCommand,
    },
    /// For a GitHub account edgekms.dev doesn't admit yet: GitHub's device flow as for
    /// `login`, then ask for an invite with an optional note on what you'll use edgekms for, or
    /// see how an earlier request stands. Nothing is printed on stdout or saved to disk.
    RequestInvite {
        /// The control plane URL; https, or http for loopback only.
        #[arg(long, default_value = control::DEFAULT_API)]
        api: String,
        /// Your own GitHub App's client id, as for `login`.
        #[arg(long)]
        client_id: Option<String>,
        /// What you'll use edgekms for, at most 500 characters. Without it you're asked, when
        /// stdin is a terminal.
        #[arg(long)]
        note: Option<String>,
    },
    /// End every control token you hold, the one in `EDGEKMS_CONTROL_TOKEN` included, before
    /// its 1800 seconds are up.
    Logout {
        /// The control plane URL; https, or http for loopback only.
        #[arg(long, default_value = control::DEFAULT_API)]
        api: String,
    },
}

#[derive(Subcommand)]
pub enum SshKeysCommand {
    /// Print `id<TAB>fingerprint<TAB>key_type<TAB>label<TAB>added_ms<TAB>added_via<TAB>last_used_ms`
    /// for each key (`last_used_ms` empty for a key that has never logged in), then
    /// `unverified<TAB><fingerprint>` for each key record that failed its integrity check and
    /// can't log in.
    List,
    /// Register a key, proving you hold it with a signature through ssh-agent (`ssh-keygen -Y
    /// sign -n edgekms-register`). Needs a login under five minutes old. The signed challenge
    /// names the GitHub account the key goes to, which is printed before signing; a challenge
    /// for any account but yours is refused. A registered key can log in, export root keys and
    /// add more keys, as your GitHub account can, so prefer a security key (sk-ssh-ed25519),
    /// which signs only with a touch, or an agent key added with `ssh-add -c`, which asks
    /// before each signature.
    Add {
        /// The public key file (ending in .pub). Without it, the one Ed25519, sk-ssh-ed25519 or
        /// ECDSA P-256 key ssh-agent holds.
        #[arg(long)]
        key: Option<PathBuf>,
        /// A label for the key, at most 64 characters. Without it, the key's comment, when that
        /// fits.
        #[arg(long)]
        label: Option<String>,
        /// The GitHub id of the account the key must go to. Without it, the account
        /// `EDGEKMS_CONTROL_TOKEN` says it is for.
        #[arg(long)]
        expect_github_id: Option<u64>,
    },
    /// Remove a key, by the id or the SHA256: fingerprint `list` prints. Every control token it
    /// minted stops working.
    Remove {
        /// The key's id or fingerprint.
        key: String,
    },
}

#[derive(Subcommand)]
pub enum TenantCommand {
    /// List the tenants you are a member of, with your role in each.
    List,
    /// List your pending invites, with the role each offers.
    Invites,
    /// Accept a pending invite to a tenant.
    Accept { name: String },
    /// Decline a pending invite to a tenant.
    Decline { name: String },
    /// Print a tenant's details, config, members and pending invites as JSON.
    Show { name: String },
    /// Create a tenant, optionally from an existing root key. Besides your personal tenant,
    /// a tenant you create is named after your GitHub login: `<login>-<suffix>`.
    Create {
        name: String,
        /// The tenant config, checked locally against the hosted rules before it's sent. The
        /// control plane replaces its `root_id` with the new tenant's unless you import. Without
        /// it the control plane writes a default config.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Import an existing root key with this root id. The key is read as base64 from stdin
        /// (never a terminal), and --config is required.
        #[arg(long)]
        import_root_id: Option<String>,
    },
    /// Read or replace a tenant's config.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Invite, change or remove a tenant member (owners only).
    #[command(visible_alias = "members")]
    Member {
        #[command(subcommand)]
        command: MemberCommand,
    },
    /// Print a tenant's root key as base64 on stdout (owners only, with a login under five
    /// minutes old). Pipe it straight into sops or another encrypted store.
    Export { name: String },
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Print the config JSON on stdout and its version on stderr.
    Get { name: String },
    /// Replace the config with a file, checked locally first.
    Set {
        name: String,
        file: PathBuf,
        /// The version being replaced; without it the current version is read first.
        #[arg(long)]
        if_version: Option<u64>,
    },
}

#[derive(Subcommand)]
pub enum MemberCommand {
    /// Invite a user by numeric GitHub id, or offer a member the owner role. Nothing changes
    /// until they run `edgekms tenant accept`; only lowering an owner to member applies at once.
    Add {
        name: String,
        #[arg(long)]
        github_id: u64,
        /// Make them an owner; members are read-only.
        #[arg(long)]
        owner: bool,
    },
    /// Remove a member or withdraw a pending invite; the last owner can't be removed.
    Remove {
        name: String,
        #[arg(long)]
        github_id: u64,
    },
}

#[derive(Subcommand)]
pub enum LoginMethod {
    /// Sign a challenge with `ssh-keygen -Y sign` (ssh-agent, FIDO keys included).
    Ssh {
        /// Worker URL; https, or http for loopback only.
        #[arg(long)]
        addr: String,
        /// The role to log in as, from the deployment's config.
        #[arg(long)]
        role: String,
        /// The public key file; ssh-keygen finds the private half in ssh-agent. If the agent
        /// doesn't hold it, ssh-keygen falls back to the private key file beside it (the same
        /// path without .pub) and may prompt for its passphrase.
        #[arg(long)]
        key: PathBuf,
        /// The SSH auth mount name.
        #[arg(long, default_value = "ssh")]
        mount: String,
    },
    /// GitHub's OAuth device flow: enter a code at github.com, from any browser.
    Github {
        /// Worker URL; https, or http for loopback only.
        #[arg(long)]
        addr: String,
        /// The role to log in as, from the deployment's config.
        #[arg(long)]
        role: String,
        /// The client ID of the deployment's GitHub OAuth App (device flow enabled).
        #[arg(long, env = "EDGEKMS_GITHUB_CLIENT_ID")]
        client_id: String,
        /// The GitHub user auth mount name.
        #[arg(long, default_value = "github-user")]
        mount: String,
    },
    /// OIDC in a browser: authorization code with PKCE, redirected to 127.0.0.1.
    ///
    /// A client secret, for providers that issue one to desktop clients, is read from
    /// `EDGEKMS_OIDC_CLIENT_SECRET`, never from the command line.
    Oidc {
        /// Worker URL; https, or http for loopback only.
        #[arg(long)]
        addr: String,
        /// The role to log in as, from the deployment's config.
        #[arg(long)]
        role: String,
        /// The JWT auth mount that trusts this issuer.
        #[arg(long, default_value = "oidc")]
        mount: String,
        /// The issuer URL, as the provider's discovery document names it.
        #[arg(long, env = "EDGEKMS_OIDC_ISSUER")]
        issuer: String,
        #[arg(long, env = "EDGEKMS_OIDC_CLIENT_ID")]
        client_id: String,
        /// Space-separated scopes; must include openid.
        #[arg(long, default_value = "openid email")]
        scope: String,
        /// Loopback port for the redirect, `http://127.0.0.1:<port>/oidc/callback`; 0 picks a
        /// free one, for providers that accept any loopback port.
        #[arg(long, default_value_t = 8250)]
        port: u16,
        /// Print the URL without trying to open a browser.
        #[arg(long)]
        no_browser: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_config_set() {
        let cli = Cli::parse_from([
            "edgekms",
            "tenant",
            "config",
            "set",
            "acme",
            "c.json",
            "--if-version",
            "3",
        ]);
        let Command::Tenant { api, command } = cli.command else {
            panic!("not a tenant command");
        };
        assert_eq!(api.api, control::DEFAULT_API);
        let TenantCommand::Config {
            command:
                ConfigCommand::Set {
                    name,
                    file,
                    if_version,
                },
        } = command
        else {
            panic!("not config set");
        };
        assert_eq!(name, "acme");
        assert_eq!(file, PathBuf::from("c.json"));
        assert_eq!(if_version, Some(3));
    }
}
