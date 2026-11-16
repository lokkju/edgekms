# Install the CLI

The `edgekms` CLI is a single binary, built for Linux on x86_64 and arm64 and for macOS on Apple
silicon. You need it to log in to a tenant from a terminal (SSH, GitHub or OIDC), to manage hosted
tenants without the [web console](console.md), and for the offline break-glass commands, which
decrypt and export keys from a root key with no server at all.

## With mise

```sh
mise use -g github:lokkju/edgekms
edgekms --version
```

mise picks the release archive for your platform from GitHub. Pin a version with
`github:lokkju/edgekms@0.2.1`.

## From a release

Download the archive for your platform from the
[latest release](https://github.com/lokkju/edgekms/releases/latest), with the `.sha256` file
beside it, check it, and put `edgekms` on your PATH:

```sh
sha256sum -c edgekms-<version>-x86_64-unknown-linux-gnu.tar.gz.sha256   # shasum -a 256 -c on macOS
tar -xzf edgekms-<version>-x86_64-unknown-linux-gnu.tar.gz
install edgekms-<version>-x86_64-unknown-linux-gnu/edgekms ~/.local/bin/
edgekms --version
```

The archives are named for their Rust target: `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu` and `aarch64-apple-darwin`.

## From source

With a Rust toolchain:

```sh
cargo install --git https://github.com/lokkju/edgekms edgekms-cli
```

The CLI keeps nothing on disk. Every login prints its token on stdout for you to export
(`VAULT_TOKEN` for a tenant, `EDGEKMS_CONTROL_TOKEN` for the hosted control plane), and root keys
are only ever read from stdin, never from a terminal or a flag.
