# Changelog

All notable changes to the `edgekms` CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/lokkju/edgekms/compare/v0.2.1...v0.3.0) - 2026-11-13

### Added

- *(cli)* help text for the role, config, key and ciphertext arguments
- *(cli)* account login --ssh and account ssh-keys
- *(cli)* SSH signer takes the SSHSIG namespace
- *(cli)* request an invite and manage invite requests
- *(cli)* edgekms ops tenant suspend and resume

### Fixed

- *(cli)* escape server-supplied strings in login and ssh-keys output

### Other

- Merge remote-tracking branch 'origin/main' into lokkju/public-split
- Merge origin/main into lokkju/site
- *(cli)* move the clap definitions into the library
- Merge remote-tracking branch 'origin/main' into lokkju/invite-requests

## [0.2.1](https://github.com/lokkju/edgekms/compare/v0.2.0...v0.2.1) - 2026-11-10

### Added

- *(cli)* explain signup and naming refusals, add ops allowlist commands
- *(cli)* make api.edgekms.dev the official control plane
- *(cli)* follow the control plane as built: invites, logout and /v1/info
- *(cli)* add account login and tenant commands for the hosted control plane

### Fixed

- *(cli)* don't decode the body of a 204 from the control plane
- *(cli)* accept loopback names under localhost and a local GitHub stub
- *(core)* parse jwks_url with a WHATWG parser against the configured apex

### Other

- add hosted-tier module stubs and request fields

## [0.2.0](https://github.com/lokkju/edgekms/compare/v0.1.1...v0.2.0) - 2026-11-02

### Added

- *(cli)* add login github and login oidc; never follow redirects
- bind SSH login challenges to the server's origin

### Fixed

- *(cli)* unbuffered root key read, zeroized replies, resilient OIDC callback
- *(cli)* close zeroization gaps and guard the root key on stdin

## [0.1.1](https://github.com/lokkju/edgekms/compare/v0.1.0...v0.1.1) - 2026-10-05

### Other

- start the CLI changelog

## [0.1.0] - 2026-10-04

First release of the `edgekms` command line.

- `edgekms login ssh` signs a challenge with `ssh-keygen -Y sign` (ssh-agent, FIDO keys included) and prints the Worker token on stdout. It takes `--addr`, `--role`, `--key` (the public key file) and `--mount`.
- `edgekms decrypt` decrypts a ciphertext offline, with the root key read as base64 from stdin and the key name and config file given on the command line.
- `edgekms export` prints the raw base64 key for one key version, offline, from the same root key.
