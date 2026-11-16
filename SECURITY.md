# Security

edgekms holds root keys and issues tokens that decrypt secrets, so I treat a vulnerability in it
as urgent, whether it affects the hosted service at edgekms.dev, a self-hosted Worker or the CLI.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting: the repository's
**Security** tab, then **Report a vulnerability**
(<https://github.com/lokkju/edgekms/security/advisories/new>). Please don't open a public issue,
pull request or discussion for it.

Include what you found, the version or commit, how to reproduce it, and what an attacker gains.
A proof of concept against your own deployment or a local `wrangler dev` is welcome; please don't
test against other people's tenants on edgekms.dev or try to read data that isn't yours.

I'll acknowledge your report as soon as I can. I'll work out the fix and its timing with you in
the advisory, fix the hosted service first, and publish the advisory (crediting you, if you want)
once a fixed release and deploy are out.

## Supported versions

Fixes go into the latest release of the CLI and the current `main`, which is what edgekms.dev runs.
Self-hosted deployments should rebuild from the fixed release.
