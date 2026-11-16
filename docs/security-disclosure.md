# Reporting a vulnerability

If you find a security problem in edgekms, please tell me privately before telling anyone else.

## How to report

Email **security@edgekms.dev**, or use GitHub's private vulnerability reporting on the
[edgekms repository](https://github.com/lokkju/edgekms/security). Include what you found, how to
reproduce it, and what you think an attacker could do with it. If you used a tenant of your own
to test, name it.

I'll acknowledge a report as soon as I can, tell you whether I can reproduce it, and keep
you posted until it's fixed. Once it is, I'll credit you in the fix's notes unless you'd rather I
didn't.

## In scope

- The hosted service: `edgekms.dev`, `api.edgekms.dev`, `app.edgekms.dev` and tenant hosts
  (`<tenant>.edgekms.dev`).
- The `edgekms` CLI and the Worker, as published in the repository, including a self-hosted
  deployment of it.
- This site.

The findings that matter most: reading or using another tenant's keys, logging in as someone
else, getting a token with more than its role grants, decrypting or recovering a root key, and
anything that writes a tenant's config or membership without its owner.

## Out of scope

- Volumetric denial of service, and rate limits working as designed.
- Social engineering, phishing, and attacks needing physical access to someone's machine.
- Vulnerabilities in Cloudflare or GitHub themselves; report those to them.
- Findings about missing headers or best practices with no demonstrated impact.

## Testing safely

Test only against tenants you own, or a self-hosted deployment of your own. Don't access, change
or delete anyone else's data, don't degrade the service for others, and stop and report as soon
as you find something that touches another user. Research done in good faith within these rules
is welcome, and I won't pursue legal action over it.
