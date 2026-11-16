# Contributing

Bug reports and feature requests are welcome as GitHub issues. For a security problem, follow
[SECURITY.md](SECURITY.md) instead.

## Pull requests

edgekms is source available under [PolyForm Shield 1.0.0](LICENSE), and I run it as a hosted
service. For anything beyond a small fix, open an issue first so we can agree on the shape before
you write it.

By opening a pull request, you agree that:

- your contribution may be distributed under the project's license;
- you also grant Loki Coyote a perpetual, worldwide, non-exclusive, royalty-free, irrevocable
  license to use, copy, modify, distribute, sublicense and relicense your contribution under any
  terms, including a future change to the project's license; and
- the contribution is yours to give: you wrote it, or you have the right to submit it under these
  terms.

You keep the copyright in your contribution.

Workflows from forks wait for a maintainer's approval before they run, so CI on your pull request
starts once I've looked at it.

## Working on it

Tools are pinned with [mise](https://mise.jdx.dev): run `mise install` in the repo root. The
checks CI runs (`.github/workflows/ci.yml`):

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo clippy -p edgekms-worker --all-targets --target wasm32-unknown-unknown -- -D warnings
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test -p edgekms-worker --target wasm32-unknown-unknown
deploy/example-hosted/.mise/tasks/test-config
pnpm -C console install --frozen-lockfile
pnpm -C console check
pnpm -C console test
pnpm -C console build
pnpm -C console e2e
```

`scripts/e2e.sh` and `scripts/e2e-hosted.sh` run the Worker under `wrangler dev` against real
clients (Pulumi, OpenBao, the CLI); they need Docker and take a few minutes.

Commits follow [Conventional Commits](https://www.conventionalcommits.org); release-plz builds the
changelog and the version from them. [docs/design.md](docs/design.md) explains the design, and
[docs/specs/](docs/specs/) the larger features.
