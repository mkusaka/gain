# gh passthrough and token

`gain <gh args>` runs `gh` with an installation token in `GH_TOKEN`; `gain token` prints a token (reused while it has more than `--min-ttl` minutes left); `gain revoke` revokes the cached one. The profile comes from `--profile` (first argument), else `GH_APP_PROFILE`, else `default`.

## Sub-features

- `gh-pass` any non-gain args go to gh unchanged, exit code propagated.
- `token-min-ttl` `--min-ttl 0..60`, out of range rejected by the parser.
- `revoke` revokes the cached token; "no cached token" otherwise.
- `profile-select` `--profile` vs `GH_APP_PROFILE` vs `default`; bad names rejected.

## How to get to it (user POV)

- `gain pr list -R org/repo`, `gain api ...`, `gain --profile work ...`, `GH_APP_PROFILE=work gain ...`
- `gain token [--min-ttl N]`, `gain revoke`

## Driving it with drive.sh

Preconditions:

- Agent unlocked. For real success, a configured profile (see setup.md); otherwise only the error paths below are verifiable.

- **Unconfigured profile.** `$D cmd $RUN './gain.ts pr list -R cli/cli'` → `gain: profile "default" not configured; run: gain [--profile NAME] setup ...`, `[exit=1]`.
- **Env profile.** `$D cmd $RUN 'GH_APP_PROFILE=work ./gain.ts api user'` → `profile "work" not configured`.
- **Bad name.** `$D cmd $RUN './gain.ts --profile ../x pr list'` → `profile names must match [A-Za-z0-9_.-]+`.
- **min-ttl range.** `$D cmd $RUN './gain.ts token --min-ttl 61'` → parser error, non-zero exit.
- **Revoke with nothing cached.** `$D cmd $RUN './gain.ts revoke'` → `gain: no cached token`, `[exit=0]` (even for an unconfigured profile).
- **Real success** (only with a real profile): `$D cmd $RUN './gain.ts api rate_limit --jq .rate.limit'` → a number, `[exit=0]`. Never run bare `./gain.ts token` into the transcript; use `'./gain.ts token | wc -c'`.
- **Proof.** `$D snap $RUN gh-and-token`.

## Gotchas

- `--profile` must be the very first argument; later it is passed to gh.
- gain has no `--help`/`--version`; those go to gh.
- `gh pr list` silently returns nothing when the App lacks Issues: read — not a gain failure.
