# gh passthrough and token

`gain <gh args>` runs `gh` with an installation token in `GH_TOKEN`; `gain token` prints a token (reused while it has more than `--min-ttl` minutes left); `gain revoke` revokes the cached one. The profile comes from `--profile` (first argument), else `GH_APP_PROFILE`, else `default`.

## Sub-features

- `gh-pass` any non-gain args go to gh unchanged; gh's exit code is propagated (127 if gh can't start, 128+signal if killed).
- `token-min-ttl` `--min-ttl 0..60`, out of range rejected by the parser before the agent is asked.
- `revoke` revokes the cached token; `no cached token` otherwise (even for an unconfigured profile).
- `profile-select` `--profile` vs `GH_APP_PROFILE` vs `default`; bad names rejected client-side.

## How to get to it (user POV)

- `gain pr list -R org/repo`, `gain api ...`, `gain --profile work ...`, `GH_APP_PROFILE=work gain ...`
- `gain token [--min-ttl N]`, `gain revoke`

## Driving it with drive.sh

Preconditions:

- Agent unlocked. For real success, a configured profile (see setup.md); otherwise only the paths below are verifiable.

- **Unconfigured profile.** `$D cmd $RUN './gain.ts pr list -R cli/cli'` → `gain: profile "default" not configured; run: gain [--profile NAME] setup --client-id ID [--installation-id ID] --private-key-path FILE`, `[exit=1]`.
- **Env profile.** `$D cmd $RUN 'GH_APP_PROFILE=work ./gain.ts api user'` → `gain: profile "work" not configured; ...`, `[exit=1]`.
- **Bad name.** `$D cmd $RUN './gain.ts --profile ../x pr list'` → `gain: profile names must match [A-Za-z0-9_.-]+`, `[exit=1]`.
- **Trailing --profile goes to gh.** `$D cmd $RUN './gain.ts pr list --profile work'` → names `"default"`, not `"work"`.
- **min-ttl range.** `$D cmd $RUN './gain.ts token --min-ttl 61 2>&1 | grep Error'` → ``Error: `--min-ttl`: Expected a value less than or equal to 60, but got "61".`` (exit 1 unpiped).
- **Revoke with nothing cached.** `$D cmd $RUN './gain.ts --profile nope revoke'` → `gain: no cached token`, `[exit=0]`.
- **Real success** (only with a real profile): `$D cmd $RUN './gain.ts api rate_limit --jq .rate.limit'` → a number, `[exit=0]`. Never run bare `./gain.ts token` into the transcript; use `'./gain.ts token | wc -c'`.
- **Proof.** `$D snap $RUN gh-and-token`.

## Gotchas

- `--profile` must be the very first argument for gh passthrough; later it is passed to gh.
- gain has no `--help`/`--version`; those go to gh.
- `gh pr list` silently returns nothing when the App lacks Issues: read — not a gain failure.
