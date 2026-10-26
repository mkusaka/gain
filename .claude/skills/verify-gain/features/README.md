# gain verification map

Maintained source for verifying gain's user-facing behavior. Read this index, then use the matching feature file as the recipe.

## Baseline preconditions

- A fresh run from `drive.sh launch`: isolated `HOME=/tmp/gain-vfy.XXXXXX`, agent listening and locked, no vault.
- `drive.sh doctor $RUN` shows a listener `<repo>/target/debug/gain agent start` and status `locked`.
- Never drive the user's real agent (`~/.local/share/gain`), launchd, or Keychain.

## Driving conventions

- `D=.claude/skills/verify-gain/drive.sh`; every user action is `$D cmd $RUN '<command>'` in the `sh` window; prompts are answered with `$D type`.
- Test passphrase: `verify-pass-123` (>= 12 chars). Test key: `openssl genrsa -out "$HOME/app.pem" 2048` (inside the run, so `$HOME` is the run dir).
- Commands are literal; keep flags as written.

## Proof and skip reporting

- CLI proof = command, stderr/stdout and `[exit=N]` in `transcript.log`, plus a `snap` named after the feature.
- Mutation proof = a second read (`profile list`, `agent status`) and the on-disk side effect (vault mode, no plaintext key).
- If a journey needs real App credentials and you have none, report it as not verified with the 401 you got; do not count the failure path as the success path.

## Features

- [Agent lifecycle](./agent-lifecycle.md): start, first unlock creates the vault, status, lock, reset, stop, and the errors other commands give when locked/not running.
- [Setup a profile](./setup.md): verify-before-save; a failing setup saves nothing.
- [gh passthrough and token](./gh-and-token.md): `gain <gh args>`, `gain token --min-ttl`, `gain revoke`, `--profile`/`GH_APP_PROFILE`.
- [Profiles](./profiles.md): `profile list`, `profile remove`.
- [git credential helper](./credential-helper.md): `gain credential get` answers only https://github.com.

Not mapped as journeys (not isolatable, see SKILL.md): `gain agent install|uninstall` (launchd), `gain migrate-keychain` (Keychain).
