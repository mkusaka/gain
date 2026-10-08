# gain

`@mkusaka/gain`: run `gh` with a GitHub App installation token. One dependency-free TypeScript file for Node (>= 24.2) or [Bun](https://bun.sh); requires `gh` and macOS.

The App ID, Installation ID, private key and the cached token (reused until 5 minutes before expiry) are stored in the macOS Keychain under service `gain` (items `config:<profile>` and `token:<profile>`). No files or env vars; existing `gh` / git config is not touched. Values are written through the `security` CLI's stdin, so secrets never appear in process arguments.

## Setup

```sh
npm install -g @mkusaka/gain   # or from a clone: npm link (builds dist/ via prepare)
gain setup --app-id 123456 --installation-id 7890123 --private-key-path /path/to/app.private-key.pem   # verifies by issuing a token, then saves
rm /path/to/app.private-key.pem   # optional: the key now lives in Keychain
```

Grant the App only the permissions you need (e.g. Contents: read, Metadata: read). Note that `gh pr list` silently returns nothing without **Issues: read**. After changing the App's permissions, run `setup` again: it also replaces the cached token, which otherwise keeps the old permissions until it expires.

Run `setup` again to change settings; `security delete-generic-password -s gain -a config:default` (and `-a token:default`) to remove them. Only GitHub's standard 2048-bit App keys fit the Keychain write path; larger keys are rejected.

## Profiles (multiple Apps)

The profile is `--profile NAME` (must be the first argument), else `$GH_APP_PROFILE`, else `default`. Names are limited to `[A-Za-z0-9_.-]`.

```sh
gain --profile work setup --app-id 111 --installation-id 222 --private-key-path work.pem
gain --profile work pr list -R work-org/repo
GH_APP_PROFILE=work gain pr list -R work-org/repo   # e.g. via direnv per directory
```

## Usage

```sh
gain pr list -R org/private-repo
gain api repos/org/private-repo
curl -H "Authorization: Bearer $(gain token)" https://api.github.com/repos/org/private-repo
```

### git (optional)

`gain credential` is a git credential helper (answers only for `https://github.com`). Scope it to one org so the rest of your git auth is untouched; the empty `helper` clears helpers configured earlier (e.g. osxkeychain) for that URL only:

```sh
git config --global credential.https://github.com/org.useHttpPath true
git config --global --add credential.https://github.com/org.helper ''
git config --global --add credential.https://github.com/org.helper '!gain --profile work credential'
git clone https://github.com/org/private-repo
```

## Agent skill

[`skills/gain/SKILL.md`](skills/gain/SKILL.md) tells coding agents (Claude Code, Codex, ...) when and how to use `gain`. Copy or symlink it into the agent's skills directory, e.g. `ln -s "$PWD/skills/gain" ~/.claude/skills/gain`.

## Development

```sh
bun install
./gain.ts --version  # Node and Bun both run the .ts directly
bun run fmt     # oxfmt (fmt:check in CI)
bun run lint    # oxlint
node --test     # or: bun test (CI runs both)
bun run build   # dist/gain.js (types stripped by Node; Node won't run .ts inside node_modules)
```
