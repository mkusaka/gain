# ghapins

`gh-app`: run `gh` with a GitHub App installation token. Requires [Bun](https://bun.sh) and `gh` on macOS; no dependencies.

The App ID, Installation ID, private key and the cached token (reused until 1 minute before expiry) are stored in the macOS Keychain under service `gh-app` (items `config:<profile>` and `token:<profile>`). No files or env vars; existing `gh` / git config is not touched.

## Setup

```sh
ln -s "$PWD/gh-app.ts" ~/.local/bin/gh-app   # any directory on PATH
gh-app setup --app-id 123456 --installation-id 7890123 --private-key-path /path/to/app.private-key.pem   # verifies by issuing a token, then saves
rm /path/to/app.private-key.pem   # optional: the key now lives in Keychain
```

Grant the App only the permissions you need (e.g. Contents: read, Metadata: read). Run `setup` again to change settings; `security delete-generic-password -s gh-app -a config:default` (and `-a token:default`) to remove them.

## Profiles (multiple Apps)

The profile is `--profile NAME` (must be the first argument), else `$GH_APP_PROFILE`, else `default`.

```sh
gh-app --profile work setup --app-id 111 --installation-id 222 --private-key-path work.pem
gh-app --profile work pr list -R work-org/repo
GH_APP_PROFILE=work gh-app pr list -R work-org/repo   # e.g. via direnv per directory
```

## Usage

```sh
gh-app pr list -R org/private-repo
gh-app api repos/org/private-repo
```

## Development

```sh
bun install
bun run fmt     # oxfmt (fmt:check in CI)
bun run lint    # oxlint
bun test
```
