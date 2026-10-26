# gain

Run `gh` with a GitHub App installation token. macOS only.

The App's private key lives only inside `gain agent`: in memory while unlocked, and on disk only encrypted with your passphrase (`~/.local/share/gain/vault`). Other commands get a 1-hour token from the agent over a user-only Unix socket; nothing ever returns the key.

## Setup

```sh
brew install --cask mkusaka/tap/gain   # or: npm install -g @mkusaka/gain
gain agent install                     # start the agent now and at every login
gain agent unlock                      # once per login; the first time chooses a passphrase
gain setup --client-id Iv23liXXXXXXXXXXXXXX --private-key-path app.private-key.pem
rm app.private-key.pem                 # the vault is now the only copy
```

`--client-id` is the App's Client ID (the numeric App ID also works). The installation is found automatically when there is only one; otherwise pass `--installation-id`. Grant the App only what you need; `gh pr list` needs **Issues: read**. Run `setup` again after changing permissions.

Upgrading from 0.3 (key in the Keychain): `gain agent start &`, `gain agent unlock`, `gain migrate-keychain`.

## Usage

```sh
gain pr list -R org/private-repo        # any gh command
gain api repos/org/private-repo
curl -H "Authorization: Bearer $(gain token)" https://api.github.com/...
gain token --min-ttl 30                 # a token valid for at least 30 more minutes
gain revoke                             # revoke the cached token (e.g. after a leak)
```

### Profiles (multiple Apps)

`--profile NAME` (first argument), else `$GH_APP_PROFILE`, else `default`.

```sh
gain --profile work setup --client-id Iv23liYYYYYYYYYYYYYY --private-key-path work.pem
gain --profile work pr list -R work-org/repo
gain profile list
gain profile remove work
```

### git (optional)

`gain credential` is a git credential helper for `https://github.com`. Scope it to one org:

```sh
git config --global credential.https://github.com/org.useHttpPath true
git config --global --add credential.https://github.com/org.helper ''
git config --global --add credential.https://github.com/org.helper '!gain --profile work credential'
```

### Agent skill

[`skills/gain/SKILL.md`](skills/gain/SKILL.md) tells coding agents how to use `gain`: `ln -s "$PWD/skills/gain" ~/.claude/skills/gain`.

## The agent

```sh
gain agent start | stop        # foreground; starts locked
gain agent unlock | lock       # lock forgets the key and tokens
gain agent status              # locked/unlocked and the agent's version
gain agent install | uninstall # launchd: start at login
gain agent reset               # forgot the passphrase: delete the vault
```

Without a running, unlocked agent no command gets a token. Upgrades (`brew upgrade`, `npm update -g`) leave the running agent on the old version, still unlocked; it switches at the next login or with `gain agent install` + `gain agent unlock`. Before uninstalling, run `gain agent uninstall` (or `brew uninstall --zap --cask gain`).

## Security

- **Protected**: the private key. Malware running as you can't copy it to mint tokens elsewhere.
- **Not protected**: while unlocked, any process running as you can ask the agent for a token (valid up to 1 hour). `gain agent lock` closes that window.
- **Out of scope**: root, SIP turned off, a keylogger, or anything that can replace the `gain` binary or the launchd plist.

### Why Rust

Keeping the key "only in the agent's memory" depends on macOS refusing debuggers, which requires the hardened runtime. 0.4 ran on Bun, which needs JIT entitlements that weaken it; Node can't be protected at all. 0.5 is a native Rust binary:

- signed with the hardened runtime and **no entitlements**, and refuses to run without them;
- one ~7 MB binary, no runtime or script next to it;
- the vault key, private keys and tokens are zeroized when no longer needed.

Crypto comes from aws-lc-rs and RustCrypto's scrypt, HTTPS from Apple's Security.framework. The vault and socket protocol are unchanged from 0.4.

[`scripts/security-check.sh`](scripts/security-check.sh) proves it on a built binary: no entitlements, `lldb` can't attach to the agent, `DYLD_INSERT_LIBRARIES` is ignored, an unhardened copy refuses to start, files are 0700/0600. CI and releases run it; GitHub's runners have SIP off, so the `lldb`/`DYLD` checks run only locally.

### Distribution

One universal binary, Developer ID signed and notarized, shipped as a Homebrew **cask** (a formula could re-sign it) and as the npm package's `bin` (npm keeps the file as is). Archives carry a GitHub attestation (`gh attestation verify gain-*.tar.gz -R mkusaka/gain`), the npm package npm provenance. For launchd, `gain agent install` uses `/opt/homebrew/bin/gain` for the cask and a copy in `~/.local/share/gain/bin` for npm, since Node version switches delete npm installs.

## Development

```sh
cargo build --release
codesign -s - -f -o runtime target/release/gain   # the agent refuses to run without the hardened runtime
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo nextest run
scripts/security-check.sh target/release/gain     # needs SIP on; run before tagging
```

Release: push a `vX.Y.Z` tag; [release.yml](.github/workflows/release.yml) builds, signs, checks, notarizes and publishes to GitHub, npm (trusted publishing) and `mkusaka/homebrew-tap` (the cask is [packaging/homebrew/gain.rb](packaging/homebrew/gain.rb); edit it here, not in the tap). `gh workflow run Release` does everything but publishing. Secrets (environment `release`): `APPLE_DEVELOPER_ID_P12_BASE64`, `APPLE_DEVELOPER_ID_P12_PASSWORD`, `APPLE_KEYCHAIN_PASSWORD`, `APPLE_APP_STORE_CONNECT_API_KEY_BASE64`, `APPLE_APP_STORE_CONNECT_ISSUER_ID`, `APPLE_APP_STORE_CONNECT_KEY_ID`, `HOMEBREW_TAP_TOKEN`.
