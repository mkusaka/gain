# gain

Run `gh` with a GitHub App installation token. macOS only. One TypeScript file (argument parsing by [Optique](https://optique.dev)), released as a standalone binary built with [Bun](https://bun.sh) and signed with Developer ID (hardened runtime, notarized).

**0.4 is a breaking change**: keys moved from the Keychain to an encrypted vault held by `gain agent`. See [Upgrading from 0.3](#upgrading-from-03-keychain).

The App's private key never sits anywhere another process can read it. It lives only inside `gain agent`, a small background process that keeps it in memory while unlocked and on disk only in `~/.local/share/gain/vault`, encrypted with AES-256-GCM under a key derived from your passphrase (scrypt). Every other `gain` command asks the agent over a Unix socket (`~/.local/share/gain/agent.sock`, user-only) and gets back a 1-hour installation token; no request returns the key. Tokens are cached in the agent's memory only. Existing `gh` / git config is not touched.

## Setup

```sh
brew install mkusaka/tap/gain  # or a release tarball; from a clone see Development
gain agent install             # start it now and at every login (or: gain agent start &)
gain agent unlock              # first time: choose a passphrase (creates the vault)
gain setup --client-id Iv23liXXXXXXXXXXXXXX --private-key-path /path/to/app.private-key.pem   # verifies by issuing a token, then saves
rm /path/to/app.private-key.pem   # the vault is now the only copy
```

`--client-id` is the App's Client ID (`Iv23li...`, shown on the App settings page), which GitHub recommends as the JWT issuer; the numeric App ID also works. The Installation ID is looked up automatically when the App is installed on exactly one account; otherwise `setup` lists them and you pass `--installation-id` (also the number at the end of `github.com/organizations/<org>/settings/installations/<id>`).

Grant the App only the permissions you need (e.g. Contents: read, Metadata: read). Note that `gh pr list` silently returns nothing without **Issues: read**. After changing the App's permissions, run `setup` again: it also replaces the cached token, which otherwise keeps the old permissions until it expires.

Run `setup` again to change settings. If you forget the passphrase, delete the vault, generate a new private key on the App settings page and run `setup` again.

### Upgrading from 0.3 (Keychain)

0.3 kept the private key in the macOS Keychain, readable by any process running as you via `security find-generic-password` without a prompt. Move it into the vault and delete the Keychain items:

```sh
gain agent start &
gain agent unlock
gain migrate-keychain
```

If the key may already have leaked, also generate a new private key on the App settings page, delete the old one, and run `setup` with the new one.

## The agent

```sh
gain agent start    # foreground; starts locked
gain agent unlock   # passphrase from the terminal
gain agent lock     # forget the key and tokens; nothing can be issued until the next unlock
gain agent status
gain agent stop
```

The agent is not started automatically: run `gain agent start` yourself or `gain agent install` (below). Either way it starts locked. Without a running, unlocked agent no command can get a token; tokens handed out earlier stay valid until they expire (at most 1 hour). The agent refuses to run on a runtime that lets other processes attach a debugger (see [Why Bun](#why-bun)).

To start it at login, let gain register it with launchd:

```sh
gain agent install     # writes ~/Library/LaunchAgents/com.github.mkusaka.gain.agent.plist and starts the agent now
gain agent unlock      # once per login
gain agent uninstall   # stop it and remove the plist
```

The plist runs the absolute paths of your current `bun` and `gain.js` and logs to `~/Library/Logs/gain-agent.log`. It doesn't restart the agent (a restarted agent would be locked anyway); after a crash run `gain agent install` again. Run `install` again also after either path changes (e.g. gain installed under a different Node version), and `uninstall` before removing gain, or launchd keeps trying a missing file at every login.

## Design

### The problem with 0.3

0.3 stored the private key in the login Keychain through `/usr/bin/security`. The Keychain item trusts the app that created it, here `security` itself, so any process running as you could read the key without a prompt (that is also why gain never prompted):

```sh
security find-generic-password -s gain -a config:default -w | base64 -d
```

A stolen App private key is worse than a stolen OAuth refresh token ([the issue raised for `gh auth login --expiring`](https://suzuki-shunsuke.hashnode.dev/github-cli-s-new-expiring-tokens-still-leave-your-refresh-token-exposed-to-malware)): it never expires until you delete it on GitHub, using it elsewhere changes nothing for you so you can't notice, and it mints tokens for every installation of the App, not only the one you configured.

### Agent, vault, socket

So the goal is: the key is never somewhere another process can read it, and only short-lived tokens leave the process that holds it. This follows [ghtkn](https://github.com/suzuki-shunsuke/ghtkn)'s agent backend.

- **Vault**: the key is at rest only in `~/.local/share/gain/vault` (0600), AES-256-GCM encrypted under a key derived from your passphrase with scrypt. The passphrase is never stored, so copying the file is not enough.
- **Agent**: after `gain agent unlock`, only the agent process holds the decrypted key, in memory. `gain agent lock` drops the key and cached tokens.
- **Socket**: other commands ask the agent over `~/.local/share/gain/agent.sock` (directory 0700) and get a token back. No request returns the key. Tokens are cached in the agent's memory only, never on disk.

### Why Bun

"Only in the agent's memory" holds only if other processes can't read that memory. Node fails this: the official build is signed with the `get-task-allow` entitlement and Homebrew's has no hardened runtime, so `lldb -p <agent pid>` attaches without any prompt and can read the key (also, Node opens an inspector on `SIGUSR1` from any same-user process). Official Bun builds use the hardened runtime without `get-task-allow`, and `lldb` is refused. The agent checks this with `codesign` at startup and refuses to run otherwise.

The release binary goes one step further. Official Bun also carries `allow-dyld-environment-variables` and `disable-library-validation`, so `DYLD_INSERT_LIBRARIES` set in the agent's environment (e.g. by editing the launchd plist) loads arbitrary code into it. The release binary is signed with only the JIT entitlements Bun needs ([packaging/entitlements.plist](packaging/entitlements.plist)), so dyld ignores those variables. Verify a download with `gh attestation verify gain-*.tar.gz -R mkusaka/gain`.

### What this does and doesn't protect

- Protected: the private key. Malware running as you can no longer copy it and mint tokens indefinitely from elsewhere; it is never in Keychain, a plaintext file, process arguments or a socket response.
- Not protected: while the agent is unlocked, any process running as you can connect to the socket and get a token (valid up to 1 hour), the same as ghtkn's agent. Other users can't (directory 0700). `gain agent lock` (e.g. from a screen-lock hook) closes that window.
- Out of scope: root, a keylogger capturing the passphrase, or anything that can rewrite `gain.js`, your bun or the launchd plist (e.g. to add a debugger env var) before the agent starts.

## Profiles (multiple Apps)

The profile is `--profile NAME` (must be the first argument), else `$GH_APP_PROFILE`, else `default`. Names are limited to `[A-Za-z0-9_.-]`.

```sh
gain --profile work setup --client-id Iv23liYYYYYYYYYYYYYY --private-key-path work.pem
gain --profile work pr list -R work-org/repo
GH_APP_PROFILE=work gain pr list -R work-org/repo   # e.g. via direnv per directory
gain profile list                                  # configured profiles
gain profile remove work                           # delete it from the vault
```

## Usage

```sh
gain pr list -R org/private-repo
gain api repos/org/private-repo
curl -H "Authorization: Bearer $(gain token)" https://api.github.com/repos/org/private-repo
```

A token stays fixed for the life of the process it was handed to, and GitHub App tokens expire after 60 minutes. `gain token --min-ttl MINUTES` (0-60, default 5) issues a new token unless the cached one has more than that left, e.g. `--min-ttl 30` before a long `gh run watch`.

If a token leaks, `gain revoke` revokes the cached token and drops it from the agent; the next call issues a new one. Tokens handed out before that one stay valid until they expire.

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

From a clone, `npm link` installs `gain` running on Node; its agent then needs an official [Bun](https://bun.sh) on `PATH` (`gain agent start` under Node re-runs itself with `bun`). Releases: push a `vX.Y.Z` tag; [release.yml](.github/workflows/release.yml) builds, signs, notarizes, attests, publishes and updates `mkusaka/homebrew-tap`. Run it manually to validate signing without publishing.

```sh
bun install
./gain.ts --version  # Node and Bun both run the .ts directly
bun run fmt     # oxfmt (fmt:check in CI)
bun run lint    # oxlint
node --test     # or: bun test (CI runs both)
bun run build   # dist/gain.js (types stripped by Node; Node won't run .ts inside node_modules)
```
