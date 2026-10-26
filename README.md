# gain

Run `gh` with a GitHub App installation token. macOS only. One Rust file, released as a universal binary signed with Developer ID (hardened runtime, no entitlements, notarized). See [Why Rust](#why-rust) for why it moved from TypeScript/Bun.

**0.4 is a breaking change**: keys moved from the Keychain to an encrypted vault held by `gain agent`. See [Upgrading from 0.3](#upgrading-from-03-keychain).

The App's private key never sits anywhere another process can read it. It lives only inside `gain agent`, a small background process that keeps it in memory while unlocked and on disk only in `~/.local/share/gain/vault`, encrypted with AES-256-GCM under a key derived from your passphrase (scrypt). Every other `gain` command asks the agent over a Unix socket (`~/.local/share/gain/agent.sock`, user-only) and gets back a 1-hour installation token; no request returns the key. Tokens are cached in the agent's memory only. Existing `gh` / git config is not touched.

## Setup

```sh
brew install --cask mkusaka/tap/gain  # or a release tarball; from a clone see Development
gain agent install             # start it now and at every login (or: gain agent start &)
gain agent unlock              # first time: choose a passphrase (creates the vault)
gain setup --client-id Iv23liXXXXXXXXXXXXXX --private-key-path /path/to/app.private-key.pem   # verifies by issuing a token, then saves
rm /path/to/app.private-key.pem   # the vault is now the only copy
```

`--client-id` is the App's Client ID (`Iv23li...`, shown on the App settings page), which GitHub recommends as the JWT issuer; the numeric App ID also works. The Installation ID is looked up automatically when the App is installed on exactly one account; otherwise `setup` lists them and you pass `--installation-id` (also the number at the end of `github.com/organizations/<org>/settings/installations/<id>`).

Grant the App only the permissions you need (e.g. Contents: read, Metadata: read). Note that `gh pr list` silently returns nothing without **Issues: read**. After changing the App's permissions, run `setup` again: it also replaces the cached token, which otherwise keeps the old permissions until it expires.

Run `setup` again to change settings. If you forget the passphrase, run `gain agent reset` (deletes the vault after you type `reset`), choose a new passphrase with `gain agent unlock`, generate a new private key on the App settings page and run `setup` again.

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
gain agent status  # locked/unlocked and the agent's version
gain agent stop
gain agent reset   # forgot the passphrase: delete the vault (asks you to type "reset")
```

The agent is not started automatically: run `gain agent start` yourself or `gain agent install` (below). Either way it starts locked. Without a running, unlocked agent no command can get a token; tokens handed out earlier stay valid until they expire (at most 1 hour). The agent refuses to run from a binary that lets other processes attach a debugger (see [Why Rust](#why-rust)).

To start it at login, let gain register it with launchd:

```sh
gain agent install     # writes ~/Library/LaunchAgents/com.github.mkusaka.gain.agent.plist and starts the agent now
gain agent unlock      # once per login
gain agent uninstall   # stop it and remove the plist
```

The plist runs the absolute path of `gain` (`/opt/homebrew/bin/gain` for the cask) and logs to `~/Library/Logs/gain-agent.log`. It doesn't restart the agent (a restarted agent would be locked anyway); after a crash run `gain agent install` again. Remove gain with `brew uninstall --zap --cask gain` (or `gain agent uninstall` first), or launchd keeps trying a missing file at every login.

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

### Why Rust

"Only in the agent's memory" holds only if other processes can't read that memory. On macOS that is decided by the binary's code signature, not by the language: a process without the hardened runtime, or signed with `get-task-allow`, lets any process running as you attach `lldb` without a prompt and read it. That includes native binaries: a plain `cargo build` or `go build` output is only linker-signed, without the hardened runtime, and `lldb -p` reads it.

0.4 was TypeScript run by Bun, because Node can't be protected (the official build carries `get-task-allow`, Homebrew's has no hardened runtime, and Node opens an inspector on `SIGUSR1` from any same-user process). Bun can, but only with JIT entitlements, including `allow-unsigned-executable-memory` and `disable-executable-page-protection`, which switch off most of what the hardened runtime does for executable memory. From 0.5 gain is a native Rust binary:

- **No entitlements.** Nothing is JIT-compiled, so the release is signed with the hardened runtime and no entitlements at all.
- **No runtime on the side.** One binary. There is no interpreter on `PATH` and no script file next to it that the agent's security depends on, and no second "run from source" mode that is weaker than the release.
- **Secrets are wiped.** The vault key, the private keys and the cached tokens are zeroized (`zeroize`) when the agent locks, a profile is removed or replaced, or a token is dropped. In TypeScript (and Go) they are garbage-collected strings that stay in memory until overwritten. Not airtight: temporary copies made while parsing JSON or inside the TLS and crypto libraries aren't wiped.
- **Small.** About 7 MB (universal) instead of Bun's 188 MB, which also makes npm or mise practical as distribution channels later.

What Rust doesn't change: the hardened runtime and the signature are still what keeps `lldb` out; any process running as you can still ask an unlocked agent for a token; the vault format and the socket protocol are the same as 0.4, so existing vaults open as they are and a 0.4 agent keeps working with a 0.5 client until it is restarted.

Go would have given the first, second and fourth points with fewer dependencies (its standard library covers HTTP, TLS and RSA). Rust was chosen for the third, and the dependencies are kept small and pinned: crypto from [aws-lc-rs](https://github.com/aws/aws-lc-rs) (AES-256-GCM, RSA signing, randomness), scrypt from RustCrypto, HTTPS through Apple's Security.framework with the system trust store (`ureq` + `native-tls`), versions locked in `Cargo.lock` and checked by `cargo audit` in CI.

**Verified.** [`scripts/security-check.sh`](scripts/security-check.sh) checks the hardened runtime with no entitlements, that `lldb` can't attach to a running, unlocked agent, that `DYLD_INSERT_LIBRARIES` is ignored, that the agent refuses to start from a copy re-signed without the hardened runtime, and that the data directory is 0700 and the vault 0600 and sealed. The `lldb` and `DYLD_INSERT_LIBRARIES` checks first succeed against an unprotected control program, so a machine that blocks them for everything can't pass by accident. They need SIP: the kernel enforces the hardened runtime only with SIP on, and GitHub's macOS runners run with SIP off. So CI (macOS 15 and 26, ad-hoc signed) and the release workflow (the Developer ID signed binary) run the signature, self-check and file checks and skip those two with a warning; run the script on a Mac with SIP on before tagging a release (see [Development](#development)).

### Distribution

The release is a single standalone binary signed by [release.yml](.github/workflows/release.yml) and installed as a Homebrew cask. Each choice keeps the guarantees above intact on the user's machine:

- **Native binary**: users need no runtime, and the code the agent runs is exactly the signed file.
- **Developer ID, hardened runtime, no entitlements**: no `get-task-allow`, so no debugger attach; no `allow-dyld-environment-variables` or `disable-library-validation`, so `DYLD_INSERT_LIBRARIES` in the agent's environment (e.g. added to the launchd plist) is ignored instead of loading code into it. The agent also refuses to start if its own signature has any of these. The release workflow proves all of it on the signed binary with `scripts/security-check.sh`.
- **Universal (arm64 + x86_64)**: one archive, so the cask has one `url`/`sha256`. Both slices are smoke-tested in CI (x86_64 through Rosetta).
- **Notarized**: a cask download is quarantined, so Gatekeeper checks the notarization on first run.
- **Cask, not formula**: Homebrew ships prebuilt binaries as casks. A formula install may rewrite a Mach-O and ad-hoc re-sign it, dropping the Developer ID signature; a cask copies the file as is. Its `zap` stanza stops the agent and removes the plist.
- **Stable launchd path**: casks live in a versioned `Caskroom/gain/<version>/` directory, so `gain agent install` writes the `gain` found on `PATH` (`/opt/homebrew/bin/gain`) into the plist when it is the same binary.
- **Provenance**: archives carry a GitHub build attestation; verify with `gh attestation verify gain-*.tar.gz -R mkusaka/gain`. The build runs without a build cache, so a poisoned cache can't end up in the signed binary.

- **Upgrades don't stop the agent**: stopping it would lock it, and restarting from a cask hook isn't possible (Homebrew runs install steps in a sandbox that can't `launchctl bootstrap`). So `brew upgrade` leaves the agent running, still unlocked, on the old binary; it switches to the new one at the next login, or right away with `gain agent install` + `gain agent unlock`. `gain agent status` prints the agent's version and says so when it differs from the installed gain.

### What this does and doesn't protect

- Protected: the private key. Malware running as you can no longer copy it and mint tokens indefinitely from elsewhere; it is never in Keychain, a plaintext file, process arguments or a socket response.
- Not protected: while the agent is unlocked, any process running as you can connect to the socket and get a token (valid up to 1 hour), the same as ghtkn's agent. Other users can't (directory 0700). `gain agent lock` (e.g. from a screen-lock hook) closes that window.
- Out of scope: root, a Mac with SIP turned off (the hardened runtime isn't enforced there), a keylogger capturing the passphrase, or anything that can replace the `gain` binary or rewrite the launchd plist (e.g. to point it at another program) before the agent starts.

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

The agent refuses to run from a binary without the hardened runtime, and `cargo build` output only has the linker's ad-hoc signature, so sign what you build:

```sh
cargo build --release
codesign -s - -f -o runtime target/release/gain   # ad-hoc signature with the hardened runtime
target/release/gain agent start
```

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo nextest run                        # includes opening a vault sealed by 0.4
scripts/security-check.sh target/release/gain   # after the codesign above; needs SIP on
```

CI can't run the `lldb` and `DYLD_INSERT_LIBRARIES` checks (SIP is off on GitHub's runners), so run `scripts/security-check.sh` locally before tagging a release, ideally on the binary of a manual release run (`gh workflow run Release`, then download its archive).

The toolchain is pinned in `rust-toolchain.toml`. Releases: push a `vX.Y.Z` tag. [release.yml](.github/workflows/release.yml) builds the universal binary, signs, runs the security check, notarizes, attests, publishes the GitHub release and bumps `Casks/gain.rb` in `mkusaka/homebrew-tap` (see [Distribution](#distribution)). Run it manually (`gh workflow run Release`) to validate signing and notarization without publishing. It needs these secrets in the `release` environment: `APPLE_DEVELOPER_ID_P12_BASE64`, `APPLE_DEVELOPER_ID_P12_PASSWORD`, `APPLE_KEYCHAIN_PASSWORD`, `APPLE_APP_STORE_CONNECT_API_KEY_BASE64`, `APPLE_APP_STORE_CONNECT_ISSUER_ID`, `APPLE_APP_STORE_CONNECT_KEY_ID`, `HOMEBREW_TAP_TOKEN`.
