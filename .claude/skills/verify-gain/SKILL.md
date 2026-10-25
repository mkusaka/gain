---
name: verify-gain
description: Launch and drive the gain CLI (GitHub App token wrapper for gh) from this checkout to prove a change works for real — an isolated `gain agent` in tmux with a throwaway HOME, then gain commands typed the way a user would, with transcripts as evidence. Use after changing gain.ts (agent, vault, setup, profiles, token, credential helper, gh passthrough) when unit tests are not enough.
---

# verify-gain

gain is a macOS-only CLI (`gain.ts`, one file). The user touches it in a terminal: a long-running `gain agent` holds the App key, every other command talks to it over a Unix socket. This skill runs a private agent from this checkout and drives it through tmux with `drive.sh`.

**Isolation.** Every gain path hangs off `$HOME` (`$HOME/.local/share/gain/{vault,agent.sock}`), so each run gets its own `HOME=/tmp/gain-vfy.XXXXXX` and never touches the user's real agent or vault. The repo's `skills/gain/SKILL.md` forbids agents from running `gain agent ...`/`setup`/`profile remove`; that rule protects the _user's_ instance. The run instance is yours: drive it freely, but only through `drive.sh` or with `HOME=$RUN` set.

Not isolated by HOME, so never drive them here: `gain agent install|uninstall` (real launchd label `com.github.mkusaka.gain.agent`; `install` first boots out the user's real agent) and `gain migrate-keychain` (real login Keychain; deletes items).

**Not covered (release artifact).** This drives `./gain.ts` on the Bun from PATH. A green run says nothing about the Homebrew cask's compiled universal binary: its own `codesign`/entitlements startup check, the `/$bunfs/` branch of `gain agent install` (Caskroom vs `/opt/homebrew/bin/gain` path in the plist), or the cask's `uninstall launchctl:` teardown. Those stay unverified until checked on an installed release.

## Helper

`drive.sh` (next to this file, executable). All paths below are from the repo root.

```sh
D=.claude/skills/verify-gain/drive.sh
RUN=$($D launch)                    # prints /tmp/gain-vfy.XXXXXX; agent started and listening (locked)
$D doctor  $RUN                     # read-only health check
$D cmd     $RUN './gain.ts agent status'          # run, wait for exit; output lands in the pane + transcript
$D cmd     $RUN './gain.ts agent unlock' 'passphrase'   # 3rd arg: stop waiting when this regex appears
$D type    $RUN 'verify-pass-123'                 # answer a prompt (read -s: not echoed, not in transcript)
$D wait    $RUN 'again:'                          # wait for a regex on screen
$D snap    $RUN <name>                            # pane scrollback -> $EVIDENCE/<name>.txt
$D cleanup $RUN                                   # agent stop, kill tmux session, rm -rf $RUN
```

Shell state does not persist between Bash tool calls: keep `RUN` and pass it on every call. Every `cmd` appends `echo "[exit=$?] #N"` so the exit code is in the transcript.

## Launch

Prereqs: `bun` on PATH must be an official build (the agent refuses a runtime without hardened runtime or with `get-task-allow`), `tmux >= 3.2` (`new-session -e`), `node >= 24.2`, `bun install` done once.

`$D launch` creates the fake HOME, starts tmux session `gain-vfy-XXXXXX` with window `agent` running `./gain.ts agent start` (node re-execs itself under bun) and window `sh` (a clean bash with `HOME=$RUN` and `GH_APP_PROFILE` emptied so the profile is `default`, cwd = repo). Ready = `gain: agent listening on <RUN>/.local/share/gain/agent.sock (locked)` in `agent.log`; launch waits for it and fails with the log otherwise. The agent starts locked with no vault; the first `unlock` creates the vault (that is the empty-data-dir path).

## Doctor

`$D doctor $RUN` prints run dir, evidence dir, checkout commit (+dirty), tmux up, the pid/command listening on _this run's_ socket (must be `bun .../gain.ts agent start`), and `gain agent status` (`locked`/`unlocked`). If listener is `NONE` or status says `not running`, the instance is dead: cleanup and relaunch. Never fix it by touching `~/.local/share/gain`.

## Drive

Type real user commands into the `sh` window with `$D cmd`. Feature recipes live in [features/README.md](features/README.md). Prefer asserting the `gain: ...` stderr lines and `[exit=N]` markers; they are the stable handles.

Network: `setup`, `token`, gh passthrough and `revoke` call api.github.com. Without real App credentials they fail with a GitHub 401, which is still a valid observable for the verify-before-save paths (see features). Real-success journeys need the user to provide a Client ID, installation and PEM — never borrow the user's real vault.

## Evidence

Location: `${GAIN_VERIFY_EVIDENCE:-$HOME/.cache/gain-verify}/gain-vfy-XXXXXX/`

- `transcript.log` – everything in the `sh` window (commands, stdout/stderr, exit markers). Passphrases typed at `read -s` prompts are not echoed, so not recorded.
- `agent.log` – the agent's stderr.
- `<name>.txt` – `$D snap` captures.

Proof standards: drive the real CLI path (`./gain.ts ...` in the tty), never write JSON to the socket yourself. Capture the action and the resulting state: after a mutation, read it back through a second command (`profile list`, `agent status`) and check the side effect on disk (`stat` the vault, grep it for plaintext). Never print a real token (`gain token` output) into evidence.

## Cleanup

`$D cleanup $RUN`: `gain agent stop` against this run's socket, kills only the pid listening on that socket if still alive, kills the run's tmux session, deletes `$RUN` (vault, test PEM). Evidence stays. Run it after every attempt, including failed ones. Leftovers: `tmux ls | grep gain-vfy` and `ls -d /tmp/gain-vfy.*` — clean each with `$D cleanup /tmp/gain-vfy.XXXXXX`. Never `pkill bun`/`gain`: the user's real agent is a bun process too.
