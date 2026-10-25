# Agent lifecycle

The agent starts locked; the first unlock asks for a new passphrase twice and creates the encrypted vault; status/lock/stop control it; other commands fail with clear messages when it is locked or not running.

## Sub-features

- `agent-start` starts locked and listens on `$HOME/.local/share/gain/agent.sock`.
- `agent-unlock-new` first unlock creates the vault (0600) after a twice-entered passphrase of >= 12 chars.
- `agent-unlock-existing` later unlocks ask once; a wrong passphrase fails.
- `agent-lock` forgets keys; gh/token commands then fail with "locked".
- `agent-stop` stops the agent; commands then fail with "not running".

## How to get to it (user POV)

- `gain agent start` (foreground) — done by `drive.sh launch`.
- `gain agent unlock | lock | status | stop` in a terminal.

## Driving it with drive.sh

Preconditions:

- Fresh run, doctor shows status `locked`, no vault.

- **New vault.** Run `$D cmd $RUN './gain.ts agent unlock' 'new gain passphrase'`, `$D type $RUN 'verify-pass-123'`, `$D wait $RUN 'again:'`, `$D type $RUN 'verify-pass-123'`, `$D wait $RUN '\[exit='`. Transcript: `gain: created <RUN>/.local/share/gain/vault and unlocked`.
- **Status.** `$D cmd $RUN './gain.ts agent status'` → `gain: unlocked`, `[exit=0]`.
- **Vault on disk.** `$D cmd $RUN 'stat -f "%Sp" ~/.local/share/gain/vault'` → `-rw-------`.
- **Lock.** `$D cmd $RUN './gain.ts agent lock'` → `gain: agent locked`; then `$D cmd $RUN './gain.ts pr list -R cli/cli'` → `gain: the agent is locked; run: gain agent unlock`, `[exit=1]`.
- **Wrong passphrase.** `$D cmd $RUN './gain.ts agent unlock' 'gain passphrase'`, `$D type $RUN 'wrong-pass-0000'`, `$D wait $RUN '\[exit='` → `gain: wrong passphrase`, `[exit=1]`.
- **Stop.** `$D cmd $RUN './gain.ts agent stop'` → `gain: agent stopped`; `$D cmd $RUN './gain.ts agent status'` → `gain: the agent is not running; start it with: gain agent start`, `[exit=1]`. Doctor now shows listener `NONE`.
- **Proof.** `$D snap $RUN agent-lifecycle`.

## Gotchas

- `$D cmd` for `unlock` must get the prompt regex as 3rd arg, or it waits for an exit that needs your input and times out. `wait`/`cmd` only look at output since the latest `cmd`, so a prompt from an earlier command can't release them early; never `type` a passphrase before its prompt shows, or it is echoed into the transcript.
- After `stop` the `agent` tmux window exits; that is expected. Relaunch for further journeys.
- Short passphrase (< 12) on first unlock: `passphrase too short`, nothing created.
