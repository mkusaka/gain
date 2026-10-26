# Agent lifecycle

The agent starts locked; the first unlock asks for a new passphrase twice and creates the encrypted vault; status/lock/stop control it; `reset` deletes the vault for a forgotten passphrase; other commands fail with clear messages when it is locked or not running.

## Sub-features

- `agent-start` starts locked and listens on `$HOME/.local/share/gain/agent.sock`.
- `agent-unlock-new` first unlock creates the vault (0600) after a twice-entered passphrase of >= 12 chars; too short or mismatched creates nothing.
- `agent-unlock-existing` later unlocks ask once; a wrong passphrase fails; an unlocked agent answers `already unlocked` without asking.
- `agent-lock` forgets keys; every command except status/lock/unlock then fails with "locked".
- `agent-reset` asks to type `reset` (echoed), deletes the vault, leaves the agent running and locked; no vault → nothing to do.
- `agent-stop` stops the agent; commands then fail with "not running".

## How to get to it (user POV)

- `gain agent start` (foreground) — done by `drive.sh launch`.
- `gain agent unlock | lock | status | stop | reset` in a terminal.

## Driving it with drive.sh

Preconditions:

- Fresh run, doctor shows status `locked`, no vault.

- **Too short.** `$D cmd $RUN 'gain agent unlock' 'min 12 chars'`, `$D type $RUN 'short'`, `$D wait $RUN '\[exit='` → `gain: passphrase too short`, `[exit=1]`, no `again:` prompt; `ls ~/.local/share/gain/vault` fails.
- **Mismatch.** Same, type `verify-pass-123`, `$D wait $RUN 'again:'`, type `verify-pass-999`, wait `'\[exit='` → `gain: passphrases don't match`, `[exit=1]`.
- **New vault.** `$D cmd $RUN 'gain agent unlock' 'min 12 chars'`, `$D type $RUN 'verify-pass-123'`, `$D wait $RUN 'again:'`, `$D type $RUN 'verify-pass-123'`, `$D wait $RUN '\[exit='` → `gain: created <RUN>/.local/share/gain/vault and unlocked; if you forget the passphrase: gain agent reset`, `[exit=0]`.
- **Already unlocked.** `$D cmd $RUN 'gain agent unlock'` → `gain: already unlocked`, `[exit=0]`, no prompt.
- **Status.** `$D cmd $RUN 'gain agent status'` → `gain: unlocked`, `[exit=0]`.
- **Vault on disk.** `$D cmd $RUN 'stat -f "%Sp" ~/.local/share/gain/vault'` → `-rw-------`.
- **Lock.** `$D cmd $RUN 'gain agent lock'` → `gain: agent locked`; then `gain pr list -R cli/cli` and `gain profile list` → `gain: the agent is locked; run: gain agent unlock`, `[exit=1]`.
- **Wrong, then right passphrase.** `$D cmd $RUN 'gain agent unlock' '^gain passphrase:'`, `$D type $RUN 'wrong-pass-0000'`, wait `'\[exit='` → `gain: wrong passphrase`, `[exit=1]`; repeat with `verify-pass-123` → `gain: unlocked`, `[exit=0]`.
- **Reset abort.** `$D cmd $RUN 'gain agent reset' 'to confirm:'`, `$D type $RUN 'no'`, wait `'\[exit='` → `gain: aborted`, `[exit=1]`; status still `unlocked`.
- **Reset.** Same with `reset` → `gain: deleted the vault. Next: gain agent unlock (new passphrase), then gain setup with a new private key per profile`, `[exit=0]`; status → `gain: locked` (agent still up); `ls` of the vault fails; `gain agent reset` again → `gain: no vault; nothing to reset`, `[exit=0]`.
- **Stop.** `$D cmd $RUN 'gain agent stop'` → `gain: agent stopped`; `gain agent status` → `gain: the agent is not running; start it with: gain agent start`, `[exit=1]`. Doctor now shows listener `NONE`.
- **Proof.** `$D snap $RUN agent-lifecycle`.

## Gotchas

- `$D cmd` for `unlock`/`reset` must get the prompt regex as 3rd arg, or it waits for an exit that needs your input and times out. `wait`/`cmd` only look at output since the latest `cmd`, so a prompt from an earlier command can't release them early; never `type` a passphrase before its prompt shows, or it is echoed into the transcript.
- Use `'^gain passphrase:'` (anchored) for an existing vault; `'min 12 chars'` for a new one.
- The reset confirmation is echoed on purpose, so `reset`/`no` appear in the transcript.
- After `stop` the `agent` tmux window exits; that is expected. Relaunch for further journeys.
