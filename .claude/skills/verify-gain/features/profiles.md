# Profiles

`gain profile list` prints configured profile names, one per line; `gain profile remove NAME` deletes one from the vault.

## Sub-features

- `profile-list` sorted names; empty output for a new vault.
- `profile-remove` removes a profile and its cached token; unknown name errors.

## How to get to it (user POV)

- `gain profile list`, `gain profile remove NAME`

## Driving it with drive.sh

Preconditions:

- Agent unlocked. Removing an existing profile needs one saved by a real `setup` (see setup.md); without it only the empty/error paths are verifiable.

- **Empty list.** `$D cmd $RUN './gain.ts profile list'` → no lines, `[exit=0]`.
- **Remove unknown.** `$D cmd $RUN './gain.ts profile remove nope'` → `gain: profile "nope" not found`, `[exit=1]`.
- **Locked.** After `./gain.ts agent lock`, `profile list` → `the agent is locked`.
- **Remove real** (with a real profile `p`): `profile remove p` → `removed profile "p"`; `profile list` no longer shows it.
- **Proof.** `$D snap $RUN profiles`.

## Gotchas

- `profile list` needs an unlocked agent even though it returns no secrets.
