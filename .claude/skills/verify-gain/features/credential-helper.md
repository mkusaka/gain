# git credential helper

`gain credential get` reads a git credential request on stdin and answers `username=x-access-token` / `password=<token>` only for `protocol=https` + `host=github.com`; anything else gets no answer. `store`/`erase` are no-ops.

## Sub-features

- `cred-other-host` non-github / non-https: empty stdout, exit 0, no agent call.
- `cred-github` github.com: token from the agent for the profile.
- `cred-noop` `store` and `erase` print nothing.

## How to get to it (user POV)

- git calls it via `credential.<url>.helper '!gain --profile work credential'` (README). Directly: `printf 'protocol=https\nhost=github.com\n\n' | gain credential get`.

## Driving it with drive.sh

Preconditions:

- Agent running. For `cred-github` success, a real configured profile.

- **Other host.** `$D cmd $RUN 'printf "protocol=https\nhost=gitlab.com\n\n" | ./gain.ts credential get | wc -c'` → `0`, `[exit=0]`.
- **Lookalike host.** same with `host=github.com.evil.example` → `0`.
- **github.com without profile.** `$D cmd $RUN 'printf "protocol=https\nhost=github.com\n\n" | ./gain.ts credential get'` → `profile "default" not configured`, `[exit=1]`.
- **github.com with real profile.** pipe through `| sed "s/password=.*/password=<redacted>/"` → `username=x-access-token`.
- **Proof.** `$D snap $RUN credential-helper`.

## Gotchas

- Never configure git (global or repo) during verification; call the helper directly.
- Never let the real `password=` line reach the transcript.
