# git credential helper

`gain credential get` reads a git credential request on stdin and answers `username=x-access-token` / `password=<token>` only for `protocol=https` + `host=github.com`; anything else gets no answer and never contacts the agent. `store`/`erase` are no-ops.

## Sub-features

- `cred-other-host` non-github / lookalike / non-https: empty stdout, exit 0, no agent call.
- `cred-github` github.com: token from the agent for the profile.
- `cred-noop` `store` and `erase` print nothing, exit 0.

## How to get to it (user POV)

- git calls it via `credential.<url>.helper '!gain --profile work credential'` (README). Directly: `printf 'protocol=https\nhost=github.com\n\n' | gain credential get`.

## Driving it with drive.sh

Preconditions:

- github.com without profile: agent unlocked. Other-host and no-op steps: none; run them after `agent stop` to prove no agent call. `cred-github` success: a real configured profile.

- **github.com without profile.** `$D cmd $RUN 'printf "protocol=https\nhost=github.com\n\n" | ./gain.ts credential get'` → `gain: profile "default" not configured; ...`, `[exit=1]`.
- **Stop the agent.** `$D cmd $RUN './gain.ts agent stop'`.
- **Other host.** `$D cmd $RUN 'printf "protocol=https\nhost=gitlab.com\n\n" | ./gain.ts credential get | wc -c'` → `0`.
- **Lookalike host.** same with `host=github.com.evil.example` → `0`.
- **No-ops.** `$D cmd $RUN './gain.ts credential store </dev/null | wc -c; ./gain.ts credential erase </dev/null | wc -c'` → `0`, `0`.
- **github.com, agent stopped.** same request as the first step → `gain: the agent is not running; start it with: gain agent start`, `[exit=1]` — while other hosts still answered empty, so only github.com reaches the agent.
- **github.com with real profile.** pipe through `| sed "s/password=.*/password=<redacted>/"` → `username=x-access-token`.
- **Proof.** `$D snap $RUN credential-helper`.

## Gotchas

- In `... | wc -c; echo [exit=$?]` the exit code is wc's; append `; echo ${PIPESTATUS[1]}` if gain's own code matters.
- Never configure git (global or repo) during verification; call the helper directly.
- Never let the real `password=` line reach the transcript.
