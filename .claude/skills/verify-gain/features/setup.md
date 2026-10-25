# Setup a profile

`gain setup` reads the PEM file, hands the Client ID, optional installation ID and key to the agent, which first issues a real token to verify them and only then saves the profile into the vault.

## Sub-features

- `setup-input-errors` missing key file, missing `--client-id`, garbage PEM, locked agent: error, nothing saved.
- `setup-verify-fail` bad credentials: error from GitHub (token request, or installation lookup without `--installation-id`), nothing saved.
- `setup-success` real credentials: `saved profile "<p>" (installation N) to the agent's vault. You can now delete <FILE>.`, profile listed.
- `setup-installation-lookup` without `--installation-id`: auto-picks a single installation, otherwise lists them.

## How to get to it (user POV)

- `gain [--profile NAME] setup --client-id ID [--installation-id ID] --private-key-path FILE`

## Driving it with drive.sh

Preconditions:

- Fresh run. Agent locked for the first two steps, then unlocked with a new vault (agent-lifecycle `New vault` step).
- For `setup-success` and `setup-installation-lookup`: a real App Client ID, installation and PEM supplied by the user, copied into `$RUN`. Without them, report both as not verified.

- **Missing file (works locked, even with no agent).** `$D cmd $RUN './gain.ts setup --client-id X --private-key-path "$HOME/nope.pem"'` → `gain: ENOENT: no such file or directory, open '<RUN>/nope.pem'`, `[exit=1]`.
- **Test key.** `$D cmd $RUN 'openssl genrsa -out "$HOME/app.pem" 2048 2>/dev/null'`.
- **Locked.** `$D cmd $RUN './gain.ts setup --client-id X --installation-id 1 --private-key-path "$HOME/app.pem"'` → `gain: the agent is locked; run: gain agent unlock`, `[exit=1]`. Unlock now.
- **Missing --client-id.** `$D cmd $RUN './gain.ts setup --private-key-path "$HOME/app.pem"'` → usage plus ``Error: Missing option `--client-id`.``, exit 1 (no `gain:` prefix).
- **Garbage PEM.** `$D cmd $RUN 'echo garbage > "$HOME/bad.pem"; ./gain.ts setup --client-id X --installation-id 1 --private-key-path "$HOME/bad.pem"'` → `gain: error:0900006e:PEM routines:OPENSSL_internal:NO_START_LINE`, `[exit=1]`.
- **Failing token request.** `$D cmd $RUN './gain.ts setup --client-id Iv23liVERIFYFAKE00000 --installation-id 1 --private-key-path "$HOME/app.pem"'` → `gain: token request failed: 401 ...`, `[exit=1]`.
- **Failing installation lookup.** Same without `--installation-id` → `gain: installation lookup failed: 401 ...`, `[exit=1]`.
- **Nothing saved.** `$D cmd $RUN './gain.ts profile list'` → no output, `[exit=0]`.
- **Proof.** `$D snap $RUN setup`.

## Gotchas

- Use a real RSA key for the GitHub paths: a garbage PEM fails inside the agent while signing the JWT and never reaches GitHub, so it proves nothing about verify-before-save.
- Grepping the vault for `PRIVATE KEY` proves nothing: it is ciphertext whether or not a profile was saved. The read-back is `profile list`.
- An unknown `Iv23li...` client ID returns 401 `'Issuer' claim ('iss') must be an Integer`; that is GitHub's wording for "no such App", not a gain bug.
- The 401 paths call api.github.com; offline they fail with a fetch error instead.
- The parser error is printed only after the usage block; pipe through `2>&1 | tail -1` to keep the transcript short (then `[exit=]` is tail's).
