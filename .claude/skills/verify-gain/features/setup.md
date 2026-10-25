# Setup a profile

`gain setup` hands the Client ID, optional installation ID and PEM to the agent, which first issues a real token to verify them and only then saves the profile into the vault.

## Sub-features

- `setup-verify-fail` bad credentials: error from GitHub, nothing saved.
- `setup-success` real credentials: `saved profile "<p>" (installation N)`, profile listed, vault holds no plaintext key.
- `setup-installation-lookup` without `--installation-id`: auto-picks a single installation, otherwise lists them.

## How to get to it (user POV)

- `gain [--profile NAME] setup --client-id ID [--installation-id ID] --private-key-path FILE`

## Driving it with drive.sh

Preconditions:

- Agent unlocked with a new vault (agent-lifecycle `New vault` step).
- For `setup-success`: a real App Client ID, installation and PEM supplied by the user, copied into `$RUN`. Without them, report `setup-success` and `setup-installation-lookup` as not verified.

- **Test key.** `$D cmd $RUN 'openssl genrsa -out "$HOME/app.pem" 2048 2>/dev/null'`.
- **Failing setup.** `$D cmd $RUN './gain.ts setup --client-id Iv23liVERIFYFAKE00000 --installation-id 1 --private-key-path "$HOME/app.pem"'` → `gain: token request failed: 401 ...`, `[exit=1]`.
- **Nothing saved.** `$D cmd $RUN './gain.ts profile list'` → no output, `[exit=0]`.
- **No plaintext.** `$D cmd $RUN 'grep -c "PRIVATE KEY" ~/.local/share/gain/vault'` → `0`.
- **Proof.** `$D snap $RUN setup`.

## Gotchas

- Use a real RSA key even for the failure path: a garbage PEM throws locally in JWT signing and never reaches GitHub, which proves nothing about verify-before-save.
- An unknown `Iv23li...` client ID returns 401 `'Issuer' claim ('iss') must be an Integer`; that is GitHub's wording for "no such App", not a gain bug.
- The failing path still calls api.github.com; offline it fails with a fetch error instead of 401.
