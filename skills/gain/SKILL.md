---
name: gain
description: Run GitHub CLI (gh) commands, GitHub REST calls, or git fetch/clone as a GitHub App instead of the user's personal account, using the gain CLI. Use when reading private repositories through the App, when the user asks to use the GitHub App / bot / "gain" / a gain profile, or when personal gh calls hit "API rate limit exceeded" and an App profile is configured.
---

# gain

`gain` wraps `gh`: it issues a GitHub App installation token (cached in the macOS Keychain) and runs `gh` with it in `GH_TOKEN`. Everything after the optional `--profile` is passed to `gh` unchanged.

## Use

```sh
gain pr list -R org/repo                    # any gh subcommand
gain api repos/org/repo/contents/README.md  # REST via gh api
gain --profile work issue view 123 -R org/repo
GH_APP_PROFILE=work gain pr view 45 -R org/repo
gain token                                  # raw token, only for non-gh tools (see below)
```

- Use `gain <gh args>` wherever you would run `gh <gh args>` for the App. Keep plain `gh` for actions that must be done as the user.
- `--profile NAME` must be the very first argument. Without it, `$GH_APP_PROFILE` or `default` is used. Ask the user which profile to use if it isn't clear from context.
- Always pass `-R owner/repo` (or run inside the repo checkout). The token is scoped to the repos where the App is installed.

## Rules

- Never print, log, or paste the token. Don't run bare `gain token` in a way that shows its output; only use it inline, e.g. `curl -H "Authorization: Bearer $(gain token)" ...`. Prefer `gain api ...` over curl.
- Don't run `gain setup` yourself or touch the private key; setup is the user's job. If you see `profile "..." not configured`, tell the user to run `gain [--profile NAME] setup --app-id ID --installation-id ID --private-key-path FILE`.
- Don't change git config. If a git clone/fetch needs the App, point the user to the README's credential helper section.

## Troubleshooting

| Symptom                                        | Cause / action                                                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `profile "x" not configured`                   | Ask the user to run `setup` for that profile.                                                     |
| `token request failed: 401/404`                | Wrong App ID / Installation ID or revoked key. Ask the user to re-run `setup`.                    |
| `gh pr list` returns nothing                   | The App lacks **Issues: read**. Report it; don't assume the repo has no PRs.                      |
| `Resource not accessible by integration` (403) | The App lacks that permission or isn't installed on the repo. Report which permission is missing. |
| New permissions not taking effect              | The cached token predates the change. Ask the user to re-run `setup`.                             |
