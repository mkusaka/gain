cask "gain" do
  # Source of truth: mkusaka/gain packaging/homebrew/gain.rb. Its release.yml fills in version and
  # sha256 and pushes this file to the tap; edits made in the tap are overwritten.
  version "0.5.0"
  sha256 "dd9ed9662e8d2c4d8c1d6c737bfac28a2f1fb50ad7716276757744d9a724aab3"

  url "https://github.com/mkusaka/gain/releases/download/v#{version}/gain-#{version}-darwin-universal.tar.gz"
  name "gain"
  desc "Run gh with a GitHub App installation token from a passphrase-locked agent"
  homepage "https://github.com/mkusaka/gain"

  depends_on formula: "gh"

  binary "gain"

  # Upgrades leave the agent running (unlocked, on the old binary) instead of stopping it; it
  # switches to the new binary at the next login or `gain agent install`. Zap removes the
  # LaunchAgent. The vault (~/.local/share/gain) is deliberately kept: it is the only copy of the App keys.
  zap launchctl: "com.github.mkusaka.gain.agent",
      trash:     [
        "~/Library/LaunchAgents/com.github.mkusaka.gain.agent.plist",
        "~/Library/Logs/gain-agent.log",
      ]

  caveats <<~EOS
    Start the agent now and at every login, then unlock it once per login:
      gain agent install
      gain agent unlock
    First time: add your GitHub App (https://github.com/mkusaka/gain#setup):
      gain setup --client-id ID --private-key-path FILE
    Upgrades keep the running agent; it moves to the new binary at the next login
    (or run `gain agent install` and unlock again). `gain agent status` shows its version.
    Uninstall with `brew uninstall --zap gain` to also remove the LaunchAgent.
  EOS
end
