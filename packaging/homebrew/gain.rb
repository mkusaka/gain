class Gain < Formula
  desc "Run gh with a GitHub App installation token from a passphrase-locked agent"
  homepage "https://github.com/mkusaka/gain"
  version "__VERSION__"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "__DARWIN_ARM64_URL__"
      sha256 "__DARWIN_ARM64_SHA256__"
    else
      url "__DARWIN_X64_URL__"
      sha256 "__DARWIN_X64_SHA256__"
    end
  end

  depends_on "gh"

  def install
    bin.install "gain"
    (pkgshare/"skills").install Dir["skills/*"]
  end

  def caveats
    <<~EOS
      Start the agent now and at every login, then unlock it once per login:
        gain agent install
        gain agent unlock
      After `brew upgrade gain`, run `gain agent install` again so the agent runs the new binary.
    EOS
  end

  test do
    assert_match "not running", shell_output("#{bin}/gain agent status 2>&1", 1)
  end
end
