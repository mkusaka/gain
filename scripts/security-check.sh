#!/usr/bin/env bash
# Prove that a built gain binary keeps the protections README "Why Rust" relies on:
#   1. hardened runtime, no entitlements at all
#   2. a running agent refuses a debugger (lldb, same user)
#   3. DYLD_INSERT_LIBRARIES is ignored
#   4. the agent refuses to start from a binary without the hardened runtime
#   5. its data directory is user-only and the vault holds no plaintext
# 2 and 3 first run against an unprotected control program that must be readable/injectable,
# so a runner that blocks debuggers or injection for everything can't pass by accident.
# Usage: scripts/security-check.sh path/to/gain   (CI: every build; release.yml: the signed binary)
set -euo pipefail
GAIN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
T=$(mktemp -d /tmp/gain-sec.XXXXXX) # short: macOS caps Unix socket paths at 104 bytes
AGENT=
trap '[[ -n $AGENT ]] && kill "$AGENT" 2>/dev/null; rm -rf "$T"' EXIT
fail() {
  echo "FAIL: $*" >&2
  exit 1
}
ok() { echo "ok: $*"; }

# 1. Signature.
codesign -dv --entitlements - "$GAIN" >"$T/sig" 2>&1
grep -Eq 'flags=0x[0-9a-f]+\([^)]*runtime' "$T/sig" || fail "no hardened runtime: $(cat "$T/sig")"
if grep -q 'com.apple.security' "$T/sig"; then fail "unexpected entitlements: $(cat "$T/sig")"; fi
ok "hardened runtime, no entitlements"

# Controls: ad-hoc linker-signed like any unprotected native binary (ghtkn's release, a plain cargo build).
cat >"$T/control.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static char secret[32];
int main(int argc, char **argv) {
  if (argc > 1) return 0;
  strcpy(secret, "CONTROL-SECRET");
  printf("%p\n", (void *)secret);
  fflush(stdout);
  pause();
}
EOF
cat >"$T/probe.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) static void probe(void) {
  FILE *f = fopen(getenv("PROBE_OUT"), "w");
  if (f) fclose(f);
}
EOF
cc -o "$T/control" "$T/control.c"
cc -dynamiclib -o "$T/probe.dylib" "$T/probe.c"

# 2. Debugger.
"$T/control" >"$T/addr" &
CONTROL=$!
for _ in $(seq 50); do [[ -s $T/addr ]] && break; sleep 0.1; done
lldb --batch -p "$CONTROL" -o "memory read -f s $(cat "$T/addr")" >"$T/lldb-control" 2>&1 || true
kill "$CONTROL" 2>/dev/null || true
grep -q CONTROL-SECRET "$T/lldb-control" || fail "control: lldb could not read an unprotected process, so this check proves nothing: $(cat "$T/lldb-control")"
ok "control: lldb reads an unprotected process"

mkdir -p "$T/home"
HOME=$T/home "$GAIN" agent start 2>"$T/agent.log" &
AGENT=$!
SOCK=$T/home/.local/share/gain/agent.sock
for _ in $(seq 50); do [[ -S $SOCK ]] && break; sleep 0.1; done
[[ -S $SOCK ]] || fail "agent did not start: $(cat "$T/agent.log")"
# Unlocked, so it holds the vault key (no tty here: talk to the socket directly).
printf '{"cmd":"unlock","passphrase":"security-check-pass"}\n' | nc -U "$SOCK" | grep -q '"ok":true' || fail "unlock"
lldb --batch -p "$AGENT" -o "process status" >"$T/lldb-gain" 2>&1 || true
grep -q 'attach failed' "$T/lldb-gain" || fail "lldb attached to the agent: $(cat "$T/lldb-gain")"
kill -0 "$AGENT" || fail "agent died"
ok "lldb cannot attach to the agent"

# 3. Library injection.
DYLD_INSERT_LIBRARIES=$T/probe.dylib PROBE_OUT=$T/injected-control "$T/control" quit
[[ -e $T/injected-control ]] || fail "control: DYLD_INSERT_LIBRARIES had no effect, so this check proves nothing"
ok "control: DYLD_INSERT_LIBRARIES injects into an unprotected process"
HOME=$T/home DYLD_INSERT_LIBRARIES=$T/probe.dylib PROBE_OUT=$T/injected-gain "$GAIN" agent status >/dev/null 2>&1
[[ ! -e $T/injected-gain ]] || fail "DYLD_INSERT_LIBRARIES injected code into gain"
ok "DYLD_INSERT_LIBRARIES is ignored"

# 4. Self-check: the same binary without the hardened runtime must not run the agent.
cp "$GAIN" "$T/unhardened"
codesign -s - -f "$T/unhardened" 2>/dev/null
mkdir -p "$T/home2"
if HOME=$T/home2 "$T/unhardened" agent start >"$T/unhardened.log" 2>&1; then fail "the agent ran without the hardened runtime"; fi
grep -q 'allows debugger attach' "$T/unhardened.log" || fail "unexpected: $(cat "$T/unhardened.log")"
ok "the agent refuses to run without the hardened runtime"

# 5. Files at rest.
[[ $(stat -f %Lp "$T/home/.local/share/gain") == 700 ]] || fail "data dir is not 0700"
[[ $(stat -f %Lp "$T/home/.local/share/gain/vault") == 600 ]] || fail "vault is not 0600"
grep -Eqx '\{("(salt|data)":"[A-Za-z0-9+/=]+",?){2}\}' "$T/home/.local/share/gain/vault" || fail "vault is not sealed"
ok "data dir 0700, vault 0600 and encrypted"
