#!/usr/bin/env bash
# Drive a throwaway gain agent from this checkout inside tmux, with an isolated HOME.
#   drive.sh launch                      -> prints RUN (the fake HOME); starts the agent, waits until it listens
#   drive.sh doctor  RUN                 -> read-only health check of that instance
#   drive.sh cmd     RUN '<cmd>' [REGEX] -> run <cmd> in the run's shell; wait for its exit (or REGEX on screen)
#   drive.sh type    RUN '<text>'        -> type a line at a prompt (passphrases; not echoed, not logged)
#   drive.sh wait    RUN REGEX           -> wait until REGEX shows up in the output of the latest cmd
#   drive.sh snap    RUN NAME            -> save the visible pane to EVIDENCE/NAME.txt
#   drive.sh cleanup RUN                 -> stop the agent, kill the tmux session, delete RUN; evidence stays
# Evidence: ${GAIN_VERIFY_EVIDENCE:-$HOME/.cache/gain-verify}/<run name>/
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
EVROOT=${GAIN_VERIFY_EVIDENCE:-$HOME/.cache/gain-verify}
op=${1:?usage: drive.sh launch|doctor|cmd|type|snap|cleanup RUN ...}

if [[ $op == launch ]]; then
  # Short path on purpose: macOS caps Unix socket paths at 104 bytes.
  RUN=$(mktemp -d /tmp/gain-vfy.XXXXXX)
else
  RUN=${2:?missing RUN (the path printed by launch)}
  [[ $RUN == /tmp/gain-vfy.* ]] || { echo "refusing: $RUN is not a gain-vfy run" >&2; exit 2; }
fi
S=$(basename "$RUN" | tr . -)  # tmux reads "." in a target as a pane separator
EV=$EVROOT/$S
SOCK=$RUN/.local/share/gain/agent.sock
GAIN=$REPO/target/debug/gain
gain() { HOME=$RUN "$GAIN" "$@"; }

since_last_cmd() { # screen text from the latest `cmd` line on, so old output can't satisfy a wait
  local n; n=$(cat "$RUN/.n" 2>/dev/null || echo 0)
  tmux capture-pane -p -t "$S:sh" -S -3000 | awk -v m="#$n\"" 'index($0, m) { buf = ""; next } { buf = buf $0 "\n" } END { printf "%s", buf }'
}

wait_for() { # wait_for REGEX [seconds]
  for _ in $(seq $((${2:-20} * 5))); do
    since_last_cmd | grep -Eq -- "$1" && return 0
    sleep 0.2
  done
  echo "timeout waiting for /$1/; output since the last cmd:" >&2
  since_last_cmd >&2
  return 1
}

case $op in
launch)
  mkdir -p "$EV"
  # The agent refuses a binary without the hardened runtime; cargo's output is only linker-signed.
  (cd "$REPO" && cargo build -q) && codesign -s - -f -o runtime "$GAIN" 2>/dev/null
  tmux new-session -d -s "$S" -n agent -x 200 -y 50 -c "$REPO" -e HOME="$RUN" -e PATH="$PATH" \
    "exec '$GAIN' agent start 2>>'$EV/agent.log'"
  # Empty GH_APP_PROFILE: a value left in the tmux server env would change the "default" profile.
  # This checkout's gain first on PATH, so `gain ...` in the shell never reaches an installed one.
  # (set by env in the command: a PATH passed with tmux -e did not reach the window's shell)
  tmux new-window -d -t "$S" -n sh -c "$REPO" -e HOME="$RUN" -e GH_APP_PROFILE= \
    "exec env PATH='$REPO/target/debug:$PATH' PS1='gain-vfy\$ ' BASH_SILENCE_DEPRECATION_WARNING=1 bash --noprofile --norc"
  tmux pipe-pane -t "$S:sh" -o "cat >> '$EV/transcript.log'"
  for _ in $(seq 100); do grep -q 'agent listening on' "$EV/agent.log" 2>/dev/null && break; sleep 0.2; done
  grep -q 'agent listening on' "$EV/agent.log" || { cat "$EV/agent.log" >&2; exit 1; }
  echo "$RUN"
  ;;
doctor)
  echo "run:       $RUN (tmux session $S)"
  echo "evidence:  $EV"
  echo "checkout:  $REPO @ $(git -C "$REPO" rev-parse --short HEAD)$(git -C "$REPO" diff --quiet || echo ' (dirty)')"
  tmux has-session -t "$S" 2>/dev/null && echo "tmux:      up" || echo "tmux:      MISSING"
  pid=$(lsof -t "$SOCK" 2>/dev/null | head -1 || true)
  if [[ -n $pid ]]; then echo "listener:  pid $pid $(ps -o command= -p "$pid")"; else echo "listener:  NONE on $SOCK"; fi
  echo -n "status:    "; gain agent status 2>&1 || true
  ;;
cmd)
  n=$(($(cat "$RUN/.n" 2>/dev/null || echo 0) + 1)); echo "$n" >"$RUN/.n"
  tmux send-keys -t "$S:sh" -l -- "$3; echo \"[exit=\$?] #$n\""
  tmux send-keys -t "$S:sh" Enter
  wait_for "${4:-\[exit=[0-9]+\] #$n\$}"
  ;;
type)
  tmux send-keys -t "$S:sh" -l -- "$3"
  tmux send-keys -t "$S:sh" Enter
  ;;
wait)
  wait_for "${3:?REGEX}"
  ;;
snap)
  mkdir -p "$EV"; tmux capture-pane -p -t "$S:sh" -S -3000 >"$EV/${3:?NAME}.txt"; echo "$EV/$3.txt"
  ;;
cleanup)
  gain agent stop 2>/dev/null || true
  # Only ever kill the listener on this run's socket, never by process name.
  pid=$(lsof -t "$SOCK" 2>/dev/null | head -1 || true); [[ -n $pid ]] && kill "$pid" || true
  tmux kill-session -t "$S" 2>/dev/null || true
  rm -rf "$RUN"
  echo "cleaned $RUN; evidence kept in $EV"
  ;;
*) echo "unknown op: $op" >&2; exit 2 ;;
esac
