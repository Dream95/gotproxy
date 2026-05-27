#!/usr/bin/env bash
# gotproxy --cmd fork/exec child tracking test
# Usage: sudo ./scripts/test_cmd_fork.sh
# Requires: built gotproxy, curl; root (CAP_BPF).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GOTPROXY_BIN="${GOTPROXY_BIN:-$REPO_ROOT/gotproxy}"
PROXY_PORT="${PROXY_PORT:-18002}"
TEST_URL="${TEST_URL:-http://example.com}"

LOG_FILE=""
GOTPROXY_PID=""
PASSED=0
FAILED=0

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; ((PASSED++)) || true; }
fail()  { echo "[FAIL]  $*"; ((FAILED++)) || true; }
abort() { echo "[ABORT] $*"; stop_gotproxy 2>/dev/null; exit 1; }

start_gotproxy() {
  local extra_args=("$@")
  LOG_FILE=$(mktemp)
  "$GOTPROXY_BIN" --p-port "$PROXY_PORT" "${extra_args[@]}" >"$LOG_FILE" 2>&1 &
  GOTPROXY_PID=$!
  for i in {1..30}; do
    if grep -q "listening on" "$LOG_FILE" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  abort "gotproxy did not start in time, see $LOG_FILE"
}

stop_gotproxy() {
  if [[ -n "$GOTPROXY_PID" ]] && kill -0 "$GOTPROXY_PID" 2>/dev/null; then
    kill "$GOTPROXY_PID" 2>/dev/null || true
    wait "$GOTPROXY_PID" 2>/dev/null || true
  fi
  GOTPROXY_PID=""
  [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && rm -f "$LOG_FILE"
  LOG_FILE=""
}

count_original_dest() {
  [[ -z "$LOG_FILE" || ! -f "$LOG_FILE" ]] && echo 0 && return
  local c
  c=$(grep -c "Original destination:" "$LOG_FILE" 2>/dev/null)
  echo "${c:-0}"
}

check_env() {
  if [[ "$(id -u)" -ne 0 ]]; then
    abort "Please run as root: sudo $0"
  fi
  if [[ ! -x "$GOTPROXY_BIN" ]]; then
    abort "gotproxy not found: $GOTPROXY_BIN. Run make build-bpf && make first."
  fi
  if ! command -v curl &>/dev/null; then
    abort "curl not found"
  fi
}

# bash forks; child execs curl — child comm is "curl", parent comm is "bash"
test_bash_exec_curl() {
  info "Test: bash exec curl tracked via --cmd bash"
  start_gotproxy --cmd bash --proto tcp
  local n0 n1
  n0=$(count_original_dest)
  if bash -c "exec curl -s -o /dev/null --max-time 10 $TEST_URL"; then
    n1=$(count_original_dest)
    if [[ "$n1" -gt "$n0" ]]; then
      ok "bash->curl proxied (log $n0 -> $n1)"
    else
      fail "curl succeeded but proxy log unchanged ($n0 -> $n1)"
    fi
  else
    fail "curl via bash exec failed"
  fi
  stop_gotproxy
}

main() {
  check_env
  echo "=========================================="
  echo "  gotproxy --cmd fork tracking tests"
  echo "=========================================="
  test_bash_exec_curl
  echo "=========================================="
  echo "  Passed: $PASSED  Failed: $FAILED"
  echo "=========================================="
  [[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
}

trap 'stop_gotproxy; exit 130' INT TERM
main "$@"
