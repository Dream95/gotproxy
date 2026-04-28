#!/usr/bin/env bash
# gotproxy git proxy integration test (HTTPS over TCP)
# Usage: sudo ./scripts/test_git.sh
# Requires: built gotproxy, git; root (CAP_BPF).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GOTPROXY_BIN="${GOTPROXY_BIN:-$REPO_ROOT/gotproxy}"
PROXY_PORT="${PROXY_PORT:-18001}"

# Pick a public repo that supports anonymous HTTPS.
TEST_REMOTE_URL="${TEST_REMOTE_URL:-https://github.com/Dream95/gotproxy}"

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
    abort "gotproxy not found or not executable: $GOTPROXY_BIN. Run make build-bpf && make first."
  fi
  if ! command -v git &>/dev/null; then
    abort "git not found. Please install git."
  fi
  info "Using gotproxy=$GOTPROXY_BIN, port=$PROXY_PORT"
  info "Using TEST_REMOTE_URL=$TEST_REMOTE_URL"
}

git_env() {
  # Avoid any interactive prompts
  export GIT_TERMINAL_PROMPT=0
  export GIT_ASKPASS=true
}

test_git_ls_remote_proxied() {
  info "Test: git ls-remote via gotproxy (--cmd git)"
  start_gotproxy 
  local n0 n1
  n0=$(count_original_dest)

  git_env
  if git ls-remote --heads --tags "$TEST_REMOTE_URL" &>/dev/null; then
    n1=$(count_original_dest)
    if [[ "$n1" -gt "$n0" ]]; then
      ok "git ls-remote succeeded and traffic appears proxied (log increased: $n0 -> $n1)"
    else
      fail "git ls-remote succeeded but proxy log did not show forwarding (log: $n0 -> $n1)"
    fi
  else
    local log_snapshot=""
    [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && log_snapshot=$(cat "$LOG_FILE")
    stop_gotproxy
    fail "git ls-remote failed (see gotproxy log below)"
    [[ -n "$log_snapshot" ]] && { info "gotproxy log:"; echo "$log_snapshot"; }
    return
  fi

  stop_gotproxy
}

test_git_clone_proxied() {
  info "Test: git clone --depth 1 via gotproxy (--cmd git)"
  start_gotproxy 
  local n0 n1
  n0=$(count_original_dest)

  git_env
  local tmp_dir repo_dir
  tmp_dir=$(mktemp -d)
  repo_dir="$tmp_dir/repo"
  # Ensure cleanup
  trap 'rm -rf "$tmp_dir"' RETURN

  if git clone --depth 1 "$TEST_REMOTE_URL" "$repo_dir" &>/dev/null; then
    n1=$(count_original_dest)
    if [[ -d "$repo_dir/.git" ]] && [[ "$n1" -gt "$n0" ]]; then
      ok "git clone succeeded and traffic appears proxied (log increased: $n0 -> $n1)"
    elif [[ -d "$repo_dir/.git" ]]; then
      fail "git clone succeeded but proxy log did not show forwarding (log: $n0 -> $n1)"
    else
      fail "git clone reported success but repo dir looks wrong: $repo_dir"
    fi
  else
    local log_snapshot=""
    [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && log_snapshot=$(cat "$LOG_FILE")
    stop_gotproxy
    fail "git clone failed (see gotproxy log below)"
    [[ -n "$log_snapshot" ]] && { info "gotproxy log:"; echo "$log_snapshot"; }
    return
  fi

  stop_gotproxy
}

main() {
  check_env
  echo "=========================================="
  echo "  gotproxy git tests"
  echo "=========================================="
  test_git_ls_remote_proxied
  test_git_clone_proxied
  echo "=========================================="
  echo "  Passed: $PASSED  Failed: $FAILED"
  echo "=========================================="
  [[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
}

trap 'stop_gotproxy; exit 130' INT TERM
main "$@"
