#!/usr/bin/env bash
# gotproxy basic proxy integration test (TCP + UDP)
# Usage: sudo ./scripts/test_proxy.sh
# Requires: built gotproxy, curl; root (CAP_BPF). UDP test needs dig or nc.

set -e

# Infer repo root and gotproxy path from script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GOTPROXY_BIN="${GOTPROXY_BIN:-$REPO_ROOT/gotproxy}"
PROXY_PORT="${PROXY_PORT:-18001}"
LOG_FILE=""
GOTPROXY_PID=""

# Test URL: use IP directly to avoid DNS
TEST_URL="${TEST_URL:-https://1.1.1.1}"
# IP used to verify Original destination in proxy log
EXAMPLE_IP="${EXAMPLE_IP:-1.1.1.1}"
# URL for "other IP" (not matched by --ip filter) in combined IP+cmd test
TEST_OTHER_IP_URL="${TEST_OTHER_IP_URL:-https://8.8.8.8}"
OTHER_IP="${OTHER_IP:-8.8.8.8}"

PASSED=0
FAILED=0

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; ((PASSED++)) || true; }
fail()  { echo "[FAIL]  $*"; ((FAILED++)) || true; }
abort() { echo "[ABORT] $*"; stop_gotproxy 2>/dev/null; exit 1; }

# Start gotproxy; optional args appended (e.g. --cmd "curl")
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

# Count "Original destination" lines in log
count_original_dest() {
  [[ -z "$LOG_FILE" || ! -f "$LOG_FILE" ]] && echo 0 && return
  local c
  c=$(grep -c "Original destination:" "$LOG_FILE" 2>/dev/null)
  echo "${c:-0}"
}

# Check if log contains given destination (e.g. 1.1.1.1:443)
log_contains_dest() {
  local pattern="$1"
  [[ -z "$LOG_FILE" || ! -f "$LOG_FILE" ]] && return 1
  grep -q "Original destination:.*$pattern" "$LOG_FILE" 2>/dev/null
}

# Check if log contains UDP original destination (e.g. 1.1.1.1:53)
# UDP proxy may log "UDP Original destination: ..." or same format as TCP
log_contains_udp_dest() {
  local pattern="$1"
  [[ -z "$LOG_FILE" || ! -f "$LOG_FILE" ]] && return 1
  grep -qE "(UDP.*Original destination:|Original destination:).*$pattern" "$LOG_FILE" 2>/dev/null
}

# Environment checks
check_env() {
  if [[ "$(id -u)" -ne 0 ]]; then
    abort "Please run as root: sudo $0"
  fi
  if [[ ! -x "$GOTPROXY_BIN" ]]; then
    abort "gotproxy not found or not executable: $GOTPROXY_BIN. Run make build-bpf && make first."
  fi
  if ! command -v curl &>/dev/null; then
    abort "curl not found. Please install curl."
  fi
  info "Using gotproxy=$GOTPROXY_BIN, port=$PROXY_PORT"
}

# --- Basic proxy (global transparent forwarding) ---
test_basic_proxy() {
  info "Test: basic proxy (global)"
  start_gotproxy
  local code
  code=$(curl -sS -4 -o /dev/null -w "%{http_code}" --connect-timeout 10 "$TEST_URL" || echo "000")
  # 200 OK; 301/302 are common redirects (e.g. to HTTPS when using IP), still count as success
  if [[ "$code" != "200" && "$code" != "301" && "$code" != "302" ]]; then
    fail "Basic proxy: curl returned HTTP $code, expected 200/301/302"
  else
    if log_contains_dest "$EXAMPLE_IP"; then
      info "log_contains_dest \"$EXAMPLE_IP\" => true"
      ok "Basic proxy: request succeeded and was forwarded (Original destination contains $EXAMPLE_IP)"
    else
      info "log_contains_dest \"$EXAMPLE_IP\" => false"
      fail "Basic proxy: Original destination ... $EXAMPLE_IP not found in log"
    fi
  fi
  stop_gotproxy
}

# --- Process-name filter (--cmd): only matching comm is proxied ---
test_cmd_filter() {
  info "Test: process-name filter (--cmd curl)"
  start_gotproxy --cmd "curl"
  local n0 n1 n2
  n0=$(count_original_dest)
  curl -sS -4 -o /dev/null -w "" --connect-timeout 10 "$TEST_URL" || true
  n1=$(count_original_dest)
  if ! command -v wget &>/dev/null; then
    # Without wget we only check that curl was proxied
    if [[ "$n1" -gt "$n0" ]] && log_contains_dest "$EXAMPLE_IP"; then
      ok "Process-name filter: curl was proxied (wget not installed, skipped non-proxied check)"
    else
      fail "Process-name filter: expected curl to be proxied (n0=$n0 n1=$n1)"
    fi
    stop_gotproxy
    return
  fi
  # wget has different comm, should not be proxied
  wget -q -O /dev/null --timeout=10 "$TEST_URL" 2>/dev/null || true
  n2=$(count_original_dest)
  # Must check log and optionally save content BEFORE stop_gotproxy (it clears LOG_FILE and deletes the file)
  local has_dest=0
  log_contains_dest "$EXAMPLE_IP" && has_dest=1
  local log_snapshot=""
  [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && log_snapshot=$(cat "$LOG_FILE")
  stop_gotproxy
  if [[ "$n1" -gt "$n0" ]] && [[ "$n2" -eq "$n1" ]] && [[ "$has_dest" -eq 1 ]]; then
    ok "Process-name filter: only curl proxied, wget went direct (n0=$n0 n1=$n1 n2=$n2)"
  else
    fail "Process-name filter: expected only curl proxied (n0=$n0 n1=$n1 n2=$n2)"
    [[ -n "$log_snapshot" ]] && { info "log file content:"; echo "$log_snapshot"; }
  fi
}

# --- PID filter (--pids): only connections from given PIDs are proxied ---
test_pids_filter() {
  info "Test: PID filter (--pids)"
  local pid_file
  pid_file=$(mktemp)
  trap "rm -f $pid_file" RETURN
  # Subshell: write its PID, sleep so we can start gotproxy with that PID, then exec curl (same PID makes the connection)
  ( echo $BASHPID > "$pid_file"; sleep 4; exec curl -sS -4 -o /dev/null -w "" --connect-timeout 15 "$TEST_URL" ) &
  local helper_pid=$!
  # Wait for PID file to be written
  local i=0
  while [[ ! -s "$pid_file" ]] && [[ $i -lt 50 ]]; do sleep 0.2; i=$((i+1)); done
  local proxied_pid
  proxied_pid=$(cat "$pid_file" 2>/dev/null)
  if [[ -z "$proxied_pid" ]]; then
    kill $helper_pid 2>/dev/null || true
    wait $helper_pid 2>/dev/null || true
    fail "PID filter: could not get helper process PID"
    return
  fi
  start_gotproxy --pids "$proxied_pid"
  # Wait for helper to run curl (after 4s) and exit
  wait $helper_pid 2>/dev/null || true
  local n1 n2
  n1=$(count_original_dest)
  # This curl runs in main script (different PID), should NOT be proxied
  curl -sS -4 -o /dev/null -w "" --connect-timeout 10 "$TEST_URL" || true
  n2=$(count_original_dest)
  local has_dest=0
  log_contains_dest "$EXAMPLE_IP" && has_dest=1
  local log_snapshot=""
  [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && log_snapshot=$(cat "$LOG_FILE")
  stop_gotproxy
  # n1 should be 1 (helper's curl proxied), n2 should still be 1 (main's curl direct)
  if [[ "$n1" -eq 1 ]] && [[ "$n2" -eq 1 ]] && [[ "$has_dest" -eq 1 ]]; then
    ok "PID filter: only process $proxied_pid was proxied, main script curl went direct"
  else
    fail "PID filter: expected one proxied connection (n1=$n1 n2=$n2)"
    [[ -n "$log_snapshot" ]] && { info "log file content:"; echo "$log_snapshot"; }
  fi
}

# --- UDP proxy (basic): DNS over UDP is redirected and forwarded ---
# Uses DNS (UDP 1.1.1.1:53) as test traffic. Passes when proxy logs UDP original destination.
test_udp_basic_proxy() {
  if ! command -v dig &>/dev/null; then
    info "Test: UDP basic proxy — skipped (dig not installed)"
    return
  fi
  info "Test: UDP basic proxy (DNS to ${EXAMPLE_IP}:53)"
  start_gotproxy
  # DNS query over UDP; dig sends to EXAMPLE_IP:53
  dig +short +time=5 +tries=1 @"$EXAMPLE_IP" example.com &>/dev/null || true
  if log_contains_udp_dest "${EXAMPLE_IP}:53"; then
    ok "UDP proxy: DNS request was forwarded (log shows ${EXAMPLE_IP}:53)"
  else
    # UDP proxy not implemented yet: no UDP log line
    fail "UDP proxy: no UDP original destination for ${EXAMPLE_IP}:53 in log (UDP support may not be implemented yet)"
  fi
  stop_gotproxy
}

# --- Combined IP + process-name filter (--ip + --cmd): only when both match ---
test_ip_cmd_filter() {
  info "Test: combined IP + process-name filter (--ip $EXAMPLE_IP/32 --cmd curl)"
  start_gotproxy --ip "${EXAMPLE_IP}/32" --cmd "curl"
  local n0 n1 n2 n3
  n0=$(count_original_dest)
  # curl to EXAMPLE_IP: matches both --ip and --cmd -> proxied
  curl -sS -4 -o /dev/null -w "" --connect-timeout 10 "$TEST_URL" || true
  n1=$(count_original_dest)
  # curl to other IP: matches --cmd but not --ip -> not proxied
  curl -sS -4 -o /dev/null -w "" --connect-timeout 10 "$TEST_OTHER_IP_URL" || true
  n2=$(count_original_dest)
  if command -v wget &>/dev/null; then
    # wget to EXAMPLE_IP: matches --ip but not --cmd -> not proxied
    wget -q -O /dev/null --timeout=10 "$TEST_URL" 2>/dev/null || true
    n3=$(count_original_dest)
  else
    n3=$n2
  fi
  local has_dest=0
  log_contains_dest "$EXAMPLE_IP" && has_dest=1
  local no_other_ip=1
  log_contains_dest "$OTHER_IP" && no_other_ip=0
  local log_snapshot=""
  [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && log_snapshot=$(cat "$LOG_FILE")
  stop_gotproxy
  # Exactly one proxied connection (curl to EXAMPLE_IP); curl to OTHER_IP and wget to EXAMPLE_IP must not be proxied
  if [[ "$n1" -eq 1 ]] && [[ "$n2" -eq 1 ]] && [[ "$n3" -eq 1 ]] && [[ "$has_dest" -eq 1 ]] && [[ "$no_other_ip" -eq 1 ]]; then
    ok "IP+cmd filter: only curl to $EXAMPLE_IP was proxied; curl to $OTHER_IP and wget went direct"
  else
    fail "IP+cmd filter: expected exactly one proxied connection (n1=$n1 n2=$n2 n3=$n3, has_dest=$has_dest, other_ip_in_log=$no_other_ip)"
    [[ -n "$log_snapshot" ]] && { info "log file content:"; echo "$log_snapshot"; }
  fi
}

# --- Main ---
main() {
  check_env
  echo "=========================================="
  echo "  gotproxy proxy tests"
  echo "=========================================="
  test_basic_proxy
  test_cmd_filter
  test_pids_filter
  test_ip_cmd_filter
  test_udp_basic_proxy
  echo "=========================================="
  echo "  Passed: $PASSED  Failed: $FAILED"
  echo "=========================================="
  [[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
}

# Cleanup on script kill
trap 'stop_gotproxy; exit 130' INT TERM
main "$@"
