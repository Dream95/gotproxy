#!/usr/bin/env bash
# gotproxy ConnMeta integration test (pid / cmd / flags / dst)
# Usage: sudo ./scripts/test_conn_meta.sh
# Requires: built gotproxy, curl; root (CAP_BPF). UDP case needs dig (optional).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GOTPROXY_BIN="${GOTPROXY_BIN:-$REPO_ROOT/gotproxy}"
PROXY_PORT="${PROXY_PORT:-18003}"
LOG_FILE=""
GOTPROXY_PID=""

TEST_HOST="${TEST_HOST:-one.one.one.one}"
EXAMPLE_IP="${EXAMPLE_IP:-1.1.1.1}"
TEST_URL="${TEST_URL:-https://${TEST_HOST}/}"

# Keep in sync with enum match_flags / Match* in proxy.c / conn_meta.go
MATCH_CMD=$((1 << 0))
MATCH_PID=$((1 << 1))
MATCH_PGID=$((1 << 2))
MATCH_CONTAINER=$((1 << 3))
MATCH_TRACKED=$((1 << 4))

PASSED=0
FAILED=0

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; ((PASSED++)) || true; }
fail()  { echo "[FAIL]  $*"; ((FAILED++)) || true; }
abort() {
  echo "[ABORT] $*"
  if [[ -n "${LOG_FILE:-}" && -f "$LOG_FILE" ]]; then
    echo "[ABORT] gotproxy log:"
    cat "$LOG_FILE"
  fi
  stop_gotproxy 2>/dev/null
  exit 1
}

start_gotproxy() {
  local extra_args=("$@")
  LOG_FILE=$(mktemp)
  "$GOTPROXY_BIN" --p-port "$PROXY_PORT" "${extra_args[@]}" >"$LOG_FILE" 2>&1 &
  GOTPROXY_PID=$!
  for _ in {1..30}; do
    if grep -q "listening on" "$LOG_FILE" 2>/dev/null; then
      # StartProxy logs before cgroup attach + MapConfig update; give BPF a moment.
      sleep 1
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

# Extract the first TCP/UDP meta={...} line that mentions $dst_hint (optional).
# Prints the full meta={...} blob.
find_meta_blob() {
  local proto="$1"   # tcp|udp
  local dst_hint="${2:-}"
  [[ -z "$LOG_FILE" || ! -f "$LOG_FILE" ]] && return 1

  local pattern
  if [[ "$proto" == "udp" ]]; then
    pattern='UDP Original destination:.*meta=\{[^}]+\}'
  else
    pattern='Original destination:.*meta=\{[^}]+\}'
  fi

  local line
  line=$(grep -E "$pattern" "$LOG_FILE" 2>/dev/null | head -n1) || true
  if [[ -n "$dst_hint" ]]; then
    line=$(grep -E "$pattern" "$LOG_FILE" 2>/dev/null | grep -F "$dst_hint" | head -n1) || true
  fi
  [[ -z "$line" ]] && return 1
  echo "$line" | grep -oE 'meta=\{[^}]+\}'
}

parse_meta_field() {
  local blob="$1"
  local key="$2"
  case "$key" in
    comm)
      echo "$blob" | sed -n 's/.*comm="\([^"]*\)".*/\1/p'
      ;;
    flags)
      echo "$blob" | sed -n 's/.*flags=\(0x[0-9a-fA-F]*\).*/\1/p'
      ;;
    dst)
      echo "$blob" | sed -n 's/.*dst=\([^ }]*\).*/\1/p'
      ;;
    pid)
      # Prefer leading meta={pid=} — avoid matching ns(pid=...).
      echo "$blob" | sed -n 's/^meta={pid=\([0-9][0-9]*\).*/\1/p'
      ;;
    *)
      echo "$blob" | sed -n "s/.*${key}=\([0-9][0-9]*\).*/\1/p"
      ;;
  esac
}

flags_has() {
  local flags_hex="$1"
  local bit="$2"
  local flags=$((flags_hex))
  [[ $((flags & bit)) -ne 0 ]]
}

# Run curl under a known PID (same PID after exec).
# Writes PID to $1, sleeps so caller can start gotproxy + settle BPF, then exec curl.
# Sets global _HELPER_PID (do not capture via $() — that ties curl stdout to a pipe and SIGPIPEs it).
run_curl_with_known_pid() {
  local pid_file="$1"
  local delay_secs="${2:-5}"
  (
    echo "$BASHPID" >"$pid_file"
    sleep "$delay_secs"
    exec curl -sS -4 -o /dev/null -w "" --connect-timeout 15 \
      --resolve "${TEST_HOST}:443:${EXAMPLE_IP}" \
      "$TEST_URL"
  ) >/dev/null 2>&1 &
  _HELPER_PID=$!
}

# True if ConnMeta pid (TID) or tgid (TGID) equals the expected process id.
meta_pid_matches() {
  local blob="$1"
  local expect_pid="$2"
  local pid tgid
  pid=$(parse_meta_field "$blob" pid)
  tgid=$(parse_meta_field "$blob" tgid)
  [[ "$pid" == "$expect_pid" || "$tgid" == "$expect_pid" ]]
}

assert_meta() {
  local label="$1"
  local blob="$2"
  local expect_pid="$3"
  local expect_comm="$4"
  local expect_flag_bit="$5"
  local expect_dst_substr="$6"

  local pid tgid comm flags dst
  pid=$(parse_meta_field "$blob" pid)
  tgid=$(parse_meta_field "$blob" tgid)
  comm=$(parse_meta_field "$blob" comm)
  flags=$(parse_meta_field "$blob" flags)
  dst=$(parse_meta_field "$blob" dst)

  info "$label meta: pid=$pid tgid=$tgid comm=$comm flags=$flags dst=$dst"

  local bad=0
  if [[ -n "$expect_pid" ]] && ! meta_pid_matches "$blob" "$expect_pid"; then
    fail "$label: expected pid or tgid=$expect_pid, got pid=$pid tgid=$tgid"
    bad=1
  fi
  if [[ -n "$expect_comm" && "$comm" != "$expect_comm" ]]; then
    fail "$label: expected comm=$expect_comm, got comm=$comm"
    bad=1
  fi
  if [[ -n "$expect_flag_bit" ]]; then
    if [[ -z "$flags" ]] || ! flags_has "$flags" "$expect_flag_bit"; then
      fail "$label: expected flags to include bit $expect_flag_bit, got flags=$flags"
      bad=1
    fi
  fi
  if [[ -n "$expect_dst_substr" && "$dst" != *"$expect_dst_substr"* ]]; then
    fail "$label: expected dst to contain $expect_dst_substr, got dst=$dst"
    bad=1
  fi
  if [[ -z "$tgid" || "$tgid" == "0" ]]; then
    fail "$label: tgid missing or zero"
    bad=1
  fi

  if [[ "$bad" -eq 0 ]]; then
    ok "$label: ConnMeta pid/comm/flags/dst look correct"
  fi
}

# --- TCP: --cmd curl should report curl's pid/comm and MATCH_CMD ---
test_tcp_cmd_meta() {
  info "Test: TCP ConnMeta with --cmd curl"
  # Start proxy first so BPF is ready before traffic (avoids race with helper sleep).
  start_gotproxy --cmd "curl"

  local pid_file helper_pid expect_pid
  pid_file=$(mktemp)
  (
    echo "$BASHPID" >"$pid_file"
    exec curl -sS -4 -o /dev/null -w "" --connect-timeout 15 \
      --resolve "${TEST_HOST}:443:${EXAMPLE_IP}" \
      "$TEST_URL"
  ) &
  helper_pid=$!
  wait "$helper_pid" 2>/dev/null || true
  expect_pid=$(cat "$pid_file" 2>/dev/null || true)

  local blob log_snapshot=""
  blob=$(find_meta_blob tcp "$EXAMPLE_IP") || true
  [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && log_snapshot=$(cat "$LOG_FILE")
  stop_gotproxy
  rm -f "$pid_file"

  if [[ -z "$expect_pid" ]]; then
    fail "TCP --cmd meta: could not get curl PID"
    return
  fi
  if [[ -z "$blob" ]]; then
    fail "TCP --cmd meta: no meta={...} line with $EXAMPLE_IP in log"
    [[ -n "$log_snapshot" ]] && { info "log:"; echo "$log_snapshot"; }
    return
  fi
  assert_meta "TCP --cmd" "$blob" "$expect_pid" "curl" "$MATCH_CMD" "$EXAMPLE_IP"
}

# --- TCP: --pids should report that pid and MATCH_PID ---
test_tcp_pid_meta() {
  info "Test: TCP ConnMeta with --pids"
  local pid_file helper_pid expect_pid
  pid_file=$(mktemp)
  # Need PID before starting gotproxy; delay must cover start + BPF settle.
  run_curl_with_known_pid "$pid_file" 5
  helper_pid="$_HELPER_PID"
  local i=0
  while [[ ! -s "$pid_file" ]] && [[ $i -lt 50 ]]; do sleep 0.2; i=$((i + 1)); done
  expect_pid=$(cat "$pid_file" 2>/dev/null || true)
  if [[ -z "$expect_pid" ]]; then
    kill "$helper_pid" 2>/dev/null || true
    wait "$helper_pid" 2>/dev/null || true
    rm -f "$pid_file"
    fail "TCP --pids meta: could not get curl helper PID"
    return
  fi

  start_gotproxy --pids "$expect_pid"
  wait "$helper_pid" 2>/dev/null || true

  local blob log_snapshot=""
  blob=$(find_meta_blob tcp "$EXAMPLE_IP") || true
  [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && log_snapshot=$(cat "$LOG_FILE")
  stop_gotproxy
  rm -f "$pid_file"

  if [[ -z "$blob" ]]; then
    fail "TCP --pids meta: no meta={...} line with $EXAMPLE_IP in log"
    [[ -n "$log_snapshot" ]] && { info "log:"; echo "$log_snapshot"; }
    return
  fi

  local flags pid tgid comm dst
  flags=$(parse_meta_field "$blob" flags)
  pid=$(parse_meta_field "$blob" pid)
  tgid=$(parse_meta_field "$blob" tgid)
  comm=$(parse_meta_field "$blob" comm)
  dst=$(parse_meta_field "$blob" dst)
  info "TCP --pids meta: pid=$pid tgid=$tgid comm=$comm flags=$flags dst=$dst"

  local bad=0
  if ! meta_pid_matches "$blob" "$expect_pid"; then
    fail "TCP --pids: expected pid or tgid=$expect_pid, got pid=$pid tgid=$tgid"
    bad=1
  fi
  if [[ "$comm" != "curl" ]]; then
    fail "TCP --pids: expected comm=curl, got comm=$comm"
    bad=1
  fi
  if ! flags_has "$flags" "$MATCH_PID" && ! flags_has "$flags" "$MATCH_PGID"; then
    fail "TCP --pids: expected MATCH_PID or MATCH_PGID in flags=$flags"
    bad=1
  fi
  if [[ "$dst" != *"$EXAMPLE_IP"* ]]; then
    fail "TCP --pids: expected dst to contain $EXAMPLE_IP, got dst=$dst"
    bad=1
  fi
  if [[ "$bad" -eq 0 ]]; then
    ok "TCP --pids: ConnMeta pid/comm/flags/dst look correct"
  fi
}

# Send one UDP datagram to EXAMPLE_IP:53 from the current process (no worker threads).
# Must call connect() — gotproxy only hooks cgroup/connect4; bare sendto() is invisible.
udp_send_probe() {
  if command -v python3 &>/dev/null; then
    exec python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.connect(('${EXAMPLE_IP}', 53)); s.send(b'\\x00'); s.close()"
  fi
  if command -v nc &>/dev/null; then
    # Prefer connected UDP if supported; fall back to -u.
    exec nc -u -w1 "$EXAMPLE_IP" 53 </dev/null
  fi
  # Bash /dev/udp typically goes through connect.
  exec bash -c "printf '\\x00' >/dev/udp/${EXAMPLE_IP}/53"
}

# --- UDP: single-process client should report matching pid/comm and MATCH_CMD ---
test_udp_cmd_meta() {
  local udp_comm=""
  if command -v python3 &>/dev/null; then
    udp_comm="python3"
  elif command -v nc &>/dev/null; then
    udp_comm="nc"
  else
    udp_comm="bash"
  fi

  info "Test: UDP ConnMeta with --cmd ${udp_comm}"
  # Start proxy first; dig-style races are avoided by sending only after BPF is ready.
  start_gotproxy --cmd "$udp_comm" --follow-forks=false --proto udp

  local pid_file helper_pid expect_pid
  pid_file=$(mktemp)
  (
    echo "$BASHPID" >"$pid_file"
    udp_send_probe
  ) &>/dev/null &
  helper_pid=$!
  wait "$helper_pid" 2>/dev/null || true
  expect_pid=$(cat "$pid_file" 2>/dev/null || true)

  local blob log_snapshot=""
  blob=$(find_meta_blob udp "${EXAMPLE_IP}:53") || true
  # Also accept meta.dst without requiring it on the "Original destination" prefix.
  if [[ -z "$blob" ]]; then
    blob=$(find_meta_blob udp "$EXAMPLE_IP") || true
  fi
  [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && log_snapshot=$(cat "$LOG_FILE")
  stop_gotproxy
  rm -f "$pid_file"

  if [[ -z "$expect_pid" ]]; then
    fail "UDP --cmd meta: could not get helper PID"
    return
  fi
  if [[ -z "$blob" ]]; then
    fail "UDP --cmd meta: no UDP meta={...} line with ${EXAMPLE_IP}:53 in log"
    [[ -n "$log_snapshot" ]] && { info "log:"; echo "$log_snapshot"; }
    return
  fi

  assert_meta "UDP --cmd" "$blob" "$expect_pid" "$udp_comm" "$MATCH_CMD" "$EXAMPLE_IP"

  if grep -qE "UDP Original destination:.*${EXAMPLE_IP}:53" <<<"$log_snapshot" 2>/dev/null || \
     grep -qE "meta=\{.*dst=${EXAMPLE_IP}:53" <<<"$log_snapshot" 2>/dev/null; then
    ok "UDP --cmd: log shows destination ${EXAMPLE_IP}:53"
  else
    fail "UDP --cmd: missing destination ${EXAMPLE_IP}:53 in log line"
  fi
}

main() {
  check_env
  echo "=========================================="
  echo "  gotproxy ConnMeta tests"
  echo "=========================================="
  test_tcp_cmd_meta
  test_tcp_pid_meta
  test_udp_cmd_meta
  echo "=========================================="
  echo "  Passed: $PASSED  Failed: $FAILED"
  echo "=========================================="
  [[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
}

trap 'stop_gotproxy; exit 130' INT TERM
main "$@"
