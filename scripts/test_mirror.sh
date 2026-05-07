#!/usr/bin/env bash
# gotproxy traffic mirror integration test (TCP + UDP)
# Usage: sudo ./scripts/test_mirror.sh
# Requires: built gotproxy, curl, python3; root (CAP_BPF). UDP test needs dig.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GOTPROXY_BIN="${GOTPROXY_BIN:-$REPO_ROOT/gotproxy}"
PROXY_PORT="${PROXY_PORT:-18002}"
TEST_URL="${TEST_URL:-https://1.1.1.1}"
# Plain HTTP (not HTTPS): mirrored uplink is cleartext so the script can print a readable sample.
HTTPBIN_URL="${HTTPBIN_URL:-http://httpbin.org/get}"
EXAMPLE_IP="${EXAMPLE_IP:-1.1.1.1}"
MIRROR_HOST="${MIRROR_HOST:-127.0.0.1}"
MIRROR_TCP_PORT="${MIRROR_TCP_PORT:-19081}"
MIRROR_UDP_PORT="${MIRROR_UDP_PORT:-19082}"

PASSED=0
FAILED=0
LOG_FILE=""
GOTPROXY_PID=""
TCP_LISTENER_PID=""
UDP_LISTENER_PID=""
TCP_CAPTURE_FILE=""
UDP_CAPTURE_FILE=""

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; ((PASSED++)) || true; }
fail()  { echo "[FAIL]  $*"; ((FAILED++)) || true; }
abort() { echo "[ABORT] $*"; cleanup; exit 1; }

cleanup_listener_pid() {
  local pid="${1:-}"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

cleanup() {
  cleanup_listener_pid "$GOTPROXY_PID"
  cleanup_listener_pid "$TCP_LISTENER_PID"
  cleanup_listener_pid "$UDP_LISTENER_PID"
  GOTPROXY_PID=""
  TCP_LISTENER_PID=""
  UDP_LISTENER_PID=""
  [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && rm -f "$LOG_FILE"
  [[ -n "$TCP_CAPTURE_FILE" && -f "$TCP_CAPTURE_FILE" ]] && rm -f "$TCP_CAPTURE_FILE"
  [[ -n "$UDP_CAPTURE_FILE" && -f "$UDP_CAPTURE_FILE" ]] && rm -f "$UDP_CAPTURE_FILE"
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
  if ! command -v python3 &>/dev/null; then
    abort "python3 not found. Please install python3."
  fi
  info "Using gotproxy=$GOTPROXY_BIN, proxy_port=$PROXY_PORT"
}

start_gotproxy() {
  local extra_args=("$@")
  LOG_FILE=$(mktemp)
  "$GOTPROXY_BIN" --p-port "$PROXY_PORT" "${extra_args[@]}" >"$LOG_FILE" 2>&1 &
  GOTPROXY_PID=$!
  for _ in {1..40}; do
    if grep -q "listening on" "$LOG_FILE" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  abort "gotproxy did not start in time, see $LOG_FILE"
}

wait_listener_ready() {
  local file="$1"
  for _ in {1..20}; do
    [[ -f "$file" ]] && return 0
    sleep 0.1
  done
  return 1
}

start_tcp_listener() {
  TCP_CAPTURE_FILE=$(mktemp)
  local ready_file
  ready_file=$(mktemp)
  python3 - <<'PY' "$MIRROR_HOST" "$MIRROR_TCP_PORT" "$TCP_CAPTURE_FILE" "$ready_file" &
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
capture = sys.argv[3]
ready = sys.argv[4]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(8)
with open(ready, "w", encoding="utf-8") as f:
    f.write("ready")
with open(capture, "wb") as out:
    while True:
        conn, _ = s.accept()
        with conn:
            while True:
                data = conn.recv(65535)
                if not data:
                    break
                out.write(data)
                out.flush()
PY
  TCP_LISTENER_PID=$!
  if ! wait_listener_ready "$ready_file"; then
    rm -f "$ready_file"
    abort "TCP mirror listener failed to start"
  fi
  rm -f "$ready_file"
}

start_udp_listener() {
  UDP_CAPTURE_FILE=$(mktemp)
  local ready_file
  ready_file=$(mktemp)
  python3 - <<'PY' "$MIRROR_HOST" "$MIRROR_UDP_PORT" "$UDP_CAPTURE_FILE" "$ready_file" &
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
capture = sys.argv[3]
ready = sys.argv[4]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
with open(ready, "w", encoding="utf-8") as f:
    f.write("ready")
with open(capture, "ab") as out:
    while True:
        data, _ = s.recvfrom(65535)
        if not data:
            continue
        out.write(data)
        out.flush()
PY
  UDP_LISTENER_PID=$!
  if ! wait_listener_ready "$ready_file"; then
    rm -f "$ready_file"
    abort "UDP mirror listener failed to start"
  fi
  rm -f "$ready_file"
}

test_tcp_mirror() {
  info "Test: TCP uplink mirroring"
  start_tcp_listener
  start_gotproxy \
    --proto tcp \
    --mirror-enable \
    --mirror-target "${MIRROR_HOST}:${MIRROR_TCP_PORT}" \
    --mirror-proto tcp

  curl -sS -4 -o /dev/null -w "" --connect-timeout 10 "$TEST_URL" || true
  sleep 1

  local size
  size=$(wc -c < "$TCP_CAPTURE_FILE" 2>/dev/null || echo 0)
  cleanup_listener_pid "$GOTPROXY_PID"; GOTPROXY_PID=""
  cleanup_listener_pid "$TCP_LISTENER_PID"; TCP_LISTENER_PID=""

  if [[ "${size:-0}" -gt 0 ]]; then
    ok "TCP mirroring works: captured ${size} bytes at mirror target"
  else
    fail "TCP mirroring failed: mirror target captured 0 bytes"
    [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && { info "gotproxy log:"; cat "$LOG_FILE"; }
  fi
}

# Uses HTTP (not TLS): request line and headers appear as printable text in the mirror capture.
test_tcp_mirror_httpbin() {
  info "Test: TCP uplink mirroring — plain HTTP $HTTPBIN_URL (cleartext in capture)"
  start_tcp_listener
  start_gotproxy \
    --proto tcp \
    --mirror-enable \
    --mirror-target "${MIRROR_HOST}:${MIRROR_TCP_PORT}" \
    --mirror-proto tcp

  curl -sS -4 -o /dev/null -w "" --connect-timeout 15 "$HTTPBIN_URL" || true
  sleep 1

  local size
  size=$(wc -c < "$TCP_CAPTURE_FILE" 2>/dev/null || echo 0)
  local cap="$TCP_CAPTURE_FILE"
  cleanup_listener_pid "$GOTPROXY_PID"; GOTPROXY_PID=""
  cleanup_listener_pid "$TCP_LISTENER_PID"; TCP_LISTENER_PID=""

  if [[ "${size:-0}" -gt 0 ]]; then
    ok "HTTP httpbin mirror: captured ${size} bytes at mirror target"
    info "Sample of mirrored traffic (printable lines; HTTP is not encrypted here):"
    if command -v strings &>/dev/null; then
      strings -n 2 "$cap" 2>/dev/null | head -n 40 || true
    else
      LC_ALL=C head -c 1200 "$cap" | tr '\0' '.'; echo
    fi
  else
    fail "HTTP httpbin mirror: mirror target captured 0 bytes (is $HTTPBIN_URL reachable?)"
    [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && { info "gotproxy log:"; cat "$LOG_FILE"; }
  fi
  [[ -f "$cap" ]] && rm -f "$cap"
}

test_udp_mirror() {
  if ! command -v dig &>/dev/null; then
    info "Test: UDP uplink mirroring — skipped (dig not installed)"
    return
  fi
  info "Test: UDP uplink mirroring"
  start_udp_listener
  start_gotproxy \
    --proto udp \
    --mirror-enable \
    --mirror-target "${MIRROR_HOST}:${MIRROR_UDP_PORT}" \
    --mirror-proto udp

  dig +short +time=5 +tries=1 @"$EXAMPLE_IP" example.com &>/dev/null || true
  sleep 1

  local size
  size=$(wc -c < "$UDP_CAPTURE_FILE" 2>/dev/null || echo 0)
  cleanup_listener_pid "$GOTPROXY_PID"; GOTPROXY_PID=""
  cleanup_listener_pid "$UDP_LISTENER_PID"; UDP_LISTENER_PID=""

  if [[ "${size:-0}" -gt 0 ]]; then
    ok "UDP mirroring works: captured ${size} bytes at mirror target"
  else
    fail "UDP mirroring failed: mirror target captured 0 bytes"
    [[ -n "$LOG_FILE" && -f "$LOG_FILE" ]] && { info "gotproxy log:"; cat "$LOG_FILE"; }
  fi
}

main() {
  check_env
  echo "=========================================="
  echo "  gotproxy mirror tests"
  echo "=========================================="
  test_tcp_mirror
  test_tcp_mirror_httpbin
  test_udp_mirror
  echo "=========================================="
  echo "  Passed: $PASSED  Failed: $FAILED"
  echo "=========================================="
  [[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
}

trap 'cleanup; exit 130' INT TERM
trap 'cleanup' EXIT
main "$@"
