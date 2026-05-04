#!/usr/bin/env bash
# Large download stability / RSS observation for gotproxy.
# Streams a large object through the transparent proxy (wget only) and samples
# gotproxy VmRSS while the transfer runs. Intended for manual regression checks
# for runaway memory or crashes — not a substitute for valgrind/pprof.
#
# Usage: sudo ./scripts/stability/large_download_stability.sh
#
# Env:
#   GOTPROXY_BIN   path to gotproxy (default: repo root ./gotproxy)
#   PROXY_PORT     listen port (default: 18001)
#   TEST_URL       download URL (default: Apple IPSW HTTP URL below)
#   MAX_TIME       wall-clock cap via timeout(1) around wget (default: 600)
#   SAMPLE_INTERVAL seconds between RSS samples (default: 2)
#   ROUNDS         repeat the same download N times sequentially (default: 1)
#   STRICT_MEM     if 1, exit 1 when heuristic flags possible RSS growth (default: 0)
#   MEM_GROWTH_KB  STRICT threshold: end RSS minus baseline exceeds this (default: 524288 = 512 MiB)
#   WGET_QUIET     if 1, use wget -q (no progress; for logs/CI)
#   GOTPROXY_LOG_TAIL  if set (e.g. 150), only print last N lines of gotproxy log per round; empty = full log
#
# gotproxy is started with --proto tcp so only TCP is redirected (no UDP proxy path).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GOTPROXY_BIN="${GOTPROXY_BIN:-$REPO_ROOT/gotproxy}"
PROXY_PORT="${PROXY_PORT:-18001}"

# Apple CDN full restore (large); streamed to /dev/null — no disk space required.
TEST_URL="${TEST_URL:-http://updates-http.cdn-apple.com/2019WinterFCS/fullrestores/041-39257/32129B6C-292C-11E9-9E72-4511412B0A59/iPhone_4.7_12.1.4_16D57_Restore.ipsw}"

MAX_TIME="${MAX_TIME:-600}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-2}"
ROUNDS="${ROUNDS:-1}"
STRICT_MEM="${STRICT_MEM:-0}"
MEM_GROWTH_KB="${MEM_GROWTH_KB:-524288}"
WGET_QUIET="${WGET_QUIET:-0}"
GOTPROXY_LOG_TAIL="${GOTPROXY_LOG_TAIL:-}"

LOG_FILE=""
GOTPROXY_PID=""
SAMPLE_LOG=""
WGET_EXIT=0
MEM_WARN=0

info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*"; }
abort() { echo "[ABORT] $*"; stop_gotproxy 2>/dev/null || true; exit 1; }

start_gotproxy() {
  LOG_FILE=$(mktemp)
  # Only proxy wget.
  "$GOTPROXY_BIN" --p-port "$PROXY_PORT" --cmd "wget" >"$LOG_FILE" 2>&1 &
  GOTPROXY_PID=$!
  local i
  for i in {1..30}; do
    if grep -q "listening on" "$LOG_FILE" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  abort "gotproxy did not start in time, see $LOG_FILE"
}

stop_gotproxy() {
  if [[ -n "${GOTPROXY_PID:-}" ]] && kill -0 "$GOTPROXY_PID" 2>/dev/null; then
    kill "$GOTPROXY_PID" 2>/dev/null || true
    wait "$GOTPROXY_PID" 2>/dev/null || true
  fi
  GOTPROXY_PID=""
  [[ -n "${LOG_FILE:-}" && -f "$LOG_FILE" ]] && rm -f "$LOG_FILE"
  LOG_FILE=""
}

# VmRSS in kB
rss_kb() {
  local pid="$1"
  [[ -r "/proc/$pid/status" ]] || { echo 0; return; }
  awk '/^VmRSS:/ {print $2; exit}' "/proc/$pid/status"
}

check_env() {
  if [[ "$(id -u)" -ne 0 ]]; then
    abort "Please run as root: sudo $0"
  fi
  if [[ ! -x "$GOTPROXY_BIN" ]]; then
    abort "gotproxy not found or not executable: $GOTPROXY_BIN. Run make build-bpf && make first."
  fi
  if ! command -v wget &>/dev/null; then
    abort "wget not found."
  fi
  if ! command -v timeout &>/dev/null; then
    abort "timeout(1) not found (coreutils). Needed to cap download duration like curl --max-time."
  fi
  info "gotproxy=$GOTPROXY_BIN port=$PROXY_PORT (proxy: wget only, --proto tcp)"
  info "TEST_URL=$TEST_URL"
  info "MAX_TIME=${MAX_TIME}s SAMPLE_INTERVAL=${SAMPLE_INTERVAL}s ROUNDS=$ROUNDS"
}

# Sample gotproxy RSS until WGET_PID exits; append "timestamp_ms rss_kb" to SAMPLE_LOG
sample_until_wget_done() {
  local wget_pid="$1"
  local out="$2"
  : >"$out"
  while kill -0 "$wget_pid" 2>/dev/null; do
    local ts kb
    ts=$(date +%s%3N)
    kb=$(rss_kb "$GOTPROXY_PID")
    echo "$ts $kb" >>"$out"
    sleep "$SAMPLE_INTERVAL"
  done
}

summarize_samples() {
  local f="$1"
  [[ -s "$f" ]] || { echo "no samples"; return; }
  awk '
    {
      ts=$1; kb=$2+0
      if (NR==1) { min=kb; max=kb; sum=kb; t0=ts }
      if (kb<min) min=kb
      if (kb>max) max=kb
      sum+=kb; n++
      last=kb; t1=ts
    }
    END {
      if (n>0) printf "samples=%d rss_kB min=%d max=%d avg=%.0f last=%d\n", n, min, max, sum/n, last
    }
  ' "$f"
}

round_download() {
  local round="$1"
  info "Round $round/$ROUNDS: wget -> /dev/null (max ${MAX_TIME}s via timeout) ..."
  SAMPLE_LOG=$(mktemp)
  local baseline
  baseline=$(rss_kb "$GOTPROXY_PID")
  info "gotproxy VmRSS baseline before wget: ${baseline} kB"

  set +e
  # GNU wget: -4 IPv4; --show-progress prints bar to stderr (even when not a TTY); outer timeout(1) caps wall time (exit 124).
  if [[ "$WGET_QUIET" == "1" ]]; then
    timeout "$MAX_TIME" wget -q -4 -O /dev/null --timeout=30 --tries=1 "$TEST_URL" &
  else
    timeout "$MAX_TIME" wget -4 --show-progress -O /dev/null --timeout=30 --tries=1 "$TEST_URL" &
  fi
  local wget_pid=$!
  set -e

  sample_until_wget_done "$wget_pid" "$SAMPLE_LOG"
  wait "$wget_pid" || true
  WGET_EXIT=$?

  if ! kill -0 "$GOTPROXY_PID" 2>/dev/null; then
    warn "gotproxy process died during round $round."
    [[ -n "${LOG_FILE:-}" && -f "$LOG_FILE" ]] && { warn "gotproxy log (tail):"; tail -n 80 "$LOG_FILE" || true; }
    stop_gotproxy
    exit 1
  fi

  if [[ -n "${LOG_FILE:-}" && -f "$LOG_FILE" ]]; then
    info "--- gotproxy log after wget (round $round/$ROUNDS) ---"
    if [[ -n "$GOTPROXY_LOG_TAIL" ]] && [[ "$GOTPROXY_LOG_TAIL" =~ ^[0-9]+$ ]]; then
      tail -n "$GOTPROXY_LOG_TAIL" "$LOG_FILE"
    else
      cat "$LOG_FILE"
    fi
    info "--- end gotproxy log ---"
  fi

  local after
  sleep 1
  after=$(rss_kb "$GOTPROXY_PID")
  info "gotproxy VmRSS ~1s after wget: ${after} kB"
  info "Sample summary: $(summarize_samples "$SAMPLE_LOG")"

  if [[ "$WGET_EXIT" -ne 0 ]]; then
    warn "wget exited with code $WGET_EXIT (124 = timeout(1) hit MAX_TIME; 4 = network failure per wget)"
  fi

  local growth=$((after - baseline))
  info "Delta RSS (after - baseline): ${growth} kB"
  if [[ "$growth" -gt "$MEM_GROWTH_KB" ]]; then
    warn "RSS grew more than MEM_GROWTH_KB (${MEM_GROWTH_KB} kB) vs baseline — review with pprof / repeated runs."
    MEM_WARN=1
  fi

  info "Sample time series: $SAMPLE_LOG"
  rm -f "$SAMPLE_LOG"
  SAMPLE_LOG=""
}

main() {
  check_env
  echo "=========================================="
  echo "  gotproxy large-download stability"
  echo "=========================================="

  trap 'stop_gotproxy; exit 130' INT TERM

  start_gotproxy
  local r
  for r in $(seq 1 "$ROUNDS"); do
    round_download "$r"
    if [[ "$r" -lt "$ROUNDS" ]]; then
      info "Pause 3s before next round..."
      sleep 3
    fi
  done

  stop_gotproxy

  echo "=========================================="
  if [[ "$WGET_EXIT" -ne 0 && "$WGET_EXIT" -ne 124 ]]; then
    echo "  Result: wget failed (exit $WGET_EXIT) — investigate network or proxy."
    exit 1
  fi
  if [[ "$STRICT_MEM" == "1" && "$MEM_WARN" -eq 1 ]]; then
    echo "  Result: STRICT_MEM=1 and memory heuristic triggered."
    exit 1
  fi
  echo "  Result: completed (wget exit $WGET_EXIT; 124 = timeout(1) killed wget after MAX_TIME, OK)."
  echo "  Inspect sample logs / RSS deltas above for trends across runs."
  echo "=========================================="
}

main "$@"
