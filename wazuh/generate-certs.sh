#!/bin/bash
set -e

CERTS_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$CERTS_DIR"

# Generate Root CA
openssl genrsa -out "$CERTS_DIR/root-ca-key.pem" 2048
openssl req -new -x509 -sha256 -key "$CERTS_DIR/root-ca-key.pem" \
  -out "$CERTS_DIR/root-ca.pem" -days 3650 \
  -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=root-ca"

generate_cert() {
  local NAME=$1
  local CN=$2

  # Create extension file for SAN
  cat > "$CERTS_DIR/${NAME}.ext" <<EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${NAME}
DNS.2 = localhost
IP.1 = 127.0.0.1
EXTEOF

  openssl genrsa -out "$CERTS_DIR/${NAME}-key.pem" 2048
  openssl req -new -key "$CERTS_DIR/${NAME}-key.pem" \
    -out "$CERTS_DIR/${NAME}.csr" \
    -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=${CN}"
  openssl x509 -req -in "$CERTS_DIR/${NAME}.csr" \
    -CA "$CERTS_DIR/root-ca.pem" -CAkey "$CERTS_DIR/root-ca-key.pem" \
    -CAcreateserial -out "$CERTS_DIR/${NAME}.pem" -days 3650 -sha256 \
    -extfile "$CERTS_DIR/${NAME}.ext"

  rm -f "$CERTS_DIR/${NAME}.csr" "$CERTS_DIR/${NAME}.ext"
}

generate_cert "wazuh-manager" "wazuh-manager"
generate_cert "wazuh-indexer" "wazuh-indexer"
generate_cert "wazuh-dashboard" "wazuh-dashboard"
generate_cert "admin" "admin"

chmod 400 "$CERTS_DIR"/*-key.pem
chmod 444 "$CERTS_DIR"/*.pem

echo "Certificates generated in $CERTS_DIR"
