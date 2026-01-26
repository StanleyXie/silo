#!/bin/bash
set -e

mkdir -p certs/internal
cd certs/internal

# 1. Generate internal CA
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=Silo Internal CA"

# 2. Control Plane Cert
openssl genrsa -out control.key 2048
cat > control.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = control-plane.silo.internal
IP.1 = 127.0.0.1
EOF

openssl req -new -key control.key -out control.csr -subj "/CN=control-plane.silo.internal"
openssl x509 -req -in control.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out control.crt -days 365 -sha256 -extfile control.ext

# 3. Gateway Client Cert
openssl genrsa -out gateway.key 2048
cat > gateway.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = gateway.silo.internal
EOF

openssl req -new -key gateway.key -out gateway.csr -subj "/CN=gateway.silo.internal"
openssl x509 -req -in gateway.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out gateway.crt -days 365 -sha256 -extfile gateway.ext

# 4. End-User Test Cert (for mTLS Identity Extraction)
openssl genrsa -out user.key 2048
openssl req -new -key user.key -out user.csr -subj "/CN=stanley.xie"
openssl x509 -req -in user.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out user.crt -days 365 -sha256

echo "Internal mTLS certificates and user test cert generated successfully."
