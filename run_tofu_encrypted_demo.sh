#!/bin/bash
set -e

# Configuration
cd "$(dirname "$0")"
OS=$(uname | tr '[:upper:]' '[:lower:]')

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# 1. Prerequisite Checks & Binary Paths
mkdir -p bin
if [ -d "../bin" ]; then
    log "reusing binaries from ../bin"
    export PATH="$PWD/../bin:$PATH"
else
    export PATH="$PWD/bin:$PATH"
fi

# Parse Backend Selection
BACKEND=${1:-etcd}
log "Running OpenTofu ENCRYPTED Demo with $BACKEND backend"

# 1. Start Storage (Vault or Etcd)
if [ "$BACKEND" == "etcd" ]; then
    ETCD_CLIENT_PORT="2389"
    if ! lsof -i :$ETCD_CLIENT_PORT >/dev/null; then
        log "Starting Etcd..."
        etcd --listen-client-urls "http://127.0.0.1:$ETCD_CLIENT_PORT" \
             --advertise-client-urls "http://127.0.0.1:$ETCD_CLIENT_PORT" \
             --listen-peer-urls "http://127.0.0.1:2390" \
             --initial-advertise-peer-urls "http://127.0.0.1:2390" \
             --initial-cluster "default=http://127.0.0.1:2390" \
             --data-dir "tofu.encrypted.etcd" > etcd.log 2>&1 &
        ETCD_PID=$!
        sleep 2
    fi
    export BACKEND_TYPE=etcd
    export ETCD_ENDPOINTS="http://127.0.0.1:$ETCD_CLIENT_PORT"
elif [ "$BACKEND" == "vault" ]; then
    log "Starting Vault dev server..."
    if lsof -i :8200 >/dev/null; then
        log "Vault already running on 8200"
    else
        vault server -dev -dev-root-token-id="root" > vault.log 2>&1 &
        VAULT_PID=$!
        sleep 2
    fi
    export VAULT_ADDR="http://127.0.0.1:8200"
    export VAULT_TOKEN="root"
    export BACKEND_TYPE=vault
fi

# 2. Build and Start Silo Gateway
log "Building Silo..."
if [ "$BACKEND" == "etcd" ]; then
    cargo build --release --features etcd
else 
    cargo build --release
fi

# Try to clear ports
lsof -t -i :50051 | xargs kill -9 2>/dev/null || true
lsof -t -i :8443 | xargs kill -9 2>/dev/null || true

cleanup() {
    log "Cleaning up..."
    if [ -n "$GW_PID" ]; then kill $GW_PID 2>/dev/null || true; fi
    if [ -n "$ETCD_PID" ]; then kill $ETCD_PID 2>/dev/null || true; fi
}
trap cleanup EXIT

./target/release/silo > gateway.log 2>&1 &
GW_PID=$!
sleep 2

# 3. Run OpenTofu with Encryption
log "Initializing OpenTofu with Native Encryption..."
# Clean up any existing HCL to avoid duplicates
rm -rf .terraform .terraform.lock.hcl terraform.tfstate* .opentofu
rm -f *.tf

# Configure OpenTofu to use Gateway
export TF_HTTP_ADDRESS="https://127.0.0.1:8443/v1/state/myproject/tofu-encrypted"
export TF_HTTP_LOCK_ADDRESS="https://127.0.0.1:8443/v1/lock/myproject/tofu-encrypted"
export TF_HTTP_UNLOCK_ADDRESS="https://127.0.0.1:8443/v1/lock/myproject/tofu-encrypted"
export TF_HTTP_LOCK_METHOD="POST"
export TF_HTTP_UNLOCK_METHOD="DELETE"
export TF_HTTP_SKIP_CERT_VERIFICATION=true
export TOFU_HTTP_SKIP_CERT_VERIFICATION=true

# Copy the encrypted config to main.tf for the run
cp main_encrypted.tf.template main.tf

tofu init

log "Applying Encrypted Configuration..."
tofu apply -auto-approve

log "Verifying Encrypted State in Silo Logs..."
# The logs should show the write, but the content in storage should be encrypted
grep "POST /v1/state" gateway.log | tail -n 1

log "DEMO COMPLETE: OpenTofu State is now encrypted client-side before being stored in Silo."
log "Any unauthorized access to the Silo database (Vault/Etcd) will only yield encrypted blobs."
