#!/bin/bash
set -e

# Configuration
cd "$(dirname "$0")"
VAULT_ADDR="http://127.0.0.1:8200"
VAULT_TOKEN="root"
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
log "Running OpenTofu Compatibility Demo with $BACKEND backend"

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
             --data-dir "tofu.etcd.demo" > etcd.log 2>&1 &
        ETCD_PID=$!
        sleep 2
    fi
    export BACKEND_TYPE=etcd
    export ETCD_ENDPOINTS="http://127.0.0.1:$ETCD_CLIENT_PORT"
elif [ "$BACKEND" == "vault" ]; then
    log "Starting Vault dev server..."
    if lsof -i :8200 >/dev/null; then
        log "Vault already running on 8200. Will use existing instance."
    else
        vault server -dev -dev-root-token-id="$VAULT_TOKEN" > vault.log 2>&1 &
        VAULT_PID=$!
        sleep 2
    fi
    export VAULT_ADDR=$VAULT_ADDR
    export VAULT_TOKEN=$VAULT_TOKEN
    export BACKEND_TYPE=vault

    # Configure Vault
    if ! vault secrets list | grep -q "secret/"; then
        log "Enabling KV v2 at secret/"
        vault secrets enable -path=secret kv-v2
    fi
fi

# 2. Start Silo Gateway
log "Building Gateway..."
if [ "$BACKEND" == "etcd" ]; then
    cargo build --release --features etcd
else 
    cargo build --release
    export BACKEND_TYPE=vault
fi

# Ensure internal certs are there (from Phase 3)
if [ ! -d "certs/internal" ]; then
    log "Generating internal mTLS certs..."
    bash certs/generate_internal.sh
fi

# Try to clear ports before starting
lsof -t -i :50051 | xargs kill -9 2>/dev/null || true
lsof -t -i :8443 | xargs kill -9 2>/dev/null || true
lsof -t -i :6192 | xargs kill -9 2>/dev/null || true

# Start Gateway
cleanup() {
    log "Cleaning up..."
    if [ -n "$GW_PID" ]; then
        kill $GW_PID 2>/dev/null || true
    fi
    if [ -n "$ETCD_PID" ]; then
        kill $ETCD_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

export RUST_LOG=info
./target/release/silo > gateway.log 2>&1 &
GW_PID=$!
sleep 2

if ! kill -0 $GW_PID >/dev/null 2>&1; then
    cat gateway.log
    error "Gateway failed to start"
fi

# 2. Run OpenTofu
log "Initializing OpenTofu..."
rm -rf .terraform .terraform.lock.hcl terraform.tfstate* .opentofu

# Configure OpenTofu to use Gateway
export TF_HTTP_ADDRESS="https://127.0.0.1:8443/v1/state/myproject/tofu-dev"
export TF_HTTP_LOCK_ADDRESS="https://127.0.0.1:8443/v1/lock/myproject/tofu-dev"
export TF_HTTP_UNLOCK_ADDRESS="https://127.0.0.1:8443/v1/lock/myproject/tofu-dev"
export TF_HTTP_LOCK_METHOD="POST"
export TF_HTTP_UNLOCK_METHOD="DELETE"
export TF_HTTP_SKIP_CERT_VERIFICATION=true

# OpenTofu also uses TOFU_ prefixed vars or TF_ ones
export TOFU_HTTP_SKIP_CERT_VERIFICATION=true

tofu init

log "Applying OpenTofu Configuration via Secure Gateway..."
tofu apply -auto-approve

log "Verifying State in Storage..."
if [ "$BACKEND" == "etcd" ]; then
    if command -v etcdctl >/dev/null 2>&1; then
        ETCD_ENDPOINTS="http://127.0.0.1:2389"
        echo "Check etcd keys:"
        etcdctl --endpoints="$ETCD_ENDPOINTS" get secret/myproject/tofu-dev --prefix || true
    fi
fi

log "Verifying Logs for OpenTofu User-Agent..."
if grep -q "OpenTofu" gateway.log; then
    log "SUCCESS: Found OpenTofu User-Agent in logs."
else
    log "WARNING: OpenTofu User-Agent not found in logs. Check gateway.log:"
    grep "/v1/" gateway.log | tail -n 5
fi

log "OpenTofu Compatibility Demo completed successfully!"
