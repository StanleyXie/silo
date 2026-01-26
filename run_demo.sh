#!/bin/bash
set -e

# Configuration
cd "$(dirname "$0")"
VAULT_ADDR="http://127.0.0.1:8200"
VAULT_TOKEN="root"
TVB_PORT="5321"
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

cleanup() {
    log "Cleaning up..."
    if [ -n "$VAULT_PID" ]; then
        kill $VAULT_PID 2>/dev/null || true
    fi
    if [ -n "$ETCD_PID" ]; then
        kill $ETCD_PID 2>/dev/null || true
    fi

}

trap cleanup EXIT

# 1. Prerequisite Checks & Binary Paths
mkdir -p bin

# Check if we can reuse binaries from ../bin (sibling dir)
if [ -d "../bin" ]; then
    log "reusing binaries from ../bin"
    export PATH="$PWD/../bin:$PATH"
else
    # Fallback to local bin
    export PATH="$PWD/bin:$PATH"
    
    # Simple install check (simplified from original)
    if ! command -v vault >/dev/null 2>&1 || ! command -v terraform >/dev/null 2>&1; then
        log "Binaries not found in ../bin and not in path. Please install manually."
        exit 1
    fi
fi

# Parse Backend Selection
BACKEND=${1:-vault}
if [[ "$BACKEND" != "vault" && "$BACKEND" != "etcd" ]]; then
    error "Invalid backend. Usage: ./run_demo.sh [vault|etcd]"
fi

# 2. Start Storage Backend (Vault or Etcd)
if [ "$BACKEND" == "vault" ]; then
    log "Starting Vault dev server..."
    if lsof -i :8200 >/dev/null; then
        log "Vault already running on 8200. Will use existing instance."
    else
        vault server -dev -dev-root-token-id="$VAULT_TOKEN" > vault.log 2>&1 &
        VAULT_PID=$!
        sleep 2
        if ! kill -0 $VAULT_PID >/dev/null 2>&1; then
            cat vault.log
            error "Vault failed to start"
        fi
    fi
    
    export VAULT_ADDR=$VAULT_ADDR
    export VAULT_TOKEN=$VAULT_TOKEN
    
    # Configure Vault
    if ! vault secrets list | grep -q "secret/"; then
        log "Enabling KV v2 at secret/"
        vault secrets enable -path=secret kv-v2
    fi

elif [ "$BACKEND" == "etcd" ]; then
    log "Starting Etcd on alternative ports..."
    # Check if etcd is installed
    if ! command -v etcd >/dev/null 2>&1; then
        error "etcd binary not found. Please install etcd to use this backend."
    fi
    
    ETCD_CLIENT_PORT="2389"
    ETCD_PEER_PORT="2390"
    
    # Check if these ports are already running something (surgical check)
    if lsof -i :$ETCD_CLIENT_PORT >/dev/null || lsof -i :$ETCD_PEER_PORT >/dev/null; then
        log "Etcd or another process already using $ETCD_CLIENT_PORT/$ETCD_PEER_PORT. Attempting to use existing if it's Etcd..."
    else
        # Start Etcd with specific ports
        etcd --listen-client-urls "http://127.0.0.1:$ETCD_CLIENT_PORT" \
             --advertise-client-urls "http://127.0.0.1:$ETCD_CLIENT_PORT" \
             --listen-peer-urls "http://127.0.0.1:$ETCD_PEER_PORT" \
             --initial-advertise-peer-urls "http://127.0.0.1:$ETCD_PEER_PORT" \
             --initial-cluster "default=http://127.0.0.1:$ETCD_PEER_PORT" \
             --data-dir "default.etcd.demo" > etcd.log 2>&1 &
        ETCD_PID=$!
        sleep 2
        if ! kill -0 $ETCD_PID >/dev/null 2>&1; then
            cat etcd.log
            error "Etcd failed to start on $ETCD_CLIENT_PORT"
        fi
    fi
    export BACKEND_TYPE=etcd
    export ETCD_ENDPOINTS="http://127.0.0.1:$ETCD_CLIENT_PORT"
fi


# 4. Start Pingora Gateway (Converged Backend)
log "Starting Silo Gateway ($BACKEND)..."

# Ensure we have the latest build
log "Building Gateway..."
if [ "$BACKEND" == "etcd" ]; then
    cargo build --release --features etcd
else 
    cargo build --release
fi

# Generate certs if missing
mkdir -p certs
if [ ! -f "certs/server.key" ]; then
    log "Generating self-signed certs..."
    openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj '/CN=localhost'
fi

# Start Gateway
export RUST_LOG=info
./target/release/silo > gateway.log 2>&1 &
GW_PID=$!
sleep 2

if ! kill -0 $GW_PID >/dev/null 2>&1; then
    cat gateway.log
    error "Gateway failed to start"
fi

# 6. Run Terraform
log "Initializing Terraform..."
export TF_HTTP_USERNAME="$VAULT_TOKEN"
rm -rf .terraform .terraform.lock.hcl terraform.tfstate*

# Configure Terraform to use Gateway on 8443 (HTTPS)
export TF_HTTP_ADDRESS="https://127.0.0.1:8443/v1/state/myproject/dev"
export TF_HTTP_LOCK_ADDRESS="https://127.0.0.1:8443/v1/lock/myproject/dev"
export TF_HTTP_UNLOCK_ADDRESS="https://127.0.0.1:8443/v1/lock/myproject/dev"
export TF_HTTP_LOCK_METHOD="POST"
export TF_HTTP_UNLOCK_METHOD="DELETE"

# Skip cert verification for self-signed
export TF_HTTP_SKIP_CERT_VERIFICATION=true

# Create a temporary override file for backend
cat > backend_override.tf <<EOF
terraform {
  backend "http" {
    skip_cert_verification = true
  }
}
EOF

terraform init

log "Applying Terraform Configuration via Secure Gateway..."
terraform apply -auto-approve

log "Verifying State in Storage..."
if [ "$BACKEND" == "vault" ]; then
    echo "Getting state from secret/myproject/dev:"
    vault kv get secret/myproject/dev || true
elif [ "$BACKEND" == "etcd" ]; then
    echo "Check etcd keys (requires etcdctl)..."
    if command -v etcdctl >/dev/null 2>&1; then
        etcdctl --endpoints="$ETCD_ENDPOINTS" get secret/myproject/dev --prefix || true
    else
        log "etcdctl not found, skipping manual verification."
    fi
fi

log "Verifying Metrics..."
if curl -s http://127.0.0.1:6192/ | grep -q "req_counter"; then
    log "Metrics endpoint active and req_counter found."
else
    error "Metrics endpoint check failed."
fi

log "Demo completed successfully!"
# Cleanup function needs to handle PIDs
trap "cleanup" EXIT


wait
