#!/bin/bash
set -e

# Setup PATH
export PATH="/Users/stanleyxie/Workspace/Projects/tfvault/bin:$PATH"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[INFO] $1${NC}"; }
failure() { echo -e "${RED}[FAIL] $1${NC}"; }
success() { echo -e "${GREEN}[PASS] $1${NC}"; }

# Cleanup function
cleanup() {
    log "Cleaning up processes..."
    pkill -9 silo || true
    pkill -9 vault || true
    sleep 2
}
trap cleanup EXIT

log "Ensuring clean state..."
pkill -9 silo || true
pkill -9 vault || true
sleep 3

# Check if ports are in use
for port in 8443 50051 8200 6192; do
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        log "Warning: Port $port is in use. Attempting to kill the process..."
        lsof -ti :$port | xargs kill -9 2>/dev/null || true
    fi
done
sleep 1

log "Building Silo..."
cargo build --release --features openssl > /dev/null 2>&1

log "Starting Vault..."
export VAULT_TOKEN="root"
export VAULT_ADDR="http://127.0.0.1:8200"
vault server -dev -dev-root-token-id="root" > vault_reaper.log 2>&1 &

# Wait for Vault to be ready
log "Waiting for Vault..."
for i in {1..20}; do
    if vault status > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! vault status > /dev/null 2>&1; then
    failure "Vault failed to start. Logs:"
    cat vault_reaper.log
    exit 1
fi
success "Vault is ready."

log "Starting Silo with Reaper enabled..."
export RUST_LOG=info
./target/release/silo -c silo.yaml > silo_reaper.log 2>&1 &

# Wait for Silo (check 8443)
log "Waiting for Silo..."
for i in {1..20}; do
    if curl -k -s "https://127.0.0.1:8443/metrics" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done
success "Silo is ready."

# 1. Acquire Lock (creates session)
log "Acquiring lock for session creation..."
curl -k -s -v \
    -X POST \
    -H "X-Silo-Device-ID: macbook-pro-01" \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data '{"ID":"lock-456","Operation":"Plan","Who":"stanley.xie"}' \
    "https://127.0.0.1:8443/v1/lock/reaper-test" > curl_lock.log 2>&1

# 2. Verify Session exists
log "Verifying session existence in Vault..."
SESSION_ID="stanley-xie-macbook-pro-01"
if vault kv get secret/silo/sessions/$SESSION_ID > /dev/null 2>&1; then
    success "Session established in KV!"
else
    failure "Session NOT found in KV"
    log "Silo Log Extract:"
    tail -n 20 silo_reaper.log
    exit 1
fi

# 3. Perform State Update (updates heartbeat)
log "Performing state update to trigger heartbeat..."
curl -k -s \
    -X POST \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data '{"terraform_version":"1.5.0"}' \
    "https://127.0.0.1:8443/v1/state/reaper-test" > /dev/null 2>&1

# Get last_heartbeat
HEARTBEAT_V1=$(vault kv get -field=value secret/silo/sessions/$SESSION_ID | base64 -d | jq -r .last_heartbeat)
log "Initial heartbeat: $HEARTBEAT_V1"

sleep 2

# Perform another update
log "Performing second update..."
curl -k -s \
    -X POST \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data '{"terraform_version":"1.5.0-v2"}' \
    "https://127.0.0.1:8443/v1/state/reaper-test" > /dev/null 2>&1

HEARTBEAT_V2=$(vault kv get -field=value secret/silo/sessions/$SESSION_ID | base64 -d | jq -r .last_heartbeat)
log "Updated heartbeat: $HEARTBEAT_V2"

if [ "$HEARTBEAT_V1" != "$HEARTBEAT_V2" ]; then
    success "Session Heartbeat updated successfully!"
else
    failure "Session Heartbeat was NOT updated"
    exit 1
fi

# 4. Wait for Reaper (Threshold is 2 mins, check every 30s)
log "Waiting for Reaper to reclaim stale lock (this will take ~2-3 minutes)..."
log "You can monitor silo_reaper.log for [Reaper] messages."

MAX_WAIT=360
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if ! vault kv get secret/reaper-test/lock > /dev/null 2>&1; then
        success "Lock successfully reclaimed by Reaper!"
        break
    fi
    sleep 30
    WAITED=$((WAITED + 30))
    echo -n "."
done
echo ""

if [ $WAITED -ge $MAX_WAIT ]; then
    failure "Reaper timed out: Lock was NOT reclaimed"
    exit 1
fi

# 5. Verify Session is gone too
if ! vault kv get secret/silo/sessions/$SESSION_ID > /dev/null 2>&1; then
    success "Session Metadata cleaned up successfully!"
else
    failure "Session Metadata still exists after reclamation"
    exit 1
fi

success "Reaper Governance Verification COMPLETE!"
