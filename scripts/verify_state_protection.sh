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
sleep 2

log "Building Silo..."
cargo build --release --features openssl > /dev/null 2>&1

log "Starting Vault..."
export VAULT_TOKEN="root"
export VAULT_ADDR="http://127.0.0.1:8200"
vault server -dev -dev-root-token-id="root" > vault_protect.log 2>&1 &
sleep 3

log "Starting Silo..."
export RUST_LOG=info
./target/release/silo -c silo.yaml > silo_protect.log 2>&1 &
sleep 5

# --- TEST 1: Lock Guard ---
log ">>> TEST 1: Lock Guard Protection"

# 1. Acquire Lock as User A (stanley.xie)
log "User A (stanley.xie) acquiring lock..."
curl -k -s -v \
    -X POST \
    -H "X-Silo-Device-ID: dev-01" \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data '{"ID":"lock-123","Operation":"Plan","Who":"stanley.xie"}' \
    "https://127.0.0.1:8443/v1/lock/protect-test" > /dev/null 2>&1

# 2. Try to update state as User B (bad.actor)
log "User B (bad.actor) attempting to update state (Should Fail)..."
STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
    -X POST \
    --cert certs/internal/denied.crt \
    --key certs/internal/denied.key \
    --data '{"data":"malicious"}' \
    "https://127.0.0.1:8443/v1/state/protect-test")

if [ "$STATUS" == "423" ]; then
    success "Lock Guard correctly blocked unauthorized write (423 Locked)"
else
    failure "Lock Guard FAILED: Expected 423, got $STATUS"
    exit 1
fi

# 3. Try to update state as User A (stanley.xie)
log "User A (stanley.xie) updating state (Should Succeed)..."
STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "X-Silo-Device-ID: dev-01" \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data '{"data":"valid-v1"}' \
    "https://127.0.0.1:8443/v1/state/protect-test")

if [ "$STATUS" == "200" ]; then
    success "Lock Guard allowed authorized write"
else
    failure "Lock Guard FAILED: Expected 200, got $STATUS"
    exit 1
fi

# --- TEST 2: CAS (Check-And-Set) ---
log ">>> TEST 2: CAS (Check-And-Set) Atomicity"

# 1. Fetch current version
log "Verifying initial state version..."
VERSION=$(vault kv get -format=json secret/protect-test | jq -r .data.metadata.version)
log "Initial Version: $VERSION"

# 2. Try to update using STALE base version (Expected Conflict)
log "Attempting state update with STALE base version 0 (Should Fail)..."
# In Vault KV v2, if use cas=1 and it's already 1, it might pass or fail depending on if we want to overwrite.
# Actually if we send cas=0 it means don't check.
# If we want to test conflict, we need to KNOW the current version is 2, then send cas=1.

# Let's perform another write to get to version 2
log "Updating to Version 2..."
curl -k -s \
    -X POST \
    -H "X-Silo-Device-ID: dev-01" \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data '{"data":"valid-v2"}' \
    "https://127.0.0.1:8443/v1/state/protect-test" > /dev/null 2>&1

NEW_VERSION=$(vault kv get -format=json secret/protect-test | jq -r .data.metadata.version)
log "New Version: $NEW_VERSION"

# 3. Try stale write with X-Silo-Base-Version: 1 (Current is 2)
log "User A attempting update with STALE X-Silo-Base-Version: 1 (Should Fail)..."
STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "X-Silo-Device-ID: dev-01" \
    -H "X-Silo-Base-Version: 1" \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data '{"data":"stale-update"}' \
    "https://127.0.0.1:8443/v1/state/protect-test")

if [ "$STATUS" == "409" ]; then
    success "CAS correctly blocked stale write (409 Conflict)"
else
    failure "CAS FAILED: Expected 409, got $STATUS"
    exit 1
fi

# 4. Success write with X-Silo-Base-Version: 2
log "User A attempting update with CORRECT X-Silo-Base-Version: 2 (Should Succeed)..."
STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "X-Silo-Device-ID: dev-01" \
    -H "X-Silo-Base-Version: 2" \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data '{"data":"valid-v3"}' \
    "https://127.0.0.1:8443/v1/state/protect-test")

if [ "$STATUS" == "200" ]; then
    success "CAS allowed atomic write"
else
    failure "CAS FAILED: Expected 200, got $STATUS"
    exit 1
fi

log ">>> ALL TESTS PASSED: State Protection & Atomicity Verified"
