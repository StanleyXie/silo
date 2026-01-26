#!/bin/bash
# Verify mTLS Identity Extraction
# 1. Setup PATH
export PATH="/Users/stanleyxie/Workspace/Projects/tfvault/bin:$PATH"
mkdir -p "$(dirname "$0")/../bin"
cd "$(dirname "$0")/.."

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; }
failure() { echo -e "${RED}[FAIL]${NC} $1"; }

# 0. Cleanup any stale processes
log "Cleaning up stale processes..."
pkill -9 silo || true
pkill -9 vault || true
# Also kill anything on our ports just in case
lsof -ti :8443 | xargs kill -9 2>/dev/null || true
lsof -ti :50051 | xargs kill -9 2>/dev/null || true
lsof -ti :8200 | xargs kill -9 2>/dev/null || true
sleep 2

# 1. Start Vault
log "Starting Vault..."
vault server -dev -dev-root-token-id="root" > vault_mtls.log 2>&1 &
V_PID=$!
sleep 2

# 2. Build and Start Silo
log "Building Silo..."
cargo build --release --features openssl

log "Starting Silo with mTLS enabled..."
export RUST_LOG=info
./target/release/silo -c silo.yaml > silo_mtls.log 2>&1 &
S_PID=$!
sleep 2

cleanup() {
    log "Cleaning up..."
    kill $S_PID $V_PID 2>/dev/null || true
}
trap cleanup EXIT

# 3. Test with Authorized User Cert
log "Testing with stanley.xie certificate (Authorized)..."
curl -k -s -v \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    "https://127.0.0.1:8443/v1/state/test/mtls" > curl_allowed.log 2>&1

# 4. Test with Unauthorized User Cert
log "Testing with bad.actor certificate (Unauthorized)..."
curl -k -s -v \
    --cert certs/internal/denied.crt \
    --key certs/internal/denied.key \
    "https://127.0.0.1:8443/v1/state/test/mtls" > curl_denied.log 2>&1

log "Checking logs for identity extraction and RBAC..."
if grep -q "Handshake complete for identity: stanley.xie" silo_mtls.log; then
    success "Found mTLS identity extraction for stanley.xie"
else
    failure "mTLS identity extraction NOT found for stanley.xie"
    exit 1
fi

if grep -q "identity:stanley.xie" silo_mtls.log; then
    success "Found identity 'stanley.xie' in transactional request logs"
fi

if grep -q "Identity 'bad.actor' not authorized" silo_mtls.log; then
    success "Control Plane correctly denied 'bad.actor'"
else
    failure "Control Plane did NOT deny 'bad.actor' or log message missing"
    tail -n 20 silo_mtls.log
    exit 1
fi

if grep -q "403" curl_denied.log; then
    success "Gateway returned 403 Forbidden to unauthorized client"
else
    failure "Gateway did NOT return 403 to unauthorized client"
    exit 1
fi

# 5. Test Secure Config Storage (Converged Management)
log "Testing Secure Config Storage (Converged Management)..."
cat > test.tfvars <<EOF
db_password = "super-secret-password"
env = "prod"
EOF

log "Uploading test.tfvars as stanley.xie..."
curl -k -s -v \
    -X PUT \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data-binary @test.tfvars \
    "https://127.0.0.1:8443/v1/config/prod/app1.tfvars" > curl_config_put.log 2>&1

log "Retrieving test.tfvars as stanley.xie..."
curl -k -s -v \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    "https://127.0.0.1:8443/v1/config/prod/app1.tfvars" > curl_config_get.log 2>&1

if grep -q "db_password" curl_config_get.log; then
    success "Secure Config Storage verified: Successfully retrieved app1.tfvars"
else
    failure "Secure Config Storage FAILED: Could not retrieve app1.tfvars"
    exit 1
fi

log "Uploading test-v2.tfvars as stanley.xie..."
echo 'db_password = "even-more-secret"' > test-v2.tfvars
curl -k -s -v \
    -X PUT \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data-binary @test-v2.tfvars \
    "https://127.0.0.1:8443/v1/config/prod/app1.tfvars" > curl_config_put_v2.log 2>&1

log "Retrieving app1.tfvars v1..."
curl -k -s -v \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    "https://127.0.0.1:8443/v1/config/prod/app1.tfvars?version=1" > curl_config_v1.log 2>&1

if grep -q "super-secret-password" curl_config_v1.log; then
    success "Config v1 correctly retrieved"
else
    failure "Config v1 retrieval FAILED"
    exit 1
fi

# 6. Test State-Config Lineage
log "Testing State-Config Lineage..."
log "Uploading state linked to config v2..."
curl -k -s -v \
    -X POST \
    -H "X-Silo-Config-Version: 2" \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data-binary '{"terraform_version":"1.5.0"}' \
    "https://127.0.0.1:8443/v1/state/matrix/lineage-test" > curl_state_post.log 2>&1

log "Checking logs for lineage recording..."
if grep -q "Lineage recorded: State v1 -> Config v2" silo_mtls.log; then
    success "State-Config Lineage recorded successfully"
else
    failure "Lineage recording NOT found in logs"
    tail -n 20 silo_mtls.log
    exit 1
fi

# 7. Test Autonomous Shared-State Auth
log "Testing Autonomous Shared-State Auth..."
curl -k -s -v \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    "https://127.0.0.1:8443/v1/state/matrix/survivor-test" > curl_survivor.log 2>&1

if grep -q "Autonomous Auth: Identity 'stanley.xie' verified via Shared-State" silo_mtls.log; then
    success "Autonomous Shared-State Auth verified (Data Plane is independent)"
else
    failure "Autonomous Auth NOT found in logs (Data Plane may still be dependent on CP)"
    exit 1
fi

# 8. Test Session-Bound Locks
log "Testing Session-Bound Lock Governance..."
curl -k -s -v \
    -X POST \
    -H "X-Silo-Device-ID: macbook-pro-01" \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data '{"ID":"lock-123","Operation":"Plan","Who":"stanley.xie"}' \
    "https://127.0.0.1:8443/v1/lock/matrix/gov-test" > curl_lock.log 2>&1

if grep -q "LOCK: secret/matrix/gov-test/lock (caller: stanley.xie" silo_mtls.log; then
    success "Session-Bound Lock acquired and recorded!"
else
    failure "Lock acquisition NOT found in logs"
    exit 1
fi

# 9. Test Remote Runner Detached Execution (Reattach)
log "Testing Remote Runner Reattach (Handover)..."
# The session ID created in step 8 should be stanley-xie-macbook-pro-01
curl -k -s -v \
    -X POST \
    --cert certs/internal/user.crt \
    --key certs/internal/user.key \
    --data '{"execution_id":"stanley-xie-macbook-pro-01","device_id":"macbook-pro-01"}' \
    "https://127.0.0.1:8443/v1/reattach/handover" > curl_reattach.log 2>&1

if grep -q "200" curl_reattach.log && grep -q "stanley-xie-macbook-pro-01" curl_reattach.log; then
    success "Remote Runner reattach verified! (Session handover working)"
else
    failure "Remote Runner reattach FAILED"
    tail -n 20 curl_reattach.log
    exit 1
fi

log "Testing Reattach Identity Enforcement (Malicious context)..."
# Try to reattach to stanley's session using actor's certificate
curl -k -s -v \
    -X POST \
    --cert certs/internal/denied.crt \
    --key certs/internal/denied.key \
    --data '{"execution_id":"stanley-xie-macbook-pro-01","device_id":"bad-device"}' \
    "https://127.0.0.1:8443/v1/reattach/malicious" > curl_reattach_bad.log 2>&1

if grep -q "403" curl_reattach_bad.log; then
    success "Reattach Identity Enforcement verified: 'bad.actor' correctly denied access to stanley's session"
else
    failure "Reattach Identity Enforcement FAILED: Malicious reattach was not blocked with 403"
    exit 1
fi

success "All Shared-State Governance modules (Auth, Sessions, & Reattach) verified successfully!"
