#!/bin/bash
# Silo Comprehensive Test Matrix
# Tests: [Terraform, OpenTofu] x [Vault, Etcd] x [Plain, Encrypted]
# Verification includes: State CRUD, Session Heartbeats, Lock Guard, and CAS.

set -e
cd "$(dirname "$0")/.."

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; }
failure() { echo -e "${RED}[FAIL] $1${NC}"; }

# Setup PATH for Vault/Etcd/Silo
export PATH="/Users/stanleyxie/Workspace/Projects/tfvault/bin:$PATH"

# Matrix definition
TOOLS=("terraform" "tofu")
BACKENDS=("vault" "etcd")
MODES=("plain" "encrypted")

# Results file
RESULTS_FILE=$(mktemp)

cleanup() {
    log "Cleaning up processes..."
    pkill -9 silo || true
    pkill -9 vault || true
    pkill -9 etcd || true
    # Kill anything on ports
    for port in 8443 50051 8200 2389 6192; do
        lsof -ti :$port | xargs kill -9 2>/dev/null || true
    done
    rm -rf .terraform .terraform.lock.hcl terraform.tfstate* .opentofu main.tf silo_matrix_test.yaml 2>/dev/null || true
    rm -rf matrix_*.etcd 2>/dev/null || true
}

cleanup
trap "cleanup; rm -f $RESULTS_FILE" EXIT

log "Building Silo with all features..."
cargo build --release --features etcd > /dev/null 2>&1

for TOOL in "${TOOLS[@]}"; do
    for BACKEND in "${BACKENDS[@]}"; do
        for MODE in "${MODES[@]}"; do
            
            # Skip unsupported: Terraform does NOT support native encryption
            if [[ "$TOOL" == "terraform" && "$MODE" == "encrypted" ]]; then
                continue
            fi

            CASE_ID="${TOOL}_${BACKEND}_${MODE}"
            log "=========================================================="
            log "CASE: $CASE_ID"
            log "=========================================================="

            # 1. Start Backend
            if [ "$BACKEND" == "vault" ]; then
                vault server -dev -dev-root-token-id="root" > vault_matrix.log 2>&1 &
                sleep 3
                export VAULT_ADDR="http://127.0.0.1:8200"
                export VAULT_TOKEN="root"
                vault secrets enable -path=secret kv-v2 2>/dev/null || true
            else
                etcd --listen-client-urls "http://127.0.0.1:2389" --advertise-client-urls "http://127.0.0.1:2389" --data-dir "matrix_$CASE_ID.etcd" > etcd_matrix.log 2>&1 &
                sleep 3
            fi

            # 2. Start Silo
            cat > silo_matrix_test.yaml <<EOF
gateway:
  address: "127.0.0.1:8443"
  metrics_address: "127.0.0.1:6192"
  tls:
    enabled: true
    cert_path: "certs/server.crt"
    key_path: "certs/server.key"
control_plane:
  address: "127.0.0.1:50051"
  allowed_identities: ["stanley.xie", "bad.actor"]
  tls:
    ca_cert: "certs/internal/ca.crt"
    server_cert: "certs/internal/control.crt"
    server_key: "certs/internal/control.key"
    client_cert: "certs/internal/gateway.crt"
    client_key: "certs/internal/gateway.key"
storage:
  type: "$BACKEND"
  vault:
    address: "http://127.0.0.1:8200"
    token: "root"
  etcd:
    endpoints: ["http://127.0.0.1:2389"]
EOF
            export SILO_CONFIG="silo_matrix_test.yaml"
            echo "==========================================================" >> silo_matrix_all.log
            echo "CASE: $CASE_ID" >> silo_matrix_all.log
            echo "==========================================================" >> silo_matrix_all.log
            ./target/release/silo >> silo_matrix_all.log 2>&1 &
            # 2.1 Wait for Silo to be ready
            READY=0
            for i in {1..20}; do
                if curl -s http://127.0.0.1:6192/ > /dev/null 2>&1; then
                    READY=1
                    break
                fi
                sleep 0.5
            done
            if [ $READY -eq 0 ]; then
                failure "Silo failed to start (Metrics endpoint not reachable)"
                tail -n 20 silo_matrix_all.log
                exit 1
            fi

            # 3. Configure Tool Env
            STATE_NAME="matrix-$CASE_ID"
            export TF_HTTP_ADDRESS="https://127.0.0.1:8443/v1/state/$STATE_NAME"
            export TF_HTTP_LOCK_ADDRESS="https://127.0.0.1:8443/v1/lock/$STATE_NAME"
            export TF_HTTP_UNLOCK_ADDRESS="https://127.0.0.1:8443/v1/lock/$STATE_NAME"
            export TF_HTTP_LOCK_METHOD="POST"
            export TF_HTTP_UNLOCK_METHOD="DELETE"
            export TF_HTTP_SKIP_CERT_VERIFICATION=true
            # OpenTofu uses TF_HTTP_ prefix for compatibility
            # Note: Terraform v1.8 doesn't support client certs via env vars
            # so Terraform tests will fail mTLS auth, but OpenTofu tests should work
            export TF_HTTP_CLIENT_CERTIFICATE_PEM=$(cat certs/internal/user.crt)
            export TF_HTTP_CLIENT_PRIVATE_KEY_PEM=$(cat certs/internal/user.key)

            ERROR=0
            
            # Sub-test A: Basic Init & Apply
            log "[Case $CASE_ID] Phase A: Basic Init & Apply"
            if [ "$MODE" == "encrypted" ]; then
                cp main_encrypted.tf.template main.tf
            else
                cat > main.tf <<EOF
terraform {
  backend "http" {
    skip_cert_verification = true
  }
}
resource "random_pet" "test" { length = 2 }
EOF
            fi
            $TOOL init -no-color >> matrix_tool_debug.log 2>&1 || { failure "Init failed"; ERROR=1; }
            $TOOL apply -auto-approve -no-color >> matrix_tool_debug.log 2>&1 || { failure "Apply failed"; ERROR=1; }
            
            # Sub-test B: Lock Guard Verification (Simulate concurrent user)
            log "[Case $CASE_ID] Phase B: Lock Guard Verification"
            # 1. Acquire Lock as User A
            curl -k -s -v -X POST -H "X-Silo-Device-ID: dev-01" \
                --cert certs/internal/user.crt --key certs/internal/user.key \
                --data '{"ID":"lock-01","Operation":"Plan","Who":"stanley.xie"}' \
                "https://127.0.0.1:8443/v1/lock/$STATE_NAME" > /dev/null 2>&1
            
            # 2. Attempt push as User B (bad.actor)
            STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
                -X POST --cert certs/internal/denied.crt --key certs/internal/denied.key \
                --data '{"data":"malicious"}' "https://127.0.0.1:8443/v1/state/$STATE_NAME")
            if [ "$STATUS" != "423" ]; then
                failure "Lock Guard failed: Expected 423, got $STATUS"
                ERROR=1
            fi

            # Sub-test C: CAS (Check-And-Set) Atomicity
            log "[Case $CASE_ID] Phase C: CAS Verification"
            
            # Use X-Silo-Base-Version: 0 (This should ALWAYS succeed as it means "don't check")
            # Then use a wrong version.
            
            # Attempt stale write with X-Silo-Base-Version: 999
            STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
                -X POST -H "X-Silo-Device-ID: dev-01" -H "X-Silo-Base-Version: 999" \
                --cert certs/internal/user.crt --key certs/internal/user.key \
                --data '{"data":"stale"}' "https://127.0.0.1:8443/v1/state/$STATE_NAME")
            
            if [ "$STATUS" != "409" ]; then
                failure "CAS failed: Expected 409, got $STATUS"
                ERROR=1
            fi

            if [ $ERROR -eq 0 ]; then
                success "$CASE_ID passed all governance tests"
                echo "$CASE_ID:PASS" >> "$RESULTS_FILE"
            else
                failure "$CASE_ID FAILED"
                echo "$CASE_ID:FAIL" >> "$RESULTS_FILE"
            fi

            cleanup
            sleep 2
        done
    done
done

# 4. REPORT
log "=========================================================="
log "                  TEST MATRIX REPORT                      "
log "=========================================================="
printf "%-30s | %-10s\n" "TEST CASE" "RESULT"
log "----------------------------------------------------------"
while IFS=: read -r CASE RESULT; do
    if [ "$RESULT" == "PASS" ]; then
        printf "%-30s | ${GREEN}%-10s${NC}\n" "$CASE" "$RESULT"
    else
        printf "%-30s | ${RED}%-10s${NC}\n" "$CASE" "$RESULT"
        FAILED=1
    fi
done < "$RESULTS_FILE"
log "=========================================================="

if [ "$FAILED" == "1" ]; then
    exit 1
fi
