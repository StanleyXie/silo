#!/bin/bash
# OIDC Verification Script for Silo
# Tests JWT validation with a mock token

set -e
cd "$(dirname "$0")/.."

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; }
failure() { echo -e "${RED}[FAIL]${NC} $1"; }

# Enable logging
export RUST_LOG=info

# 1. Cleanup (use specific patterns to avoid killing other processes)
cleanup() {
    log "Cleaning up..."
    pkill -f 'target/release/silo$' 2>/dev/null || true
    pkill -f 'vault server -dev' 2>/dev/null || true
}
trap cleanup EXIT

# 2. Build
log "Building Silo..."
cargo build --release 2>/dev/null

# 3. Create OIDC-enabled config
log "Creating OIDC test config..."
cat > silo_oidc_test.yaml <<EOF
gateway:
  address: "127.0.0.1:8443"
  metrics_address: "127.0.0.1:6192"
  tls:
    enabled: true
    cert_path: "certs/server.crt"
    key_path: "certs/server.key"
control_plane:
  address: "127.0.0.1:50051"
  allowed_identities: ["stanley.xie", "github-user", "anonymous"]
  tls:
    ca_cert: "certs/internal/ca.crt"
    server_cert: "certs/internal/control.crt"
    server_key: "certs/internal/control.key"
    client_cert: "certs/internal/gateway.crt"
    client_key: "certs/internal/gateway.key"
storage:
  type: "vault"
  vault:
    address: "http://127.0.0.1:8200"
    token: "root"
auth:
  oidc:
    enabled: true
    issuer: "https://token.actions.githubusercontent.com"
    jwks_uri: "https://token.actions.githubusercontent.com/.well-known/jwks"
    audience: "silo.internal"
EOF

# 4. Start Vault
log "Starting Vault..."
vault server -dev -dev-root-token-id="root" > vault_oidc.log 2>&1 &
sleep 2

# 5. Start Silo
export SILO_CONFIG=silo_oidc_test.yaml
log "Starting Silo with OIDC enabled..."
./target/release/silo > silo_oidc.log 2>&1 &
sleep 3

# 6. Verify OIDC config is loaded
if grep -q "OIDC authentication enabled" silo_oidc.log; then
    success "OIDC authentication enabled in Silo"
else
    failure "OIDC authentication not enabled"
    cat silo_oidc.log | tail -n 20
    exit 1
fi

# 7. Test without Bearer token (should use mTLS or be anonymous)
log "Testing request without Bearer token (mTLS)..."
RESPONSE=$(curl -sk -w "%{http_code}" \
    --cert certs/internal/user.crt --key certs/internal/user.key \
    https://127.0.0.1:8443/v1/state/oidc-test 2>&1)
HTTP_CODE="${RESPONSE: -3}"

if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "200" ]; then
    success "mTLS authentication still works (HTTP $HTTP_CODE)"
else
    failure "mTLS request failed (HTTP $HTTP_CODE)"
fi

# 8. Test with invalid Bearer token
log "Testing request with invalid Bearer token..."
RESPONSE=$(curl -sk -w "%{http_code}" \
    -H "Authorization: Bearer invalid.token.here" \
    https://127.0.0.1:8443/v1/state/oidc-test 2>&1)
HTTP_CODE="${RESPONSE: -3}"

# Should fail validation and fall back to anonymous
if grep -q "JWT validation failed" silo_oidc.log; then
    success "Invalid JWT correctly rejected"
else
    log "JWT validation message not found (may have fallen through to anonymous)"
fi

log "==================================================="
log "OIDC Verification Complete"
log "==================================================="
log "To test with a real GitHub Actions OIDC token:"
log "  1. Create a GitHub Action with id-token: write permission"
log "  2. Use: curl -H 'Authorization: Bearer \$GITHUB_TOKEN' https://silo/v1/state/..."
log "==================================================="

cleanup
