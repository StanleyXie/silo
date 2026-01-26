#!/bin/bash
# Silo Quick Launch: Basic Configuration Example
# This script demonstrates how to launch Silo with a minimal Vault configuration.

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
header() { echo -e "\n${BOLD}=== $1 ===${NC}"; }

# 1. Prerequisite Check
log "Checking prerequisites..."
PREREQS=("vault" "terraform" "openssl")
for cmd in "${PREREQS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${BOLD}Error:${NC} $cmd is not installed. Please install it first."
        exit 1
    fi
done

# Check for released silo
if command -v silo &> /dev/null; then
    SILO_CMD="silo"
else
    echo -e "${BOLD}Error:${NC} Silo binary not found in PATH."
    echo -e "Install it via: ${BOLD}brew install StanleyXie/tap/silo${NC}"
    exit 1
fi

# 2. Cleanup
cleanup() {
    log "Cleaning up demo processes..."
    pkill -9 silo || true
    pkill -9 vault || true
    rm -f main.tf silo_quickstart.yaml vault_quickstart.log silo_quickstart.log
}
trap cleanup EXIT
cleanup

header "1. STARTING BACKEND (Vault)"
log "Launching Vault in development mode on http://127.0.0.1:8200"
vault server -dev -dev-root-token-id="root" > vault_quickstart.log 2>&1 &
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
sleep 3
# Enable KV-V2 engine for state storage
vault secrets enable -path=secret kv-v2 2>/dev/null || true

header "2. SILO CONFIGURATION"
# This serves as a template for a basic Silo mission
cat > silo_quickstart.yaml <<EOF
# Silo Basic Configuration Template
gateway:
  address: "127.0.0.1:8443"         # Listen address for Terraform clients
  metrics_address: "127.0.0.1:6192" # Prometheus metrics endpoint

storage:
  type: "vault"                     # State storage backend
  vault:
    address: "http://127.0.0.1:8200"
    token: "root"                   # Token for Vault access
EOF

log "Launching Silo with the following config (silo_quickstart.yaml):"
cat silo_quickstart.yaml
export SILO_CONFIG="silo_quickstart.yaml"
$SILO_CMD > silo_quickstart.log 2>&1 &
sleep 5

header "3. TERRAFORM USAGE"
log "Creating main.tf with Silo backend configuration..."
cat > main.tf <<EOF
terraform {
  backend "http" {
    # Silo serves as the secure gateway to Vault
    address        = "https://127.0.0.1:8443/v1/state/quickstart/dev"
    lock_address   = "https://127.0.0.1:8443/v1/lock/quickstart/dev"
    unlock_address = "https://127.0.0.1:8443/v1/lock/quickstart/dev"
    lock_method    = "POST"
    unlock_method  = "DELETE"
    skip_cert_verification = true # mTLS certificates are handled by Silo
  }
}

resource "random_pet" "server" {
  length = 2
}
EOF

echo -e "\n${GREEN}${BOLD}✔ Quick Launch Successful!${NC}"
echo -e "----------------------------------------------------------"
echo -e "Try it now:"
echo -e "  ${BOLD}terraform init && terraform apply${NC}"
echo -e ""
echo -e "Verify the state results in Vault:"
echo -e "  ${BOLD}vault kv get secret/quickstart/dev${NC}"
echo -e "----------------------------------------------------------"
echo -e "Press Ctrl+C to stop the demo and cleanup."

# Keep the script and its children alive
wait
