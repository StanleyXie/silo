#!/bin/bash
# Silo Quickstart - From Zero to Running in 30 Seconds
# This script starts Vault in dev mode, launches Silo, and prepares a Terraform demo.

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[PASS]${NC} $1"; }

# 1. Prerequisite Check
log "Checking prerequisites..."
PREREQS=("vault" "terraform" "openssl")
for cmd in "${PREREQS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${BOLD}Error:${NC} $cmd is not installed. Please install it first."
        exit 1
    fi
done

# Check for silo (brew installed or local build)
SILO_CMD="silo"
if ! command -v silo &> /dev/null; then
    if [ -f "./target/release/silo" ]; then
        SILO_CMD="./target/release/silo"
    else
        log "Silo binary not found. Building with cargo..."
        cargo build --release
        SILO_CMD="./target/release/silo"
    fi
fi

# 2. Cleanup old demo stuff
cleanup() {
    log "Cleaning up demo processes..."
    pkill -9 silo || true
    pkill -9 vault || true
    rm -f main.tf silo_quickstart.yaml vault_quickstart.log silo_quickstart.log
}
trap cleanup EXIT
cleanup

# 3. Start Vault
log "Starting Vault (Dev Mode)..."
vault server -dev -dev-root-token-id="root" > vault_quickstart.log 2>&1 &
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
sleep 3
vault secrets enable -path=secret kv-v2 2>/dev/null || true

# 4. Start Silo
log "Launching Silo..."
# Create a minimal quickstart config
cat > silo_quickstart.yaml <<EOF
gateway:
  address: "127.0.0.1:8443"
storage:
  type: "vault"
  vault:
    address: "http://127.0.0.1:8200"
    token: "root"
EOF

export SILO_CONFIG="silo_quickstart.yaml"
$SILO_CMD > silo_quickstart.log 2>&1 &
sleep 5

# 5. Prepare Terraform
log "Preparing Terraform Demo..."
cat > main.tf <<EOF
terraform {
  backend "http" {
    address        = "https://127.0.0.1:8443/v1/state/quickstart/dev"
    lock_address   = "https://127.0.0.1:8443/v1/lock/quickstart/dev"
    unlock_address = "https://127.0.0.1:8443/v1/lock/quickstart/dev"
    lock_method    = "POST"
    unlock_method  = "DELETE"
    skip_cert_verification = true
  }
}

resource "random_pet" "server" {
  length = 2
}

output "pet_name" {
  value = random_pet.server.id
}
EOF

echo -e "\n${BOLD}Silo Quickstart is Ready!${NC}"
echo -e "----------------------------------------------------------"
echo -e "1. ${BOLD}Initialize Terraform:${NC}"
echo -e "   terraform init"
echo -e ""
echo -e "2. ${BOLD}Apply Configuration:${NC}"
echo -e "   terraform apply"
echo -e ""
echo -e "3. ${BOLD}Verify in Vault:${NC}"
echo -e "   vault kv get secret/quickstart/dev"
echo -e "----------------------------------------------------------"
echo -e "${BLUE}Logs:${NC} silo_quickstart.log, vault_quickstart.log"
echo -e "Press Ctrl+C to stop the demo and cleanup."

# Keep script running to maintain processes
wait
