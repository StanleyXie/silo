#!/bin/bash
# Kill any lingering processes
pkill -f "vault server"
pkill -f "tf-silos"
pkill -f "silo"
# Clean terraform state
rm -rf .terraform .terraform.lock.hcl terraform.tfstate*
echo "Cleanup complete."
