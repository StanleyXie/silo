terraform {
  backend "http" {
    address        = "https://127.0.0.1:8443/v1/state/fulltest/dev"
    lock_address   = "https://127.0.0.1:8443/v1/lock/fulltest/dev"
    unlock_address = "https://127.0.0.1:8443/v1/lock/fulltest/dev"
    client_certificate     = "/Users/stanleyxie/.silo/certs/internal/gateway.crt"
    client_key             = "/Users/stanleyxie/.silo/certs/internal/gateway.key"
    skip_cert_verification = true
  }
}

resource "null_resource" "test" {}
