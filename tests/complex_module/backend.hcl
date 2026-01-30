# Backend configuration for Silo
address        = "https://127.0.0.1:8443/v1/state/complex-app/prod"
lock_address   = "https://127.0.0.1:8443/v1/lock/complex-app/prod"
unlock_address = "https://127.0.0.1:8443/v1/lock/complex-app/prod"
lock_method    = "POST"
unlock_method  = "DELETE"
skip_cert_verification = true 
