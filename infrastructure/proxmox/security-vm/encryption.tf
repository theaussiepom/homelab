variable "state_passphrase" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.state_passphrase) >= 32
    error_message = "Use the independently recoverable private per-root state key."
  }
}
terraform {
  encryption {
    key_provider "pbkdf2" "root" { passphrase = var.state_passphrase }
    method "aes_gcm" "root" { keys = key_provider.pbkdf2.root }
    state {
      method   = method.aes_gcm.root
      enforced = true
    }
    plan {
      method   = method.aes_gcm.root
      enforced = true
    }
  }
}
