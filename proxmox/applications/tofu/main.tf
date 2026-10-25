provider "proxmox" {
  endpoint = var.site.api_endpoint
  insecure = false
}

variable "site" {
  type = object({ node = string, api_endpoint = string })
  validation {
    condition     = can(regex("^https://[^/]+:8006/$", var.site.api_endpoint))
    error_message = "Use the verified HTTPS Proxmox endpoint, including port 8006 and the trailing slash."
  }
}

variable "guest" {
  type = any
}

variable "ssh_public_keys" {
  type = list(string)
  validation {
    condition     = length(var.ssh_public_keys) > 0 && alltrue([for key in var.ssh_public_keys : can(regex("^ssh-ed25519 [A-Za-z0-9+/=]+$", key))])
    error_message = "Supply the deployment public key, without a comment or private key material."
  }
}

module "guest" {
  source          = "./guest"
  node            = var.site.node
  guest           = var.guest
  ssh_public_keys = var.ssh_public_keys
}

output "identity" {
  value = module.guest.identity
}
