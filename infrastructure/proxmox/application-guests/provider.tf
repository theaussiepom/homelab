provider "proxmox" {
  endpoint = var.site.api_endpoint
  insecure = false
  # Authentication is supplied only through scoped private environment inputs.
}
