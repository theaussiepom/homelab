mock_provider "proxmox" {}

run "single_deploy_guest" {
  command = plan
  assert {
    condition     = output.deploy_identity.name == "deploy" && output.deploy_identity.vmid == var.deploy.vmid
    error_message = "Only the catalog deployment guest may be selected."
  }
}

# Cached-template hash checking and SSH transfer are exercised by the Python
# fixtures. OpenTofu receives an existing template ID and creates only the guest.
