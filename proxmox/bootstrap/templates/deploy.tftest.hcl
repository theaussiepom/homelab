mock_provider "proxmox" {
  mock_resource "proxmox_virtual_environment_download_file" {
    defaults = { id = "local:vztmpl/debian-13.tar.zst" }
  }
}

run "single_deploy_guest" {
  command = plan
  assert {
    condition     = output.deploy_identity.name == "deploy" && output.deploy_identity.vmid == var.deploy.vmid
    error_message = "Only the catalog deployment guest may be selected."
  }
}

run "fresh_host_template_download" {
  command = plan
  variables {
    template = {
      url          = "https://example.invalid/debian-13.tar.zst"
      sha256       = "1111111111111111111111111111111111111111111111111111111111111111"
      file_name    = "debian-13.tar.zst"
      datastore_id = "local"
    }
  }
  assert {
    condition = (
      proxmox_virtual_environment_download_file.template[0].content_type == "vztmpl" &&
      proxmox_virtual_environment_download_file.template[0].checksum == var.template.sha256 &&
      proxmox_virtual_environment_download_file.template[0].checksum_algorithm == "sha256"
    )
    error_message = "A fresh host must download the exact pinned template before guest creation."
  }
}
