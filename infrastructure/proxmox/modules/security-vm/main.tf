variable "bootstrap_user" {
  type     = string
  nullable = false
}
resource "proxmox_virtual_environment_vm" "guest" {
  node_name                            = var.node
  vm_id                                = var.guest.vmid
  name                                 = var.guest.key
  description                          = "Frozen cloud-init birth record; later networking belongs to Ansible"
  protection                           = true
  started                              = false
  on_boot                              = false
  migrate                              = false
  reboot_after_update                  = false
  delete_unreferenced_disks_on_destroy = false
  agent { enabled = true }
  cpu { cores = var.guest.cpu }
  memory { dedicated = var.guest.memory_mib }
  disk {
    datastore_id = var.guest.storage_id
    interface    = "scsi0"
    file_id      = var.guest.template_file_id
    size         = var.guest.root_gib
    file_format  = "raw"
    backup       = true
  }
  dynamic "disk" {
    for_each = var.guest.mounts
    content {
      datastore_id = var.guest.storage_id
      interface    = disk.value.slot
      size         = disk.value.size_gib
      file_format  = "raw"
      backup       = true
    }
  }
  initialization {
    datastore_id = var.guest.storage_id
    user_account {
      username = var.bootstrap_user
      keys     = var.ssh_public_keys
    }
    dynamic "ip_config" {
      for_each = var.guest.interfaces
      content {
        ipv4 { address = "dhcp" }
      }
    }
  }
  dynamic "network_device" {
    for_each = var.guest.interfaces
    content {
      bridge      = network_device.value.bridge
      mac_address = network_device.value.mac
      vlan_id     = network_device.value.vlan
      firewall    = true
      model       = "virtio"
    }
  }
  startup { order = var.guest.boot_order }
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [started, on_boot, initialization]
  }
}
resource "proxmox_virtual_environment_firewall_options" "guest" {
  node_name     = var.node
  vm_id         = proxmox_virtual_environment_vm.guest.vm_id
  enabled       = true
  dhcp          = true
  macfilter     = true
  ndp           = true
  radv          = false
  input_policy  = "DROP"
  output_policy = "DROP"
  lifecycle { prevent_destroy = true }
}
output "identity" { value = { vmid = proxmox_virtual_environment_vm.guest.vm_id, name = var.guest.key } }
