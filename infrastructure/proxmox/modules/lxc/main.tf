resource "proxmox_virtual_environment_container" "guest" {
  node_name        = var.node
  vm_id            = var.guest.vmid
  description      = "Catalog-managed guest; native lifecycle owns later power state"
  unprivileged     = true
  protection       = true
  started          = false
  start_on_boot    = false
  migrate          = false
  purge_on_destroy = false
  cpu { cores = var.guest.cpu }
  memory {
    dedicated = var.guest.memory_mib # LXC limit; not physically reserved RAM.
    swap      = 0
  }
  disk {
    datastore_id = var.guest.storage_id
    size         = var.guest.root_gib
    replicate    = true
  }
  features {
    nesting = var.guest.nesting
    keyctl  = var.guest.keyctl
  }
  dynamic "idmap" {
    for_each = var.guest.idmaps == null ? [] : var.guest.idmaps
    content {
      type         = idmap.value.type
      container_id = idmap.value.container_id
      host_id      = idmap.value.host_id
      size         = idmap.value.size
    }
  }
  operating_system {
    template_file_id = var.guest.template_file_id
    type             = var.guest.os_type
  }
  initialization {
    hostname = var.guest.key
    user_account { keys = var.ssh_public_keys }
    dynamic "ip_config" {
      for_each = var.guest.interfaces
      content {
        ipv4 { address = "dhcp" }
      }
    }
  }
  dynamic "network_interface" {
    for_each = var.guest.interfaces
    iterator = nic
    content {
      name        = "eth${nic.key}"
      bridge      = nic.value.bridge
      mac_address = nic.value.mac
      vlan_id     = nic.value.vlan
      firewall    = true
      enabled     = true
    }
  }
  dynamic "mount_point" {
    for_each = var.guest.mounts
    content {
      volume    = var.guest.storage_id
      size      = "${mount_point.value.size_gib}G"
      path      = mount_point.value.path
      backup    = true
      replicate = mount_point.value.replicate
    }
  }
  startup { order = var.guest.boot_order }
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [started, start_on_boot]
  }
}

resource "proxmox_virtual_environment_firewall_options" "guest" {
  node_name     = var.node
  container_id  = proxmox_virtual_environment_container.guest.vm_id
  enabled       = true
  dhcp          = true
  macfilter     = true
  ndp           = true
  radv          = false
  input_policy  = "DROP"
  output_policy = "DROP"
  lifecycle { prevent_destroy = true }
}

output "identity" {
  value = { vmid = proxmox_virtual_environment_container.guest.vm_id, name = var.guest.key }
}
