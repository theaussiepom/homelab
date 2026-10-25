resource "proxmox_virtual_environment_container" "guest" {
  node_name        = var.node
  vm_id            = var.guest.vmid
  description      = "Homelab application guest managed by its private deployment repository"
  unprivileged     = true
  protection       = true
  started          = var.guest.started
  start_on_boot    = var.guest.start_on_boot
  purge_on_destroy = false
  cpu { cores = var.guest.cpu }
  memory {
    dedicated = var.guest.memory_mib
    swap      = 0
  }
  disk {
    datastore_id = var.guest.storage_id
    size         = var.guest.root_gib
  }
  features {
    nesting = var.guest.nesting
    keyctl  = var.guest.keyctl
  }
  operating_system {
    template_file_id = var.guest.template_file_id
    type             = "debian"
  }
  initialization {
    hostname = var.guest.hostname
    user_account { keys = var.ssh_public_keys }
    dns { servers = var.guest.dns_servers }
    dynamic "ip_config" {
      for_each = var.guest.interfaces
      content {
        ipv4 {
          address = ip_config.value.ipv4
          gateway = ip_config.value.gateway
        }
        dynamic "ipv6" {
          for_each = ip_config.value.ipv6 == null ? [] : [ip_config.value.ipv6]
          content { address = ipv6.value }
        }
      }
    }
  }
  dynamic "network_interface" {
    for_each = var.guest.interfaces
    content {
      name        = "eth${network_interface.key}"
      bridge      = network_interface.value.bridge
      vlan_id     = network_interface.value.vlan
      mac_address = network_interface.value.mac
      firewall    = true
    }
  }
  dynamic "mount_point" {
    for_each = var.guest.volumes
    content {
      volume    = var.guest.storage_id
      size      = "${mount_point.value.size_gib}G"
      path      = mount_point.value.path
      backup    = true
      replicate = true
    }
  }
  startup { order = var.guest.boot_order }
  wait_for_ip { ipv4 = true }
  lifecycle { prevent_destroy = true }
}

resource "proxmox_virtual_environment_firewall_options" "guest" {
  node_name     = var.node
  container_id  = var.guest.vmid
  enabled       = true
  dhcp          = false
  ndp           = true
  radv          = false
  input_policy  = "DROP"
  output_policy = "DROP"
  depends_on    = [proxmox_virtual_environment_container.guest]
  lifecycle { prevent_destroy = true }
}

resource "proxmox_virtual_environment_firewall_rules" "guest" {
  node_name    = var.node
  container_id = var.guest.vmid
  dynamic "rule" {
    for_each = var.guest.rules
    content {
      type    = rule.value.direction
      action  = "ACCEPT"
      proto   = rule.value.proto
      dport   = rule.value.port
      source  = rule.value.source
      dest    = rule.value.destination
      comment = rule.value.comment
    }
  }
  depends_on = [proxmox_virtual_environment_firewall_options.guest]
  lifecycle { prevent_destroy = true }
}

output "identity" {
  value = { vmid = var.guest.vmid, hostname = var.guest.hostname, interfaces = var.guest.interfaces }
}
