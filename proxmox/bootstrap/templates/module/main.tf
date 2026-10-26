resource "proxmox_virtual_environment_container" "guest" {
  node_name        = var.node
  vm_id            = var.guest.vmid
  description      = "Homelab initial deployment guest"
  unprivileged     = true
  protection       = true
  started          = true
  start_on_boot    = true
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
  operating_system {
    template_file_id = var.guest.template_file_id
    type             = "debian"
  }
  initialization {
    hostname = "deploy"
    user_account { keys = var.ssh_public_keys }
    ip_config {
      ipv4 {
        address = var.guest.ipv4
        gateway = var.guest.gateway
      }
    }
    dynamic "dns" {
      for_each = length(var.guest.dns_servers) > 0 ? [1] : []
      content { servers = var.guest.dns_servers }
    }
  }
  network_interface {
    name        = "eth0"
    bridge      = var.guest.bridge
    vlan_id     = var.guest.vlan
    mac_address = var.guest.mac
    firewall    = true
  }
  startup { order = 1 }
  wait_for_ip { ipv4 = true }
  lifecycle {
    prevent_destroy = true
    # The host-side bootstrap owns and verifies its sole NAS bind mount.
    # A separated API token must not gain arbitrary host-path mount authority.
    ignore_changes = [mount_point]
  }
}

resource "proxmox_virtual_environment_firewall_options" "guest" {
  node_name     = var.node
  container_id  = proxmox_virtual_environment_container.guest.vm_id
  enabled       = true
  dhcp          = true
  input_policy  = "DROP"
  output_policy = "ACCEPT"
  lifecycle { prevent_destroy = true }
}

resource "proxmox_virtual_environment_firewall_rules" "ssh" {
  node_name    = var.node
  container_id = proxmox_virtual_environment_container.guest.vm_id
  rule {
    type    = "in"
    action  = "ACCEPT"
    proto   = "tcp"
    dport   = "22"
    source  = var.admin_cidr
    comment = "Bootstrap SSH from the administration network"
  }
  depends_on = [proxmox_virtual_environment_firewall_options.guest]
  lifecycle { prevent_destroy = true }
}

output "identity" {
  value = { vmid = proxmox_virtual_environment_container.guest.vm_id, name = "deploy", ipv4 = var.guest.ipv4 }
}
