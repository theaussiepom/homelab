resource "proxmox_virtual_environment_container" "guest" {
  node_name = var.node
  vm_id     = var.guest.vmid
  description = join("\n", concat(
    ["Homelab application guest managed by its private deployment repository"],
    [for key in sort(keys(var.guest.routing_labels)) : "${key}: ${var.guest.routing_labels[key]}"]
  ))
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
        ipv6 { address = coalesce(ip_config.value.ipv6, "manual") }
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
    for_each = [for key in(var.guest.volume_order == null ? sort(keys(var.guest.volumes)) : var.guest.volume_order) : var.guest.volumes[key]]
    content {
      volume    = var.guest.storage_id
      size      = "${mount_point.value.size_gib}G"
      path      = mount_point.value.path
      backup    = mount_point.value.backup
      replicate = true
    }
  }
  startup { order = var.guest.boot_order }
  wait_for_ip { ipv4 = true }
  lifecycle {
    prevent_destroy = true
    # A registered host capability owns devices; API tokens cannot modify them.
    ignore_changes = [device_passthrough]
  }
}

resource "proxmox_virtual_environment_firewall_options" "guest" {
  node_name     = var.node
  container_id  = var.guest.vmid
  enabled       = true
  dhcp          = anytrue([for nic in var.guest.interfaces : nic.ipv4 == "dhcp"])
  ndp           = true
  radv          = false
  input_policy  = "DROP"
  output_policy = "DROP"
  depends_on    = [proxmox_virtual_environment_container.guest]
  lifecycle { prevent_destroy = true }
}

resource "proxmox_virtual_environment_firewall_ipset" "ip_filter" {
  for_each = { for slot, nic in var.guest.interfaces : tostring(slot) => nic if nic.ip_filter }

  node_name    = var.node
  container_id = var.guest.vmid
  name         = "ipfilter-net${each.key}"
  comment      = "HomeLab per-interface source IP filter"

  # Empty LXC sets inherit only this NIC's configured addresses and MAC-derived
  # IPv6 link-local address. Do not enable the guest-wide ipfilter option.
  depends_on = [proxmox_virtual_environment_firewall_options.guest]
  lifecycle { prevent_destroy = true }
}

locals {
  # Keep the validated logical rules intact. Bound only adjacent, otherwise
  # identical transport allowances into the provider's literal destination list.
  firewall_rule_keys = [
    for rule in var.guest.rules : rule.destination == null ? null : (
      contains(["tcp", "udp"], rule.proto) && can(regex("^[0-9A-Fa-f:./]+$", rule.destination)) ? jsonencode({
        fields = { for name, value in rule : name => value if name != "destination" }
        ipv6   = strcontains(rule.destination, ":")
      }) : null
    )
  ]
  firewall_rule_starts = [
    for index, key in local.firewall_rule_keys : index
    if key == null ? true : (index == 0 ? true : key != local.firewall_rule_keys[index - 1])
  ]
  firewall_rule_chunks = flatten([
    for group, start in local.firewall_rule_starts : [
      for rows in chunklist(slice(var.guest.rules, start,
        concat(local.firewall_rule_starts, [length(var.guest.rules)])[group + 1]), 8) : {
        rows        = rows
        destination = local.firewall_rule_keys[start] == null ? null : join(",", [for rule in rows : rule.destination])
      }
    ]
  ])
  firewall_rules = flatten([
    for chunk in local.firewall_rule_chunks : chunk.destination == null ? chunk.rows : (
      length(chunk.rows) == 1 || length(chunk.destination) > 512 ? chunk.rows : [
        merge(chunk.rows[0], { destination = chunk.destination })
      ]
    )
  ])
}

resource "proxmox_virtual_environment_firewall_rules" "guest" {
  node_name    = var.node
  container_id = var.guest.vmid
  dynamic "rule" {
    for_each = local.firewall_rules
    content {
      type    = rule.value.direction
      action  = "ACCEPT"
      proto   = rule.value.proto
      iface   = rule.value.interface
      dport   = rule.value.port
      source  = rule.value.source
      dest    = rule.value.destination
      comment = rule.value.comment
    }
  }
  depends_on = [proxmox_virtual_environment_firewall_options.guest, proxmox_virtual_environment_firewall_ipset.ip_filter]
  lifecycle { prevent_destroy = true }
}

output "identity" {
  value = {
    vmid       = var.guest.vmid
    hostname   = var.guest.hostname
    interfaces = [for nic in var.guest.interfaces : {
      for key, value in nic : key => value if key != "ip_filter" || nic.ip_filter
    }]
  }
}
