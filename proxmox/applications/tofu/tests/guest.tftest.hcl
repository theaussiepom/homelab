mock_provider "proxmox" {}

run "explicit_backup_flags_preserve_managed_volume_paths_and_sizes" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      volumes = {
        retained = { path = "/srv/retained", size_gib = 8, backup = true }
        cache    = { path = "/srv/cache", size_gib = 2, backup = false }
      }
      volume_order = ["retained", "cache"]
    })
  }
  assert {
    condition = (
      proxmox_virtual_environment_container.guest.mount_point[0].backup &&
      !proxmox_virtual_environment_container.guest.mount_point[1].backup &&
      proxmox_virtual_environment_container.guest.mount_point[0].path == "/srv/retained" &&
      proxmox_virtual_environment_container.guest.mount_point[1].path == "/srv/cache" &&
      proxmox_virtual_environment_container.guest.mount_point[0].size == "8G" &&
      proxmox_virtual_environment_container.guest.mount_point[1].size == "2G"
    )
    error_message = "Only the declared native backup flags change; volume identities, order and sizes stay explicit."
  }
}

run "dedicated_backup_staging_is_a_new_unprotected_pool_allocation" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      volumes = {
        retained = { path = "/srv/retained", size_gib = 8, backup = true }
        staging  = { path = "/srv/backup-stage", size_gib = 1, backup = false }
      }
      volume_order = ["retained", "staging"]
    })
  }
  assert {
    condition = (
      length(proxmox_virtual_environment_container.guest.mount_point) == 2 &&
      proxmox_virtual_environment_container.guest.mount_point[0].path == "/srv/retained" &&
      proxmox_virtual_environment_container.guest.mount_point[0].backup &&
      proxmox_virtual_environment_container.guest.mount_point[1].path == "/srv/backup-stage" &&
      proxmox_virtual_environment_container.guest.mount_point[1].size == "1G" &&
      proxmox_virtual_environment_container.guest.mount_point[1].volume == var.guest.storage_id &&
      !proxmox_virtual_environment_container.guest.mount_point[1].backup &&
      proxmox_virtual_environment_container.guest.mount_point[1].replicate &&
      length(setsubtract(toset(keys(proxmox_virtual_environment_container.guest.mount_point[1])), toset([
        "path", "size", "volume", "backup", "replicate", "acl", "quota", "read_only", "shared", "mount_options", "path_in_datastore"
      ]))) == 0 &&
      alltrue([for flag in [
        proxmox_virtual_environment_container.guest.mount_point[1].acl,
        proxmox_virtual_environment_container.guest.mount_point[1].quota,
        proxmox_virtual_environment_container.guest.mount_point[1].read_only,
        proxmox_virtual_environment_container.guest.mount_point[1].shared
      ] : flag == null || flag == false]) &&
      (proxmox_virtual_environment_container.guest.mount_point[1].mount_options == null ? true : length(proxmox_virtual_environment_container.guest.mount_point[1].mount_options) == 0)
    )
    error_message = "Staging uses a fresh last-slot allocation in the selected pool, never an existing volume or app backup."
  }
}

run "omitted_internal_backup_flag_preserves_the_existing_provider_default" {
  command = plan
  module { source = "./guest" }
  variables {
    node  = "practice-pve"
    guest = jsondecode(file("tests/base-guest.json"))
  }
  assert {
    condition     = alltrue([for volume in proxmox_virtual_environment_container.guest.mount_point : volume.backup])
    error_message = "Existing callers without the root PBS feature retain their previous native volume protection."
  }
}

run "ipv6_discovery_mld_and_ipv4_membership_reach_the_pinned_provider" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [
        { direction = "in", proto = "udp", source = "fe80::/64", destination = "ff02::fb/128", port = "5353", interface = "net0", comment = "Selected IPv6 mDNS" },
        { direction = "in", proto = "icmpv6", source = "fe80::/64", destination = "ff02::1/128", port = "130", interface = "net0", comment = "Selected MLD query" },
        { direction = "out", proto = "icmpv6", source = "fe80::1/128", destination = "ff02::16/128", port = "143", interface = "net0", comment = "Selected MLD report" },
        { direction = "out", proto = "igmp", source = "198.18.100.20/32", destination = "224.0.0.22/32", interface = "net0", comment = "Selected IPv4 membership" }
      ]
    })
  }
  assert {
    condition = (
      proxmox_virtual_environment_firewall_rules.guest.rule[0].source == "fe80::/64" &&
      proxmox_virtual_environment_firewall_rules.guest.rule[0].dest == "ff02::fb/128" &&
      proxmox_virtual_environment_firewall_rules.guest.rule[0].dport == "5353" &&
      proxmox_virtual_environment_firewall_rules.guest.rule[1].proto == "icmpv6" &&
      proxmox_virtual_environment_firewall_rules.guest.rule[1].dport == "130" &&
      proxmox_virtual_environment_firewall_rules.guest.rule[2].dport == "143" &&
      proxmox_virtual_environment_firewall_rules.guest.rule[3].proto == "igmp" &&
      alltrue([for row in proxmox_virtual_environment_firewall_rules.guest.rule : row.iface == "net0" && row.action == "ACCEPT"])
    )
    error_message = "Preserve family, group, ICMP type, interface and order at the actual provider boundary."
  }
  assert {
    condition = (
      proxmox_virtual_environment_firewall_options.guest.enabled &&
      proxmox_virtual_environment_firewall_options.guest.ndp &&
      !proxmox_virtual_environment_firewall_options.guest.radv &&
      proxmox_virtual_environment_firewall_options.guest.input_policy == "DROP" &&
      proxmox_virtual_environment_firewall_options.guest.output_policy == "DROP"
    )
    error_message = "Adding rule values must preserve the existing guest options; cluster enforcement is outside this module."
  }
}

run "mixed_firewall_address_families_refuse" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "out", proto = "udp", source = "198.18.100.20/32", destination = "ff02::fb/128", port = "5353", comment = "Wrong family" }]
    })
  }
  expect_failures = [var.guest]
}

run "ipv4_igmp_cannot_select_ipv6" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "out", proto = "igmp", destination = "ff02::16/128", comment = "Wrong protocol family" }]
    })
  }
  expect_failures = [var.guest]
}

run "icmpv6_cannot_select_ipv4" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "out", proto = "icmpv6", destination = "224.0.0.22/32", port = "143", comment = "Wrong protocol family" }]
    })
  }
  expect_failures = [var.guest]
}

run "igmp_cannot_have_transport_ports" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "out", proto = "igmp", destination = "224.0.0.22/32", port = "1900", comment = "No IGMP port" }]
    })
  }
  expect_failures = [var.guest]
}

run "icmpv6_type_is_one_byte_not_a_port_range" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "out", proto = "icmpv6", destination = "ff02::16/128", port = "130:143", comment = "No ICMP range" }]
    })
  }
  expect_failures = [var.guest]
}

run "scoped_literal_cannot_replace_interface_binding" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "out", proto = "udp", destination = "ff02::fb%eth0", port = "5353", comment = "Select interface explicitly" }]
    })
  }
  expect_failures = [var.guest]
}

run "ipv6_zero_prefix_spelling_refuses" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "in", proto = "udp", source = "::/00", port = "5353", comment = "No unrestricted source" }]
    })
  }
  expect_failures = [var.guest]
}

run "ipv6_host_bits_with_zero_prefix_refuse" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "in", proto = "udp", source = "2001:db8::/00", port = "5353", comment = "No unrestricted source" }]
    })
  }
  expect_failures = [var.guest]
}

run "ipv6_three_zero_prefix_spelling_refuses" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "in", proto = "udp", source = "::/000", port = "5353", comment = "No unrestricted source" }]
    })
  }
  expect_failures = [var.guest]
}

run "ipv4_zero_prefix_spelling_refuses" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "in", proto = "udp", source = "0.0.0.0/00", port = "5353", comment = "No unrestricted source" }]
    })
  }
  expect_failures = [var.guest]
}

run "ipv4_host_bits_with_zero_prefix_refuse" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "in", proto = "udp", source = "192.0.2.1/00", port = "5353", comment = "No unrestricted source" }]
    })
  }
  expect_failures = [var.guest]
}

run "null_inbound_source_refuses_without_a_function_error" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "in", proto = "udp", source = null, port = "5353", comment = "Source required" }]
    })
  }
  expect_failures = [var.guest]
}

run "invalid_inbound_source_refuses_without_a_function_error" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "in", proto = "udp", source = "not-an-address", port = "5353", comment = "Literal source required" }]
    })
  }
  expect_failures = [var.guest]
}

run "bare_inbound_addresses_keep_host_scope" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [
        { direction = "in", proto = "udp", source = "192.0.2.10", port = "5353", comment = "IPv4 host" },
        { direction = "in", proto = "udp", source = "2001:db8::10", port = "5353", comment = "IPv6 host" }
      ]
    })
  }
  assert {
    condition = (
      proxmox_virtual_environment_firewall_rules.guest.rule[0].source == "192.0.2.10" &&
      proxmox_virtual_environment_firewall_rules.guest.rule[1].source == "2001:db8::10"
    )
    error_message = "Bare literals remain single hosts and do not acquire a /0 permission."
  }
}

run "interface_scoped_firewall_reaches_the_provider" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "out", proto = "tcp", port = "443", destination = "198.19.107.23/32", interface = "net0", comment = "Inverter fixture" }]
    })
  }
  assert {
    condition     = proxmox_virtual_environment_firewall_rules.guest.rule[0].iface == "net0"
    error_message = "A scoped interface must reach the actual provider rule."
  }
}

run "undeclared_firewall_interface_is_rejected" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "out", proto = "tcp", port = "443", destination = "198.19.107.23/32", interface = "net2", comment = "Invalid interface fixture" }]
    })
  }
  expect_failures = [var.guest]
}

run "active_radio_leaves_host_devices_to_its_capability" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      vmid = 209, hostname = "radio", started = true, start_on_boot = true
    })
  }
  assert {
    condition     = proxmox_virtual_environment_container.guest.started && proxmox_virtual_environment_container.guest.start_on_boot
    error_message = "Radio must deploy active and start at boot."
  }
  assert {
    condition     = length(proxmox_virtual_environment_container.guest.device_passthrough) == 0
    error_message = "Device attachment belongs to the restricted host capability, outside token-authenticated API requests."
  }
}

run "stopped_desired_state_is_rejected" {
  command = plan
  module { source = "./guest" }
  variables {
    node  = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), { started = false })
  }
  expect_failures = [var.guest]
}


variables {
  site = {
    node         = "practice-pve"
    api_endpoint = "https://pve.example.invalid:8006/"
  }
  protected_guests = [900]
  ssh_public_keys  = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
  guest            = jsondecode(file("tests/base-guest.json"))
}

run "one_unprivileged_guest_and_drop_firewall" {
  command = plan
  assert {
    condition     = module.guest.identity.vmid == 6101
    error_message = "The plan must select only the application guest."
  }
  assert {
    condition     = length(module.guest.identity.interfaces) == 1
    error_message = "Guest interfaces must match the private selection."
  }
}

run "protected_controller_is_rejected" {
  command = plan
  module {
    source = "./guest"
  }
  variables {
    node = "practice-pve"
    guest = {
      vmid        = 900, hostname = "practice-controller", cpu = 1, memory_mib = 1024,
      root_gib    = 8, storage_id = "practice-zfs", template_file_id = "practice:vztmpl/debian.tar.zst",
      started     = true, start_on_boot = true, boot_order = 10, nesting = false, keyctl = false,
      dns_servers = ["198.18.100.53"],
      interfaces  = [{ bridge = "vmbr0", mac = "02:00:00:00:09:00", ipv4 = "198.18.25.11/24", gateway = "198.18.25.1" }],
      volumes     = {}, rules = []
    }
  }
  expect_failures = [var.guest]
}

run "fractional_memory_is_rejected" {
  command = plan
  module { source = "./guest" }
  variables {
    node  = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), { memory_mib = 256.5 })
  }
  expect_failures = [var.guest]
}

run "dhcp_guest_has_automatic_dhcp_firewall_support" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      interfaces = [{ bridge = "vmbr0", mac = "02:00:00:00:61:01", ipv4 = "dhcp" }]
    })
  }
  assert {
    condition     = proxmox_virtual_environment_firewall_options.guest.dhcp
    error_message = "DHCP leases must not be blocked by the guest firewall."
  }
}

run "fractional_root_disk_is_rejected" {
  command = plan
  module { source = "./guest" }
  variables {
    node  = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), { root_gib = 4.5 })
  }
  expect_failures = [var.guest]
}

run "fractional_boot_order_is_rejected" {
  command = plan
  module { source = "./guest" }
  variables {
    node  = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), { boot_order = 1.5 })
  }
  expect_failures = [var.guest]
}

run "fractional_volume_size_is_rejected" {
  command = plan
  module { source = "./guest" }
  variables {
    node  = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), { volumes = { data = { path = "/srv/homelab", size_gib = 1.5 } } })
  }
  expect_failures = [var.guest]
}
