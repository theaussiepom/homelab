mock_provider "proxmox" {}

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
