mock_provider "proxmox" {}

variables {
  ssh_public_keys  = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
  protected_guests = [900]
  node             = "practice-pve"
  guest            = jsondecode(file("tests/base-guest.json"))
}

run "omission_has_no_ipsets_or_global_filter" {
  command = plan
  module { source = "./guest" }
  assert {
    condition     = length(proxmox_virtual_environment_firewall_ipset.ip_filter) == 0 && proxmox_virtual_environment_firewall_options.guest.ipfilter != true
    error_message = "Existing consumers must not acquire per-NIC or guest-wide IP filters."
  }
}

run "one_selected_static_nic_only" {
  command = plan
  module { source = "./guest" }
  variables {
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      interfaces = concat(jsondecode(file("tests/base-guest.json")).interfaces, [{
        bridge = "practice-backend", mac = "02:00:00:30:61:01", ipv4 = "198.18.30.20/24", ipv6 = "manual", ip_filter = true
      }])
    })
  }
  assert {
    condition = (
      length(proxmox_virtual_environment_firewall_ipset.ip_filter) == 1 &&
      contains(keys(proxmox_virtual_environment_firewall_ipset.ip_filter), "1") &&
      proxmox_virtual_environment_firewall_ipset.ip_filter["1"].name == "ipfilter-net1" &&
      proxmox_virtual_environment_firewall_ipset.ip_filter["1"].node_name == var.node &&
      proxmox_virtual_environment_firewall_ipset.ip_filter["1"].container_id == var.guest.vmid &&
      (proxmox_virtual_environment_firewall_ipset.ip_filter["1"].cidr == null ? true : length(proxmox_virtual_environment_firewall_ipset.ip_filter["1"].cidr) == 0) &&
      proxmox_virtual_environment_firewall_options.guest.ipfilter != true &&
      proxmox_virtual_environment_container.guest.network_interface[0].mac_address == var.guest.interfaces[0].mac &&
      proxmox_virtual_environment_firewall_rules.guest.container_id == var.guest.vmid
    )
    error_message = "Create only the selected empty per-NIC container set; keep global options and existing guest identities."
  }
}

run "explicit_false_has_no_ipsets" {
  command = plan
  module { source = "./guest" }
  variables {
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      interfaces = [merge(jsondecode(file("tests/base-guest.json")).interfaces[0], { ip_filter = false })]
    })
  }
  assert {
    condition     = length(proxmox_virtual_environment_firewall_ipset.ip_filter) == 0
    error_message = "False is the unchanged initial default, not enrollment."
  }
}

run "dhcp_filter_refuses" {
  command = plan
  module { source = "./guest" }
  variables {
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      interfaces = [merge(jsondecode(file("tests/base-guest.json")).interfaces[0], {
        ipv4 = "dhcp", gateway = null, ipv6 = "manual", ip_filter = true
      })]
    })
  }
  expect_failures = [var.guest]
}

run "automatic_ipv6_filter_refuses" {
  command = plan
  module { source = "./guest" }
  variables {
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      interfaces = [merge(jsondecode(file("tests/base-guest.json")).interfaces[0], { ip_filter = true })]
    })
  }
  expect_failures = [var.guest]
}
