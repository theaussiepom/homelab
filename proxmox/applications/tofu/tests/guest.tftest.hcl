mock_provider "proxmox" {}

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
  ssh_public_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
  guest           = jsondecode(file("tests/base-guest.json"))
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
