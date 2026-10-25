mock_provider "proxmox" {}

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
