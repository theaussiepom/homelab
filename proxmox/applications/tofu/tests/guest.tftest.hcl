mock_provider "proxmox" {}

variables {
  site = {
    node         = "practice-pve"
    api_endpoint = "https://pve.example.invalid:8006/"
  }
  ssh_public_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
  guest = {
    vmid        = 6101, hostname = "practice-automation", cpu = 2, memory_mib = 4096,
    root_gib    = 8, storage_id = "practice-zfs", template_file_id = "practice:vztmpl/debian.tar.zst",
    started     = true, start_on_boot = true, boot_order = 50, nesting = true, keyctl = true,
    dns_servers = ["198.18.100.53"],
    interfaces  = [{ bridge = "vmbr0", vlan = 100, mac = "02:00:00:00:61:01", ipv4 = "198.18.100.20/24", gateway = "198.18.100.1", ipv6 = "auto" }],
    volumes     = { appdata = { path = "/srv/homelab", size_gib = 16 } },
    rules = [{ direction = "in", proto = "tcp", port = "22", source = "198.18.25.11/32", comment = "Deployment guest SSH" },
    { direction = "out", proto = "tcp", port = "443", destination = "0.0.0.0/0", comment = "Pinned package/image downloads" }]
  }
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
