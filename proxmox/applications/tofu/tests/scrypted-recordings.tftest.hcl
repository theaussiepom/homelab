mock_provider "proxmox" {}

variables {
  protected_guests = [900]
  ssh_public_keys  = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
}

run "recordings_append_preserves_local_state_and_pbs_staging" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      volumes = {
        state = { path = "/srv/state", size_gib = 16, backup = true }
        stage = { path = "/srv/backup-stage", size_gib = 16, backup = false }
      }
      volume_order = ["state", "stage"]
      recording_mount = {
        source = "/mnt/example/recordings"
        path   = "/srv/recordings"
        slot   = 2
      }
    })
  }
  assert {
    condition = (
      length(proxmox_virtual_environment_container.guest.mount_point) == 3 &&
      proxmox_virtual_environment_container.guest.mount_point[0].path == "/srv/state" &&
      proxmox_virtual_environment_container.guest.mount_point[0].size == "16G" &&
      proxmox_virtual_environment_container.guest.mount_point[0].backup &&
      proxmox_virtual_environment_container.guest.mount_point[0].replicate &&
      proxmox_virtual_environment_container.guest.mount_point[1].path == "/srv/backup-stage" &&
      proxmox_virtual_environment_container.guest.mount_point[1].size == "16G" &&
      !proxmox_virtual_environment_container.guest.mount_point[1].backup &&
      proxmox_virtual_environment_container.guest.mount_point[1].replicate &&
      proxmox_virtual_environment_container.guest.mount_point[2].volume == "/mnt/example/recordings" &&
      proxmox_virtual_environment_container.guest.mount_point[2].path == "/srv/recordings" &&
      proxmox_virtual_environment_container.guest.mount_point[2].size == "" &&
      !proxmox_virtual_environment_container.guest.mount_point[2].backup &&
      !proxmox_virtual_environment_container.guest.mount_point[2].replicate &&
      # The pinned SDK mock leaves this omitted optional flag null; the provider
      # and the later exact native/guest checks require the default writable bind.
      (proxmox_virtual_environment_container.guest.mount_point[2].read_only == null ||
      proxmox_virtual_environment_container.guest.mount_point[2].read_only == false)
    )
    error_message = "The NAS bind is the last exact mount and never becomes an allocated, backed-up or replicated local volume."
  }
}

run "recording_slot_cannot_replace_an_existing_local_volume" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      recording_mount = { source = "/mnt/example/recordings", path = "/srv/recordings", slot = 0 }
    })
  }
  expect_failures = [var.guest]
}

run "recording_source_cannot_expose_a_control_directory" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      recording_mount = { source = "/etc/example", path = "/srv/recordings", slot = 1 }
    })
  }
  expect_failures = [var.guest]
}

run "recording_target_cannot_shadow_guest_control_paths" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      recording_mount = { source = "/mnt/example/recordings", path = "/etc/example", slot = 1 }
    })
  }
  expect_failures = [var.guest]
}

run "recording_source_cannot_traverse_its_declared_root" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      recording_mount = { source = "/mnt/example/../private", path = "/srv/recordings", slot = 1 }
    })
  }
  expect_failures = [var.guest]
}
