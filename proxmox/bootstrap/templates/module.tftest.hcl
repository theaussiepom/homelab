mock_provider "proxmox" {}

run "running_protected_unprivileged_guest" {
  command = plan
  assert {
    condition = (
      proxmox_virtual_environment_container.guest.unprivileged &&
      proxmox_virtual_environment_container.guest.protection &&
      proxmox_virtual_environment_container.guest.started &&
      proxmox_virtual_environment_container.guest.start_on_boot &&
      length(proxmox_virtual_environment_container.guest.network_interface) == 1 &&
      proxmox_virtual_environment_container.guest.network_interface[0].firewall &&
      proxmox_virtual_environment_firewall_options.guest.input_policy == "DROP" &&
      proxmox_virtual_environment_firewall_options.guest.output_policy == "ACCEPT" &&
      proxmox_virtual_environment_firewall_rules.ssh.rule[0].source == var.admin_cidr
    )
    error_message = "The deployment guest must boot, accept administration SSH and remain protected/unprivileged."
  }
}
