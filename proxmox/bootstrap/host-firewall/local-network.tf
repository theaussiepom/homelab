resource "proxmox_virtual_environment_firewall_alias" "local_network" {
  depends_on = [
    proxmox_virtual_environment_firewall_rules.host,
    proxmox_virtual_environment_cluster_firewall.cluster,
  ]
  name    = "local_network"
  cidr    = "${var.policy.host_address}/32"
  comment = "HomeLab standalone host management"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.policy.local_network == "host-only"
      error_message = "Select host-only management trust before managing the local network alias."
    }
  }
}
