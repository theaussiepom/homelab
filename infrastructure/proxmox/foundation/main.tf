resource "proxmox_network_linux_bridge" "trunk" {
  node_name  = var.site.node
  name       = var.foundation.bridge_name
  ports      = var.foundation.bridge_ports
  vlan_aware = true
  reload     = false # Stage only; exact network apply/adoption remains separately qualified.
  mtu        = var.foundation.mtu
  lifecycle { prevent_destroy = true }
}
resource "proxmox_storage_zfspool" "local" {
  id             = var.foundation.storage_id
  zfs_pool       = var.foundation.zfs_pool
  nodes          = [var.site.node]
  content        = ["images", "rootdir"]
  thin_provision = true
  lifecycle { prevent_destroy = true }
}
# Datacenter/node firewall objects and network apply/adoption are held pending
# exact provider schema/role qualification. Never fill that gap with a provisioner.
