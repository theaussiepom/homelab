variable "guest" {
  type = object({
    vmid       = number, cpu = number, memory_mib = number, root_gib = number,
    storage_id = string, template_file_id = string, ipv4 = string,
    gateway    = optional(string), dns_servers = list(string),
    bridge     = string, vlan = optional(number), mac = string
  })
  validation {
    condition     = !contains([4914, 4915, 4920], var.guest.vmid) && var.guest.vmid >= 100
    error_message = "Choose an unused deployment guest ID; protected rehearsal IDs are excluded."
  }
}
variable "node" { type = string }
variable "ssh_public_keys" {
  type = list(string)
  validation {
    condition     = length(var.ssh_public_keys) > 0
    error_message = "Supply the bootstrap SSH public key."
  }
}
variable "admin_cidr" { type = string }
