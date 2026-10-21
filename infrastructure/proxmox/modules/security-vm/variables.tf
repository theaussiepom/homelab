variable "guest" {
  description = "Validated catalog projection; unknown production fields remain null and held."
  type        = any
  validation {
    condition = alltrue([
      var.guest.vmid != null, var.guest.cpu != null, var.guest.memory_mib != null,
      var.guest.root_gib != null, var.guest.boot_order != null,
      try(length(trimspace(var.guest.storage_id)) > 0, false),
      try(length(trimspace(var.guest.template_file_id)) > 0, false),
      alltrue([for nic in var.guest.interfaces : try(length(trimspace(nic.mac)) > 0 && length(trimspace(nic.ipv4)) > 0 && length(trimspace(nic.bridge)) > 0, false)]),
      alltrue([for mount in var.guest.mounts : try(mount.size_gib > 0 && length(trimspace(mount.path)) > 0, false)])
    ])
    error_message = "Unresolved target identity, template, mount or allocation refuses before provider defaults."
  }
  validation {
    condition     = var.guest.started == false && var.guest.on_boot == false && var.guest.protection == true
    error_message = "Creation must be stopped, off at boot and protected."
  }
}
variable "node" {
  type     = string
  nullable = false
}
variable "ssh_public_keys" {
  type = list(string)
  validation {
    condition     = length(var.ssh_public_keys) > 0
    error_message = "Bind actual trusted public bootstrap keys before PVE creation."
  }
}
