variable "node" { type = string }
variable "ssh_public_keys" { type = list(string) }
variable "guest" {
  type = object({
    vmid     = number, hostname = string, cpu = number, memory_mib = number,
    root_gib = number, storage_id = string, template_file_id = string,
    started  = bool, start_on_boot = bool, boot_order = number,
    nesting  = bool, keyctl = bool, dns_servers = list(string),
    interfaces = list(object({
      bridge  = string, vlan = optional(number), mac = string, ipv4 = string,
      gateway = optional(string), ipv6 = optional(string)
    })),
    volumes = map(object({ path = string, size_gib = number })),
    rules = list(object({
      direction = string, proto = string, port = optional(string),
      source    = optional(string), destination = optional(string), comment = string
    }))
  })
  validation {
    condition = (
      var.guest.vmid >= 100 && floor(var.guest.vmid) == var.guest.vmid &&
      !contains([900, 4914, 4915, 4920], var.guest.vmid) &&
      can(regex("^[a-z][a-z0-9-]{0,62}$", var.guest.hostname)) &&
      var.guest.cpu >= 1 && floor(var.guest.cpu) == var.guest.cpu &&
      var.guest.memory_mib >= 256 && var.guest.root_gib >= 4 &&
      length(var.guest.storage_id) > 0 && length(var.guest.template_file_id) > 0
    )
    error_message = "Choose an application guest with explicit resources; the deployment controller and protected rehearsal IDs are excluded."
  }
  validation {
    condition = (
      length(var.guest.interfaces) > 0 &&
      length(distinct([for nic in var.guest.interfaces : nic.mac])) == length(var.guest.interfaces) &&
      length([for nic in var.guest.interfaces : nic.gateway if nic.gateway != null]) == 1 &&
      alltrue([for nic in var.guest.interfaces :
        can(cidrnetmask(nic.ipv4)) && can(regex("^([0-9a-f]{2}:){5}[0-9a-f]{2}$", nic.mac)) &&
        (nic.vlan == null ? true : nic.vlan >= 1 && nic.vlan <= 4094 && floor(nic.vlan) == nic.vlan)
      ])
    )
    error_message = "Use explicit static IPv4 addresses, unique literal MACs, valid VLANs and exactly one default gateway."
  }
  validation {
    condition = alltrue([for volume in values(var.guest.volumes) :
      volume.size_gib >= 1 && can(regex("^(/srv/homelab|/var/lib/(mysql|postgresql|influxdb))(/[a-z0-9_-]+)*$", volume.path))
    ])
    error_message = "Data volumes must be managed guest volumes at explicit service paths, never host bind mounts."
  }
  validation {
    condition = alltrue([for rule in var.guest.rules :
      contains(["in", "out"], rule.direction) && contains(["tcp", "udp", "icmp", "icmpv6"], rule.proto) &&
      (rule.direction == "in" ? rule.source != null && rule.source != "0.0.0.0/0" && rule.source != "::/0" : rule.destination != null)
    ])
    error_message = "Declare each guest firewall allowance; inbound access must name a restricted source."
  }
}
