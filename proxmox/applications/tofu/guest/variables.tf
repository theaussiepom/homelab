variable "node" { type = string }
variable "ssh_public_keys" { type = list(string) }
variable "protected_guests" {
  type = list(number)
  validation {
    condition     = length(distinct(var.protected_guests)) == length(var.protected_guests) && alltrue([for vmid in var.protected_guests : vmid >= 1 && floor(vmid) == vmid])
    error_message = "Declare unique positive protected guest identities in the execution context."
  }
}
variable "guest" {
  type = object({
    vmid           = number, hostname = string, cpu = number, memory_mib = number,
    root_gib       = number, storage_id = string, template_file_id = string,
    started        = bool, start_on_boot = bool, boot_order = number,
    nesting        = bool, keyctl = bool, dns_servers = list(string),
    routing_labels = optional(map(string), {}),
    interfaces = list(object({
      bridge  = string, vlan = optional(number), mac = string, ipv4 = string,
      gateway = optional(string), ipv6 = optional(string)
    })),
    volumes      = map(object({ path = string, size_gib = number })),
    volume_order = optional(list(string)),
    rules = list(object({
      direction = string, proto = string, port = optional(string),
      source    = optional(string), destination = optional(string), comment = string, interface = optional(string)
    }))
  })
  validation {
    condition     = var.guest.started
    error_message = "Deploy active guests."
  }
  validation {
    condition = alltrue([for key, value in var.guest.routing_labels :
      can(regex("^traefik\\.[A-Za-z0-9_.-]+$", key)) && length(value) <= 2048 &&
      length(regexall("[\r\n]", value)) == 0
    ])
    error_message = "Discovery labels must be single-line Traefik facts generated from resolved stack routes."
  }
  validation {
    condition = (
      var.guest.vmid >= 100 && floor(var.guest.vmid) == var.guest.vmid &&
      !contains(var.protected_guests, var.guest.vmid) &&
      can(regex("^[a-z][a-z0-9-]{0,62}$", var.guest.hostname)) &&
      var.guest.cpu >= 1 && floor(var.guest.cpu) == var.guest.cpu &&
      var.guest.memory_mib >= 256 && floor(var.guest.memory_mib) == var.guest.memory_mib &&
      var.guest.root_gib >= 4 && floor(var.guest.root_gib) == var.guest.root_gib &&
      var.guest.boot_order >= 0 && floor(var.guest.boot_order) == var.guest.boot_order &&
      length(var.guest.storage_id) > 0 && length(var.guest.template_file_id) > 0
    )
    error_message = "Choose an application guest with explicit resources; the deployment controller and protected rehearsal IDs are excluded."
  }
  validation {
    condition = (
      length(var.guest.interfaces) > 0 &&
      length(distinct([for nic in var.guest.interfaces : nic.mac])) == length(var.guest.interfaces) &&
      length([for nic in var.guest.interfaces : nic.gateway if nic.gateway != null]) +
      length([for nic in var.guest.interfaces : nic if nic.ipv4 == "dhcp"]) == 1 &&
      alltrue([for nic in var.guest.interfaces :
        (nic.ipv4 == "dhcp" ? nic.gateway == null : can(cidrnetmask(nic.ipv4))) && can(regex("^([0-9a-f]{2}:){5}[0-9a-f]{2}$", nic.mac)) &&
        (nic.ipv6 == null ? true : contains(["auto", "dhcp", "manual"], nic.ipv6) || can(cidrhost(nic.ipv6, 0))) &&
        (nic.vlan == null ? true : nic.vlan >= 1 && nic.vlan <= 4094 && floor(nic.vlan) == nic.vlan)
      ])
    )
    error_message = "Use static IPv4 or one DHCP interface, unique literal MACs, valid VLANs and exactly one default route. DHCP supplies its own gateway."
  }
  validation {
    condition = var.guest.volume_order == null ? true : (
      length(var.guest.volume_order) == length(var.guest.volumes) &&
      length(distinct(var.guest.volume_order)) == length(var.guest.volume_order) &&
      alltrue([for key in var.guest.volume_order : contains(keys(var.guest.volumes), key)])
    )
    error_message = "Bind every provider volume once in its validated persistent slot order."
  }
  validation {
    condition = alltrue([for volume in values(var.guest.volumes) :
      volume.size_gib >= 1 && floor(volume.size_gib) == volume.size_gib && can(regex("^(/srv/[a-z0-9_-]+|/var/lib/(mysql|postgresql|influxdb))(/[a-z0-9_-]+)*$", volume.path))
    ])
    error_message = "Data volumes must be managed guest volumes at explicit service paths, never host bind mounts."
  }
  validation {
    condition = alltrue([for rule in var.guest.rules :
      contains(["in", "out"], rule.direction) && contains(["tcp", "udp", "icmp", "icmpv6", "igmp"], rule.proto) &&
      (rule.interface == null ? true : contains([for index, nic in var.guest.interfaces : "net${index}"], rule.interface)) &&
      (rule.direction == "in" ? rule.source != null && try(tonumber(split("/", rule.source)[1]) > 0, true) : rule.destination != null) &&
      alltrue([for address in [rule.source, rule.destination] : address == null ? true : (
        !strcontains(address, "%") && can(cidrhost(strcontains(address, "/") ? address : "${address}/${strcontains(address, ":") ? 128 : 32}", 0))
      )]) &&
      (rule.source == null || rule.destination == null ? true : strcontains(rule.source, ":") == strcontains(rule.destination, ":")) &&
      alltrue([for address in [rule.source, rule.destination] : address == null ? true : (
        rule.proto == "icmpv6" ? strcontains(address, ":") : contains(["icmp", "igmp"], rule.proto) ? !strcontains(address, ":") : true
      )]) &&
      (rule.proto == "igmp" ? rule.port == null : contains(["icmp", "icmpv6"], rule.proto) ? (
        rule.port == null ? true : can(regex("^(0|[1-9][0-9]{0,2})$", rule.port)) && try(tonumber(rule.port) <= 255, false)
      ) : true)
    ])
    error_message = "Declare each guest firewall allowance; inbound access must name a restricted source."
  }
}
