mock_provider "proxmox" {
  mock_resource "proxmox_virtual_environment_container" {
    defaults = { id = "fixture-container-6101" }
  }
  mock_resource "proxmox_virtual_environment_firewall_options" {
    defaults = { id = "fixture-options-6101" }
  }
  mock_resource "proxmox_virtual_environment_firewall_rules" {
    defaults = { id = "fixture-rules-6101" }
  }
}

variables {
  ssh_public_keys  = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
  protected_guests = [900]
}

run "transport_order_and_duplicates" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = jsondecode(file("tests/firewall-consolidation.json")).transport_order_and_duplicates.rules
    })
  }
  assert {
    condition     = length(proxmox_virtual_environment_firewall_rules.guest.rule) == 8
    error_message = "Only eligible adjacent transport destinations may share one bounded provider row."
  }
  assert {
    condition = jsonencode(flatten([
      for rule in proxmox_virtual_environment_firewall_rules.guest.rule : [
        for destination in(rule.dest == null || rule.dest == "" ? [null] : split(",", rule.dest)) : {
          direction   = rule.type
          proto       = rule.proto
          port        = rule.dport == "" ? null : rule.dport
          source      = rule.source == "" ? null : rule.source
          destination = destination
          comment     = rule.comment
          interface   = rule.iface == "" ? null : rule.iface
        }
      ]
    ])) == jsonencode(var.guest.rules)
    error_message = "Expanding provider destinations must recover every original field, row and duplicate in order."
  }
  assert {
    condition = (
      proxmox_virtual_environment_container.guest.vm_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_options.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.node_name == var.node
    )
    error_message = "Consolidation cannot change the existing three resource subjects."
  }
}

run "field_boundaries" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = jsondecode(file("tests/firewall-consolidation.json")).field_boundaries.rules
    })
  }
  assert {
    condition     = length(proxmox_virtual_environment_firewall_rules.guest.rule) == 7
    error_message = "Only eligible adjacent transport destinations may share one bounded provider row."
  }
  assert {
    condition = jsonencode(flatten([
      for rule in proxmox_virtual_environment_firewall_rules.guest.rule : [
        for destination in(rule.dest == null || rule.dest == "" ? [null] : split(",", rule.dest)) : {
          direction   = rule.type
          proto       = rule.proto
          port        = rule.dport == "" ? null : rule.dport
          source      = rule.source == "" ? null : rule.source
          destination = destination
          comment     = rule.comment
          interface   = rule.iface == "" ? null : rule.iface
        }
      ]
    ])) == jsonencode(var.guest.rules)
    error_message = "Expanding provider destinations must recover every original field, row and duplicate in order."
  }
  assert {
    condition = (
      proxmox_virtual_environment_container.guest.vm_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_options.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.node_name == var.node
    )
    error_message = "Consolidation cannot change the existing three resource subjects."
  }
}

run "family_and_nonadjacency" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = jsondecode(file("tests/firewall-consolidation.json")).family_and_nonadjacency.rules
    })
  }
  assert {
    condition     = length(proxmox_virtual_environment_firewall_rules.guest.rule) == 3
    error_message = "Only eligible adjacent transport destinations may share one bounded provider row."
  }
  assert {
    condition = jsonencode(flatten([
      for rule in proxmox_virtual_environment_firewall_rules.guest.rule : [
        for destination in(rule.dest == null || rule.dest == "" ? [null] : split(",", rule.dest)) : {
          direction   = rule.type
          proto       = rule.proto
          port        = rule.dport == "" ? null : rule.dport
          source      = rule.source == "" ? null : rule.source
          destination = destination
          comment     = rule.comment
          interface   = rule.iface == "" ? null : rule.iface
        }
      ]
    ])) == jsonencode(var.guest.rules)
    error_message = "Expanding provider destinations must recover every original field, row and duplicate in order."
  }
  assert {
    condition = (
      proxmox_virtual_environment_container.guest.vm_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_options.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.node_name == var.node
    )
    error_message = "Consolidation cannot change the existing three resource subjects."
  }
}

run "empty" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = jsondecode(file("tests/firewall-consolidation.json")).empty.rules
    })
  }
  assert {
    condition     = length(proxmox_virtual_environment_firewall_rules.guest.rule) == 0
    error_message = "Only eligible adjacent transport destinations may share one bounded provider row."
  }
  assert {
    condition = jsonencode(flatten([
      for rule in proxmox_virtual_environment_firewall_rules.guest.rule : [
        for destination in(rule.dest == null || rule.dest == "" ? [null] : split(",", rule.dest)) : {
          direction   = rule.type
          proto       = rule.proto
          port        = rule.dport == "" ? null : rule.dport
          source      = rule.source == "" ? null : rule.source
          destination = destination
          comment     = rule.comment
          interface   = rule.iface == "" ? null : rule.iface
        }
      ]
    ])) == jsonencode(var.guest.rules)
    error_message = "Expanding provider destinations must recover every original field, row and duplicate in order."
  }
  assert {
    condition = (
      proxmox_virtual_environment_container.guest.vm_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_options.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.node_name == var.node
    )
    error_message = "Consolidation cannot change the existing three resource subjects."
  }
}

run "single" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = jsondecode(file("tests/firewall-consolidation.json")).single.rules
    })
  }
  assert {
    condition     = length(proxmox_virtual_environment_firewall_rules.guest.rule) == 1
    error_message = "Only eligible adjacent transport destinations may share one bounded provider row."
  }
  assert {
    condition = jsonencode(flatten([
      for rule in proxmox_virtual_environment_firewall_rules.guest.rule : [
        for destination in(rule.dest == null || rule.dest == "" ? [null] : split(",", rule.dest)) : {
          direction   = rule.type
          proto       = rule.proto
          port        = rule.dport == "" ? null : rule.dport
          source      = rule.source == "" ? null : rule.source
          destination = destination
          comment     = rule.comment
          interface   = rule.iface == "" ? null : rule.iface
        }
      ]
    ])) == jsonencode(var.guest.rules)
    error_message = "Expanding provider destinations must recover every original field, row and duplicate in order."
  }
  assert {
    condition = (
      proxmox_virtual_environment_container.guest.vm_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_options.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.node_name == var.node
    )
    error_message = "Consolidation cannot change the existing three resource subjects."
  }
}

run "at_512_bytes" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = jsondecode(file("tests/firewall-consolidation.json")).at_512_bytes.rules
    })
  }
  assert {
    condition     = length(proxmox_virtual_environment_firewall_rules.guest.rule) == 1
    error_message = "Only eligible adjacent transport destinations may share one bounded provider row."
  }
  assert {
    condition = jsonencode(flatten([
      for rule in proxmox_virtual_environment_firewall_rules.guest.rule : [
        for destination in(rule.dest == null || rule.dest == "" ? [null] : split(",", rule.dest)) : {
          direction   = rule.type
          proto       = rule.proto
          port        = rule.dport == "" ? null : rule.dport
          source      = rule.source == "" ? null : rule.source
          destination = destination
          comment     = rule.comment
          interface   = rule.iface == "" ? null : rule.iface
        }
      ]
    ])) == jsonencode(var.guest.rules)
    error_message = "Expanding provider destinations must recover every original field, row and duplicate in order."
  }
  assert {
    condition = (
      proxmox_virtual_environment_container.guest.vm_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_options.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.node_name == var.node
    )
    error_message = "Consolidation cannot change the existing three resource subjects."
  }
}

run "over_512_bytes" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = jsondecode(file("tests/firewall-consolidation.json")).over_512_bytes.rules
    })
  }
  assert {
    condition     = length(proxmox_virtual_environment_firewall_rules.guest.rule) == 8
    error_message = "Only eligible adjacent transport destinations may share one bounded provider row."
  }
  assert {
    condition = jsonencode(flatten([
      for rule in proxmox_virtual_environment_firewall_rules.guest.rule : [
        for destination in(rule.dest == null || rule.dest == "" ? [null] : split(",", rule.dest)) : {
          direction   = rule.type
          proto       = rule.proto
          port        = rule.dport == "" ? null : rule.dport
          source      = rule.source == "" ? null : rule.source
          destination = destination
          comment     = rule.comment
          interface   = rule.iface == "" ? null : rule.iface
        }
      ]
    ])) == jsonencode(var.guest.rules)
    error_message = "Expanding provider destinations must recover every original field, row and duplicate in order."
  }
  assert {
    condition = (
      proxmox_virtual_environment_container.guest.vm_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_options.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.node_name == var.node
    )
    error_message = "Consolidation cannot change the existing three resource subjects."
  }
}

run "large_logical_set" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = jsondecode(file("tests/firewall-consolidation.json")).large_logical_set.rules
    })
  }
  assert {
    condition     = length(proxmox_virtual_environment_firewall_rules.guest.rule) == 104
    error_message = "Only eligible adjacent transport destinations may share one bounded provider row."
  }
  assert {
    condition = jsonencode(flatten([
      for rule in proxmox_virtual_environment_firewall_rules.guest.rule : [
        for destination in(rule.dest == null || rule.dest == "" ? [null] : split(",", rule.dest)) : {
          direction   = rule.type
          proto       = rule.proto
          port        = rule.dport == "" ? null : rule.dport
          source      = rule.source == "" ? null : rule.source
          destination = destination
          comment     = rule.comment
          interface   = rule.iface == "" ? null : rule.iface
        }
      ]
    ])) == jsonencode(var.guest.rules)
    error_message = "Expanding provider destinations must recover every original field, row and duplicate in order."
  }
  assert {
    condition = (
      proxmox_virtual_environment_container.guest.vm_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_options.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.container_id == var.guest.vmid &&
      proxmox_virtual_environment_firewall_rules.guest.node_name == var.node
    )
    error_message = "Consolidation cannot change the existing three resource subjects."
  }
}

run "comma_lists_cannot_bypass_logical_literal_validation" {
  command = plan
  module { source = "./guest" }
  variables {
    node = "practice-pve"
    guest = merge(jsondecode(file("tests/base-guest.json")), {
      rules = [{ direction = "out", proto = "tcp", destination = "192.0.2.1/32,192.0.2.2/32", port = "443", comment = "Internal lists are not authored rule literals" }]
    })
  }
  expect_failures = [var.guest]
}
