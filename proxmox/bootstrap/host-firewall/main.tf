terraform {
  backend "local" {}
}

provider "proxmox" {
  endpoint = var.policy.endpoint
  insecure = false
}

resource "proxmox_virtual_environment_firewall_rules" "host" {
  node_name = var.policy.node
  dynamic "rule" {
    for_each = var.policy.allowances
    content {
      type           = "in"
      action         = "ACCEPT"
      enabled        = true
      proto          = "tcp"
      source         = rule.value.source
      dest           = "${coalesce(rule.value.destination, var.policy.host_address)}/32"
      dport          = tostring(rule.value.port)
      comment        = rule.value.comment
      iface          = ""
      log            = ""
      macro          = ""
      sport          = ""
      security_group = ""
    }
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "proxmox_virtual_environment_cluster_firewall" "cluster" {
  depends_on     = [proxmox_virtual_environment_firewall_rules.host]
  enabled        = var.policy.cluster.enabled
  ebtables       = var.policy.cluster.ebtables
  input_policy   = var.policy.cluster.input_policy
  output_policy  = var.policy.cluster.output_policy
  forward_policy = var.policy.cluster.forward_policy
  log_ratelimit {
    enabled = var.policy.cluster.log_ratelimit.enabled
    rate    = var.policy.cluster.log_ratelimit.rate
    burst   = var.policy.cluster.log_ratelimit.burst
  }
  lifecycle {
    prevent_destroy = true
  }
}
