mock_provider "proxmox" {}

variables {
  policy = {
    schema       = "homelab-host-firewall-v1"
    endpoint     = "https://pve.example.invalid:8006/"
    node         = "pve"
    host_address = "198.18.25.10"
    allowances = [
      { source = "198.18.25.11/32", port = 8006, comment = "Existing API" },
      { source = "192.0.2.0/24", port = 22, comment = "Reviewed management SSH" }
    ]
    cluster = {
      enabled        = true
      ebtables       = true
      input_policy   = "DROP"
      output_policy  = "ACCEPT"
      forward_policy = "ACCEPT"
      log_ratelimit  = { enabled = true, rate = "1/second", burst = 5 }
    }
  }
}

run "desired_policy" {
  command = plan
  assert {
    condition = (proxmox_virtual_environment_firewall_rules.host.node_name == "pve" &&
      proxmox_virtual_environment_firewall_rules.host.container_id == null &&
    proxmox_virtual_environment_firewall_rules.host.vm_id == null)
    error_message = "Host policy cannot select a guest."
  }
  assert {
    condition = (length(proxmox_virtual_environment_firewall_rules.host.rule) == 2 &&
      proxmox_virtual_environment_firewall_rules.host.rule[0].dport == "8006" &&
      proxmox_virtual_environment_firewall_rules.host.rule[1].source == "192.0.2.0/24" &&
      proxmox_virtual_environment_firewall_rules.host.rule[1].dest == "198.18.25.10/32" &&
      proxmox_virtual_environment_firewall_rules.host.rule[1].dport == "22" &&
    proxmox_virtual_environment_firewall_rules.host.rule[1].proto == "tcp")
    error_message = "Preserve ordered declared host allowances."
  }
  assert {
    condition = (proxmox_virtual_environment_cluster_firewall.cluster.enabled &&
      proxmox_virtual_environment_cluster_firewall.cluster.ebtables &&
      proxmox_virtual_environment_cluster_firewall.cluster.input_policy == "DROP" &&
      proxmox_virtual_environment_cluster_firewall.cluster.output_policy == "ACCEPT" &&
      proxmox_virtual_environment_cluster_firewall.cluster.forward_policy == "ACCEPT" &&
      proxmox_virtual_environment_cluster_firewall.cluster.log_ratelimit[0].enabled &&
      proxmox_virtual_environment_cluster_firewall.cluster.log_ratelimit[0].burst == 5 &&
    proxmox_virtual_environment_cluster_firewall.cluster.log_ratelimit[0].rate == "1/second")
    error_message = "Global enabling must explicitly preserve declared defaults."
  }
}

run "same_desired_policy" {
  command = plan
  assert {
    condition     = proxmox_virtual_environment_cluster_firewall.cluster.enabled
    error_message = "The same source remains enabled on later runs."
  }
}

run "additional_address_preserves_management_policy" {
  command = plan
  variables {
    policy = {
      schema       = "homelab-host-firewall-v1"
      endpoint     = "https://pve.example.invalid:8006/"
      node         = "pve"
      host_address = "198.18.25.10"
      allowances = [
        { source = "198.18.25.11/32", port = 8006, comment = "Existing API" },
        { source = "192.0.2.0/24", port = 22, comment = "Reviewed management SSH" },
        { source = "198.18.40.33/32", destination = "198.18.40.10", port = 8006, comment = "Application ingress to host UI" }
      ]
      cluster = {
        enabled        = true
        ebtables       = true
        input_policy   = "DROP"
        output_policy  = "ACCEPT"
        forward_policy = "ACCEPT"
        log_ratelimit  = { enabled = true, rate = "1/second", burst = 5 }
      }
    }
  }
  assert {
    condition = (proxmox_virtual_environment_firewall_rules.host.node_name == "pve" &&
      proxmox_virtual_environment_firewall_rules.host.container_id == null &&
      proxmox_virtual_environment_firewall_rules.host.vm_id == null &&
      length(proxmox_virtual_environment_firewall_rules.host.rule) == 3 &&
      proxmox_virtual_environment_firewall_rules.host.rule[0].dest == "198.18.25.10/32" &&
      proxmox_virtual_environment_firewall_rules.host.rule[0].source == "198.18.25.11/32" &&
      proxmox_virtual_environment_firewall_rules.host.rule[0].dport == "8006" &&
      proxmox_virtual_environment_firewall_rules.host.rule[1].dest == "198.18.25.10/32" &&
      proxmox_virtual_environment_firewall_rules.host.rule[1].source == "192.0.2.0/24" &&
      proxmox_virtual_environment_firewall_rules.host.rule[1].dport == "22" &&
      proxmox_virtual_environment_firewall_rules.host.rule[2].dest == "198.18.40.10/32" &&
      proxmox_virtual_environment_firewall_rules.host.rule[2].source == "198.18.40.33/32" &&
    proxmox_virtual_environment_firewall_rules.host.rule[2].dport == "8006")
    error_message = "An additional host address must preserve management allowances and host ownership."
  }
}
