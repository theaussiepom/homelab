variable "policy" {
  type = object({
    schema       = string
    endpoint     = string
    node         = string
    host_address = string
    allowances = list(object({
      source      = string
      destination = optional(string)
      port        = number
      comment     = string
    }))
    cluster = object({
      enabled        = bool
      ebtables       = bool
      input_policy   = string
      output_policy  = string
      forward_policy = string
      log_ratelimit = object({
        enabled = bool
        rate    = string
        burst   = number
      })
    })
  })
  validation {
    condition = (var.policy.schema == "homelab-host-firewall-v1" &&
      length(var.policy.allowances) > 0 && length(var.policy.allowances) <= 32 &&
      alltrue([for rule in var.policy.allowances :
    rule.port == floor(rule.port) && rule.port >= 1 && rule.port <= 65535]))
    error_message = "Use the closed validated host firewall policy and finite TCP allowances."
  }
}
