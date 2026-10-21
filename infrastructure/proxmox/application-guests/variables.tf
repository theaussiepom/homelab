variable "site" {
  type = any
  validation {
    condition     = try(startswith(var.site.api_endpoint, "https://") && length(var.site.node) > 0, false)
    error_message = "Explicit verified-TLS PVE endpoint and node are required; ambient endpoint fallback is not selected."
  }
}
variable "foundation" { type = any }
variable "guests" { type = any }
