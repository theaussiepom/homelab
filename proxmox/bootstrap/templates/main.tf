module "guests" {
  source          = "./modules/deploy"
  for_each        = { deploy = var.deploy }
  node            = var.site.node
  guest           = each.value
  ssh_public_keys = var.site.ssh_public_keys
  admin_cidr      = var.admin_cidr
}

variable "site" { type = any }
variable "deploy" { type = any }
variable "admin_cidr" { type = string }
provider "proxmox" {
  endpoint = var.site.api_endpoint
  insecure = false
}

output "deploy_identity" { value = module.guests["deploy"].identity }
