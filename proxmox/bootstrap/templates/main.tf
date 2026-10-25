module "guests" {
  source          = "./modules/deploy"
  for_each        = { deploy = var.deploy }
  node            = var.site.node
  guest           = merge(each.value, { template_file_id = var.template == null ? each.value.template_file_id : proxmox_virtual_environment_download_file.template[0].id })
  ssh_public_keys = var.site.ssh_public_keys
  admin_cidr      = var.admin_cidr
}

variable "site" { type = any }
variable "deploy" { type = any }
variable "admin_cidr" { type = string }
variable "template" {
  type    = object({ url = string, sha256 = string, file_name = string, datastore_id = string })
  default = null
}

resource "proxmox_virtual_environment_download_file" "template" {
  count              = var.template == null ? 0 : 1
  node_name          = var.site.node
  content_type       = "vztmpl"
  datastore_id       = var.template.datastore_id
  file_name          = var.template.file_name
  url                = var.template.url
  checksum           = var.template.sha256
  checksum_algorithm = "sha256"
  lifecycle { prevent_destroy = true }
}

provider "proxmox" {
  endpoint = var.site.api_endpoint
  insecure = false
}

output "deploy_identity" { value = module.guests["deploy"].identity }
