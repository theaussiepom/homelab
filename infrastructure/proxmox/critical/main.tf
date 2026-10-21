module "guests" {
  source          = "../modules/lxc"
  for_each        = { for k, g in var.guests : k => g if g.state_root == "critical" }
  guest           = each.value
  node            = var.site.node
  ssh_public_keys = var.site.ssh_public_keys
}
output "identities" { value = { for k, g in module.guests : k => g.identity } }
