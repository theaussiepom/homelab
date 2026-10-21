module "guests" {
  source          = "../modules/security-vm"
  for_each        = { for k, g in var.guests : k => g if g.state_root == "security_VM" }
  guest           = each.value
  node            = var.site.node
  ssh_public_keys = var.site.ssh_public_keys
  bootstrap_user  = var.site.bootstrap_user
}
output "identities" { value = { for k, g in module.guests : k => g.identity } }
