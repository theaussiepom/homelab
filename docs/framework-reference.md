# Framework operations reference

Use [the stack contract](stack-contract.md) for the current deployment process. These existing guides describe separate framework components and installation, migration or recovery procedures that require separate operator action:

- [Proxmox and bootstrap](../proxmox/README.md)
- [Application components](../proxmox/applications/README.md)
- [Safe contributions](contributing-safely.md)
- [Attended ISO builder](../proxmox/iso/README.md)
- [Database backup and recovery](../services/database-backup/README.md)

The current application entrypoint is `proxmox/applications/deploy.py`. Host/ISO bootstrap and recovery are separate current subsystems. Old application deployment and migration requests are available through Git history only; they are not alternate current entrypoints.

- [Host firewall desired policy through bootstrap CD](../proxmox/bootstrap/HOST-FIREWALL.md): allow rules for nodes already managed by HomeLab and cluster options, separate from application guest policy.
