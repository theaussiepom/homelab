# Framework operations reference

Use [the stack contract](stack-contract.md) for current ordinary deployment.
These existing guides describe separate framework components and explicitly
operated installation, migration or recovery procedures:

- [Proxmox and bootstrap](../proxmox/README.md)
- [Application components](../proxmox/applications/README.md)
- [Safe contributions](contributing-safely.md)
- [Attended ISO builder](../proxmox/iso/README.md)
- [Database backup and recovery](../services/database-backup/README.md)

The current application entrypoint is `proxmox/applications/deploy.py`. Host/ISO
bootstrap and recovery are separate current subsystems. Old application deployment
and migration requests are available through Git history only; they are not
alternate current entrypoints.
