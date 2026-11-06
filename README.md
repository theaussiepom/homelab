# HomeLab

HomeLab turns a typed site configuration and reusable application library into
validated deployment inputs for Debian 13 LXC guests on Proxmox. OpenTofu owns
infrastructure and state; Ansible owns guest configuration and services.

**Begin with [your first offline configuration](docs/guides/first-configuration.md).**
The complete example needs Python and Git; no host, credentials, image pull or
service startup is involved.

| Your next decision | Documentation |
| --- | --- |
| Understand what a site describes | [Start here](docs/start-here.md) → [Configuration model](docs/concepts.md) |
| Find an accepted field or relationship | [Contract reference](docs/reference/README.md) |
| Move from a working example to real inputs | [Prepare a deployment](docs/guides/prepare-deployment.md) |
| Install or update a supported owned service | [Operations](docs/operations/README.md) and [support limits](docs/reference/support.md) |
| Change the framework | [Contributing](docs/contributing/README.md) |

A library supplies profiles and defaults; a site places instances and binds
resources. The framework defines what those declarations mean and which actions
are allowed. [homelab-stack](https://github.com/theaussiepom/homelab-stack) is the
reusable profile library; each consumer owns its allocations, protected inputs
and operating procedure. Cross-repository selections must remain compatible.

Compilation proves source consistency and packet construction. Installation
requires supported adapter capability, qualified prerequisites and protected CD.
A completed deployment still needs [service verification](docs/operations/verify-and-maintain.md).
The same supported `fresh` source continues through ordinary owned updates;
`retained` requires genuine HomeLab ownership and is not an import mechanism.

[Documentation index](docs/README.md) · [Security](SECURITY.md) ·
[Lifecycle](docs/reference/lifecycle.md) ·
[Separate host, installer and recovery subsystems](docs/framework-reference.md)
