# HomeLab

HomeLab turns a configuration describing your Proxmox guests and applications into validated deployment inputs for Debian 13 LXC. You choose where services run, how they connect and which resources they use. OpenTofu owns infrastructure and state; Ansible owns guest configuration and services.

**Start with [what you want to build](docs/start-here.md).** If you are choosing applications for your own homelab, follow the [HomeLab Stack getting-started route](https://github.com/theaussiepom/homelab-stack/blob/main/docs/start-here.md). It owns the reusable profiles, templates and application choices. Use this framework's [configuration walkthrough](docs/guides/first-configuration.md) to learn how those choices become a complete site and inspect what the compiler produces.

| Your next result | Documentation |
| --- | --- |
| A personalised configuration you can compile locally | [Write and inspect your first configuration](docs/guides/first-configuration.md) |
| An explanation of a field or relationship | [Configuration model](docs/concepts.md) and [contract reference](docs/reference/README.md) |
| Real site inputs ready for review | [Prepare a deployment](docs/guides/prepare-deployment.md) |
| A supported installation or owned update | [Operations](docs/operations/README.md) and [support limits](docs/reference/support.md) |
| A reviewed framework change | [Contributing](docs/contributing/README.md) |

A library supplies profiles and defaults; your site places instances and binds resources. This framework defines accepted fields, resolution and execution boundaries. Keep the framework revision compatible with the selected library; each consumer owns its allocations, protected inputs and operating procedure.

The local walkthrough needs Git and Python, with no Proxmox access. Compilation checks source consistency and builds packets. Installation also requires a supported adapter, qualified prerequisites and protected CD, followed by [service verification](docs/operations/verify-and-maintain.md). The same supported `fresh` source continues through ordinary owned updates; `retained` requires genuine HomeLab ownership and is not an import mechanism.

[Documentation index](docs/README.md) · [Security](SECURITY.md) · [Lifecycle](docs/reference/lifecycle.md) · [Separate host, installer and recovery subsystems](docs/framework-reference.md)
