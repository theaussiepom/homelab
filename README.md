# HomeLab

HomeLab turns a configuration describing your Proxmox guests and applications into validated deployment inputs for Debian 13 LXC. You choose where services run, how they connect and which resources they use. OpenTofu owns infrastructure and state; Ansible owns guest configuration and services.

**Start with [what you want to build](docs/start-here.md).** If you are choosing applications for your own homelab, follow the [HomeLab Stack getting-started route](https://github.com/theaussiepom/homelab-stack/blob/main/docs/start-here.md). The stack library supplies the reusable profiles, templates and application choices. Use this framework's [configuration walkthrough](docs/guides/first-configuration.md) to learn how those choices become a complete site and inspect what the compiler produces.

| Your next result | Documentation |
| --- | --- |
| A personalised configuration you can compile locally | [Write and inspect your first configuration](docs/guides/first-configuration.md) |
| An explanation of a field or relationship | [Configuration model](docs/concepts.md) and [contract reference](docs/reference/README.md) |
| Real site inputs ready for review | [Prepare a deployment](docs/guides/prepare-deployment.md) |
| A supported installation or update to an existing HomeLab installation | [Operations](docs/operations/README.md) and [support limits](docs/reference/support.md) |
| A reviewed framework change | [Contributing](docs/contributing/README.md) |

A library supplies profiles and defaults; your site places instances and binds resources. This framework defines which fields are accepted, how references are resolved and which operations are supported. Keep the framework revision compatible with the selected library; you supply your own allocations, protected inputs and operating procedure.

The local walkthrough needs Git and Python, with no Proxmox access. Compilation checks that the source is consistent and builds deployment packets: files containing generated deployment inputs. Installation also requires an adapter that supports the operation, verified prerequisites and a protected continuous deployment (CD) workflow, followed by [service verification](docs/operations/verify-and-maintain.md). Keep supported `fresh` source for later updates to the same HomeLab installation. `retained` requires an installation already owned by HomeLab; it cannot import another installation.

[Documentation index](docs/README.md) · [Security](SECURITY.md) · [Lifecycle](docs/reference/lifecycle.md) · [Separate host, installer and recovery subsystems](docs/framework-reference.md)
