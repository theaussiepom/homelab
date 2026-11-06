# HomeLab

Compose Debian LXC guests from reusable application profiles, then compile their
infrastructure, configuration and ordered deployment phases. HomeLab uses
OpenTofu for infrastructure and Ansible for packages and services.

**Start with a successful offline compilation:** [First configuration](docs/guides/first-configuration.md).
It needs no host, credentials, Docker or private repository.

## Choose your path

| I want to… | Start here |
| --- | --- |
| Understand the model | [Start here](docs/start-here.md) and [Concepts](docs/concepts.md) |
| Configure a field | [Configuration reference](docs/reference/README.md) |
| Select an application | [homelab-stack library](https://github.com/theaussiepom/homelab-stack) at your compatible selected revision; [framework support limits](docs/reference/support.md) |
| Validate or generate workflows | [Validate and generate](docs/guides/validate-and-generate.md) |
| Deploy or investigate a failure | [Operations](docs/operations/README.md) |
| Extend a component | [Contributing](docs/contributing/README.md) |

## A small example

An app selects a library profile and binds its roles to a guest. This is a
fragment; the [complete tutorial source](docs/examples/first-configuration/site.yaml)
also declares the context, networks, storage and guest.

```yaml
apps:
  recursive_a:
    profile: recursive
    guest: resolver
    lifecycle: fresh
    interfaces:
      private: {scope: app-network, network: default}
      local: {scope: guest-loopback}
```

A site can split complete guests, apps, connections and exposures into confined
typed files. Named address groups reuse ordered network values. References do
not implicitly grant access or create startup waits.

## Three source owners

| Owner | Responsibility |
| --- | --- |
| This framework | Configuration grammar, compilation, phase runner, infrastructure and tests |
| homelab-stack application library | Profiles, templates, software versions, runtime defaults and synthetic compositions |
| Consumer site | Allocations, placement, bindings, protected input references and deployment policy |

The executable platform is **Debian 13 LXC on Proxmox**. A valid configuration is
not a deployment or a working service. Fresh commissioning depends on the
adapter; retained continuation requires genuine owned receipts and state.
[Lifecycle](docs/reference/lifecycle.md) explains these limits.

[All documentation](docs/README.md) · [Security](SECURITY.md) ·
[Testing](docs/contributing/testing.md) ·
[Separate host, ISO and recovery subsystems](docs/framework-reference.md)
