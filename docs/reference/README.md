# Configuration reference

This reference describes `homelab-components-v1`, the current public authored API.
All objects are closed: unknown fields refuse. Required fields have no default
unless a table explicitly says otherwise. A list is ordered unless documented
otherwise. Null is not interchangeable with omission.

Configuration pages distinguish syntax, concrete worked values and complete
sites. A value fragment still needs its named surrounding context; the
[tutorial](../guides/first-configuration.md) is the complete runnable offline
path. Named examples are exercised by existing component validators and real
compiler integrations, including the documented invalid variations. Passing an
example's source boundary does not prove deployment or service readiness.

## Documents and declarations

| Contract | Fields covered |
| --- | --- |
| [Site](site.md) | Every top-level site map and root Zabbix selection |
| [Library](library.md) | Templates, profiles, software/runtime/health/auth/monitoring definitions, assets and bundles |
| [Sources](sources.md) | Complete typed files, confined paths and JSON/YAML rules |
| [Contexts](contexts.md) | Provider, trust, credentials, paths, DNS and serial capabilities |
| [Networks](networks.md) | IPv4 networks, NICs, external endpoints, domains, aliases and address groups |
| [Guests](guests.md) | Identity, defaults, resources, startup, security, projects and readiness |
| [Apps](apps.md) | Profile/placement, identity, interfaces, storage, selection and origin |
| [Application properties](app-properties.md) | Every adapter's closed property object |
| [Storage](storage.md) | Pools, provider volumes, root paths and profile mount roles |
| [Connections](connections.md) | Consumer/target, accounts, credential, transport, hostname and readiness |
| [Exposures](exposures.md) | DNS records, HTTPS ingress, domain aliases, middleware and origin |
| [Policies](policies.md) | Network rules, bindings, transport, TLS, middleware and authentication |
| [Identity and secrets](identity-and-secrets.md) | Providers, accounts, source roles and material continuity |
| [Supporting types](supporting-types.md) | Profile listeners/endpoints, resources, software, runtime, images/assets, health/devices/evidence |
| [PBS backup](backup.md) | Coordinated encrypted jobs, recovery classification and explicit volume selection |
| [Zabbix](zabbix.md) | Presence/null/server semantics and derived monitoring behavior |

## Commands and behavior

[CLI](cli.md) · [Lifecycle and updates](lifecycle.md) · [Support matrix](support.md)

The reference does not promise automatic replacement or rollback. Infrastructure
changes are subject to the native guarded plan; app changes to owned identities
and material must satisfy runtime continuity. Every page's update notes use
those same [lifecycle rules](lifecycle.md).
