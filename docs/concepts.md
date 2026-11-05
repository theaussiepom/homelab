# Concepts

HomeLab compiles an explicit site. It has no fixed catalogue of guests.

```mermaid
flowchart LR
  library[Library: profiles and defaults] --> plan[Resolved typed plan]
  site[Site: instances and bindings] --> plan
  plan --> packet[Closed guest packets]
  plan --> graph[Generated workflow graph]
  packet --> infra[OpenTofu infrastructure]
  infra --> preparation[Ansible preparation]
  preparation --> apps[Selected app phases]
  apps --> agent[Optional monitoring agent]
```

## Definitions and instances

A template supplies guest resource/startup/security defaults. A profile declares
one adapter's interface, storage, listener, software and health roles.
A site guest allocates a stable VMID, hostname, NICs and storage. A site app
selects a profile and binds its roles to that guest. Multiple apps can share a
guest only when their owned namespaces, listeners and resource budgets agree.

Complete source files are a way to organise a declaration. They do not add a
layer of configuration merging. [Sources](reference/sources.md) defines the
allowed files; [Guest defaults](reference/guests.md#defaults-and-resolution)
defines the few actual field-level inheritance rules.

## Three separate relationships

| Relationship | Example | Effect |
| --- | --- | --- |
| Value reference | Connection targets an app endpoint | Reuses its declared address, port and protocol |
| Readiness | Connection has `readiness: start` | Adds an allowed explicit dependency |
| Network policy | Ordered guest ACCEPT rules | Declares permissions; required cross-guest flows must match |

A value reference alone creates neither wait nor grant. An app-local network or
same-guest connection has different reachability from a cross-guest socket.
The [reference guide](guides/references-and-reuse.md) walks through these cases.
The explicit root [Zabbix feature](reference/zabbix.md) is an exception with its
own documented derived monitoring grants.

## Resolution and execution

The compiler reads bounded snapshots, validates shapes and references, resolves
identities and graphs, checks budgets/traffic and lowers a sealed plan.
Source pins record the actual consumed bytes. Runtime packets and receipts are
JSON even when authored source is YAML.

Compilation does not open declared private files. The phase runner later selects
only that phase's protected inputs. OpenTofu owns infrastructure/state; Ansible
owns guest configuration. A canonical ordinary receipt, immutable operation
receipt, sealed payloads and backend identity together establish normal retained
ownership. They are not an import mechanism. [Lifecycle](reference/lifecycle.md)
describes what a subsequent run may change.
