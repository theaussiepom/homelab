# Library and site contract

The current authored API is [homelab-components-v1](reference/README.md).
[Library](reference/library.md) defines reusable profiles/defaults;
[Site](reference/site.md) defines allocations and typed relationships.

Compilation uses the same confined JSON/YAML reader and sealed plan for packets
and workflow generation. [References](guides/references-and-reuse.md) keep values,
readiness and grants separate. Runtime packets/receipts remain JSON.
[Lifecycle](reference/lifecycle.md) defines normal ownership and unsupported
adoption/reset behavior. Older APIs remain only at their immutable source pins.

[Documentation index](README.md)
