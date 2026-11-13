# Library and site contract

The current authored API is [homelab-components-v1](reference/README.md). [Library](reference/library.md) defines reusable profiles/defaults; [Site](reference/site.md) defines allocations and typed relationships.

Packet and workflow generation use the same JSON/YAML reader, which restricts file access to the selected source roots, and the same completed plan. [References](guides/references-and-reuse.md) keep shared values, startup dependencies and access permissions separate. Runtime packets/receipts remain JSON. [Lifecycle](reference/lifecycle.md) defines normal ownership checks and explains why adoption and resets are unsupported. Older APIs remain only at their immutable source pins.

[Documentation index](README.md)
