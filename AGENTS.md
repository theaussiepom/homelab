# Deployment working agreement

Keep one permanent reusable workflow per guest, with one deployment job and ordered
Infrastructure, Preparation and application phases as plainly named steps. Reuse
preparation capabilities once per guest; keep real dependency edges explicit. Ordinary deployment never restores
data, rewrites migration configuration or bootstraps initial application accounts.
Keep actual credentials outside Git. Preserve all state, identity, locks, holds
and failed evidence. No automatic retries, state adoption, replacement or rollback.
Public source changes validate only. Native deployment requires deliberate private
site adoption and a reviewed main merge through the existing global queue.
All declared guests participate by default; only an explicit disabled list excludes
guests. Missing prerequisites fail validation. Debian LXC is the implemented platform.
