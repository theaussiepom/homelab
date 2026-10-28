# Accepted ingress ACME baseline for additive Influx networking

This is an explicit opt-in extension to the existing database network planner
and saved-plan apply/verify primitives. It is limited to the commissioned ingress
VMID212 as a single additive Influx client. It does not change another engine's
helper selection, adopt current state, rewrite original inputs, or grant native
planning/apply permission. Existing calls without the new option retain their
original contract.

## Private input and custody

The planner accepts both `--ingress-acme-baseline PATH` and
`--ingress-acme-baseline-sha256 SHA256`. PATH must be the selected guest's
`/var/lib/homelab-applications/212/ingress-acme-network-baseline.json`.
It is a private owned regular file, separately reviewed before use. No current
manifest, saved plan or executable operation is included in public source.

The closed `homelab-ingress-acme-network-baseline-v1` manifest contains:

* `vmid`:212 and the accepted `operation` name derived from the resolver packet.
* `files`: exact raw SHA256s for the local ACME `claim.json`, `complete.json`,
  `attempt/dns.tfplan`, `attempt/dns.tfplan.json`, `attempt/reviewed-plan.json`,
  and `attempt/tofu/site.auto.tfvars.json`. Include both confirmation claim and
  completion when the existing accepted operation used confirmation.
* `state_before` and `state_after`: each is a closed object containing `file`,
  `sha256`, and `receipt_sha256`. These select the original NAS state backups
  named with the `before-acme-resolver-update` and `after-acme-firewall-update`
  labels and their original JSON receipts. Arbitrary backup paths are refused.

Custody checks bind local/NAS accepted claim and completion, confirmation and
original failed evidence where applicable, original foundation completion,
original plan, saved DNS plan, and exact before/after state ancestry. NAS mount
identity must match the original private configuration. Private custody roots
remain mode0700; copied original ToFu subdirectories may retain mode0755 beneath
those private roots. Symlinks, hard links, writable/public files, missing or
changed evidence, incomplete confirmations and different guest identity refuse.
No ownership or mode is normalized.

The new caller must use the original ingress installer and its own original
`deploy.source_hash` algorithm. Do not substitute an identity installer or a
later source-hash algorithm to make historical receipts appear current.

## Derived baseline and exact addition

The baseline is computed from the unchanged commissioned guest plus exactly the
accepted two-resolver/four-rule ACME append. The accepted DNS plan and tfvars
must describe that same change, and its raw state snapshots must match it.
The initial network plan requires canonical state to equal the accepted ACME
completion. No arbitrary baseline guest can be supplied.

The additive candidate preserves all original NICs, routes and DNS rules and
adds only the catalogue-selected private Influx NIC and its one scoped outbound
TCP8086 rule. This ingress has no historical SQL-port rule to use as a template.
Its opt-in checker therefore binds the one existing ordinary outbound TCP80,443
provider rule for safe defaults: ACCEPT, enabled, no interface, macro, source
port, security group, extra keys or active logging. It replaces only declared
rule semantics and positions for the new row, deriving both /32 peers and port
from the catalogue. Existing raw rules and their ordering are preserved. This
special case cannot be selected by another guest, engine, phase or client list.

The planner retains the exact manifest beside the saved plan. Its request/review
also bind the manifest reference and all additional checker/runtime source files.
Apply admission reconstructs the same baseline and candidate, preserves original
installation custody and checks the same candidate tfvars. Apply and later
verification retain matching manifest copies on the runner and NAS. Existing
one-use claims, standard holds, exact saved-plan checks and restart-approval
requirements remain in force.

## Successor verification

An opted-in network apply and later verification use the new candidate for the
existing read-only no-op network check. They then invoke only the installed
resolver helper's `--verify-only` path through Ansible, using the exact accepted
resolver packet. That path verifies the current image, Compose and resolver
configuration without feeding the original NIC configuration back to OpenTofu.
It never calls the old ACME controller plan/apply path.

The private CD successor must select this network overlay branch and skip old
image/resolver/original-install verification calls that bind the pre-network
state. It must also qualify the new NIC's startup readiness through the existing
network-startup primitives and actual saved startup hashes before admission;
this helper does not install a new startup gate or claim that change occurred.
Preserve existing ingress routing/Docker dependencies and other applications.

Network verification is not Influx service acceptance, current browser SSO,
consumer inactivity or authorization to narrow the server listener. Those need
separate fresh scoped evidence and the reviewed server/browser ordering.

## Source qualification

Synthetic tests cover the four-rule baseline, exact NIC/rule addition with and
without provider positions, receipt and state drift, incomplete/accepted
confirmation, failure evidence, rule-authority substitution, restricted scope,
original-input preservation, saved-plan admission, simulated apply and repeated
no-op verification. Native lifecycle effects remain unverified until separately
admitted target work. No target is contacted by these tests.
