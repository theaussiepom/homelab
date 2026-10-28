# One ingress backend firewall addition

`ingress_firewall.py` prepares one firewall-only saved plan for the commissioned
four-interface ingress. It is an adapter for the existing application saved-plan
maintenance/apply driver, not a database engine, guest installer or runtime fix.
It appends one outbound TCP rule with exact `/32` source and destination and one
port on the existing backend subnet. Source must be the installed eth1 address.
The container, all NICs, firewall options and every previous raw rule are no-ops.

The closed `homelab-ingress-egress-policy-v1` policy binds guest212, source,
destination, port and the accepted baseline: canonical state hash/lineage/serial,
completed network overlay reference, original saved network plan directory,
exact operation catalogue reference, accepted ACME manifest reference, and the
completed browser packet hash. Private references stay under guest212 custody.
The catalogue can be staged as an exact copy; its hash must match the accepted
network request. Staging that inert file is separate from selecting a native plan.

The baseline reader verifies original installation/source/input custody, derives
the accepted ACME plus Influx candidate from its old saved plan, and matches its
four NICs and rules to the accepted state snapshot. Local/NAS network claim,
overlay and state-after bytes must match. Completed browser claim and completion
must match locally and on NAS; the original shared-file backup remains bound.
This does not reapply or rerender the old three-interface configuration.

Prepare a separately authorized read-only plan with the unchanged commissioned
installer checkout:

```sh
python3 ingress_firewall.py --source ORIGINAL_INSTALLER \
  --config ORIGINAL_INSTALLED_SITE --policy EXACT_PRIVATE_POLICY \
  --evidence /var/lib/homelab-applications/212/database-network-plan-UNIQUE
```

The planner uses the existing workflow/deployment locks, private directory rules,
canonical state backend, pinned original ToFu/provider files and failure holds.
Its request and review bind the exact policy, helpers, binary/JSON saved plan and
candidate hashes. Planning is not apply authority or endpoint acceptance.

After review and separate native admission, the existing
`database_network_apply.py` accepts `homelab-ingress-egress-apply-v1` with vmid212,
request/review/apply-helper SHA256 fields, and `allow_guest_restart: false`.
Its existing `--catalogue` argument receives the exact firewall policy file for
this schema. Other arguments and behavior are unchanged: one claim, existing
HOLD, saved binary admission, local/NAS originals and completions, and a fresh
post-apply no-op plan. No runtime command, Ansible, service restart, network reload,
route rewrite or automatic retry is added. Its infrastructure result retains the
existing network-overlay schema and does not claim service or browser acceptance.

Do not add this to recurring checks. A completed browser installation job bound
to the old state must be retired in the coordinated private deployment change,
while preserving its installed route and original claim/completion records.
A second port or backend requires its own selected policy and native review.
