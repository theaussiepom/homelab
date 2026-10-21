# Configure the private deployment repository

Create one private site repository after separately authorizing its concrete GitHub creation. Keep reusable modules/roles/commands in the public implementation; the private repository binds exact reviewed releases, actual inventory and protected-store references. Do not copy the implementation into the private repository or attach a public remote to a mixed live worktree.

1. Review/publish the public implementation and fleet release through their own release procedure. Select immutable commit/artifact hashes, tool/provider locks and expected schemas. Branch names/latest URLs are not deployment pins.
2. Use `examples/site` as the repository layout. Replace synthetic data in `catalog/site.json` with the actual site and retain one authoritative catalog. Fill the exact hardware, VMID/MAC/IP/DHCP reservations, storage/template digests, paths/owners/maps, package/role pins, desired flows and scope evidence. Null means unresolved; false/zero are distinct. Do not guess a default to make a render apply.
3. Keep actual credential values elsewhere. Record private references for scoped PVE API/SSH/TLS trust, per-root state keys/backend tokens, separate authenticated-history identity, application keys/fabrics and independent recovery custody. A vault password does not replace its key file. Never place these values in workflow input strings or public plans/logs.
4. Bootstrap from an external workstation through the same exact public code and private catalog. The initial management LXC must be in the design; it cannot be the sole means of creating or recovering itself. Preserve an independently usable workstation bundle and admit explicit execution-owner takeover.
5. Configure a runner registered only to the private site repository after its account, native artifact, data volumes, resources, private trust and lifecycle are qualified. Do not attach public PR jobs to it. Public PR validation runs hosted with synthetic inputs and no production credentials/connectivity.
6. Bind an available approval mechanism to the exact release/catalog/tool/plan/target/downtime/expiry. Qualify its actual account features; GitHub environment names or workflow_dispatch alone are not proof of a reviewed production approval. Keep the approval authority and routine deployment credentials separate.
7. Qualify native state encryption, S3 conditional locking, one global execution owner, authenticated encrypted pre/post history including partial failure, private plan handling and independent recovery. GitHub concurrency is additional coordination, not a distributed lock. R2 is a candidate until its actual tests pass.
8. Install manual UniFi/DSM prerequisites and verify current access/retained clients. Network/firewall intent belongs in the catalog; initial UniFi writes are manual supported operations. Do not introduce an undocumented API just to automate a prerequisite.

## Execute the same implementation manually

From the private checkout, point to the reviewed public release:

```bash
export HOMELAB_IMPLEMENTATION_ROOT=/absolute/path/to/reviewed/homelab
python "$HOMELAB_IMPLEMENTATION_ROOT/bin/homelab" validate --catalog catalog/site.json
python "$HOMELAB_IMPLEMENTATION_ROOT/bin/homelab" render --catalog catalog/site.json --out .work/reviewed-render
```

These commands work now for local design validation/draft rendering. They do not clear unresolved inputs. Real `plan/apply/verify --target pve` is deliberately refused by this starter release until its adapters and admission contracts are implemented/qualified. Do not bypass that hold with direct ad hoc OpenTofu/Ansible commands. Synthetic execution uses a synthetic catalog; changing its environment flag cannot authorize production.

The private workflow template is a thin caller of a pinned reusable public workflow. All `.yml.example` files are inactive until reviewed, repository/ref placeholders replaced and their remaining production mechanisms qualified. Keep real plan output private/encrypted; do not upload it as a public Actions artifact. Local users and CI invoke the same public commands, including the same refusal behavior.

## Release and recovery

Freeze exact code/catalog/dependency/template/package inputs and operation evidence. Preserve the selected source/private generation before mutation; keep unrelated edits outside the frozen release. Approve a saved private preview and apply those same bytes under locks, then observe effective state and an explained no-op. Never regenerate a different plan at apply or overwrite edited live HA/Node-RED source during ordinary convergence. Recover state only after checking lineage/serial/partial operations; never push a stale local state to the backend automatically.
