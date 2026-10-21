# Rehearsal and readiness evidence

## Executable local checks now

Run the README commands against the public synthetic catalog; repeat the final plan to establish an explained local no-op. Pytest covers duplicate/mistyped identities, forbidden privilege/boot/backup changes, wrong/missing/ambiguous disks, missing/changed/checksum-wrong recovery files, wrong mounts/owners, stale plans/state, tampered/expired approval and execution-lock contention. Ansible local check-mode tests prove default preparation refusal and missing-manifest verification refusal with no changes.

Check Ansible syntax with an explicit non-production inventory:

```bash
cd ansible
ansible-playbook -i localhost, --syntax-check playbooks/discover.yml
ansible-playbook -i localhost, --syntax-check playbooks/prepare.yml
ansible-playbook -i localhost, --syntax-check playbooks/verify.yml
```

The pinned provider can be initialized with backend disabled and all four roots validated. Supply a temporary fixture passphrase only for these isolated checks; production has independently recoverable per-root keys. Do not use a public fixture key to encrypt production state. The local native-encryption helper configures only the built-in provider and writes into a new private test directory.

## Required full disposable rehearsal

| Stage | Required observable pass | Stop condition |
|---|---|---|
| Frozen inputs | Exact code/tool/template/native package/image/private fixture release | Floating/unresolved/incorrect target identity |
| Installer | Native answer validation, wrong-disk refusal, correct EFI/firstboot/tagged management, trust and persistent reboot | Missing payload/recovery path, ambiguous disk or network |
| Foundation | Import/adopt exact bootstrap objects, scoped API role and no-op; final staged network/firewall apply | Overlapping owner, unexpected replacement/pending change/access loss |
| Guests/controller | Stopped filtered creation and managed volume backup/maps; workstation/deploy handover under locks | Missing filter/identity/map/runner isolation/state recovery |
| Native services | Compatible package IDs and full actual-state restore into isolated targets; native integrity/auth/clean drain | Unsupported account/package, stale/incomplete generation or ambiguous shutdown |
| Application consumers | Real required API/TLS/auth/listener/DB/broker paths using controlled fixtures | Unqualified private state, failed consumer or device side effect |
| Recovery/lifecycle | Native guest/file/native-service restore; missing-source holds; checkpoint on partial failure; external takeover | Empty-source fallback, lost generation, lock/history/key ambiguity |
| Packet paths | Required allows and denies across role/return/IPv6/Thread boundaries | Broad trust, unintended route/DNS/WAN or disrupted retained client |

Record exact receipts, measured duration and limitations. Preserve earlier valid bounded tests; repeat only affected boundaries. Synthetic records/TOML/schema/Ansible syntax cannot replace full PVE/native restore/physical acceptance. Actual radio commands, resets, physical device actions and power exercises require their own scope and are absent from this local harness.

Prioritize DNS/management, required databases, MQTT/HA/Node-RED/Zigbee and required Traefik/auth, then Bitwarden/remaining apps. Bring a route online when its own backend/auth/TLS dependencies pass; an unrelated failed database is not a global barrier. Keep each controller sole-active and protect new target writes during admission.
