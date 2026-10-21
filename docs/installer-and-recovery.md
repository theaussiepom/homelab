# Installer and workstation recovery drafts

The installation remains a separately destructive attended release step. This package has not built a bootable ISO, executed a native answer parser, installed a disposable VM or changed firmware/networking. The answer generator is intentionally synthetic-only and cannot render the actual production catalog.

## Exact disk observation and refusal

On an already admitted Linux inspection host, the following helper reads block/by-id metadata only:

```bash
python infrastructure/bootstrap/observe-disks.py > observed-disks.json
python bin/homelab disk-check --expected expected-disk.json --input observed-disks.json
```

`expected-disk.json` has `by_id`, `serial`, and `size_bytes`. Freeze those exact values from trusted read-only evidence; never use a positional device name or wildcard as erase selection. Zero/multiple/mismatched disks and unknown/read-only state refuse. A matching result explicitly has `erase_authorized:false`. Recheck on the actual installer immediately before the separate wipe decision.

## Answer and media preparation

Supply a valid protected supported password-hash file; do not put the hash/key or real site answer in public Git:

```bash
python bin/homelab installer-answer --catalog examples/site/catalog/site.json --root-password-hash-file /protected/root-password.hash --out .work/answer.toml
```

The generator uses supported official answer fields, exact serial filter, single-disk ZFS and before-network firstboot ordering. Python TOML parsing is tested; native helper/build acceptance remains required. NIC udev filters must be observed on the intended installer rather than assumed from current Ubuntu interface names.

After pinning the actual installer/helper and **implementing/qualifying the firstboot payload**, the official helper exposes:

```bash
proxmox-auto-install-assistant validate-answer answer.toml
proxmox-auto-install-assistant prepare-iso BASE.iso --fetch-from iso --answer-file answer.toml --on-first-boot first-boot.sh --output PREPARED.iso
```

Those native commands are vendor interfaces documented from source; they were not run here. `first-boot.sh` is an outstanding required release artifact, not a supplied working payload. A media builder must refuse before producing usable production media when that payload, its hash or required network/trust fields are absent.

The answer alone does not establish the intended tagged management network. Freeze installer-access topology, actual NIC identities/udev properties, final tagged bridge/static recovery, DNS/gateway, SSH/API trust, ZFS geometry and missing-source safeguards. Implement an offline firstboot payload from those inputs, with exact prior-file/target checks and preserved recovery access. Qualify the full disposable EFI install, intended Secure Boot behavior, firstboot ordering and persistent reboot. Nested success does not establish physical NIC/firmware equivalence.

Wrong-disk refusal tests run on synthetic observations only. No installer boot, partition write, filesystem creation, mount operation or firmware change is performed by these Python helpers.

## Recovery from the external workstation

Keep the exact public implementation/tool release, private catalog, key files/passphrases, independent PVE/SSH/backend trust and current authenticated encrypted state history independently accessible. Validate/render through the same public commands as private CI. Before a takeover stop/revoke the old runner, establish latest lineage/serial/partial operations and acquire the admitted global lock. A job must never depend on surviving its own deploy-LXC or Beast shutdown.

After source-SSD erasure, recovery is rebuild-and-restore. Before erasure require coherent off-SSD app/native DB/private-source/image capture and a demonstrated rebuild path. `capture-manifest.example.json` illustrates the actual generic file-verifier input; replace every filename/size/hash with current admitted capture metadata. `homelab recovery-check` hashes files without changing them, but a checksum pass does not test database/fabric recovery. Service-native capture/restore commands come from the owning qualified release, not a generic archive wrapper.
