# PBS interface firewall

This separate host configuration uses `homelab-pbs-firewall-v1`; it is not a guest/app declaration and does not use the PBS backup API token. `proxmox/bootstrap/pbs_firewall.py` validates the explicitly named YAML file with the shared bounded authored loader. Unknown keys, omitted fields, null and empty values are refused. There are no implicit defaults or references to a site/library.

## Complete input and field index

The maintained [complete synthetic example](../../proxmox/bootstrap/pbs-firewall.example.yaml) is safe to validate offline and deliberately does not identify a deployable host:

```yaml
schema: homelab-pbs-firewall-v1
target:
  address: 198.18.25.3
  hostname: backup
apps:
  interface: ens5
  mac: '02:00:00:00:40:03'
  address: 198.18.40.3
  proxy: 198.18.40.33
```

| Path | Presence/type | Meaning and refusal |
| --- | --- | --- |
| `schema` | Required string | Exactly `homelab-pbs-firewall-v1`. Other versions are unsupported. |
| `target.address` | Required string | One canonical unicast IPv4 management host; no CIDR, hostname, loopback, link-local, multicast, unspecified or reserved address. |
| `target.hostname` | Required string | Observed short hostname, 1–63 ASCII letters/digits/hyphens, beginning and ending with a letter/digit. It binds the sole inventory alias and actual host. |
| `apps.interface` | Required string | Observed Linux Ethernet name, 1–15 ASCII letters/digits/underscore/dot/hyphen, beginning with a letter; `lo` is refused. No assumed naming or NIC creation. |
| `apps.mac` | Required string | Canonical lowercase six-octet unicast MAC, excluding all-zero. It must uniquely identify the selected interface on the host. |
| `apps.address` | Required string | Canonical unicast IPv4 service address; same host rules as `target.address`, distinct from management and proxy. No prefix or gateway is accepted. |
| `apps.proxy` | Required string | Sole canonical unicast IPv4 caller, distinct from both PBS addresses. CIDRs, groups and additional ports are unsupported. |

These fields are identities/allowance values, not a request to configure networking. Existing management, selected interface/MAC and selected service address remain fixed after first ownership; later CD can update the proxy allowance. A different network identity needs a separately reviewed handover rather than implicit takeover.

## Policy and persistence

Only local INPUT on the selected interface is filtered in the dedicated `inet homelab_pbs_apps` table. In order: drop IPv6, drop invalid traffic, accept IPv4 established/related **reply-direction** traffic, accept the exact proxy→service TCP8007 request in NEW or established state, then drop remaining input there. Other interfaces pass this chain. There are no OUTPUT/FORWARD/ARP rules, NAT, address assignment, network reload, application restart or reboot. See the upstream [conntrack direction and INPUT semantics](https://netfilter.org/projects/nftables/manpage.html); these explain the expressions but do not establish target acceptance.

The support floor is Debian 13 with the installed nftables 1.1.3 package and its stock service. First use requires the package's unmodified configuration, empty kernel ruleset, inactive/disabled service and no overrides. This deliberately refuses coexistence/takeover of another policy owner. Later use requires the exact root-owned generated configuration, owned stop-action drop-in and matching active table; unknown files, extra tables/rules, overrides or changed identity refuse before mutation.

The generated `/etc/nftables.conf` replaces only this table in a single nft batch. It contains no global flush or includes. The [stock Debian service](https://sources.debian.org/src/nftables/1.1.3-1/debian/nftables.service/) loads it at boot and reload; the owned drop-in clears only its global `ExecStop`. CD syntax-checks before copying, loads when changed, enables/starts the stock service without restart, then verifies exact file, loaded unit and rules. Stopping that service leaves its policy in place. A failed or uncertain update stops CD and retains its real logs; there is no automatic rollback, retry, repair or policy-removal branch.

## Validate and deploy

From the selected framework checkout, using its locked Python tools:

```sh
python3 proxmox/bootstrap/pbs_firewall.py --config proxmox/bootstrap/pbs-firewall.example.yaml --check
python3 proxmox/bootstrap/pbs_firewall.py --config proxmox/bootstrap/pbs-firewall.example.yaml --emit
```

`--check` reports acceptance only; `--emit` writes the same validated document as JSON. Neither contacts a host or reads SSH credentials. Supplying a missing file, duplicate YAML key or sibling format is refused by the shared loader. For example `apps.proxy: 198.18.40.0/24` fails source validation; supply the exact permitted host instead. A well-formed but wrong MAC passes offline validation and fails the target preflight.

The private protected main workflow must run the existing `deployment_state.bootstrap_closed()` guard before inventory, credentials or contact. An absent authored PBS binding means unselected. It builds **one** `pbs` inventory host whose alias equals `target.hostname`, `ansible_host` equals `target.address`, and `ansible_user=root`, with SSH as the connection.

Keep the private key outside Git: its explicit absolute path must name a single
regular file owned by the actual CD actor, mode 0600. The independently reviewed
known-hosts file must be a single root/CD-owned regular file, mode 0600 or 0644,
at most 64 KiB, containing only this target's literal management address
(optionally also its exact hostname) and public host keys. Its
`UserKnownHostsFile` value must be one literal absolute path: percent/dollar
expansion, whitespace, quotes and backslash syntax are unsupported.
[OpenSSH can expand tokens and environment variables or select multiple files](https://man.openbsd.org/OpenBSD-7.7/ssh_config.5#UserKnownHostsFile);
the local validator and SSH must read the same selected file. Links,
wildcard/hashed/CA entries, unrelated hosts and writable trust files are refused.

The private-key path must also be literal and absolute. Percent tokens,
`${...}` environment expansion, double quotes, backslashes and line breaks
are unsupported because OpenSSH can expand or reparse the `IdentityFile`
argument. Ansible quotes this argument, so ordinary spaces and apostrophes
remain supported. The selected private key and known-hosts file must be
different files, including when different path spellings identify the same
file; the precontact check must never open the selected private key as a
public host pin.

Both selected files require root/CD-owned ancestor directories without symlink
components. Group/other-writable directories are refused unless their sticky
bit protects the next root/CD-owned entry, as in a standard `/tmp` directory
under the [Linux rename restrictions](https://man7.org/linux/man-pages/man2/rename.2.html#ERRORS).
Every child directory and leaf still has to satisfy its ownership checks; a
sticky parent does not admit a foreign-owned child. These checks preserve the
selected path against replacement by other users until SSH reads it. Root and
the CD actor remain trusted; this does not isolate conflicting writers using
the same account. Apply the same checks on first installation and later CD;
do not loosen file or directory ownership to pass admission.

The precontact check reads the actual Ansible SSH option resolution, including CLI overrides. Its effective host, user and port must match the selected management address, `root` account and port 22. Matching SSH aliases are supported; conflicting aliases or an inherited different port refuse before contact. It requires standard SSH, no extra SSH/SCP/SFTP arguments, `-F /dev/null` to exclude inherited configuration, `StrictHostKeyChecking=yes`, `GlobalKnownHostsFile=/dev/null`, explicit `UserKnownHostsFile`, `BatchMode=yes`, `IdentitiesOnly=yes`, `ControlMaster=no`, `VerifyHostKeyDNS=no` and `UpdateHostKeys=no`; conflicting repeated options are refused. It reads only metadata for the private key, never its content. Do not weaken controller `NoNewPrivileges` or use local sudo. Then invoke stock Ansible with `pbs_firewall_config` set to the absolute authored path:

```sh
ANSIBLE_SSH_ARGS='-F /dev/null -o ControlMaster=no' \
ansible-playbook -i /private/reviewed/inventory.json \
  --private-key /private/protected/ssh-key \
  --ssh-common-args '-o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o UserKnownHostsFile=/private/reviewed/known_hosts -o BatchMode=yes -o IdentitiesOnly=yes -o ControlMaster=no' \
  proxmox/bootstrap/ansible/pbs-firewall.yml \
  -e pbs_firewall_config=/private/reviewed/pbs-firewall.yaml
```

This command is invocation notation: the paths must be replaced with reviewed private inputs. Local revalidation and inventory assertions are delegated with `become:false` before any remote facts. Remote configuration uses the existing explicitly authorized SSH account; no credential/grant creation or PBS token extension is implemented.

## Installation, updates and verification

Before first CD, independently establish console/management recovery, installed package/service, a disconnected positively identified extra NIC and an approved maintenance window. The selected NIC must not be enslaved to a bridge/bond/master or own management, a default route, another global address or an existing NFS storage route. Bridged/bonded interface filtering and multipath or unresolved default routes are unsupported; CD does not add another route-resolution mechanism. Mounted NFS sources must name literal IPv4/IPv6 servers so the existing storage route can be checked without guessing hostname resolution; ambiguous sources are unsupported. Retain its disconnected state until CD's exact policy/persistence checks succeed; subsequent network exposure remains a separate operation.

Persistence observation disables checksum and MIME content probes. Before
reading the fixed files, CD requires root ownership, one hard link, the
declared regular-file modes and at most 16 KiB per file. It also checks the
optional override directory's root ownership and mode 0755. Linked, foreign,
writable or oversized files refuse before their content is read.

Later deployments verify current ownership before applying the declared proxy change. Repeat unchanged input is idempotent; changed native policy/configuration is refused. Verify the intended proxy TLS path, non-proxy TCP8007/SSH/other IPv4 and all IPv6 denials on the selected NIC, continuing DNS/NFS/egress and unchanged management. CD cannot prove those client paths or future boot behavior without target observation. Preserve real failure evidence and obtain a reviewed next action instead of forcing adoption.

Network readback preserves interface/address identity, route attributes and their order. It ignores only the native address lifetime and route-expiry countdowns; elapsed lease or Router Advertisement time is not a configuration change. Address, prefix, route, interface and other attribute changes still refuse.

## Source evidence and navigation

[Validator](../../proxmox/bootstrap/pbs_firewall.py), [playbook](../../proxmox/bootstrap/ansible/pbs-firewall.yml), [template](../../proxmox/bootstrap/ansible/pbs-firewall.nft.j2), [focused contract tests](../../proxmox/bootstrap/tests/test_pbs_firewall.py) and [shared SSH path controls](../../proxmox/bootstrap/tests/test_bootstrap_ssh.py) are maintained together. The test-local coverage map associates every field and example with direct validation, target/ownership refusals and isolated Linux policy controls. Fakes do not establish native installation; target acceptance is separate.

[Server setup](../backup/server.md#limit-a-separate-browser-interface-through-cd) · [Backup guide](../backup/README.md) · [Reference index](README.md)
