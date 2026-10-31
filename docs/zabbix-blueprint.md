# Zabbix blueprint

Add an empty root property to the private deployment configuration:

```yaml
zabbix:
```

The existing JSON configuration represents that as `"zabbix": null`. Presence
selects the MVP defaults. An absent property leaves the existing eleven guests
and their deployment packets unchanged. Boolean values and custom objects are
rejected until a later version explicitly implements configurable settings.

The feature adds the permanent `monitoring` blueprint, displayed as **Zabbix**,
and creates its own Debian LXC through the existing OpenTofu guest implementation.
The stack supplies its VMID, resources, interfaces and pinned official images;
the private site supplies its real addresses and a domain such as `zabbix.example.invalid`.
The current proposal uses VMID216, 2 CPUs, 2 GiB RAM and a 12 GiB root disk.
Actual identity/address availability must be checked before native creation.

## Monitoring defaults

- Agent2 on every selected guest, including the Zabbix guest, with the active
  Linux template and an individual PSK. No passive listener or remote command
  execution is enabled. Agents can start before the server exists.
- The active Docker template on guests declaring the Docker capability. The
  guest-local agent joins that guest's Docker group; this grants access to its
  privileged Docker API. No Docker API is published on a network, no socket
  permissions are relaxed, and the central server receives no Docker socket.
- PostgreSQL and MariaDB templates with dedicated local statistics accounts,
  configured only by the database guest's existing CD job. Application accounts
  and passwords are preserved.
- InfluxDB2 instance health and Prometheus metrics through its internal network.
  Organization/bucket discovery is outside this MVP because it needs a separate
  scoped API credential; the prepared template omits that discovery rule.
- The official Proxmox HTTP template using the existing dedicated read-only
  monitoring identity and full certificate/hostname verification.

The compiler derives host names, template selections, exact firewall connections,
the dedicated PostgreSQL storage allowance, DNS and the Traefik route. The new
server depends on PostgreSQL and ingress. Neither PostgreSQL nor any other guest
depends on the monitoring server. Existing disabled-leaf selection remains valid.

## Credentials and initial installation

The existing controller state directory holds create-once, private records under
`monitoring-credentials/`. They bind the node, VMID and guest identity. Individual
PSKs, the new storage password, the administrator password and statistics
passwords are never placed in Git or printed. A short file-custody lock protects
concurrent key creation; it does not serialize guest deployment. Missing or
changed credentials are not an instruction to rotate a commissioned key.

PostgreSQL CD creates only the new `zabbix` database/owner and verifies its
ownership and authentication on later runs. Existing application data is not
restored, migrated or recommissioned. The new server imports the pinned templates
and creates the inventory's hosts. Subsequent runs preserve PSKs, secret macros,
host identities and history; no import uses destructive `deleteMissing` rules.

The first frontend binds only to guest loopback until the factory administrator
password has been replaced and template/host configuration succeeds. The normal
Compose phase then publishes the browser listener behind Traefik. The API
configurator continues to use only guest loopback over the existing pinned SSH
channel, so it does not send its administrator credential between guests.

Normal host commissioning remains mandatory: the application deployer needs its
guest216 grant and verified guest SSH trust; Traefik's existing discovery token
needs its scoped read grant; `proxmox/bootstrap/monitoring_access.py` owns creation
of the dedicated read-only Proxmox token and private receipt. The guest deployment
reads that retained token from
`/var/lib/homelab-bootstrap/monitoring-access/token.json`. It never substitutes the
application deployment token or silently grants itself host permissions. The
existing bootstrap CD accepts a closed `monitoring` selection containing the
Zabbix VMID and management address, with the same `zabbix` application identity
and normal application network grants. That phase calls the existing read-only
access transaction and retains its private owner/token/READY receipts. Extend the
existing discovery guest scope through its normal receipt-bound bootstrap path.
These are explicit native commissioning operations, not extra root user settings.

Every selected guest's input preparation verifies the exact completed monitoring
bootstrap owner/READY/token before creating a key or changing a guest. Those files
join normal input identity hashes. A missing/held/foreign bootstrap result stops
CD before any monitoring agent or database reader is installed.

Before native commissioning, review the actual access impact: the dedicated
Proxmox identity has nonexpiring, cluster-wide `Sys.Audit`, `VM.Audit` and
`Datastore.Audit` grants, plus one server-address `/32` host API allowance.
Docker monitoring grants the guest-local agent root-equivalent Docker engine
access on each Docker-capable guest. The root property selects these defaults;
there are no extra per-guest user flags. Source publication does not approve or
perform those native grants. Their actual commissioning and the private CD
selection remain separately reviewed before activation.

All native steps remain within existing per-guest locks, ordered phases, failure
holds and the private reviewed-main deployment queue. There is no second
monitoring deployment controller, automatic failed-attempt replay or rollback.

## Completion evidence

Source compilation and fixtures are distinct from native acceptance. The MVP is
complete only after actual CD creates the dedicated guest, the verified HTTPS UI
works, Proxmox and every enabled guest report fresh data, Docker and database
metrics are supported, and another deployment preserves identities and history.
Notifications, remediation and custom monitoring rules are future work.
