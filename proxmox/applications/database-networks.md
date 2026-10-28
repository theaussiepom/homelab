# Private networks for database guests

[Proxmox guide](../README.md) · [Application deployment](README.md) · [Bootstrap](../bootstrap/README.md)

Each database gets its own small network inside Proxmox. Only that database
server and the guests that use it join the network. Management, internet access
and application traffic keep their existing connections.

An **internal bridge** is a virtual switch inside Proxmox. It needs no cable,
router address or UniFi VLAN. Guest database interfaces have a static address,
no VLAN tag and no gateway. They do not replace the management interface.

## Put the network choices in one place

Keep a private `networks/databases.json`, following the
[example](examples/database-networks.example.json). It lists each bridge's
purpose, subnet, database server and allowed client guests. Actual site values
belong in your private deployment repository.

The reusable [renderer](database_networks.py) derives guest interfaces, database
endpoints and exact client firewall rules from that file. Service-specific CD
uses the same file and pins its hash in its reviewed inputs. It must not keep a
second, separately maintained list of database addresses.

| Owner | What it maintains |
| --- | --- |
| Host bootstrap | Internal bridges, their purpose descriptions and the deployment token's declared bridge permissions |
| Database guest CD | The server's database interface, listener and client access rules |
| Application guest CD | That client's database interface, connection setting and outbound rule |

The bootstrap renderer accepts `--database-networks` to add the declared bridges
to its host configuration. This option leaves commissioned application profiles
unchanged. Existing bootstrap inputs without that option retain their original
behavior. Bridge descriptions are saved in Proxmox's **Comment** field.

## Move an existing service in stages

```mermaid
flowchart LR
  B[Create internal bridge] --> D[Replace selected database connection]
  D --> C[Update selected client connections and endpoints]
  C --> V[Test authenticated database use]
```

Choose the transition in the reviewed deployment packet. A direct cutover
replaces the old database interface, listener and access rules in the coordinated
server/client update. It does not retain an old database fallback path. Any
brief service interruption belongs in that exact cutover plan.

Preserve existing interface names and the management default route. Client
HTTP and MQTT interfaces can still use the shared application bridge; removing
a database's old connection does not remove that bridge or unrelated app traffic.

For an installed server, use a reviewed maintenance operation. **Do not rerun
its initial deployment or restore its database just to change networking.** The
existing database CD deliberately refuses changed installation inputs and later
runs only verification. This renderer does not bypass that protection.

PostgreSQL needs its listener and allowed client addresses updated together.
MariaDB host-specific grants also need checking. InfluxDB keeps its existing
organization, buckets and tokens. Do not replace application credentials as
part of this move.

## What is proved by these checks?

Source tests exercise the contract, finite membership, generated interfaces,
firewall rules and bootstrap reconciliation. They check one network reload,
repeat runs without changes and refusal of unrelated host edits. These checks
do not prove that a bridge exists on your server or that an application can use
its new connection. Record those results after the approved CD run.

## Maintenance preparation for existing guests

[database_network_maintenance.py](database_network_maintenance.py) prepares a
read-only plan with the original installer and its existing state/backend and
locks. It records the contract and original installation bindings separately.
For PostgreSQL, the checker permits only the selected database NIC replacement
and SQL-rule changes. It keeps management, storage and other settings intact.
It rejects resource creation, replacement, deletion, unrelated changes and
unknown values. A failed planning attempt remains held across new run IDs.
The provider also refreshes observed IP addresses and can represent an omitted
value as empty instead of null. The checker records these limited differences
without changing the saved evidence. Changes to actual interfaces, routes,
permissions, disks or other configuration still stop the operation.

[database_network_apply.py](database_network_apply.py) applies an exact checked
saved plan once. It uses the same original state and locks, keeps the original
installation records, and saves separate local/NAS maintenance evidence. Later
CD runs verify the new network without applying it again or checking the retired
address. A failure or interrupted attempt remains held for review.

For the existing PostgreSQL server, Authentik and pgAdmin, the
[coordinator](database_network_cutover.py) checks all three prepared operations
before pausing either client. It updates the network, PostgreSQL listener and
client settings together, then verifies the maintained services. It does not
restore databases, reinstall applications, replace credentials or change web
addresses. The service owners supply Authentik and pgAdmin's small runtime
adapters; their source pins remain separate from the original installers.

A reviewed native plan and complete server/client activation packet are still
needed before an actual cutover. Source availability is not deployment approval.
Before approving it, confirm the current SQL consumer inventory: every existing
consumer must be in the selected group or explicitly deferred while inactive.
The approval also covers partial failure: if one client stops and the next step
fails, that client stays stopped; after both stop, either or both may remain
stopped until the failure is reviewed. CD never clears that hold or resumes a
partly moved group automatically.
A provider's `update` plan alone does not prove lifecycle effects; the packet
explicitly covers any required guest cycle and the selected PostgreSQL restart.
After removing an old address, use new-network checks; preserving historical
installation receipts does not mean continuing to probe the retired address.

Existing Authentik, pgAdmin and database guests can update their startup gate
with [network-update.yml](ansible/network-update.yml). The maintenance packet
must supply the exact current startup-file hashes. The playbook waits for the
selected interfaces, updates the shared dependency and checks the running
service process stayed unchanged. It does not restart Docker or the database.
Application activation remains a separate, explicitly selected cutover step.
