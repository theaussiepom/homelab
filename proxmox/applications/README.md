# Application deployment

The component compiler emits a closed guest packet with explicit ordered phases,
provider inputs, app identities, project filenames and health checks. Start with
[component configuration](../../docs/components.md) and
[testing](../../docs/testing.md). The fixed guest-bundle authored API is available
at older immutable pins; this head does not translate that source or migrate its
state, receipts, credentials or data.

| Boundary | Owner |
| --- | --- |
| Component packet and selected phases | [component_guest.py](component_guest.py) |
| Static desired inputs | [component_inputs.py](component_inputs.py) |
| One app's private inputs | [component_prepare.py](component_prepare.py), [component_payload.py](component_payload.py) |
| Locks, holds and ordinary receipts | [deployment_state.py](deployment_state.py) |
| Provider/state reconciliation | [proxmox_guest.py](proxmox_guest.py), [OpenTofu module](tofu/guest/main.tf) |
| Selected Ansible variables and execution | [component_ansible.py](component_ansible.py) |
| App rendering and owned file identities | [component_runtime.py](component_runtime.py), [application_contract.py](application_contract.py) |

`deploy.py` remains the phase entrypoint used by protected CD. It validates the
packet before materialization, enters existing locks and hold checks, binds static
inputs, then prepares only the selected app payload. STARTED binds the exact
payload digest before native work; completion rechecks its bytes and metadata.
Incomplete publication, source drift, failed phases or ownership changes refuse.
There is no automatic adoption, retry, recovery or hold-clearing path.

OpenTofu owns guest resources and state. The declared execution context supplies
protected IDs, API/trust and control-interface authority. Ansible owns packages,
configuration and service reconciliation. Compose starts only explicitly selected
services with `--no-deps`; peer services and their private payloads are not read or
reconciled as a side effect. Shared source Compose files contain no peer late
`env_file` requirement. Workflow secrets are direct finite scalar inputs only to
the selected Deploy step; setup and common credential binding receive none of
those application secrets.

Retained data, controller-file inputs and package-account identities must match
their selected contracts. Fresh directory initialization is profile-owned,
create-only under a proven provider volume, and accepts an exact owned repeat.
It cannot chown or adopt foreign/retained data. Display labels do not own paths,
service names, credential IDs or custody directories. Changing a stable app ID
cannot transfer another app's existing persistent namespace.

Support is adapter-specific. Native database adapters use their supported package
service/config/data layout and explicit memory reservation. Namespace-aware
Unbound and proxy instances can be composed independently; fixed Pi-hole sidecars
and Zigbee coordinator receipts currently permit one instance per guest. Unsupported
commissioning or placement refuses rather than inventing a successful baseline.

Explorer's saved broker hostname uses only the compiler-derived selected endpoint
alias. Its public DNS, GUI listener, saved profile and credential owner remain
separate. Managed-account preparation preserves the retained broker container,
old account bytes and credential record. Existing-credential profiles use the
profile-only helper and cannot invoke broker account changes. Profile/workspace
or custody drift holds rather than rotates or rewrites an existing record.

Music state is checked read-only before startup. Zigbee retains its exact network
receipt. Pi-hole reconciles only its owned DNS records after startup and restarts
only when those records change. Authentik callback maintenance invokes the exact
retained provider/claim guard with the reviewed declarations. Root Zabbix keeps
monitoring-owned credentials and configures its local frontend before publication.
These are finite app hooks, not authored commands or generic scripts.

Run the commands in [testing.md](../../docs/testing.md). Source and disposable
container fixtures are integration evidence; they do not establish deployed PVE,
application, household or device acceptance. End-to-end verification requires
configuration through protected CD and actual service checks under its own scope.
