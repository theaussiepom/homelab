# Application deployment

The component compiler produces a guest packet: a file containing the generated deployment inputs. It includes ordered phases, provider inputs, app identities, project filenames and health checks, and accepts only the fields defined by its contract. Start with [component configuration](../../docs/components.md) and [testing](../../docs/testing.md). The earlier API for fixed guest bundles remains available at its original source revisions. This revision does not translate that source or migrate its state, receipts, credentials or data.

| Boundary | Owner |
| --- | --- |
| Component packet and selected phases | [component_guest.py](component_guest.py) |
| Static desired inputs | [component_inputs.py](component_inputs.py) |
| One app's private inputs | [component_prepare.py](component_prepare.py), [component_payload.py](component_payload.py) |
| Locks, holds and ordinary receipts | [deployment_state.py](deployment_state.py) |
| Provider/state reconciliation | [proxmox_guest.py](proxmox_guest.py), [OpenTofu module](tofu/guest/main.tf) |
| Selected Ansible variables and execution | [component_ansible.py](component_ansible.py) |
| App rendering and owned file identities | [component_runtime.py](component_runtime.py), [application_contract.py](application_contract.py) |

`deploy.py` remains the phase entrypoint used by protected CD. It validates the packet before writing its files, acquires the existing locks, checks for holds, binds the static inputs, then prepares only the selected app's payload. Before work begins on the target, the STARTED record stores the exact payload digest. Completion checks the bytes and metadata again. The runner rejects incomplete publication, changed source, failed phases or changed ownership. There is no automatic adoption, retry, recovery or hold-clearing path.

OpenTofu owns guest resources and state. The declared execution context supplies protected guest IDs, API credentials, trust inputs and the selected control interface. Ansible owns packages, configuration and service reconciliation. Compose starts only explicitly selected services with `--no-deps`. It does not read or reconcile other services or their private payloads as a side effect. Shared source Compose files do not require a late-bound `env_file` from another app. Workflow secrets are passed directly as individual values only to the selected Deploy step. Setup and common credential binding receive none of those application secrets.

Retained data, controller-file inputs and package-account identities must match their selected contracts. The profile controls initialization of new directories. Initialization creates them only under a verified provider volume and assigns the required owner to each new app directory. A repeat is accepted only when the existing directory exactly matches the recorded owner and settings. Initialization cannot change the Unix owner of an existing directory or adopt existing data, whether retained or owned by someone else. Display labels do not determine ownership of paths, service names, credential IDs or directories holding protected inputs. Changing a stable app ID cannot transfer another app's existing persistent paths and identities.

Support is adapter-specific. Native database adapters use their supported package, service, configuration and data layout, with an explicit memory reservation. Namespace-aware Unbound and proxy instances can be composed independently; fixed Pi-hole sidecars and Zigbee coordinator receipts currently permit one instance per guest. Deployment rejects initial setup or placement that the adapter does not support.

Explorer's saved broker hostname uses only the compiler-derived selected endpoint alias. Its public DNS, GUI listener, saved profile and credential owner remain separate. Managed-account preparation preserves the retained broker container, old account bytes and credential record. Existing-credential profiles use the profile-only helper and cannot invoke broker account changes. If the profile, workspace or credential ownership no longer matches, deployment stops with a hold. It does not rotate credentials or rewrite the existing record.

Music state is checked read-only before startup. Zigbee retains its exact network receipt. Pi-hole reconciles only its owned DNS records after startup and restarts only when those records change. Authentik callback maintenance invokes the exact retained provider/claim guard with the reviewed declarations. Root Zabbix keeps monitoring-owned credentials and configures its local frontend before publication. These hooks perform defined app-specific operations. Source declarations cannot replace them with arbitrary commands or scripts.

Run the commands in [testing.md](../../docs/testing.md). Tests using source and disposable containers provide evidence about integration. They do not establish that deployment to Proxmox VE succeeded or that applications, household services or devices work. End-to-end verification requires configuration through protected CD and actual service checks under its own scope.
