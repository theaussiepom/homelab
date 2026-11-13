# Deploy and verify

Use this guide when your configuration is ready to deploy to its intended hosts. Begin with real site inputs and compatible, reviewed framework and library revisions fixed to exact commits. The procedure applies only to installations and changes that the selected adapter supports.

## Prerequisites

1. A supported Debian 13 LXC platform, a suitable host and template, sufficient storage and network capacity, and appropriate provider and SSH permissions.
2. Correct real endpoint allocations and SSH public keys. Source admission—the check that source is suitable for deployment—rejects known example bindings.
3. Existing trusted certificate-authority (CA) and known-host inputs, plus protected controller paths with the required Unix ownership and permissions. Compilation does not test those files.
4. Either a supported first-installation path, or current receipts, backend state and payloads proving that HomeLab owns the existing installation. There must be no conflicting active or pending marker. A site originally installed with `fresh` keeps that source for later deployments; there is no required lifecycle toggle. `retained` is not an import mechanism.
5. Exact declared software and artifact selections, the app's required data, credentials, databases and devices, and the required network access.
6. Generated workflows in the library and your deployment repository, the selected protected environment and runner labels, and named secrets forwarded at every reusable-workflow call.
7. Current source tests and the required security, history and signature checks and the applicable review decision for the current commit. A skipped review is not acceptance.
8. Explicit authority for the selected deployment/change, with recovery readiness appropriate to its effects.

Your deployment repository's guide supplies the actual paths and trigger. Public docs do not provide a default production repository, runner or credential.

## First installation

Complete [deployment preparation](../guides/prepare-deployment.md) and choose an adapter that supports first installation. Use your deployment repository's reviewed procedure to supply the actual trigger, fixed source revisions, target context and protected inputs. Deployment admission deliberately rejects the public synthetic examples. A valid plan does not supply missing trust inputs, data or accounts, or perform initial setup that must be completed through the vendor's own process.

Run only that supported procedure under authority for the selected installation. The phase contract below explains what the procedure does and when it stops. For an installation already managed by HomeLab follow [later deployments](verify-and-maintain.md#later-deployments); keep supported `fresh` source unchanged rather than toggling lifecycle.

## Review source before execution

Compile offline and check the generated workflow. Review changes to identities, storage, policies and private-source metadata, including the values inherited from defaults. Passing these checks does not authorize destructive operations or allow deployment with missing state. Generate and review every artifact from the same fixed source revisions.

## Phases and ordering

### Controller tools in CD

After checking out the immutable framework selection, each job's **Prepare tools** step creates a private virtual environment under `RUNNER_TEMP`. It installs that selection's complete `requirements.lock.txt` with pip's isolated mode, required package hashes and dependency resolution disabled. It then runs that environment's `ansible-playbook --version` before publishing its Python path and adding its executables to the job's `PATH`. Compilation, credential loading and deployment use the selected Python dependencies; Ansible commands resolve to the same environment.

Every job gets a separate directory, including parallel guest, selection and Backup jobs. The setup does not modify the controller's shared `/opt/homelab-tools`, require root access or reinstall/register the runner. First and later deployments use the same procedure; upgrading the reviewed framework selection selects its locked tools on the next job. OpenTofu and other native controller prerequisites retain their existing preparation path.

Environment creation, package installation or the Ansible version check failing stops setup before tools are published or a deployment phase runs. Keep the failed job's evidence. Package download access and the runner's existing Python/`venv` support must work. Source and isolated setup tests do not establish adoption on a live controller: inspect the actual job's version output and successful affected phases after CD.

### Guest phases

The generator creates one job for each enabled guest and preserves the declared dependencies between guests. Each job runs infrastructure, preparation, app phases and, when selected, the monitoring agent followed by the enrolled guest’s **Backup** phase. See the [backup sequence and readiness boundary](../backup/configure.md#review-the-generated-change). The infrastructure phase uses OpenTofu with the required plan and state checks. Preparation uses its defined data transfer object (DTO), which contains the inputs for that phase. Each app phase then selects its own fixed payload and protected inputs, plus the Ansible tasks owned by its adapter.

Declared readiness dependencies change the order in which phases run. Value references alone do not. The workflow rejects a selection that disables a required dependency or required monitoring server. Failure stops the chain; the normal CD workflow does not retry, release a HOLD or relabel an incomplete phase as success.

For a declared [source reply policy](../reference/guests.md#source-reply-routing),
preparation manages the existing guest-local routing helper and boot service.
It reconciles the selected policy without restarting the guest, Docker or an
application. Infrastructure NIC changes can still require a provider-managed
guest reboot; these are distinct operations and must be reviewed in the plan.

## Compare current infrastructure with the target

Plan admission compares the provider's refreshed current resources with the
proposed declared state. Historical mutable-value differences are retained as
evidence, not rejected merely because the saved state previously recorded
something else. For example, declared firewall allowances already present on
the owned guest can converge without removing and re-adding them. An undesired
extra rule in the fully owned guest policy can be reconciled to the declared
target. This does not authorize changing another guest, host or router policy.

Resource/node identity, root disk and existing data-volume identities and order
remain protected against both historical ownership loss and unsafe proposed
changes. Unknown required values, deletion, replacement, import, incomplete
plans and foreign resources remain refusals. Prepared backup staging still
requires its exact allocation/API/filesystem proof. Apply the admitted saved
plan even when only refreshed state needs persistence; never edit the backend
or canonical receipt manually to make the comparison pass.

Live configuration convergence does not release an interrupted operation.
The backend, exact HOLD, phase markers and applied infrastructure checkpoint
have separate custody checks. An existing phase-completion writer is not
permission to bypass a failed phase's entry checks; any supervised completion
requires a separately reviewed operation, actual complete phase success and
preservation of the failed evidence. The original failed workflow remains
failed even if a later authorized operation restores service or completes work.

## Observe and verify

Check the exact workflow, source revisions, run and attempt. Confirm the result of every affected guest phase and its completion receipt—the saved record of that successful operation. Preserve generic or redacted failure output. Where needed, use a separately reviewed read-only check limited to the evidence needed to establish the cause. Do not dump private controller files or the runtime environment into CI logs.

After successful CD, verify the intended layer: DNS answer, public TLS, backend transport, application health, authentication and data/device behavior. For telemetry use fresh observations; a cached healthy value is insufficient. Service acceptance and household/device acceptance can require additional checks beyond the pipeline. Use the [service verification guide](verify-and-maintain.md#service-verification) to define and record the actual outcome.

## Failure and recovery

Preserve the current pointer to the last successful operation, its immutable receipt, current HOLD and STARTED markers, checkpoints, and input evidence. Do not delete markers or edit state to rerun. Recovery, restore or an explicitly reviewed operator action requires separate authority; this guide introduces no generic override. [Lifecycle](../reference/lifecycle.md) and [Troubleshooting](troubleshooting.md) describe the boundaries.

[Operations index](README.md)
