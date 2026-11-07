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

The generator creates one job for each enabled guest and preserves the declared dependencies between guests. Each job runs infrastructure, preparation, app phases and, when selected, a final monitoring-agent phase in that order. The infrastructure phase uses OpenTofu with the required plan and state checks. Preparation uses its defined data transfer object (DTO), which contains the inputs for that phase. Each app phase then selects its own fixed payload and protected inputs, plus the Ansible tasks owned by its adapter.

Declared readiness dependencies change the order in which phases run. Value references alone do not. The workflow rejects a selection that disables a required dependency or required monitoring server. Failure stops the chain; the normal CD workflow does not retry, release a HOLD or relabel an incomplete phase as success.

## Observe and verify

Check the exact workflow, source revisions, run and attempt. Confirm the result of every affected guest phase and its completion receipt—the saved record of that successful operation. Preserve generic or redacted failure output. Where needed, use a separately reviewed read-only check limited to the evidence needed to establish the cause. Do not dump private controller files or the runtime environment into CI logs.

After successful CD, verify the intended layer: DNS answer, public TLS, backend transport, application health, authentication and data/device behavior. For telemetry use fresh observations; a cached healthy value is insufficient. Service acceptance and household/device acceptance can require additional checks beyond the pipeline. Use the [service verification guide](verify-and-maintain.md#service-verification) to define and record the actual outcome.

## Failure and recovery

Preserve the current pointer to the last successful operation, its immutable receipt, current HOLD and STARTED markers, checkpoints, and input evidence. Do not delete markers or edit state to rerun. Recovery, restore or an explicitly reviewed operator action requires separate authority; this guide introduces no generic override. [Lifecycle](../reference/lifecycle.md) and [Troubleshooting](troubleshooting.md) describe the boundaries.

[Operations index](README.md)
