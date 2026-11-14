# Verify and maintain an owned installation

A completed workflow is evidence that its selected phases completed. Establish the intended service result with fresh observations, then retain the source and ownership context needed to review the next change. Begin after the [deployment procedure](deployment.md); use the selected library profile for its application-specific acceptance requirements.

## Service verification

Generated CD already runs native readiness and [shared HTTPS exposure checks](../reference/exposures.md#https-deployment-checks). Use additional checks only for changed behaviour those cannot establish, such as authenticated access, data or device operations.

| Intended result | Useful observation | Insufficient on its own |
| --- | --- | --- |
| DNS publication | Current answer from the intended resolver, with expected name/address | An emitted DNS record in a packet |
| Browser ingress | Public endpoint, certificate/hostname and backend response | Internal HTTP health alone |
| Authentication | The intended sign-in and authorization flow | A healthy unauthenticated endpoint |
| Persistent service | Named data visible and usable under the expected owner | Container/process running state |
| Integration/device behavior | Fresh protocol/device/user action and resulting state | Cached telemetry or source fixtures |

Record exact revisions, run/attempt, observation time, service/endpoint and the result. Keep private values and credentials out of public logs. A check omitted from the operation remains unverified; failure should preserve deployment and service evidence rather than trigger an invented retry. See [troubleshooting](troubleshooting.md) for stage-specific diagnosis.

## Later deployments

1. Change the desired configuration in the repository responsible for it. A library default affects instances that inherit it; a binding in your configuration affects the selected instance. Preserve stable guest and app identities and the ownership and protection of private sources.
2. Compare the effective plan at the selected compatible revisions. Inspect allocations, NICs, paths, metadata for private input roles, software, policies and explicit dependencies; use [validate and generate](../guides/validate-and-generate.md).
3. Review [change limits](../reference/lifecycle.md#change-effects), selected profile constraints, affected phases and possible interruption. HomeLab may reject an operation even if the provider can propose it.
4. Run the required source and review checks and your protected deployment procedure under the authority for this change. Keep the original supported `fresh` policy for ordinary updates; do not toggle it after installation.
5. Verify the affected service behavior and retain the new completion receipt and observations. These results do not establish that an untested recovery or future update will work.

Before updating an existing installation, HomeLab requires current receipts from its actual successful operations, sealed payloads whose contents remain fixed, and a matching backend identity. Changing `lifecycle` cannot repair missing ownership, take over another installation, import data or release a HOLD. The [lifecycle reference](../reference/lifecycle.md#later-deployments-and-ownership-checks) explains these requirements.

## When the result is incomplete

A failed phase may follow completed infrastructure or preparation work. Preserve the pointer to the latest success, its immutable receipt, current STARTED and HOLD markers, and checkpoints. Diagnose the phase that failed without deleting markers or editing state to force continuation. Recovery, restore and operator actions require their actual supported procedure and separate authority; no universal rollback or repeat command is supplied here.

[Operations index](README.md) · [Prepare a deployment](../guides/prepare-deployment.md) · [Evidence levels](../concepts/evidence.md)
