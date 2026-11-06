# Verify and maintain an owned installation

A completed workflow is evidence that its selected phases completed. Establish
the intended service result with fresh observations, then retain the source and
ownership context needed to review the next change. Begin after the
[deployment procedure](deployment.md); use the selected library profile for its
application-specific acceptance requirements.

## Service verification

Choose checks that demonstrate the actual changed behavior. These are review
categories, not a generic script that contacts every service.

| Intended result | Useful observation | What another observation cannot substitute |
| --- | --- | --- |
| DNS publication | Current answer from the intended resolver, with expected name/address | An emitted DNS record in a packet |
| Browser ingress | Public endpoint, certificate/hostname and backend response | Internal HTTP health alone |
| Authentication | The intended sign-in and authorization flow | A healthy unauthenticated endpoint |
| Persistent service | Named data visible and usable under the expected owner | Container/process running state |
| Integration/device behavior | Fresh protocol/device/user action and resulting state | Cached telemetry or source fixtures |

Record exact revisions, run/attempt, observation time, service/endpoint and the
result. Keep private values and credentials out of public logs. A check omitted
from the operation remains unverified; failure should preserve deployment and
service evidence rather than trigger an invented retry. See
[troubleshooting](troubleshooting.md) for stage-specific diagnosis.

## Later deployments

1. Change desired source at its owner. A library default affects inheriting
   instances; a consumer binding affects its selected instance. Preserve stable
   guest/app identity and private-source custody.
2. Compare the effective plan at the selected compatible revisions. Inspect
   allocations, NICs, paths, private role metadata, software, policies and explicit
   dependencies; use [validate and generate](../guides/validate-and-generate.md).
3. Review [change limits](../reference/lifecycle.md#change-effects), selected
   profile constraints, affected phases and possible interruption. The provider's
   ability to propose an operation does not make it admitted by HomeLab.
4. Run the required source/review gates and the consumer's protected procedure
   under the authority for this change. Keep the original supported `fresh`
   policy for ordinary updates; do not toggle it after installation.
5. Verify the affected service behavior and retain the new ordinary completion
   evidence. Untested recovery or future updates are not established.

Existing ownership requires current genuine receipts, sealed payloads and
backend identity. Changing `lifecycle` cannot repair missing/foreign ownership,
import data or release a HOLD. The [lifecycle reference](../reference/lifecycle.md#later-deployments-and-ownership-checks)
explains these requirements.

## When the result is incomplete

A failed phase may follow completed infrastructure or preparation work. Preserve
canonical/immutable success evidence and current STARTED/HOLD/checkpoints. Diagnose
the named boundary without deleting markers or editing state to force continuation.
Recovery, restore and operator actions require their actual supported procedure
and separate authority; no universal rollback or repeat command is supplied here.

[Operations index](README.md) · [Prepare a deployment](../guides/prepare-deployment.md) ·
[Evidence levels](../concepts/evidence.md)
