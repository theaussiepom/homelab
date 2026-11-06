# Deploy and verify

This is the supported deployment path, not an instruction to deploy an arbitrary
example. Begin with a real consumer site and compatible reviewed immutable
framework/library selections.

## Prerequisites

1. Supported Debian13 LXC platform, host/template/storage/network capacity and
   appropriate provider/SSH permissions.
2. Correct real endpoint allocations and SSH public keys; source admission
   rejects known example bindings.
3. Existing trusted CA/known-host inputs and protected controller paths with
   their required ownership/modes. Compile does not test those files.
4. A supported first-installation path or genuine current owned
   receipt/backend/payload continuation, with no conflicting active/pending marker.
   A site originally installed with `fresh` keeps that source for later deployments;
   there is no required lifecycle toggle. `retained` is not an import mechanism.
5. Declared exact software/artifact selections, app-specific data/credential/
   database/device prerequisites and required traffic.
6. Generated library/consumer workflows, selected protected environment and
   runner labels, named secrets forwarded at every reusable-workflow edge.
7. Current source tests, security/history/signature gates and the applicable
   exact-current-head review decision. A skipped review is not acceptance.
8. Explicit authority for the selected deployment/change, with recovery readiness
   appropriate to its effects.

The consumer's guide supplies its actual paths and trigger. Public docs do not
provide a default production repository, runner or credential.

## First installation

Complete [deployment preparation](../guides/prepare-deployment.md) and select an
adapter with an actual supported fresh path. The consumer's reviewed procedure
supplies its real trigger, immutable source selections, target context and
protected inputs. Public synthetic examples are deliberately inadmissible.
A valid plan does not create missing trust, data, accounts or vendor commissioning.

Run only that supported procedure under authority for the selected installation.
The phase contract below explains its effects and stopping boundary. For an
already owned installation follow [later deployments](verify-and-maintain.md#later-deployments);
keep supported `fresh` source unchanged rather than toggling lifecycle.

## Review source before execution

Compile offline, check workflow generation, inspect changed identities, storage,
policies, private-source metadata and effective defaults.
A successful check does not approve destructive operations or missing state.
Keep generated artifacts tied to the same immutable source selections.

## Phases and ordering

Each enabled guest has one generated job, preserving explicit guest dependencies.
Its ordered phases are infrastructure, preparation, app phases, then an optional
final monitoring agent. Infrastructure uses the guarded OpenTofu plan/state
contract. Preparation uses the explicit preparation DTO, then app phases select
their own immutable payload/material and adapter-owned Ansible tasks.

Declared readiness changes ordering. Values alone do not. Required dependency
or monitoring-server disablement refuses. Failure stops the chain; ordinary CD
does not retry, release a HOLD or relabel an incomplete phase as success.

## Observe and verify

Check the exact workflow/source/run/attempt, every affected guest phase and
ordinary completion receipt. Preserve generic/redacted failures and use a
separately reviewed bounded read to establish cause where needed.
Do not dump private controller files or runtime environment into CI logs.

After successful CD, verify the intended layer: DNS answer, public TLS,
backend transport, application health, authentication and data/device behavior.
For telemetry use fresh observations; a cached healthy value is insufficient.
Service acceptance and household/device acceptance can require additional checks
beyond the pipeline. Use the [service verification guide](verify-and-maintain.md#service-verification)
to define and record the actual outcome.

## Failure and recovery

Preserve prior canonical/immutable success, current HOLD/STARTED/checkpoint and
input evidence. Do not delete markers or edit state to rerun.
A recovery/restore or explicitly reviewed operator action has its own authority;
this guide introduces no generic override.
[Lifecycle](../reference/lifecycle.md) and [Troubleshooting](troubleshooting.md)
describe the boundaries.

[Operations index](README.md)
