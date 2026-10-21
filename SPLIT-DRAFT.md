# Repository integration status

Reusable infrastructure and shared execution tooling. The earlier Proxmox draft remains held for real PVE execution.

Source is published on the `prepare/repository-split` branch for review in PR #1.
The initial source PR is not deployment authorization. Existing production paths,
UID/GID values, runtime data and editor writers remain unchanged.

The source was assembled into clean initial history with signed commits and a
GitHub noreply author address. Fast staged-file checks and CI source/history scans
are installed. CI and code-review findings must be resolved or explicitly triaged
before merge. A passing source check does not establish live runtime acceptance.

Private catalog, credentials, generated configuration and historical acceptance
records remain outside this public repository. Reconcile each private deployment
input and qualify the resulting configuration before any separately approved rollout.
