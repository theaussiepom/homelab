# Start here

You need basic Git, YAML or JSON, and IPv4 networking to author a site.
You do not need a running Proxmox host to complete the offline tutorial.

## What you are configuring

A **library** supplies guest templates and app profiles. A **site** chooses those
definitions, places app instances on guests and binds concrete resources.
An app profile owns a finite adapter contract; it is not an arbitrary Compose
document. [Concepts](concepts.md) shows how these pieces fit.

Use compatible, reviewed immutable framework/library revisions. The library's
workflow selection identifies its framework. Do not replace those selections
with an unreviewed branch tip just to make compilation succeed.

## Local prerequisites

Use Git and Python 3.12 or newer. Install the selected framework's
`requirements.lock.txt` with `--require-hashes` in an isolated environment.
The [tutorial](guides/first-configuration.md) defines every path and command.
The source reader uses locked PyYAML; no custom YAML functions or tags exist.

## Decide what success means

| Check | Establishes |
| --- | --- |
| Offline compilation | The selected typed source resolves and lowers to packets |
| Workflow generation | The generated graph matches that same selected plan |
| Controller/helper tests | The exercised ownership, file or protocol behavior, with stated fakes |
| Protected CD | The actual selected deployment phases completed |
| Service verification | The affected application's real health and user-facing behavior |

A Docker fixture does not establish physical radio behavior, a household login
or native state ownership. For an existing installation, read
[Lifecycle](reference/lifecycle.md) before changing identities or private inputs.

**Next:** [First configuration](guides/first-configuration.md).
