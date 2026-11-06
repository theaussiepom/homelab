# Start here

HomeLab describes a desired installation in typed YAML and compiles it before
execution. You can learn the entire source path without a running Proxmox host.
The first result to aim for is a [synthetic guest packet](guides/first-configuration.md),
which demonstrates accepted configuration without making a target change.

## Choose the owner before choosing a setting

| You want to change… | Owner | Read next |
| --- | --- | --- |
| What a field accepts or how it compiles | Framework | [Contract reference](reference/README.md) |
| Which app profile, software or defaults are selected | Compatible library | [Library contract](reference/library.md) and that library's catalogue |
| Guest placement, addresses, paths or secret-source references | Consumer site | [Site contract](reference/site.md) |
| An existing installation's actual resources/services | Consumer's protected deployment procedure | [Preparation](guides/prepare-deployment.md) and [lifecycle](reference/lifecycle.md) |

A profile is a finite adapter contract, not an arbitrary Compose override. A
source reference includes a complete typed declaration, not an overlay language.
The [model](concepts.md) explains how these choices fit together.

## Prepare for the offline tutorial

You need basic Git, YAML and IPv4 knowledge, Git, and Python 3.12 or newer. Work
from a reviewed checkout of this framework. The tutorial creates an isolated
virtual environment and installs that checkout's `requirements.lock.txt` with
`--require-hashes`. The authored reader uses locked PyYAML; there are no custom
functions or tags to learn.

The tutorial's library, catalogue and site live together in the framework
checkout, so there is no external library revision to guess. When using
homelab-stack, its selected framework revision is the compatibility authority;
an unrelated current framework branch is a different selection. See
[compatibility preparation](guides/prepare-deployment.md#select-compatible-source).

## Know what each result means

Parsing, validation and real compiler lowering are separate checks; none opens
a target service. A workflow result identifies completed phases, while actual
service acceptance requires current observations. The
[evidence guide](concepts/evidence.md) names each boundary.

Continue with [your first configuration](guides/first-configuration.md), then
[prepare a real deployment](guides/prepare-deployment.md). Existing operators
can go directly to [later maintenance](operations/verify-and-maintain.md#later-deployments).
