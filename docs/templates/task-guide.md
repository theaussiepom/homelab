# Template: task guide

**Reusable template, not an executable procedure.** Replace these authoring instructions with the finished guide and follow the [documentation standard](../contributing/documentation-standard.md).

## Outcome and boundary

Name the task, its intended result and the evidence needed to establish that result. Explain what successful configuration checks cannot prove about a target or running service.

## Prerequisites

Identify the source repository and compatible revision, working directory, interpreter, locked dependencies and input files. State prerequisites for trust, data and credentials, and any required authorisation. Never include actual private values.

## Perform the task

Give concrete commands or configuration edits in order. Define every variable and path before use. Put outputs in a new child path that does not yet exist, and resolve symlinks in temporary source paths first. Explain each step's purpose and expected output.

## Verify the result

Give the configuration, compiler or service checks needed for the stated outcome. Identify test fakes and platform limits. Explain what a successful exit code proves and which further observations are needed.

## First installation and later deployments

Explain whether the task supports first installation, later deployments or both. Keep fresh configuration for ordinary updates. Do not instruct users to toggle lifecycle or use retained to import an installation HomeLab does not own. State which persistent identities, files and credentials must remain unchanged.

## Failure and recovery boundary

Explain a meaningful failure, the evidence to preserve and the supported next diagnostic step. Do not invent automatic retries, deletion, rollback or HOLD release. Link to separately authorised operating procedures where needed.

## Related contracts

Link to canonical field records, a complete maintained example, lifecycle and support guidance, and the relevant contributor or operations index.

## Author review before publication

Connect named examples to complete canonical files and the existing parser, validator and compiler tests. Record compatible source selections, evidence obtained and any hosted or target checks not performed. Follow the [assurance guide](../contributing/documentation-assurance.md), check local link destinations and read the full rendered guide. Use ordinary verbs, name who performs each action and explain project-specific terms at first use. Preserve exact requirements and evidence limits. Remove all authoring instructions and placeholders before publication.
