# Operations

Use these guides to prepare, deploy and maintain a configuration through its supported operations. Your deployment setup supplies real allocations, trust inputs, protected files, runner and environment policy, and authority to act. These docs explain the reusable requirements it must satisfy.

| Situation | Route |
| --- | --- |
| A synthetic example compiles; real prerequisites are next | [Prepare a deployment](../guides/prepare-deployment.md) |
| A supported new installation is ready to execute | [Deploy and verify](deployment.md#first-installation) |
| An existing service managed by HomeLab needs a declared change | [Later deployments](verify-and-maintain.md#later-deployments) and [lifecycle](../reference/lifecycle.md) |
| The workflow completed and the service needs verification | [Service verification](verify-and-maintain.md#service-verification) |
| Source, admission, a phase or the service failed | [Troubleshooting](troubleshooting.md) |
| Host installation/bootstrap or a specific recovery subsystem is needed | [Separate subsystem contracts](../framework-reference.md) |

Compilation, workflow generation, protected deployment and service acceptance have different effects and [evidence boundaries](../concepts/evidence.md). Choose the procedure that matches the observed stage; successful source checks cannot establish ownership on the target or supply an initial setup procedure that the adapter does not support.

[Documentation index](../README.md) · [Supported adapters](../reference/support.md)
