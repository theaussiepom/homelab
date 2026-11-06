# Operations

Follow a configuration through its actual operating boundary. The consumer owns
real allocations, trust, material, runner/environment policy and authority; this
suite documents the reusable contracts it must satisfy.

| Situation | Route |
| --- | --- |
| A synthetic example compiles; real prerequisites are next | [Prepare a deployment](../guides/prepare-deployment.md) |
| A supported new installation is ready to execute | [Deploy and verify](deployment.md#first-installation) |
| An existing owned service needs a declared change | [Later deployments](verify-and-maintain.md#later-deployments) and [lifecycle](../reference/lifecycle.md) |
| The workflow completed and the service needs verification | [Service verification](verify-and-maintain.md#service-verification) |
| Source, admission, a phase or the service failed | [Troubleshooting](troubleshooting.md) |
| Host installation/bootstrap or a specific recovery subsystem is needed | [Separate subsystem contracts](../framework-reference.md) |

Compilation, workflow generation, protected deployment and service acceptance
have different effects and [evidence boundaries](../concepts/evidence.md).
Choose the procedure that matches the observed stage; a source success cannot
supply native ownership or an unavailable commissioning path.

[Documentation index](../README.md) · [Supported adapters](../reference/support.md)
