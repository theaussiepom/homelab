# Broker, browser and HTTPS relationships

This directory is a complete synthetic **offline** site and library: one guest contains MQTT app `broker`, MQTT Explorer app `browser` and Traefik app `ingress`. It demonstrates a broker account created once with a generated credential, a named domain, an explicit authentication outpost endpoint and policy, a browser origin owned by the app, HTTPS exposure, and named middleware for headers and client address ranges. It does not contact any service.

The source files are [site.yaml](site.yaml), [stack.json](stack.json) and [images.json](images.json). The library's fixed JSON indexes are intentional; the authored site uses YAML. No separate reusable library checkout is needed.

From a reviewed framework root with its locked requirements installed:

```sh
python blueprints/compile.py --stack docs/examples/relationships --site docs/examples/relationships/site.yaml --check
```

Expected result: `All component guests compile offline`. The real compiler resolves the complete three-app composition and generates its deployment inputs; the maintained reference tests also compare the named connection/account/exposure examples with these actual source values. Deployment admission deliberately refuses the synthetic addresses, fake image digests and absent genuine public SSH key. Configured `/never-read` credential paths are never opened by compilation.

## Find each relationship

| Source location in site.yaml | Purpose |
| --- | --- |
| apps.broker / apps.browser / apps.ingress | Placement and explicit profile roles/identities |
| connections.broker | Browser role → broker backend, account `client`, hostname `broker` |
| accounts.client / secret_sources.browser_password | Stable create-once MQTT owner and generated credential identity |
| connections.outpost / external_endpoints.outpost | Browser → explicit synthetic authentication outpost |
| exposures.browser / apps.browser.origin | Owned HTTPS route and origin |
| policies.middlewares / address_groups | Explicit selected headers and ordered client ranges |
| guests.resolver.network_policy | Explicit outpost access, independent of readiness/value references |

The individual [connection](../../reference/connections.md), [exposure](../../reference/exposures.md), [policy](../../reference/policies.md) and [identity/account](../../reference/identity-and-secrets.md) pages explain the fields and refusal cases. Copy the whole directory to a disposable physical path before experimenting. The compiler must reject either of these changes: adding `credential` beside `account` on the broker connection, or duplicating the exposure's domain in its aliases.

## First installation and later deployments

This is not a first-installation or import recipe. The synthetic broker profile requires prepared data and configuration, plus private probe inputs. Compiling their references does not create or verify those inputs. A real retained guest/app must already have genuine HomeLab ownership. A supported fresh app can be added only when its real prerequisites are met, its required paths and identities are available, and sufficient capacity exists. Later deployments keep the selected lifecycle policies and check that existing ownership, data and protected inputs are preserved; they do not rotate the generated account or silently adopt an unowned service.

[Complete first tutorial](../first-configuration/README.md) · [Lifecycle](../../reference/lifecycle.md)

## Compatibility and evidence ownership

The framework revision is the reviewed checkout containing this example. Library, site and image-catalogue revisions are that same checkout: their complete files are vendored together here, so no external library branch is silently selected. The catalogue's fake image identity is source-test input and must never be pulled or treated as a deployment pin. Use that framework's hash-locked tooling.

The [reference example tests](../../../blueprints/test_component_reference_examples.py) parse maintained excerpts and exercise real reference resolution and packet generation. The [documentation tests](../../../blueprints/test_component_documentation.py) check the tutorial CLI, its refusal to overwrite output, and source admission checks. See [evidence levels](../../concepts/evidence.md), then [prepare real inputs](../../guides/prepare-deployment.md) for the next stage.
