# Inspect configured route verification

This complete synthetic [site](site.yaml), [library](stack.json) and [image catalogue](images.json) compose a broker, browser gateway, ingress and filtering DNS on one guest. The browser's HTTP exposure declares its managed resolver and expected external identity-provider redirect. The guest selects inline checks from its management interface. Self-prerequisites do not create a deployment cycle.

The image catalogue is synthetic. The configuration establishes source relationships and packet generation, not a working installation or valid certificates. No credential file is opened by the compiler. The external identity provider is an expected redirect origin; no external health job or credentialed login is added.

From the framework root with its hash-locked Python environment prepared, inspect it offline:

```sh
python3 blueprints/compile.py --stack docs/examples/route-checks --site docs/examples/route-checks/site.yaml --check
```

Expected result: accepted source without target access. The [integration test](../../../blueprints/test_component_routed_checks.py) also lowers the real packet and checks the inline mode, provider origin and empty self-dependency list. The [contract](../../reference/routed-checks.md) explains explicit deferral, source-policy refusals and first/later deployment semantics. Normal protected deployment and actual DNS/TLS/response evidence remain separate.
