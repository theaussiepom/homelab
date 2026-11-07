# Verify a separate HTTPS backend

This complete synthetic offline site puts Traefik in one guest and routes `backend.example.invalid` to a separate HTTPS service. Browser HTTPS uses the existing ACME contract. The internal connection uses the backend's own public certificate and verifies its hostname; it never disables certificate checks.

Read [site.yaml](site.yaml) and its typed [transport.yaml](transport.yaml). The example reuses the existing [relationship library](../relationships/stack.json) and [image catalogue](../relationships/images.json), rather than copying them. The certificate is a synthetic test fixture, with no retained private key; it is not a credential for a real service.

From the framework root, with its locked Python requirements installed:

```sh
python blueprints/compile.py --stack docs/examples/relationships --site docs/examples/backend-transport/site.yaml --check
```

Expected result: `All component guests compile offline`. This checks the actual parser, references, complete guest/app composition and packet generation. It does not read credential files or contact a backend. Deployment admission deliberately rejects these documentation-only addresses, image digests and absent genuine SSH key. Do not deploy this example unchanged.

The four explicit relationships are:

- `exposures.backend` selects the external HTTPS endpoint, browser domain, ingress and TLS policies.
- `policies.transport.backend` selects the public certificate and resolves `server_name.domain` through `domains.backend`.
- `guests.edge.network_policy` separately permits only that endpoint's TCP port. A route or certificate reference does not grant network access or add execution waits.
- The compiler owns the selected certificate file and read-only Traefik mount. The provider context's CA remains separate. No private key or backend certificate renewal is added.

Before a real first installation, create and independently identify the external service, replace the synthetic allocations/library inputs and obtain its public certificate through a trusted administrative path. During later deployments, replace only the named public trust value when its intended certificate changes; reconcile through normal protected CD and verify browser HTTPS, backend TLS and application sign-in separately.

[Transport field reference](../../reference/policies.md#backend-transport-properties) · [Exposures](../../reference/exposures.md) · [Network policy](../../reference/policies.md#network-rules) · [Lifecycle](../../reference/lifecycle.md) · [Documentation index](../../README.md)
