# First configuration source

These three files are the complete synthetic library/site used by the [configuration walkthrough](../../guides/first-configuration.md). Keep them together: `stack.json` and `images.json` form the library, and `site.yaml` is the starting site configuration. They use documentation addresses, reference-only private paths and a fake image digest. The files can be compiled, but deployment admission intentionally rejects them.

The starting site has two guest NICs and is also used by the reference examples. The walkthrough replaces a disposable copy with a complete one-NIC site, then changes placement, identity, storage selection, addressing, memory and timezone using a decision worksheet. That complete source is maintained in the guide itself and executed by the documentation tests, so readers can see and copy every field in context. The library's Unbound profile publishes UDP DNS only on guest loopback port 5335; it does not provide household DNS access.

The tests resolve the real source, produce its deployment packet, compare authored decisions with provider/runtime results, execute the printed inspection command, check that invalid resource and CIDR values are rejected, and verify typed source extraction preserves meaning. They also preserve the original example's inheritance, output mode, create-only behavior and checks that deployment admission rejects the example. No target is contacted.

## Compatibility and evidence ownership

The framework revision is the reviewed checkout containing this example. Library, site and image-catalogue revisions are that same checkout: their complete files are vendored together here, so no external library branch is silently selected. The catalogue's fake image identity is source-test input and must never be pulled or treated as a deployment pin. Use that framework's hash-locked tooling.

The [reference example tests](../../../blueprints/test_component_reference_examples.py) parse maintained excerpts and exercise real reference resolution and packet generation. The [documentation tests](../../../blueprints/test_component_documentation.py) execute the walkthrough source and commands. These are source acceptance checks, not proof that a first-time reader has understood the journey or that a real service works. See [evidence levels](../../concepts/evidence.md), then [prepare real inputs](../../guides/prepare-deployment.md) for the next stage.
