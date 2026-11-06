# First configuration source

These three files are the complete synthetic library/site used by the
[offline tutorial](../../guides/first-configuration.md). Keep them together:
`stack.json` and `images.json` form the library, and `site.yaml` is the consumer.
They use documentation addresses, reference-only private paths and a fake image
digest. Compilation is supported; deployment admission is intentionally refused.

The documentation integration test resolves the real source, lowers the packet,
checks phases, validates default inheritance and tests that admission refuses.
There is no extra documentation parser or target dependency.

## Compatibility and evidence ownership

The framework revision is the reviewed checkout containing this example. Library,
site and image-catalogue revisions are that same checkout: their complete files
are vendored together here, so no external library branch is silently selected.
The catalogue's fake image identity is source-test input and must never be pulled
or treated as a deployment pin. Use that framework's hash-locked tooling.

The [reference example tests](../../../blueprints/test_component_reference_examples.py)
parse maintained excerpts and exercise real resolution/lowering. The
[documentation tests](../../../blueprints/test_component_documentation.py) check
the tutorial CLI, create-only output and source-admission boundary. See
[evidence levels](../../concepts/evidence.md), then
[prepare real inputs](../../guides/prepare-deployment.md) for the next stage.
