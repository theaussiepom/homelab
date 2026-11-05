# First configuration source

These three files are the complete synthetic library/site used by the
[offline tutorial](../../guides/first-configuration.md). Keep them together:
`stack.json` and `images.json` form the library, and `site.yaml` is the consumer.
They use documentation addresses, reference-only private paths and a fake image
digest. Compilation is supported; deployment admission is intentionally refused.

The documentation integration test resolves the real source, lowers the packet,
checks phases, validates default inheritance and tests that admission refuses.
There is no extra documentation parser or target dependency.
