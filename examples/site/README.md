# Synthetic private-site starter

Copy this data/workflow layout when setting up a private site, then bind real data only there. Consume the shared public implementation at exact reviewed pins; never copy its execution logic. All current data is synthetic, including dummy image checksums/template names and isolated address ranges. The local example runs completely through the shared CLI; those placeholder images are not asserted available or suitable for a physical PVE lab. Real lab/production execution needs actual images and qualified input/adapter contracts.

See `../../docs/configure-private-site.md` and `../../docs/execution.md`. `.yml.example` workflows are inactive templates requiring repository/commit/approval/runner setup. Public CI exercises the same Python commands against these synthetic inputs with no production access.
