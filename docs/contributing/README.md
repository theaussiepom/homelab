# Contributing

The framework owns reusable contracts and execution capabilities. The library
owns selectable profiles/defaults/software. Consumers own concrete allocations,
bindings and operating policy. Keep private facts out of reusable source.

## Change workflow

1. Find the owning contract and existing component before adding another.
2. State the user-visible behavior and unsupported cases.
3. Implement the smallest closed typed change using existing resolution and
   deployment architecture.
4. Update reference, examples and tests together. New fields need type/default/
   constraints/reference/update documentation.
5. Run focused component/app/guest/compiler checks, then the existing complete
   coverage, source/security/history/signature and current-head hosted/review gates.
6. Retire superseded callers/tests only after proving their useful guards'
   replacements. Preserve required historical evidence at its existing boundary.
7. Publish normally signed source through a reviewable PR. Merge and deployment
   are separate decisions.

Read [Components](components.md), [Testing](testing.md) and the existing
[security/signing procedure](../contributing-safely.md).
Do not bypass hooks, reduce thresholds or suppress an unexplained failure.
