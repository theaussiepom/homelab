# Testing component changes

Use the selected framework revision's locked Python tools. Install requirements with `--require-hashes` in an isolated environment rather than relying on unpinned global packages. Generated workflow setup installs the selected parser dependency without changing the interpreter used for runtime credentials and deployment.

## Test the boundary you change

- Component unit tests exercise each validator directly: valid values, defaults, optional and null values, wrong types, missing and unknown keys, limits, unsafe paths, references, identity conflicts, redaction and failure propagation.
- App units mock conforming component contracts and shared builders. They test adapter semantics, conditional requirements and wiring.
- Guest units mock app/component results. They test placement, budgets, explicit control interfaces, stable namespaces and supported fresh/retained ownership.
- Compiler integration tests exercise each actual component through reference resolution and packet generation, with unrelated collaborators stubbed. A smaller set of complete-plan tests checks composition, repeated profiles, alternate placement and preserved artifacts.
- Runtime integration uses only disposable owned local resources under explicit test scope. State exactly which processes, files and protocols were verified.
- End-to-end means configuration through protected CD to deployed services and actual service verification. Source or container tests do not establish it.

Focused development commands from the framework root:

```sh
python3 -m unittest discover -s blueprints -p 'test_component*.py' -q
python3 -m unittest discover -s proxmox/applications/tests -p 'test_component*.py' -q
python3 -m unittest discover -s blueprints -p test_credentials.py -q
python3 -m pytest -q tests/test_component_boundaries.py
ansible-playbook --syntax-check -i localhost, proxmox/applications/ansible/component-reconcile.yml
```

The localhost inventory above validates syntax without an application target. Tests needing temporary loopback listeners or Docker must retain those boundaries and use an explicitly local daemon. Preserve failed results, establish whether the fixture or implementation is wrong, and correct only the established cause.

## Complete the feature gates

From the framework root, select the locked interpreter above and a verified Gitleaks 8.30.1 executable. Run the seven framework suites into a nonexistent child of a disposable private directory:

```sh
export GITLEAKS_BIN=/absolute/path/to/verified/gitleaks
WORK="$(mktemp -d)"
python3 tools/measure_coverage.py --all --fail-under 100 --output "$WORK/coverage"
```

Optional `--stack /path/to/library --site /path/to/site` adds the two consuming repository suites for a nine-suite cross-repository run. Keep those private results inside their intended boundary; never upload coverage artifacts.

Focused tests are development evidence. Before publication, run the repository's complete seven-suite coverage gate and require every production Python file to have 100% executable lines and branches. Keep the security/boundary, history, signature and exact-current-head hosted CI/review gates. Coverage does not replace the success and failure matrix for each component.

Verify generated files from their authoritative recipe; do not hand-patch them or weaken setup hashes, thresholds or disabled-selection behavior. Keep secrets out of logs and public artifacts. Direct workflow scalar inputs remain unchanged and are available only to the selected Deploy step.

Retire tests for removed APIs once useful guards have replacement tests at the right layer. Remove dead implementation and temporary candidate-loading scaffolding rather than retaining them to satisfy coverage. Historical failures and proof documents remain evidence; do not rewrite them as a successful run.

For source splitting and address groups, use the actual compiler to compare inline and referenced documents, detect source files that change between reads, and check ordered duplicates and exact expanded policy rows. Test cycles, unknown references, wrong types and exceeded limits directly. References that supply values must not introduce execution dependencies or access permissions.

Ownership integration tests must use genuine controller receipts, static configuration files, AppPayloads, local Git ancestry and backend generations; replace only native operations with fakes. Cover fresh creation, two updates and a later repeat, changed API or owner, state drift, a rolled-back canonical pointer, foreign or newer history, pending markers, the exact HOLD belonging to the operation, and preservation of private roles and credentials. Historical component fields remain sealed bytes, while new configuration must reject those retired fields. DNS retirement tests must cover exact records from the previous owner, preservation of unrelated aliases and order, conflicts, first installation without a prior record, repetition of the same immutable source and a later source generation.

Keep platform guards on tests of Linux filesystem metadata. A mocked macOS filesystem result does not verify Linux ownership or xattrs. Require the actual Linux hosted fixture before claiming those checks are complete.

## Check documentation

Use [Documentation assurance](documentation-assurance.md#reproduce-the-focused-checks) for the 16-control network/NIC pilot, its mappings, the check that required tests are discovered, and local navigation commands. The [canonical standard](documentation-standard.md) also requires review of field descriptions, lifecycle explanations and plain English beyond those automated checks.

The maintained offline tutorial is exercised by the real compiler/packet tests. Run it from its documented working directory using a disposable workspace. Keep the site YAML-first; the library's fixed JSON indexes and runtime JSON are distinct contracts. Complete examples should compile, and intentionally invalid examples must reach their intended refusal.

Check local relative links and heading anchors, including the compatibility entry pages. Reference updates must cover nested fields, defaults, null/absence, conditional requirements and update limits, not just a list of section names. Use current public validators to validate examples; do not create a parallel documentation configuration parser.

[Contributor index](README.md)
