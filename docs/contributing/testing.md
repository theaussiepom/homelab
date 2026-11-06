# Testing component changes

Use the selected framework's locked Python tooling. Install requirements with
`--require-hashes` in an isolated environment; do not depend on unpinned global
packages. Generated workflow setup installs the exact selected parser dependency
without changing the runtime credential/deployment interpreter.

## Test the boundary you change

- Component units exercise each validator directly: valid/default/optional/null
  forms, wrong types, missing and unknown keys, bounds, unsafe paths, references,
  identity conflicts, redaction and failure propagation.
- App units mock conforming component contracts and shared builders. They test
  adapter semantics, conditional requirements and wiring.
- Guest units mock app/component results. They test placement, budgets, explicit
  control interfaces, stable namespaces and supported fresh/retained ownership.
- Compiler integration exercises each real component through resolution and
  lowering, with unrelated collaborators stubbed. A smaller whole-plan set tests
  composition, repeated profiles, alternate placement and preserved artifacts.
- Runtime integration uses only disposable owned local resources under explicit
  test scope. State exactly which processes, files and protocols were verified.
- End-to-end means configuration through protected CD to deployed services and
  actual service verification. Source or container tests do not establish it.

Focused development commands from the framework root:

```sh
python3 -m unittest discover -s blueprints -p 'test_component*.py' -q
python3 -m unittest discover -s proxmox/applications/tests -p 'test_component*.py' -q
python3 -m unittest discover -s blueprints -p test_credentials.py -q
python3 -m pytest -q tests/test_component_boundaries.py
ansible-playbook --syntax-check -i localhost, proxmox/applications/ansible/component-reconcile.yml
```

The localhost inventory above validates syntax without an application target.
Tests needing temporary loopback listeners or Docker must retain those boundaries
and use an explicitly local daemon. Preserve failed results, establish whether
the fixture or implementation is wrong, and correct only the established cause.

## Complete the feature gates

From the framework root, select the locked interpreter above and a verified
Gitleaks 8.30.1 executable. Run the seven framework suites into a nonexistent
child of a disposable private directory:

```sh
export GITLEAKS_BIN=/absolute/path/to/verified/gitleaks
WORK="$(mktemp -d)"
python3 tools/measure_coverage.py --all --fail-under 100 --output "$WORK/coverage"
```

Optional `--stack /path/to/library --site /path/to/site` adds the two consuming
repository suites for a nine-suite cross-repository run. Keep those private
results inside their intended boundary; never upload coverage artifacts.

Focused tests are development evidence. Before publication, run the repository's
complete seven-suite coverage gate and require every production Python file to
have 100% executable lines and branches. Keep the security/boundary, history,
signature and exact-current-head hosted CI/review gates. Coverage does not replace
the success and failure matrix for each component.

Verify generated files from their authoritative recipe; do not hand-patch them or
weaken setup hashes, thresholds or disabled-selection behavior. Keep secrets out
of logs and public artifacts. Direct workflow scalar inputs remain unchanged and
are available only to the selected Deploy step.

Retire tests for removed APIs once useful guards have replacement tests at the
right layer. Remove dead implementation and temporary candidate-loading
scaffolding rather than retaining them to satisfy coverage. Historical failures
and proof documents remain evidence; do not rewrite them as a successful run.

For source splitting and address groups, compare inline/referenced documents,
source-leaf drift, ordered duplicates and exact expanded policy rows through the
real compiler. Test cycle/unknown/type/bound refusals directly; value references
must not introduce dependencies or permissions.

Normal ownership integration must use genuine controller receipts, static files,
AppPayloads, local Git ancestry and backend generations, with only native bodies
faked. Cover fresh creation, two updates and a later repeat, changed API/owner,
state drift, pointer rollback, foreign/newer history, pending markers, exact own
HOLD and private-material continuity. Historical old component fields remain
sealed bytes; active new source must reject them. DNS retirement tests must cover
exact previous-owner records, unrelated aliases/order, conflict refusal, no-prior
fresh use, immutable same-source repeat and a later source generation.

Platform-gated Linux metadata tests keep their native guards. A macOS mocked
filesystem result does not qualify Linux ownership/xattrs; require the actual
Linux hosted fixture before claiming that layer complete.

## Check documentation

Use [Documentation assurance](documentation-assurance.md#reproduce-the-focused-checks)
for the live 16-control network/NIC pilot, pointer mappings, normal collection
guard and local navigation commands. The [canonical standard](documentation-standard.md)
adds authored property/lifecycle review beyond those source assertions.


The maintained offline tutorial is exercised by the real compiler/packet tests.
Run it from its documented working directory using a disposable workspace.
Keep the site YAML-first; the library's fixed JSON indexes and runtime JSON
are distinct contracts. Complete examples should compile, and intentionally
invalid examples must reach their intended refusal.

Check local relative links and heading anchors, including the compatibility
entry pages. Reference updates must cover nested fields, defaults, null/absence,
conditional requirements and update limits, not just a list of section names.
Use current public validators to validate examples; do not create a parallel
documentation configuration parser.

[Contributor index](README.md)
