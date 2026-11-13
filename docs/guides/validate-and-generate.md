# Validate and generate

Use the selected framework checkout and the library/site paths you intend to review. Start at the framework root in the isolated hash-locked Python environment from the [tutorial](first-configuration.md#prepare-an-isolated-workspace) or [testing guide](../contributing/testing.md). `LIBRARY` must be the selected library root and `SITE` the complete site file compatible with that library; the absolute paths below are explicit placeholders to replace, not executable examples. These are local source operations.

```sh
FRAMEWORK="$(pwd -P)"
LIBRARY="/absolute/path/to/selected-library"
SITE="/absolute/path/to/consumer/site.yaml"
python3 "$FRAMEWORK/blueprints/compile.py" --stack "$LIBRARY" --site "$SITE" --check
python3 "$FRAMEWORK/blueprints/workflows.py" --stack "$LIBRARY" --site "$SITE" --check
```

The compiler checks the whole source and produces deployment packets containing only the fields their contracts allow. The workflow checker compares generated files with the selected plan; it refuses stale files. To regenerate deliberately, omit `--check` from the workflow command, then review its changes. Generation writes the library's three workflow files and composite action files; do not hand-edit generated output.

Use `--disabled '["guest_id"]'` only for actual guest IDs. Required enabled dependencies cannot be disabled. When root monitoring is selected, its server cannot be disabled while any guests remain enabled. An all-disabled source can be inspected, but a disabled packet cannot be admitted for deployment.

To inspect a resolved plan without writing a packet, from the framework root:

```sh
PYTHONPATH="$FRAMEWORK/blueprints" python3 -c 'import compile,sys; p=compile.resolve_plan(sys.argv[1],sys.argv[2]); print(list(p.resolved["guests"])); print(p.resolved["guest_dependencies"])' "$LIBRARY" "$SITE"
```

Treat real resolved output and packets as private. Do not print secret material or upload coverage/packet artifacts. A compiler check does not test controller paths, live state, API permissions or application behavior.

Before publishing a change, run the selected repository's required tests and security and signature checks. Before executing it, satisfy [deployment prerequisites](../operations/deployment.md). Full flags and effects are in the [CLI reference](../reference/cli.md).
