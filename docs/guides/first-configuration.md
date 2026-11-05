# Compile your first configuration

This source-only tutorial produces a private guest packet for one synthetic
Unbound app. It does not contact a host, read credentials, pull an image or start
a service. Its example addresses and image digest are deliberately unsuitable
for deployment admission.

## Prepare an isolated workspace

Start in a reviewed checkout of this framework. The example's library and site
are complete maintained files under [examples/first-configuration](../examples/first-configuration/README.md).

```sh
FRAMEWORK="$(pwd -P)"
WORK="$(mktemp -d)"
python3 -m venv "$WORK/venv"
. "$WORK/venv/bin/activate"
python -m pip install --require-hashes -r "$FRAMEWORK/requirements.lock.txt"
cp -R "$FRAMEWORK/docs/examples/first-configuration" "$WORK/config"
```

The commands assume this working directory contains `blueprints/compile.py`.
`WORK` is disposable local storage. Keep it private if you later compile real
site packets.

## Read the three inputs

The authored site uses YAML. The library manifest and image catalogue currently
use the fixed JSON index filenames required by the implementation; their typed
definition leaves may use YAML. Generated runtime packet files remain JSON.

| File | Purpose |
| --- | --- |
| [stack.json](../examples/first-configuration/stack.json) | Complete base template and independent Unbound profile/software/runtime/health definitions |
| [images.json](../examples/first-configuration/images.json) | Synthetic declared image identity, never downloaded by compilation |
| [site.yaml](../examples/first-configuration/site.yaml) | One fresh guest, two NICs and a fresh Unbound instance |

The guest's management NIC is its only default route. The app binds a private
app network and guest loopback. The profile publishes UDP DNS on loopback port
5335. The example context paths and token/key sources are references only:
nothing reads `/never-read` while compiling.

## Validate, then produce a packet

```sh
python "$FRAMEWORK/blueprints/compile.py" --stack "$WORK/config" --site "$WORK/config/site.yaml" --check
python "$FRAMEWORK/blueprints/compile.py" --stack "$WORK/config" --site-root "$WORK/config" --guest resolver --output "$WORK/resolver.json"
python -c 'import json,sys; p=json.load(open(sys.argv[1])); c=json.loads(p["files"]["site.json"]); print(p["schema"]); print(c["deployment"]["phases"])' "$WORK/resolver.json"
```

Expected output includes `All component guests compile offline`, packet schema
`homelab-component-guest-deployment-v1` and phases
`['preparation', 'recursive_a']`. Infrastructure is the separate leading workflow
phase. The new packet is mode 0600 and create-only: running the second command
again against the same output refuses rather than overwriting it.

Do not run `deploy.py` with this tutorial packet. `--admit` rejects the known
synthetic addresses and missing genuine SSH key; it is useful only after
deliberately binding a real supported site's prerequisites.

## Make one harmless source change

Add `display_name: Example recursive resolver` to the app entry in the copied
site. Run `--check` again and produce a second packet at a new output path.
The display label changes; stable app/service ownership does not become a new
identity merely because its display text changes.

## What to learn next

- [Site anatomy](../reference/site.md) explains every top-level section.
- [Guests](../reference/guests.md) explains inherited resource defaults.
- [Sources](../reference/sources.md) shows complete typed file extraction.
- [Validate and generate](validate-and-generate.md) explains a selected library's
  generated workflows.
- [Deployment](../operations/deployment.md) lists the additional real prerequisites.
