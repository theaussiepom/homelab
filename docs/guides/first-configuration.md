# Compile your first configuration

Build a complete synthetic Unbound configuration, inspect its guest packet and
make a change that preserves its identity. By the end you will have exercised
real parsing, validation, reference resolution and lowering. No host, credential
read, image pull or service startup is needed. The example deliberately cannot
pass deployment admission.

## Prepare an isolated workspace

Start at the root of a reviewed framework checkout, using Git and Python 3.12 or
newer. The example's library, site and image catalogue are the maintained files
in [first-configuration](../examples/first-configuration/README.md), all at that
same checkout revision. There is no external library selection for this lesson.
Install this framework's hash-locked dependencies in a disposable environment:

```sh
FRAMEWORK="$(pwd -P)"
WORK="$(mktemp -d)"
WORK="$(cd "$WORK" && pwd -P)"
python3 -m venv "$WORK/venv"
. "$WORK/venv/bin/activate"
python -m pip install --require-hashes -r "$FRAMEWORK/requirements.lock.txt"
cp -R "$FRAMEWORK/docs/examples/first-configuration" "$WORK/config"
```

The starting directory must contain `blueprints/compile.py`. Resolving `WORK`
physically avoids a symlinked temporary ancestor, including the usual macOS
`/var` alias; the confined reader still refuses symlink paths. Keep the virtual
environment active and use the same shell for subsequent commands.

## Read the three inputs

| File | What it owns | Reference |
| --- | --- | --- |
| [stack.json](../examples/first-configuration/stack.json) | Base template, independent Unbound profile and software/runtime/health choices | [Library](../reference/library.md) |
| [images.json](../examples/first-configuration/images.json) | Synthetic declared image identity; never downloaded by compilation | [Image forms](../reference/supporting-types.md#images) |
| [site.yaml](../examples/first-configuration/site.yaml) | Context, two networks, storage, one guest and one app | [Site](../reference/site.md) |

The site is authored YAML. Library/catalogue root filenames are fixed JSON
indexes; typed definition leaves may use YAML. Runtime packets are JSON outputs.
[Source documents](../reference/sources.md) explains these distinct contracts.

Trace the configuration in this order:

1. `guests.resolver` selects `contexts.lab`, `root_storage: local` and template
   `base`. Omitted resources/startup/security inherit that template by direct field.
2. `interfaces.management` selects `networks.primary`, a static address and the
   only default route. `control_interface: management` identifies its management
   endpoint. The secondary NIC remains non-default. Read the
   [network/NIC field records](../reference/networks.md#network-property-index).
3. `apps.recursive_a` selects profile `recursive` on this guest. Its `private`
   role binds the app network; its `local` role binds guest loopback. The profile
   publishes UDP DNS on loopback port 5335. That does not publish DNS externally
   or add firewall permissions. See [app role branches](../reference/apps.md#interface-roles).

The `/never-read` private paths and fake image digest are nonfunctional metadata.
The compiler validates their shape without opening them or obtaining an image.

## Validate, then produce a packet

Run the whole-source check before selecting one output guest:

```sh
python "$FRAMEWORK/blueprints/compile.py" --stack "$WORK/config" --site "$WORK/config/site.yaml" --check
python "$FRAMEWORK/blueprints/compile.py" --stack "$WORK/config" --site-root "$WORK/config" --guest resolver --output "$WORK/resolver.json"
python -c 'import json,sys; p=json.load(open(sys.argv[1])); c=json.loads(p["files"]["site.json"]); print(p["schema"]); print(c["deployment"]["phases"])' "$WORK/resolver.json"
```

Expected result: `All component guests compile offline`, packet schema
`homelab-component-guest-deployment-v1` and phase list
`['preparation', 'recursive_a']`. Infrastructure is the separate leading workflow
phase. The output is private mode 0600 and create-only: a repeated write to the
same output filename refuses instead of overwriting it.

This is your first completed result: source has resolved and lowered into the
expected packet. It is not a guest installation. Do not feed this synthetic
packet to `deploy.py`; source admission intentionally refuses its example
bindings and absent genuine SSH public key.

## Make one harmless source change

In the copied `$WORK/config/site.yaml`, add this field inside `apps.recursive_a`,
alongside `profile` and `guest`. This is an **explanatory change fragment**, not a
standalone site:

```yaml
display_name: Example recursive resolver
```

Check again and use a new output filename:

```sh
python "$FRAMEWORK/blueprints/compile.py" --stack "$WORK/config" --site "$WORK/config/site.yaml" --check
python "$FRAMEWORK/blueprints/compile.py" --stack "$WORK/config" --site "$WORK/config/site.yaml" --guest resolver --output "$WORK/resolver-labelled.json"
```

The display name changes while persistent service/project identity stays the
same. This is the [display-name contract](../reference/apps.md#app-display-name),
not an app rename or transfer of ownership. The maintained tutorial test compares
those identities through the real resolver.

## Learn from one refused value

In your copied site, temporarily change `networks.primary.cidr` from
`198.18.20.0/24` to `198.18.20.10/24`, then repeat only the `--check` command.
It must fail with `component.invalid at networks.primary`: a CIDR must name the
canonical network address, not a host within the subnet. Restore the original
value and check again. [Network diagnostics](../reference/networks.md#network-and-nic-diagnostics)
explain this and the DHCP/manual branches without weakening validation.

## First installation and later deployments

The lesson ends at offline compilation. [Prepare a deployment](prepare-deployment.md)
explains what a real consumer must supply: compatible library/profile selection,
qualified target/trust/material/capacity/network inputs, protected workflow and
actual authority. The chosen adapter must implement its first-installation path.

Supported `fresh` source continues through ordinary owned updates; do not toggle
it after a successful install. `retained` requires genuine HomeLab ownership
and is not an import shortcut. Read [lifecycle](../reference/lifecycle.md), then
[deployment](../operations/deployment.md) and [service verification](../operations/verify-and-maintain.md).

## What to learn next

| Next question | Continue with |
| --- | --- |
| How can I split this source without changing meaning? | [Typed source extraction](../reference/sources.md#worked-extraction-without-an-overlay) |
| How do apps share values, access and readiness? | [References and reuse](references-and-reuse.md), then [complete relationships](../examples/relationships/README.md) |
| How do I inspect workflow selection? | [Validate and generate](validate-and-generate.md) |
| What did the lesson actually verify? | [Evidence levels](../concepts/evidence.md) and [maintained tutorial checks](../../blueprints/test_component_documentation.py) |
| What is needed before installation? | [Deployment preparation](prepare-deployment.md) |

Only `$WORK` is disposable lesson output; keep any real packets private. The
source-controlled example remains unchanged because you edited its copy.

[Documentation index](../README.md) · [Start here](../start-here.md)
