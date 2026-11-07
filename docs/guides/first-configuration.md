<a id="compile-your-first-configuration"></a>
# Write and inspect your first configuration

Build a complete site for one Proxmox guest, choose its identity, network, storage and memory, and inspect the deployment inputs produced from those choices. You will finish with a configuration you can explain and change yourself. This is an offline language exercise using a small maintained library: its image identity and protected paths are deliberately synthetic, and it cannot be deployed.

If your immediate goal is to choose real applications, start with [HomeLab Stack's practical getting-started route](https://github.com/theaussiepom/homelab-stack/blob/main/docs/start-here.md). That guide covers application profiles and their requirements. This lesson teaches the framework grammar and inspection tools you use with any compatible library.

## Prepare an isolated workspace

You need Git, Python 3.12 or newer and a text editor. Start at the root of a reviewed framework checkout: the directory containing `blueprints/compile.py` and this page. If you do not have a checkout, run `git clone https://github.com/theaussiepom/homelab.git` in your working directory, then `cd homelab`; review or select the revision you intend to learn from and read its copy of this guide. Record `git rev-parse HEAD` so your notes identify that selection. A clone of current main is not a compatibility selection for an existing stack deployment.

Create a disposable working directory and install that checkout's hash-locked dependencies, whose versions and file hashes are fixed in the lock file. Keep this shell and its virtual environment active throughout the lesson:

```sh
FRAMEWORK="$(pwd -P)"
WORK="$(mktemp -d)"
WORK="$(cd "$WORK" && pwd -P)"
python3 -m venv "$WORK/venv"
. "$WORK/venv/bin/activate"
python -m pip install --require-hashes -r "$FRAMEWORK/requirements.lock.txt"
cp -R "$FRAMEWORK/docs/examples/first-configuration" "$WORK/config"
```

`WORK` is resolved physically because the confined source reader refuses symlink paths, including a symlinked temporary ancestor such as the usual macOS `/var` alias. You will edit only `$WORK/config/site.yaml`; the framework checkout remains your source of tools and examples.

## Read the three inputs

| File in `$WORK/config` | What it supplies | What you do with it |
| --- | --- | --- |
| [stack.json](../examples/first-configuration/stack.json) | Guest template `base`, app profile `recursive`, and their software/runtime/health selections | Keep it unchanged during the lesson; these are library choices |
| [images.json](../examples/first-configuration/images.json) | Synthetic image catalogue used by `recursive` | Keep it unchanged; compilation reads identity metadata without downloading an image |
| [site.yaml](../examples/first-configuration/site.yaml) | Context, networks, storage, a guest and the app placed on it | Replace it with your complete site below |

The copied site is a maintained two-interface example used throughout the reference. Your new version will use one interface, a different allocation and an explicit memory choice. All three inputs and this lesson belong to the same framework revision; no external library revision is selected.

The library root filenames are fixed JSON indexes. A site may be YAML or JSON. You can later move a supported declaration into a separate YAML file containing that complete declaration and its type headers; this is called a **typed leaf**. A generated packet is JSON containing deployment inputs, not a new file to edit. See [source documents](../reference/sources.md) for the exact format boundaries.

## Decide what your guest should look like

For this first pass, choose practice values rather than copying live credentials or allocation data. The “worked choice” column is the configuration printed below; you can choose the alternative values as a complete second exercise. Keep the internal keys `lab`, `primary`, `local`, `resolver` and `recursive_a` so references and inspection commands continue to agree.

| Decision | Worked choice | Another practice choice | Exact field to edit |
| --- | --- | --- | --- |
| Which Proxmox node receives the guest? | `practice-pve` | `workshop-pve` | [`contexts.lab.node`](../reference/contexts.md#context-node) |
| Which API endpoint identifies that authority? | `192.0.2.20` | `192.0.2.30` | `external_endpoints.api.address`; selected by [`contexts.lab.api_endpoint`](../reference/contexts.md#context-api-endpoint) |
| Which storage pool and template supply the root disk? | Pool `practice-local`, template `practice:vztmpl/debian-13.tar.zst` | Pool `workshop-local`, template `workshop:vztmpl/debian-13.tar.zst` | [`storage.local.pool`](../reference/storage.md#storage-pool), [`guests.resolver.template_file_id`](../reference/guests.md#guest-template-file-id) |
| What stable guest identity should this new site use? | VMID `620`, hostname `practice-resolver` | VMID `720`, hostname `workshop-resolver` | [`guests.resolver.identity`](../reference/guests.md#guest-identity) |
| Which subnet, bridge and default gateway? | `198.18.30.0/24`, `practice0`, `198.18.30.1` | `198.18.40.0/24`, `workshop0`, `198.18.40.1` | [`networks.primary`](../reference/networks.md#network-property-index); keep `vlan: null` for this untagged exercise |
| Which static address and MAC belong to this guest? | `198.18.30.20`, `02:00:00:30:00:20` | `198.18.40.20`, `02:00:00:40:00:20` | [`guests.resolver.interfaces.management`](../reference/networks.md#nic-property-index), `address.value` and `mac` |
| Which DNS service does the guest use? | `198.18.30.53` | `198.18.40.53` | `external_endpoints.dns.address`; inherited from [`contexts.lab.dns_servers`](../reference/contexts.md#context-dns-servers) |
| How much guest memory and which timezone? | `1024` MiB, `Etc/UTC` | `1536` MiB, `Australia/Brisbane` | [`guests.resolver.resources.memory_mib`](../reference/guests.md#guest-resources-memory-mib), [`contexts.lab.timezone`](../reference/contexts.md#context-timezone) |

In this exercise, a subnet change means changing its gateway, the guest address and the same-subnet DNS endpoint together. In a real site, DNS may instead remain on another reachable network. A MAC identifies a virtual NIC; it is not the Proxmox host's physical MAC. The declaration checks internal consistency but does not reserve any address, VMID or MAC in your environment. [Preparation](prepare-deployment.md#replace-practice-values-with-known-facts) explains where to obtain real values later.

## Write the complete site

Open `$WORK/config/site.yaml` in your editor and replace its entire contents with this complete site. Apply your worksheet choices in the named fields; do not append a second `guests` or `networks` section. YAML indentation determines which object owns a field.

<!-- example: personalised-site -->
```yaml
schema: homelab-components-v1
kind: site
contexts:
  lab:
    backend: proxmox-lxc
    node: practice-pve
    api_endpoint: {external: api}
    trust:
      ca_file: /example/ca.pem
      known_hosts: /example/known_hosts
    credentials: {api_token: token, ssh_private_key: ssh}
    paths:
      state_root: /example/state
      backup_directory: /example/backup/data
      backup_mount: /example/backup
      backup_source: example:/backup
    protected_guests: [9900]
    ssh_public_keys: []
    dns_servers: [{external: dns}]
    timezone: Etc/UTC
secret_sources:
  token: {type: file, path: /never-read/token}
  ssh: {type: file, path: /never-read/ssh}
external_endpoints:
  api: {protocol: https, address: 192.0.2.20, port: 8006}
  dns: {protocol: udp, address: 198.18.30.53, port: 53}
networks:
  primary:
    context: lab
    cidr: 198.18.30.0/24
    bridge: practice0
    vlan: null
    gateway: 198.18.30.1
storage:
  local: {context: lab, pool: practice-local}
guests:
  resolver:
    context: lab
    template: base
    lifecycle: fresh
    identity: {vmid: 620, hostname: practice-resolver}
    template_file_id: practice:vztmpl/debian-13.tar.zst
    root_storage: local
    resources: {memory_mib: 1024}
    control_interface: management
    interfaces:
      management:
        network: primary
        slot: 0
        mac: 02:00:00:30:00:20
        address: {mode: static, value: 198.18.30.20}
        default_route: true
        ipv6: manual
apps:
  recursive_a:
    profile: recursive
    guest: resolver
    lifecycle: fresh
    interfaces:
      private: {scope: app-network, network: default}
      local: {scope: guest-loopback}
```

Read the result from its goal back to its prerequisites: `apps.recursive_a` selects the library's `recursive` profile and runs on `guests.resolver`; that guest selects the `base` template, the `local` storage declaration and the `lab` context. Its `management` NIC selects the `primary` network and supplies both its control address and its only default route. Map keys are IDs; `profile: recursive` is a reference to a library entry, not an instruction to invent a new profile. The [site reference](../reference/site.md) explains the remaining top-level maps.

You only override memory. CPU 1, root disk 8 GiB and the other resource/startup/security values come from the tutorial's `base` template. These guest objects merge by direct field; other objects have their own rules. The authored OS reserve is 128 MiB, while runtime budgeting applies an effective 256 MiB floor. The app reserves 256 MiB, so the worked guest's 1024 MiB covers both. See [guest defaults](../reference/guests.md#defaults-and-resolution).

The app's `private` interface means its private application network, while `local` means guest loopback. Neither is a second guest NIC. This profile publishes UDP DNS at `127.0.0.1:5335` inside the guest; it does not expose a DNS server to your home network or create firewall permissions. The guest's configured DNS endpoint is a separate existing-service reference. The [app role contract](../reference/apps.md#interface-roles) distinguishes these scopes.

Leave the `/example` and `/never-read` paths, empty key list and synthetic image catalogue in place for the lesson. They provide metadata in the required format; compilation does not open the referenced files. Their presence is also why source success cannot make this a prepared installation.

## Validate, then produce a packet

Run the whole-site check, then produce a packet for the guest whose source key is `resolver`:

<!-- walkthrough: compile -->
```sh
python "$FRAMEWORK/blueprints/compile.py" --stack "$WORK/config" --site "$WORK/config/site.yaml" --check
python "$FRAMEWORK/blueprints/compile.py" --stack "$WORK/config" --site-root "$WORK/config" --guest resolver --output "$WORK/resolver.json"
```

The first command prints `All component guests compile offline; no credentials or targets accessed.` The second writes a new packet with file mode 0600, so only its owner can read or write it. `--site` names one exact source file; `--site-root` discovers the sole `site.yaml`, `site.yml` or `site.json` in that directory. Do not leave another root file named `site` with a different supported extension beside your YAML. The reader also refuses symlink source components. See the [CLI reference](../reference/cli.md#compile-blueprintscompilepy).

Inspect the actual generated values using this local-only command:

<!-- walkthrough: inspect -->
```sh
python - "$WORK/resolver.json" <<'PY'
import json, sys
packet = json.load(open(sys.argv[1]))
config = json.loads(packet['files']['site.json'])
runtime = json.loads(packet['files']['component-runtime.json'])
guest = config['guest']
listener = runtime['applications']['recursive_a']['listeners']['udp']
print('schema:', packet['schema'])
print('node:', config['site']['node'])
print('guest:', guest['vmid'], guest['hostname'])
print('storage:', guest['storage_id'], guest['template_file_id'])
print('resources:', guest['cpu'], guest['memory_mib'], guest['root_gib'])
print('interfaces:', len(guest['interfaces']), guest['interfaces'][0]['ipv4'],
      guest['interfaces'][0]['bridge'], guest['interfaces'][0]['gateway'])
print('dns:', guest['dns_servers'])
print('timezone:', runtime['guest']['timezone'])
print('app publication:', listener['publication_address'], listener['publish']['port'])
print('phases:', config['deployment']['phases'])
PY
```

For the worked choices, expect:

<!-- walkthrough: expected -->
```text
schema: homelab-component-guest-deployment-v1
node: practice-pve
guest: 620 practice-resolver
storage: practice-local practice:vztmpl/debian-13.tar.zst
resources: 1 1024 8
interfaces: 1 198.18.30.20/24 practice0 198.18.30.1
dns: ['198.18.30.53']
timezone: Etc/UTC
app publication: 127.0.0.1 5335
phases: ['preparation', 'recursive_a']
```

Compare each line with your worksheet if you chose different values. This verifies that the source choices reached the provider and runtime inputs; it still does not test a host, trust file, image or service. Infrastructure is a separate leading workflow phase, so it does not appear in this packet's application phase list. Keep actual production packets private.

The output is create-only: running the packet command again with the same filename refuses rather than replacing it. For another version, choose a new output name such as `$WORK/resolver-second.json` and inspect that file. Do not feed this synthetic packet to `deploy.py`; deployment admission intentionally refuses its bindings.

<a id="make-one-harmless-source-change"></a>
## Make the configuration yours

If you used the worked values, now use the alternative column in the worksheet to create a second complete practice selection. Replace the named values in the same `site.yaml`, run `--check` again, then compile to `$WORK/resolver-second.json`. The same inspection command with that filename should show VMID 720, node `workshop-pve`, address `198.18.40.20/24` and memory 1536. You have changed a guest allocation and proved its effective result without changing a profile or a template. In an actual installation managed by HomeLab, these identity changes are more than renames; the [lifecycle rules](../reference/lifecycle.md) govern updates.

For a cosmetic change, add `display_name: My practice resolver` inside `apps.recursive_a`, alongside `profile` and `guest`, then check and compile to a third new filename. This changes its display name while persistent service/project identity stays the same. It is the [display-name contract](../reference/apps.md#app-display-name), not a transfer of ownership. The maintained tests check both the meaningful allocation changes and this identity-preserving case.

## Learn from one refused value

Use the worked site for this exercise, or substitute your chosen subnet consistently. Change `networks.primary.cidr` from `198.18.30.0/24` to `198.18.30.20/24` and run only `--check`. Expect `component.invalid at networks.primary`: a CIDR must name the network address, not a host within the subnet. Restore `198.18.30.0/24` and check again.

A second useful refusal is `resources: {memory_mib: 256}` on this guest. Although 256 MiB is a structurally accepted guest allocation, it cannot fit this app's 256 MiB reservation plus the 256 MiB effective OS reserve; expect `component.memory-budget`. Restore your chosen memory allocation and check again. This is why schema acceptance and a complete compilation are different checks.

If an error occurs before the expected diagnostic, start with the field path reported by the compiler and compare the complete containing object with this page. Duplicate YAML keys, unknown fields and incorrect indentation are not overrides. [Network diagnostics](../reference/networks.md#network-and-nic-diagnostics) and [troubleshooting](../operations/troubleshooting.md) explain how to correct the source within the supported rules.

## Split an app into its own file

When the site becomes harder to navigate, keep the root `site.yaml` and move a complete supported declaration into a typed leaf. Create the directory with `mkdir "$WORK/config/apps"`, create `$WORK/config/apps/recursive.yaml`, and put this complete leaf in it:

<!-- example: personalised-app-leaf -->
```yaml
schema: homelab-components-v1
kind: app
profile: recursive
guest: resolver
lifecycle: fresh
interfaces:
  private: {scope: app-network, network: default}
  local: {scope: guest-loopback}
```

Replace the entire `recursive_a` value under `apps` in `site.yaml` with this root fragment:

<!-- example: personalised-app-reference -->
```yaml
apps:
  recursive_a:
    source: apps/recursive.yaml
```

If you added a display name, move it inside the leaf too. The root map key still owns the identity. The relative path is resolved from the site directory, and the leaf's `schema` and `kind` identify the complete body it contains; the original inline value did not need these two headers. A source reference cannot also contain `display_name` or other overrides. Compile again to a new filename: unchanged app values produce the same packet, although the consumed source paths and hashes change. [Source extraction](../reference/sources.md#worked-extraction-without-an-overlay) covers other supported leaves and confinement rules.

## First installation and later deployments

You now have a complete site, a way to change its decisions and evidence that those changes reach the generated configuration. The next step is [preparing real inputs](prepare-deployment.md), beginning with a compatible library and a profile that supports the installation you intend. Use the [stack design journey](https://github.com/theaussiepom/homelab-stack/blob/main/docs/start-here.md) to choose applications and layouts; do not turn this synthetic lesson's image catalogue into a deployment selection.

Keep supported `fresh` source for later updates to the same installation; do not toggle it after a successful install. `retained` requires an installation already owned by HomeLab and cannot import another installation. Read [lifecycle](../reference/lifecycle.md), then [deployment](../operations/deployment.md) and [service verification](../operations/verify-and-maintain.md).

## What to learn next

| Next question | Continue with |
| --- | --- |
| Where do my real Proxmox, network and credential references belong? | [Prepare a deployment](prepare-deployment.md) |
| How do apps share values, access and readiness? | [References and reuse](references-and-reuse.md), then [complete relationships](../examples/relationships/README.md) |
| How do I inspect workflow selection? | [Validate and generate](validate-and-generate.md) |
| What other field shapes can I use? | [Reference index](../reference/README.md) |
| What did this lesson verify? | [Evidence levels](../concepts/evidence.md) and [maintained walkthrough tests](../../blueprints/test_component_documentation.py) |

Only `$WORK` is disposable lesson output. Save any configuration you want to keep in your own source directory before discarding it; keep actual credentials, protected files and deployment packets private. The maintained source examples remain unchanged because you edited their copy.

[Documentation index](../README.md) · [Start here](../start-here.md)
