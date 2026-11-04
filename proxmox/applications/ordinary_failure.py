"""Read only explicitly reviewed current-contract failed infrastructure checkpoints.

This never releases a hold or declares an application successful. An operator
must first preserve the exact own failed hold inside its immutable operation.
Every unselected or changed failure continues to refuse ordinary deployment.
"""
from pathlib import Path
import os
import re
import stat
from coordinated_contract import fingerprint, shape
from custody_records import decode, no_markers, read_existing
from private_io import digest, private_directory, require, encoded


def historical_network_paths(attributes):
    """Bind the denied path to its pinned past backend, not future profiles."""
    interfaces = attributes.get("network_interface")
    require(isinstance(interfaces, list) and 0 < len(interfaces) <= 16,
            "Bind the frozen failed backend network interfaces")
    paths = set()
    for nic in interfaces:
        require(isinstance(nic, dict) and isinstance(nic.get("bridge"), str)
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,14}", nic["bridge"]),
                "Bind the frozen failed backend network interfaces")
        vlan = nic.get("vlan_id")
        require(vlan is None or type(vlan) is int and 0 <= vlan <= 4094,
                "Bind the frozen failed backend network interfaces")
        if vlan:
            paths.add(f"/sdn/zones/localnetwork/{nic['bridge']}/{vlan}")
    return paths


def infrastructure_review(attempt, member, path, held, ready, row):
    """Read an exact operator-reviewed SDN refusal; never complete or retry it."""
    from coordinated_generation import backend

    shape(ready, {"schema", "status", "binding", "operation", "previous_operation",
                  "previous_state_sha256", "state_sha256", "state_identity", "plan_sha256",
                  "failure_kind", "permission_path", "configuration_unchanged", "guest_healthy"})
    permission = ready["permission_path"]
    require(ready["schema"] == "homelab-reviewed-infrastructure-failure-v1"
            and ready["status"] == "reviewed_failure"
            and ready["failure_kind"] == "pve_sdn_use_denied_before_update"
            and ready["configuration_unchanged"] is True and ready["guest_healthy"] is True
            and isinstance(permission, str)
            and ready["binding"] == held["binding"] and ready["operation"] == str(path),
            "Require the exact reviewed pre-update SDN refusal, not a successful checkpoint")
    previous = ready["previous_operation"]
    require(isinstance(previous, str) and re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", previous)
            and tuple(map(int, previous.split("-")[1:])) < tuple(map(int, path.name.split("-")[1:])),
            "Keep the prior immutable success before this failed attempt")
    previous_raw = read_existing(attempt.work / previous / "complete.json")
    previous_value = decode(previous_raw)
    require(isinstance(previous_value, dict) and digest(previous_raw) == row["previous_ordinary_sha256"]
            and previous_value.get("status") == "passed"
            and previous_value.get("state_sha256") == ready["previous_state_sha256"],
            "Preserve the exact prior success and its original backend")
    state_hash, identity = backend(path / "infrastructure", member)
    require(state_hash == row["state_sha256"] == ready["state_sha256"]
            and identity == ready["state_identity"],
            "Bind the frozen failed backend identity; never restore or adopt it")
    def guest_attributes(folder):
        value = decode(read_existing(folder / "terraform.tfstate"))
        return next(r["instances"][0]["attributes"] for r in value["resources"]
                    if r["type"] == "proxmox_virtual_environment_container")
    failed_guest = guest_attributes(path / "infrastructure")
    require(permission in historical_network_paths(failed_guest),
            "Require the exact reviewed pre-update SDN refusal, not a successful checkpoint")
    plan = decode(read_existing(path / "plan.json"))
    window = decode(read_existing(path / "apply-window.json"))
    shape(window, {"plan_sha256", "started_at_ns"})
    require(plan.get("binding") == held["binding"] and plan.get("existing_guest") is True
            and plan.get("changed") is True and type(window["started_at_ns"]) is int
            and window["started_at_ns"] > 0
            and digest(read_existing(path / "guest.tfplan")) == ready["plan_sha256"]
            == plan.get("plan_sha256") == window["plan_sha256"],
            "Preserve the exact unfinished saved-plan attempt")
    log = read_existing(path / "infrastructure.log")
    require(("received an HTTP 403 response - Reason: Permission check failed (" + permission + ", SDN.Use)").encode() in log
            and b"Modifications complete" not in log,
            "A different or partially completed apply needs separate review")
    previous_folder = path / "infrastructure" / "previous"
    previous_hash, previous_identity = backend(previous_folder, member)
    require(previous_hash == ready["previous_state_sha256"] and previous_identity == identity,
            "Keep the exact prior backend and all resource identities across the failed apply")
    return identity, {"before": failed_guest,
                      "after": guest_attributes(previous_folder)}


def _row(cfg, row):
    """The finite row union, independent of a future source selection."""
    before = isinstance(row, dict) and row.get('boundary') == 'before-started'
    fields = {"operation", "phase", "hold_sha256", "infrastructure_sha256",
              "previous_ordinary_sha256", "state_sha256"}
    shape(row, fields | ({'boundary', 'preceding_completions_sha256'} if before else {'log_sha256'}))
    name = row["operation"]
    require(isinstance(name, str) and re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", name),
            "Select each exact failed ordinary operation once")
    require(isinstance(row["phase"], str)
            and (re.fullmatch(r"[a-z][a-z0-9_-]{0,62}" if cfg.get('schema')=='homelab-component-guest-v1'
                              else r"[a-z][a-z0-9_]{0,31}", row["phase"])
                 or row["phase"] == "zabbix-agent"),
            "Select a fixed failed application phase")
    if before:
        prefix = row['preceding_completions_sha256']
        require(cfg.get('schema') == 'homelab-component-guest-v1'
                and row['phase'] not in {'infrastructure', 'preparation', 'zabbix-agent'}
                and isinstance(prefix, dict) and 0 < len(prefix) <= 128
                and 'preparation' in prefix and row['phase'] not in prefix
                and all(isinstance(name, str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', name)
                        for name in prefix), 'Select only the closed component pre-started app boundary')
        for value in prefix.values():
            fingerprint(value)
    for key in row.keys() - {"operation", "phase", 'boundary', 'preceding_completions_sha256'}:
        fingerprint(row[key])


def selection(cfg):
    rows = cfg.get("reviewed_ordinary_failures", [])
    require(isinstance(rows, list) and len(rows) <= 16, "Use bounded reviewed ordinary failures")
    require(not rows or "coordinated_custody" in cfg or "initial_ordinary" in cfg,
            "Reviewed failures require selected ordinary custody")
    names = set()
    for row in rows:
        _row(cfg, row)
        require(row['operation'] not in names, "Select each exact failed ordinary operation once")
        names.add(row['operation'])
    return rows


def phase_start(attempt,path,row,held,raw):
    """A component STARTED binds its selected payload; the global hold stays exact."""
    from component_payload import AppPayload,BINDING_SCHEMA,SCHEMA,_directory,_read,_id
    binding=held['binding']
    if binding.get('schema')!=BINDING_SCHEMA:
        require(raw==read_existing(path/(row['phase']+'-started.json')),
                "Bind only the failed attempt's completed infrastructure checkpoint")
        return
    from coordinated_generation import component_binding
    component_binding(binding)
    shape(held,{'binding','operation','automatic_retry','workflow','run_number','site_revision',
                'previous_ordinary_sha256'})
    started_raw=read_existing(path/(row['phase']+'-started.json'))
    started=decode(started_raw)
    require(raw==encoded(held) and started_raw==encoded(started),
            'Preserve the exact generated component hold and phase-start bytes')
    if row['phase']=='preparation':
        require(encoded(started)==encoded(held),'Preserve the failed preparation input boundary')
        return
    require(isinstance(started,dict) and set(started)==set(held)|{'phase_inputs'}
            and {key:value for key,value in started.items()if key!='phase_inputs'}==held,
            'Preserve the exact failed component phase start')
    proof=started['phase_inputs']
    shape(proof,{'schema','identity','app','payload_sha256'})
    require(proof['schema']==SCHEMA and _id(proof['app']) and proof['identity']==binding['input_identity'],
            'Preserve the failed phase input identity')
    selected=Path(binding['app_inputs_directory'])
    AppPayload.load(selected/proof['app'],proof)
    with _directory(selected.parent)as directory:
        site=_read(directory,'site.json')
    require(digest(site)==binding['site_sha256'],'Preserve the failed phase static source')
    cfg=decode(site)
    require(cfg.get('schema')=='homelab-component-guest-v1'
            and cfg['site']['node']==attempt.cfg['site']['node']
            and all(cfg['guest'][key]==attempt.cfg['guest'][key]for key in ('vmid','hostname'))
            and cfg['deployment']['payload_phases'].get(row['phase'])==proof['app'],
            'Preserve the failed phase selected app owner')


def _sealed_component(binding):
    """Read the existing immutable publication, never construct another packet."""
    import component_inputs
    from component_payload import _directory, _read
    from coordinated_generation import component_binding
    component_binding(binding)
    directory = Path(binding['app_inputs_directory']).parent
    with _directory(directory) as descriptor:
        site = _read(descriptor, 'site.json')
        runtime = _read(descriptor, 'component-runtime.json')
    require(digest(site) == binding['site_sha256'], 'Preserve the failed boundary static source')
    cfg = decode(site)
    hashes = component_inputs.inspect(cfg, directory/'site.json')
    require(all(binding['input_hashes'].get(path) == value for path, value in hashes.items())
            and binding['input_hashes'].get(str(directory/'component-runtime.json')) == digest(runtime)
            and cfg['deployment']['input_identity'] == binding['input_identity']
            and binding['app_inputs_directory'] == str(directory/'applications')
            and cfg['guest']['vmid'] == binding['vmid'], 'Preserve every sealed component source input')
    value = decode(runtime)
    require(isinstance(value, dict) and value.get('schema') == 'homelab-component-runtime-v1'
            and isinstance(value.get('applications'), dict)
            and set(value['applications']) == {row['id'] for row in cfg['deployment']['applications'].values()},
            'Preserve the sealed runtime application set')
    return cfg, value


def _inventory(path):
    """Bound descriptor-relative names and identities without reading leaf contents."""
    from component_payload import _directory, _identity
    with _directory(path) as directory:
        names = os.listdir(directory)
        require(len(names) <= 4096, 'Bound the failed operation inventory')
        entries = {name: os.stat(name, dir_fd=directory, follow_symlinks=False) for name in names}
        require(all((stat.S_ISREG(info.st_mode) and info.st_nlink == 1 or stat.S_ISDIR(info.st_mode))
                    and info.st_uid == os.getuid() for info in entries.values()),
                'Preserve failed boundary file and directory identities')
        return _identity(os.fstat(directory)), {name: _identity(info) for name, info in entries.items()}


def _prefix(attempt, path, row, held, raw, ready):
    """Immutable old source and whole pre-STARTED prefix; no current-state pin."""
    import component_guest
    from component_payload import AppPayload, _directory, _read
    old, runtime = _sealed_component(held['binding'])
    phases = component_guest.phases(old)
    phase = row['phase']
    require(phase in old['deployment']['applications']
            and runtime['applications'][old['deployment']['payload_phases'][phase]]['lifecycle'] == 'retained',
            'Select only an old retained application boundary')
    require(ready.get('binding') == held['binding'] and ready.get('state_sha256') == row['state_sha256']
            and isinstance(ready.get('state_identity'), dict),
            'Preserve the immutable failed infrastructure checkpoint')
    prefix, remaining = phases[:phases.index(phase)], phases[phases.index(phase):]
    require(set(row['preceding_completions_sha256']) == set(prefix),
            'Preserve the complete ordered old phase prefix')
    inventory = _inventory(path)
    markers = {name for name in inventory[1] if name.endswith(('-started.json', '-complete.json'))}
    require(markers == {'infrastructure-complete.json',
                       *(name+suffix for name in prefix for suffix in ('-started.json', '-complete.json'))},
            'Preserve exactly the old prefix marker inventory')
    require(not set(remaining) & set(inventory[1])
            and all(not stat.S_ISDIR(info[2]) or name in {'tofu', *prefix}
                for name, info in inventory[1].items())
            and all(not name.endswith('.log') or name == 'infrastructure.log' for name in inventory[1]),
            'A selected, later or unknown phase has a work or log directory')
    applications = Path(held['binding']['app_inputs_directory'])
    payload_inventory = _inventory(applications)
    require(set(payload_inventory[1]) == {old['deployment']['payload_phases'][name]
                for name in prefix if name != 'preparation'},
            'Selected, later and unknown app or agent payloads must be absent')
    for name in prefix:
        phase_start(attempt, path, {'phase': name}, held, raw)
        complete_raw = read_existing(path/(name+'-complete.json'))
        require(digest(complete_raw) == row['preceding_completions_sha256'][name],
                'Preserve the exact completed prefix bytes')
        complete = decode(complete_raw)
        started = decode(read_existing(path/(name+'-started.json')))
        proof = None if name == 'preparation' else started['phase_inputs']
        shape(complete, {'binding', 'result'} | ({'phase_inputs'} if proof is not None else set()))
        require(complete_raw == encoded(complete) and complete['binding'] == held['binding']
                and isinstance(complete['result'], dict) and complete['result'].get('status') == 'passed'
                and type(complete['result'].get('changed')) is bool
                and (proof is None or complete['phase_inputs'] == proof),
                'Preserve the successful prefix completion and selected proof')
        if proof is not None:
            payload = AppPayload.load(applications/proof['app'], proof)
            with _directory(payload.directory) as directory:
                app = decode(_read(directory, 'application.json'))
            require(app == runtime['applications'][old['deployment']['payload_phases'][name]],
                    'Preserve the prefix payload application from its sealed runtime')
        work = path/name
        if work.exists():
            private_directory(work)
            no_markers(work)
    require(inventory == _inventory(path) and payload_inventory == _inventory(applications),
            'Failed boundary inventory changed while reading')
    return old, runtime, ready['state_identity']


def before_started(attempt, member, path, row, held, raw, ready):
    """Future admission retains current ownership and ancestry, not old state hashes."""
    import commands
    from component_ownership import identity
    old, runtime, backend_identity = _prefix(attempt, path, row, held, raw, ready)
    current, current_runtime = _sealed_component(attempt.binding)
    require(current == attempt.cfg and held['binding']['schema'] == attempt.binding['schema'],
            'Preserve the current sealed source for failed-boundary admission')
    phase = row['phase']
    require(phase in current['deployment']['applications'],
            'Select the same retained application phase from the old and current source')
    selected = runtime['applications'][old['deployment']['payload_phases'][phase]]
    now = current_runtime['applications'][current['deployment']['payload_phases'][phase]]
    require(now['lifecycle'] == 'retained' and selected['adapter'] == now['adapter']
            and runtime['guest']['id'] == current_runtime['guest']['id']
            and identity(old, selected) == identity(current, now),
            'Preserve the retained failed app and every persistent runtime owner')
    fingerprint(held['site_revision'], 40)
    require(commands.is_ancestor(attempt.workspace, held['site_revision'], attempt.site_revision),
            'Preserve failed-source workflow ancestry')
    return backend_identity


def _record(path, row, hold_raw):
    """The same exact historical bytes for normal and operator read-only callers."""
    infrastructure = row['phase'] == 'infrastructure'
    before = row.get('boundary') == 'before-started'
    private_directory(path)
    no_markers(path)
    if not before:
        private_directory(path / row['phase'])
        no_markers(path / row['phase'])
    require(not any((path / name).exists() or (path / name).is_symlink()
                    for name in ('complete.json', row['phase'] + '-complete.json')),
            'A failed checkpoint cannot replace a completed operation')
    names = {'hold_sha256': 'preserved-failed-hold.json',
             'infrastructure_sha256': ('infrastructure/review.json' if infrastructure else 'infrastructure-complete.json'),
             **({} if before else {'log_sha256': ('infrastructure.log' if infrastructure else row['phase'] + '/application.log')})}
    raw = {key: (hold_raw if key == 'hold_sha256' else read_existing(path / name))
           for key, name in names.items()}
    require(all(digest(value) == row[key] for key, value in raw.items()),
            'Preserve exact reviewed failed operation bytes')
    held, ready = decode(raw['hold_sha256']), decode(raw['infrastructure_sha256'])
    require(isinstance(held, dict) and isinstance(ready, dict), 'Preserve typed failed operation records')
    return held, ready


def inspect_historical(context, member, binding_key, row, hold_raw):
    """Read original failed context before an operator preserves its exact HOLD.

    This validates no future run/source selection and grants no release. Mutable
    canonical/backend pins belong only here, not repeated ordinary admission.
    """
    import initial_ordinary
    import coordinated_contract
    from coordinated_generation import backend
    _row(context.cfg, row)
    path = Path(context.cfg['paths']['state_root'])/str(context.cfg['guest']['vmid'])/row['operation']
    require(context.cfg.get('schema') == 'homelab-component-guest-v1' and row['phase'] != 'infrastructure'
            and context.work == path.parent and context.operation == path
            and context.receipt == path.parent/'ordinary-complete.json',
            'Bind only the original component failed-operation context')
    held, ready = _record(path, row, hold_raw)
    old, _ = _sealed_component(held['binding'])
    require(old == context.cfg and held['binding'] == context.binding,
            'Preserve the exact original sealed failed source and binding')
    initial = initial_ordinary.selection(old)
    selected = initial if initial is not None else coordinated_contract.selection(old)['members'][old['app']['kind']]
    key = initial_ordinary.BINDING if initial is not None else 'coordinated_custody_sha256'
    custody = initial_ordinary.selection_digest(old) if initial is not None else coordinated_contract.selection_digest(old)
    require(member == selected and binding_key == key and context.binding.get(key) == custody,
            'Preserve the original selected historical guest custody')
    shape(held, {'binding', 'operation', 'automatic_retry', 'workflow', 'run_number', 'site_revision',
                 'previous_ordinary_sha256'})
    fingerprint(held['site_revision'], 40)
    require(hold_raw == encoded(held) and held['operation'] == str(path) and held['automatic_retry'] is False
            and held['workflow'] == context.workflow and held['run_number'] == context.run_number
            and type(held['run_number']) is int and held['run_number'] > 0
            and held['site_revision'] == context.site_revision
            and held['previous_ordinary_sha256'] == row['previous_ordinary_sha256'],
            'Preserve the exact original failed workflow and prior success')
    if row.get('boundary') == 'before-started':
        _, _, identity = _prefix(context, path, row, held, hold_raw, ready)
    else:
        phase_start(context, path, row, held, hold_raw)
        require(ready.get('binding') == context.binding and ready.get('state_sha256') == row['state_sha256']
                and isinstance(ready.get('state_identity'), dict),
                'Preserve the original failed infrastructure checkpoint')
        identity = ready['state_identity']
    state_hash, current_identity = backend(context.work, member)
    require(digest(read_existing(context.receipt)) == row['previous_ordinary_sha256']
            and state_hash == row['state_sha256'] and current_identity == identity,
            'Preserve the exact pre-preservation canonical success and current backend')
    return dict(row, identity=identity)


def inspect_record(attempt, member, binding_key, row, hold_raw):
    """Validate one selected failed record from supplied exact HOLD bytes, read only.

    This entrypoint retains future source selection and run-order policy. Normal
    admission supplies only the fixed preserved file; original operator context
    uses inspect_historical instead. Neither entrypoint grants a release.
    """
    require(row in selection(attempt.cfg), 'Inspect only an exact selected failed operation row')
    path = attempt.work / row["operation"]
    infrastructure = row["phase"] == "infrastructure"
    before = row.get('boundary') == 'before-started'
    require(path != attempt.operation and (infrastructure or row["phase"] in attempt.phases),
            "A reviewed failure cannot replay as the current operation")
    held, ready = _record(path, row, hold_raw)
    binding = held.get("binding", {})
    require(isinstance(binding, dict) and binding.get("vmid") == member["vmid"]
            and binding.get(binding_key) == attempt.binding[binding_key]
            and held.get("operation") == str(path) and held.get("workflow") == attempt.workflow
            and type(held.get("run_number")) is int and 0 < held["run_number"] < attempt.run_number
            and held.get("automatic_retry") is False
            and held.get("previous_ordinary_sha256") == row["previous_ordinary_sha256"],
            "Preserve the exact own failed workflow and prior success")
    if before:
        identity = before_started(attempt, member, path, row, held, hold_raw, ready)
    elif infrastructure:
        identity, reviewed_drift = infrastructure_review(attempt, member, path, held, ready, row)
    else:
        phase_start(attempt,path,row,held,hold_raw)
        require(ready.get("binding") == binding and ready.get("state_sha256") == row["state_sha256"]
                and isinstance(ready.get("state_identity"), dict),
                "Bind only the failed attempt's completed infrastructure checkpoint")
        identity = ready["state_identity"]
    return dict(row, identity=identity,
                **({"reviewed_drift": reviewed_drift} if infrastructure else {}))


def inspect(attempt, member, binding_key):
    found = {}
    for row in selection(attempt.cfg):
        path = attempt.work / row['operation'] / 'preserved-failed-hold.json'
        found[row['operation']] = inspect_record(attempt, member, binding_key, row, read_existing(path))
    return found
