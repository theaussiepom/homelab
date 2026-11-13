"""Existing component receipts, sealed payloads and backend ownership; no migration inputs."""
from pathlib import Path
import json
import re
from private_io import require,digest,encoded,private_directory,read_json,regular,sha
from plan_policy import RESOURCES, IP_FILTER_RESOURCE, ip_filter_values, ip_filter_slots, resource_fields
from custody_records import decode,read_existing,no_markers
from component_payload import AppPayload,SCHEMA as APP_SCHEMA,BINDING_SCHEMA

COMPONENT_COMPLETE='homelab-component-ordinary-complete-v1'

def shape(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys), "Use closed component receipt fields")


def fingerprint(value, length=64):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", value),
            "Pin an exact component proof digest")


def absolute(value):
    require(isinstance(value, str) and len(value) <= 4096 and Path(value).is_absolute()
            and ".." not in Path(value).parts and str(Path(value)) == value,
            "Use canonical absolute component input paths")


def component_binding(binding):
    """The same closed common input binding for complete and failed phases."""
    require(isinstance(binding,dict),'Preserve the component ordinary binding')
    required={'schema','vmid','site_sha256','source_sha256','input_identity','app_inputs_directory','input_hashes'}
    optional={'coordinated_custody_sha256','initial_ordinary_sha256'}
    require(required<=set(binding)<=required|optional and len(set(binding)&optional)<=1
            and binding['schema']==BINDING_SCHEMA and type(binding['vmid']) is int and binding['vmid']>0,
            'Use the closed component ordinary binding')
    for field in ('site_sha256','source_sha256','input_identity',*(set(binding)&optional)):
        fingerprint(binding[field])
    absolute(binding['app_inputs_directory'])
    require(isinstance(binding['input_hashes'],dict),'Preserve component static input pins')
    for path,digest in binding['input_hashes'].items():
        absolute(path);fingerprint(digest)
    return binding


def component_success(value, operation):
    """Validate only versioned component history; leave legacy nine fields separate."""
    binding=value.get('binding',{}) if isinstance(value,dict) else {}
    component=isinstance(value,dict) and ('schema' in value or isinstance(binding,dict)
                                          and 'schema' in binding)
    if not component:
        return False
    component_binding(binding)
    optional={'coordinated_custody_sha256','initial_ordinary_sha256'}
    fields={'schema','status','binding','state_sha256','result','workflow','run_number','site_revision',
            'operation','phase_inputs'}
    if set(binding)&optional or 'state_identity'in value:fields.add('state_identity')
    shape(value,fields)
    require(value['schema']==COMPONENT_COMPLETE and value['status']=='passed'
            and isinstance(value['result'],dict) and value['operation']==str(operation),
            'Preserve a complete component ordinary success')
    fingerprint(value['state_sha256']);fingerprint(value['site_revision'],40)
    workflow=value['workflow']
    require(isinstance(workflow,list) and len(workflow)==2 and all(isinstance(x,str) for x in workflow)
            and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',workflow[0])
            and re.fullmatch(re.escape(workflow[0])+r'/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml',workflow[1])
            and type(value['run_number']) is int and value['run_number']>0,
            'Preserve component workflow and run provenance')
    phases=value['phase_inputs']
    require(isinstance(phases,dict) and 0<len(phases)<=128 and 'preparation' in phases
            and phases['preparation'] is None
            and all(isinstance(p,str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}',p) for p in phases),
            'Preserve the component completion phase set')
    absolute(str(operation))
    require(re.fullmatch(r'ordinary-[1-9][0-9]*-[1-9][0-9]*',operation.name),'Keep the immutable component operation identity')
    private_directory(operation);no_markers(operation)
    found={path.name for path in operation.iterdir()
           if path.name!='infrastructure-complete.json' and re.fullmatch(r'[a-z][a-z0-9_-]{0,62}-(started|complete)\.json',path.name)}
    require(found=={p+suffix for p in phases for suffix in ('-started.json','-complete.json')},
            'Preserve every immutable completed component phase')
    ready=decode(read_existing(operation/'infrastructure-complete.json'))
    require(isinstance(ready,dict) and ready.get('binding')==binding
            and ready.get('state_sha256')==value['state_sha256']
            and ('state_identity' not in fields or ready.get('state_identity')==value['state_identity']),
            'Preserve component infrastructure checkpoint provenance')
    common={'binding':binding,'operation':str(operation),'automatic_retry':False,'workflow':workflow,
            'run_number':value['run_number'],'site_revision':value['site_revision']}
    prior=object();unselected=prior
    for phase,proof in phases.items():
        if phase!='preparation':
            shape(proof,{'schema','identity','app','payload_sha256'})
            require(proof['schema']==APP_SCHEMA and proof['identity']==binding['input_identity']
                    and isinstance(proof['app'],str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}',proof['app']),
                    'Preserve this phase selected-app identity')
            fingerprint(proof['payload_sha256'])
            AppPayload.load(Path(binding['app_inputs_directory'])/proof['app'],proof)
        started=decode(read_existing(operation/(phase+'-started.json')))
        complete=decode(read_existing(operation/(phase+'-complete.json')))
        require(isinstance(started,dict),'Preserve the component phase start marker')
        marker=dict(common)
        if 'previous_ordinary_sha256' in started:
            previous=started['previous_ordinary_sha256']
            if previous is not None:fingerprint(previous)
            marker['previous_ordinary_sha256']=previous
        if proof is not None:marker['phase_inputs']=proof
        require(encoded(started)==encoded(marker),'Preserve the exact component phase start ownership')
        previous=marker.get('previous_ordinary_sha256','absent')
        require(prior is unselected or prior==previous,'Preserve the component prior-success binding')
        prior=previous
        shape(complete,{'binding','result'}|({'phase_inputs'} if proof is not None else set()))
        require(complete['binding']==binding and isinstance(complete['result'],dict)
                and (proof is None or complete['phase_inputs']==proof),
                'Preserve the completed phase selected-app proof')
    return True


def backend(work, member):
    """Project identity without freezing mutable attributes or serial/hash."""
    raw = read_existing(work / "terraform.tfstate")
    value = decode(raw)
    require(isinstance(value, dict) and value.get("version") == 4
            and isinstance(value.get("lineage"), str) and 0 < len(value["lineage"]) <= 128
            and type(value.get("serial")) is int and value["serial"] >= 0
            and isinstance(value.get("resources"), list)
            and len(value["resources"]) in (len(RESOURCES), len(RESOURCES)+1),
            "Preserve the authoritative backend generation")
    identities = {}
    for row in value["resources"]:
        require(isinstance(row, dict) and row.get("mode") == "managed", "Preserve managed backend identities")
        address = ".".join(str(row.get(k, "")) for k in ("module", "type", "name"))
        filtered = address == IP_FILTER_RESOURCE
        require((filtered or address in RESOURCES) and isinstance(row.get('instances'), list)
                and (1 <= len(row['instances']) <= 32 if filtered else len(row['instances']) == 1),
                "Keep exactly the commissioned backend resources")
        for instance in row['instances']:
            require(isinstance(instance, dict) and instance.get('deposed') is None,
                    'Preserve an unambiguous backend instance')
            selected = address
            if filtered:
                index = instance.get('index_key')
                require(isinstance(index, str) and re.fullmatch(r'0|[1-9]|[12][0-9]|3[01]', index),
                        'Preserve the exact per-NIC IP filter slot')
                selected += '["' + index + '"]'
                require(ip_filter_values(instance.get('attributes'), int(index)),
                        'Preserve only owned empty per-NIC IP filters')
            else:
                require(instance.get('index_key') is None, 'Preserve an unambiguous backend instance')
            require(selected not in identities, 'Preserve unique backend resource instances')
            attrs = instance.get('attributes', {})
            key = 'container_id' if filtered else RESOURCES[address]
            require(isinstance(attrs, dict) and type(attrs.get(key)) is int and attrs[key] == member['vmid']
                    and attrs.get('node_name') == member['node'] and isinstance(attrs.get('id'), str)
                    and 0 < len(attrs['id']) <= 256, 'Preserve backend VMID, node and resource ID')
            identities[selected] = {'id': attrs['id'], 'vmid': attrs[key], 'node': attrs['node_name']}
    require(set(RESOURCES) <= set(identities), 'Preserve all commissioned guest and firewall identities')
    return digest(raw), {"lineage": value["lineage"], "resources": identities}


def identity_extension(previous, current, slots):
    """Only selected new filters may extend a genuine infrastructure checkpoint."""
    return (isinstance(current, dict) and set(current.get('resources', {})) == set(resource_fields(slots))
            and (previous is None or current.get('lineage') == previous.get('lineage')
                 and all(current['resources'].get(address) == fields
                         for address, fields in previous['resources'].items())))


def plan_identity(value, identity, *, ip_filter_slots=()):
    """A reviewed existing plan must not alter the admitted provider IDs."""
    for row in value["resource_changes"]:
        if row['address'] not in identity['resources']:
            require(row['address'] in set(resource_fields(ip_filter_slots)) - set(RESOURCES)
                    and row['change']['before'] is None and row['change']['actions'] == ['create'],
                    'Only a selected missing IP filter may extend backend ownership')
            continue
        expected = identity["resources"][row["address"]]["id"]
        require(all(row["change"][side].get("id") == expected for side in ("before", "after"))
                and not row["change"].get("after_unknown", {}).get("id"),
                "The plan changed or deferred an admitted backend resource ID")


def binding(value):
    """New ordinary inputs have only the permanent seven-field binding."""
    component_binding(value)
    require(set(value)=={'schema','vmid','site_sha256','source_sha256','input_identity',
                        'app_inputs_directory','input_hashes'},'Use only normal component input fields')
    from component_guest import path
    path(value['app_inputs_directory'])
    for filename in value['input_hashes']:
        path(filename)
    return value


def backup_continuity(previous, current):
    """Omission, new destinations and implicit key rotation are not routine updates."""
    old = previous.get('backup', {}).get('job')
    if old is None:
        return
    new = current.get('backup', {}).get('job')
    require(new is not None and old['group'] == new['group'],
            'Retire existing backup protection explicitly; ordinary deployment cannot disable it')
    # Scheduling/capture and the independently verified TLS certificate can change.
    # Account ownership, private key locations and recovery recipients cannot drift.
    require(old['secrets'] == new['secrets'] and old['recovery_public_key'] == new['recovery_public_key']
            and {k:v for k,v in old['destination'].items() if k != 'fingerprint'} ==
                {k:v for k,v in new['destination'].items() if k != 'fingerprint'},
            'Preserve backup destination and encryption ownership; rotation needs an explicit handover')


def previous(attempt):
    """Validate the actual prior canonical/immutable component and sealed inputs."""
    if not attempt.receipt.exists() and not attempt.receipt.is_symlink():return None
    raw=regular(attempt.receipt,private=True);value=decode(raw)
    require(isinstance(value,dict)and isinstance(value.get('operation'),str),
            'Existing ownership requires a genuine component ordinary success')
    require(isinstance(value.get('binding'),dict) and value['binding'].get('vmid')==attempt.vmid,
            'Preserve the prior component guest binding')
    operation=Path(value['operation'])
    require(operation.parent==attempt.work and component_success(value,operation)
            and read_existing(operation/'complete.json')==raw,
            'Preserve the exact canonical and immutable component success')
    selected=value['binding'];directory=Path(selected['app_inputs_directory']).parent
    site=directory/'site.json';runtime=directory/'component-runtime.json'
    require(sha(site)==selected['site_sha256'] and selected['input_hashes'].get(str(runtime))==sha(runtime),
            'Preserve prior sealed component source and runtime')
    cfg=read_json(site,private=True);apps=read_json(runtime,private=True)['applications']
    from component_guest import phases
    phases(cfg)
    from component_inputs import static
    hashes=static(cfg,site)
    require(all(selected['input_hashes'].get(path)==value for path,value in hashes.items()),
            'Preserve every prior sealed static input')
    require(cfg.get('schema')=='homelab-component-guest-v1'
            and cfg['site']['node']==attempt.cfg['site']['node']
            and cfg['site']['api_endpoint']==attempt.cfg['site']['api_endpoint']
            and all(cfg['guest'][key]==attempt.cfg['guest'][key]for key in('vmid','hostname'))
            and cfg['deployment']['input_directory']==str(directory)
            and selected['app_inputs_directory']==str(directory/'applications')
            and cfg['deployment']['input_identity']==selected['input_identity']
            and cfg['deployment']['runtime_file']==str(runtime)
            and set(value['phase_inputs'])==set(cfg['deployment']['phases'])
            and cfg['deployment']['payload_phases']=={phase:proof['app']for phase,proof in value['phase_inputs'].items()if proof is not None},
            'Preserve the prior component guest and phase owners')
    require(set(apps)=={proof['app']for phase,proof in value['phase_inputs'].items()
                       if proof is not None and phase in cfg['deployment']['applications']},
            'Preserve the complete prior app selection')
    from component_continuity import validate
    for phase,proof in value['phase_inputs'].items():
        if proof is None:continue
        payload=AppPayload.load(Path(selected['app_inputs_directory'])/proof['app'],proof)
        app=read_json(payload.directory/'application.json',private=True)
        if phase == 'pbs-agent':
            require(app == cfg['app']['backup'], 'Preserve the prior PBS preparation owner')
        elif proof['app']=='agent':
            require(app=={'schema':'homelab-component-agent-input-v1','monitoring':cfg['app']['monitoring']},
                    'Preserve the prior agent owner')
        else:
            require(app==apps[proof['app']],'Preserve the prior sealed app descriptor')
            validate(app,read_json(payload.directory/'private-material.json',private=True))
    backup_continuity(cfg['app'], attempt.cfg['app'])
    return value,cfg,apps


def current(attempt):
    """Admit normal ownership or one exact held continuation, never old adoption."""
    attempt._select_run()
    old=previous(attempt)
    attempt.previous_configuration = None if old is None else old[1]
    if old is None:
        require(attempt.cfg['deployment']['lifecycle']=='fresh'
                and all(row['lifecycle']=='fresh'for row in attempt.cfg['deployment']['applications'].values()),
                'Retained resources require a genuine current component success')
        attempt.previous_ordinary_sha256=None;attempt.marker['previous_ordinary_sha256']=None
        if attempt.hold.exists()or attempt.hold.is_symlink():
            require(regular(attempt.hold,private=True)==encoded(attempt.marker),
                    'Preserve exact first fresh run hold ownership')
            state_hash,identity=backend(attempt.work,{'vmid':attempt.vmid,'node':attempt.cfg['site']['node']})
            ready=decode(read_existing(attempt.operation/'infrastructure-complete.json'))
            require(ready.get('binding')==attempt.binding and ready.get('state_sha256')==state_hash
                    and ready.get('state_identity')==identity,
                    'Preserve first fresh infrastructure ownership')
            require(not any(p!=attempt.operation for p in attempt.work.glob('ordinary-*')),
                    'A fresh attempt cannot adopt prior ordinary history')
            return identity
        require(not(attempt.work/'terraform.tfstate').exists(),
                'Fresh source cannot adopt an existing backend')
        return None
    value,_,_=old
    require(value['workflow']==attempt.workflow and value['run_number']<=attempt.run_number,
            'Preserve the current workflow and reject older runs')
    state_hash,identity=backend(attempt.work,{'vmid':attempt.vmid,'node':attempt.cfg['site']['node']})
    previous_hash=digest(encoded(value))
    # Canonical bytes are generated with encoded(); a reformatted pointer cannot
    # acquire a different prior-success identity under unchanged immutable proof.
    require(regular(attempt.receipt,private=True)==encoded(value),'Preserve canonical component serialization')
    attempt.previous_ordinary_sha256=previous_hash;attempt.marker['previous_ordinary_sha256']=previous_hash
    if attempt.hold.exists()or attempt.hold.is_symlink():
        require(regular(attempt.hold,private=True)==encoded(attempt.marker),
                'Preserve exact current run hold ownership')
        ready=decode(read_existing(attempt.operation/'infrastructure-complete.json'))
        require(ready.get('binding')==attempt.binding and ready.get('state_sha256')==state_hash
                and ready.get('state_identity')==identity,
                'Preserve this run owned infrastructure checkpoint')
    else:
        require(state_hash==value['state_sha256'] and ('state_identity'not in value or value['state_identity']==identity),
                'Current backend changed outside its ordinary success')
    require('state_identity'not in value or value['state_identity']==identity
            or (attempt.hold.exists() or attempt.hold.is_symlink())
            and identity_extension(value['state_identity'], identity,
                                   ip_filter_slots(attempt.cfg['guest']['interfaces'])),
            'Preserve the existing backend resource identity')
    canonical=Path(value['operation']);epoch=tuple(int(x)for x in canonical.name.removeprefix('ordinary-').split('-'))
    for path in attempt.work.iterdir():
        if not re.fullmatch(r'ordinary-[1-9][0-9]*-[1-9][0-9]*',path.name):continue
        private_directory(path);no_markers(path)
        if path==canonical:continue
        if path==attempt.operation and(attempt.hold.exists()or attempt.hold.is_symlink()):continue
        number=tuple(int(x)for x in path.name.removeprefix('ordinary-').split('-'))
        require(number<epoch,'Preserve newer unresolved ordinary history; no pointer fallback')
        for started_path in path.glob('*-started.json'):
            envelope=decode(read_existing(started_path))
            selected=envelope.get('binding')if isinstance(envelope,dict)else None
            if isinstance(selected,dict)and selected.get('schema')==BINDING_SCHEMA:
                require(selected.get('vmid')==attempt.vmid and envelope.get('workflow')==attempt.workflow
                        and type(envelope.get('run_number'))is int
                        and 0<envelope['run_number']<=value['run_number'],
                        'Preserve foreign or newer component history')
        # Earlier inactive directories are historical evidence, not successful
        # receipts or a source of new ownership. The genuine current success is
        # the sole epoch; every active/pending marker above remains a refusal.
    return identity
