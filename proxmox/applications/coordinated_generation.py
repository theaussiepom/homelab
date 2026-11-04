"""Closed backend identity and ordinary receipt relationships; no state writes."""

from pathlib import Path
import json
import re
from private_io import require, digest, encoded, private_directory
from plan_policy import RESOURCES
from custody_records import decode, read_existing, no_markers
from coordinated_contract import shape, fingerprint, absolute
from component_payload import AppPayload, SCHEMA as APP_SCHEMA, BINDING_SCHEMA
import ordinary_failure


COMPONENT_COMPLETE='homelab-component-ordinary-complete-v1'


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
    if set(binding)&optional:fields.add('state_identity')
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
            and isinstance(value.get("resources"), list) and len(value["resources"]) == len(RESOURCES),
            "Preserve the authoritative backend generation")
    identities = {}
    for row in value["resources"]:
        require(isinstance(row, dict) and row.get("mode") == "managed", "Preserve managed backend identities")
        address = ".".join(str(row.get(k, "")) for k in ("module", "type", "name"))
        require(address in RESOURCES and address not in identities
                and isinstance(row.get("instances"), list) and len(row["instances"]) == 1,
                "Keep exactly the commissioned backend resources")
        instance = row["instances"][0]
        require(isinstance(instance, dict) and instance.get("index_key") is None and instance.get("deposed") is None,
                "Preserve an unambiguous backend instance")
        attrs = instance.get("attributes", {})
        key = RESOURCES[address]
        require(isinstance(attrs, dict) and type(attrs.get(key)) is int and attrs[key] == member["vmid"]
                and attrs.get("node_name") == member["node"] and isinstance(attrs.get("id"), str)
                and 0 < len(attrs["id"]) <= 256, "Preserve backend VMID, node and resource ID")
        identities[address] = {"id": attrs["id"], "vmid": attrs[key], "node": attrs["node_name"]}
    return digest(raw), {"lineage": value["lineage"], "resources": identities}


def plan_identity(value, identity):
    """A reviewed existing plan must not alter the admitted provider IDs."""
    for row in value["resource_changes"]:
        expected = identity["resources"][row["address"]]["id"]
        require(all(row["change"][side].get("id") == expected for side in ("before", "after"))
                and not row["change"].get("after_unknown", {}).get("id"),
                "The plan changed or deferred an admitted backend resource ID")


def initial_copy(work, member, *, raw=None):
    initial = member["initial_ordinary"]
    if initial is None:
        return None
    raw = read_existing(work / initial["operation"] / "complete.json") if raw is None else raw
    require(digest(raw) == initial.get("immutable_sha256", initial["sha256"]),
            "Preserve the exact initial immutable ordinary copy")
    value = decode(raw)
    shape(value, {"status", "binding", "state_sha256", "result"})
    require(value["status"] == "passed" and value["state_sha256"] == member["initial_state_sha256"]
            and isinstance(value["binding"], dict) and type(value["binding"].get("vmid")) is int
            and value["binding"]["vmid"] == member["vmid"]
            and value["binding"].get("source_sha256") == initial["source_sha256"],
            "Bind only the exact qualified initial ordinary success")
    return raw


def initial_canonical(raw, member, baseline):
    """Recognize only the separately pinned initial pointer and full typed record."""
    if baseline is None or raw is None or digest(raw) != member["initial_ordinary"]["sha256"]:
        return False
    value = decode(raw)
    shape(value, {"status", "binding", "state_sha256", "result"})
    require(json.dumps(value, sort_keys=True, allow_nan=False)
            == json.dumps(decode(baseline), sort_keys=True, allow_nan=False),
            "Preserve the complete typed initial ordinary record")
    return True


def latest_success(attempt, member, *, binding_key="coordinated_custody_sha256"):
    """An older anchor/pointer cannot supersede any recorded later F success."""
    found = {}
    reviewed = ordinary_failure.inspect(attempt, member, binding_key)
    attempt.reviewed_failures = reviewed
    for path in attempt.work.iterdir():
        if not re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", path.name):
            continue
        private_directory(path)
        if path.name in reviewed:
            continue
        if binding_key == "initial_ordinary_sha256":
            no_markers(path)
        active = path == attempt.operation and attempt.hold.exists()
        complete = path / "complete.json"
        if binding_key == "initial_ordinary_sha256" and path.name in member.get("incomplete_operations", []):
            require(path != attempt.operation and not complete.exists() and not complete.is_symlink(),
                    "Preserve qualified historical incompletion; no replay or success claim")
            continue
        if active:
            require(not complete.exists() and not complete.is_symlink(), "Preserve interrupted final receipt custody")
            continue
        raw = read_existing(complete)
        value = decode(raw)
        require(isinstance(value, dict), "Preserve unexpected ordinary operation custody")
        binding = value.get("binding", {})
        standalone = binding_key == "initial_ordinary_sha256"
        if standalone:
            require(isinstance(binding, dict), "Preserve malformed initial ordinary history")
            anchor_run = int(member["initial_ordinary"]["operation"].split("-")[1])
            require(int(path.name.split("-")[1]) <= anchor_run
                    or binding_key in binding and "workflow" in value,
                    "A later ordinary operation cannot become an initial legacy record")
        if isinstance(binding, dict) and (binding_key in binding
                or standalone and "workflow" in value):
            require(binding.get(binding_key) == attempt.binding[binding_key]
                    and binding.get("vmid") == member["vmid"] and value.get("status") == "passed"
                    and value.get("operation") == str(path) and value.get("workflow") == attempt.workflow
                    and type(value.get("run_number")) is int and value["run_number"] > 0,
                    "Preserve foreign or failed coordinated ordinary history")
            component_success(value, path)
            number = value["run_number"]
            require(number not in found, "Preserve ambiguous ordinary run history")
            found[number] = raw
    return found[max(found)] if found else None


def classify(attempt, member, lineage, baseline, *, binding_key="coordinated_custody_sha256"):
    """Own-run continuation precedes latest F success, then the exact first anchor."""
    require(binding_key in {"coordinated_custody_sha256", "initial_ordinary_sha256"},
            "Select a closed ordinary generation binding")
    state_hash, identity = backend(attempt.work, member)
    require(identity["lineage"] == lineage, "Preserve the commissioned backend lineage")
    attempt._select_run()
    canonical = attempt.receipt
    raw = read_existing(canonical) if canonical.exists() or canonical.is_symlink() else None
    latest = latest_success(attempt, member, binding_key=binding_key)
    require(latest is None or raw == latest, "Preserve the latest ordinary success; no older anchor fallback")
    initial = initial_canonical(raw, member, baseline)
    if initial:
        attempt.initial_ordinary = raw
    if attempt.hold.exists() or attempt.hold.is_symlink():
        held = decode(read_existing(attempt.hold))
        require(isinstance(held, dict), "Preserve malformed ordinary custody")
        previous = held.pop("previous_ordinary_sha256", "missing")
        require(encoded(held) == encoded(attempt.marker)
                and previous == (None if raw is None else digest(raw)), "Preserve foreign or changed ordinary custody")
        ready = decode(read_existing(attempt.operation / "infrastructure-complete.json"))
        require(isinstance(ready, dict) and ready.get("binding") == attempt.binding and ready.get("state_sha256") == state_hash
                and ready.get("state_identity") == identity, "Preserve incomplete or changed infrastructure custody")
    else:
        previous = None if raw is None else digest(raw)
        if raw is not None:
            if initial:
                require(state_hash == member["initial_state_sha256"], "The initial backend has unproven changes")
            else:
                value = decode(raw)
                operation = value.get("operation") if isinstance(value, dict) else None
                require(isinstance(operation, str) and Path(operation).parent == attempt.work
                        and re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", Path(operation).name),
                        "Keep this member's immutable ordinary operation")
                if not component_success(value, Path(operation)):
                    shape(value, {"status", "binding", "state_sha256", "state_identity", "result", "workflow", "run_number", "site_revision", "operation"})
                checkpoints = [row for row in attempt.reviewed_failures.values()
                               if row["previous_ordinary_sha256"] == digest(raw)
                               and row["state_sha256"] == state_hash and row["identity"] == identity]
                require(read_existing(Path(operation) / "complete.json") == raw
                        and value["status"] == "passed"
                        and (value["state_sha256"] == state_hash and value["state_identity"] == identity
                             or len(checkpoints) == 1)
                        and isinstance(value["binding"], dict) and value["binding"].get("vmid") == member["vmid"]
                        and value["binding"].get(binding_key) == attempt.binding[binding_key],
                        "Preserve the latest exact ordinary success; no anchor fallback")
                if value["state_sha256"] != state_hash and len(checkpoints) == 1:
                    attempt.reviewed_infrastructure_drift = checkpoints[0].get("reviewed_drift")
        else:
            require(baseline is None and state_hash == member["initial_state_sha256"],
                    "Require the selected initial ordinary disposition and backend")
    attempt.previous_ordinary_sha256 = previous
    attempt.marker["previous_ordinary_sha256"] = previous
    return identity
