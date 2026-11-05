"""Synthetic native data with genuine current controller generations for OS tests."""
import copy
import json
from pathlib import Path
import os
from unittest.mock import patch
import component_guest
import component_inputs
import component_ownership
import component_payload
import component_continuity
from component_generation_fixtures import backend
import private_io as io


def backend_bytes(serial=2):
    return io.encoded(backend(808,serial))


def configuration(root, *, fresh=False):
    root = Path(root).resolve()
    lifecycle='fresh' if fresh else 'retained'
    cfg = {'site': {'node': 'fixture-pve', 'api_endpoint': 'https://192.0.2.10:8006/'},
        'guest': {'vmid': 808, 'hostname': 'fixture', 'memory_mib': 1024,
                  'interfaces': [{'ipv4': '198.18.25.8/24', 'mac': '02:00:00:00:00:08',
                                  'bridge': 'example0', 'vlan': None}]},
        'ssh_public_keys': ['ssh-ed25519 fixture-public-key'],
        'paths': {name: str(root / leaf) for name, leaf in (
            ('state_root', 'state'), ('backup_mount', 'nas'), ('backup_directory', 'nas/backups'),
            ('ca_file', 'ca'), ('api_token', 'api'), ('private_key', 'key'), ('known_hosts', 'hosts'))},
        'app': {'vmid': 808, 'hostname': 'fixture', 'memory_mib': 1024,
                'address': '198.18.25.8', 'mac': '02:00:00:00:00:08', 'packages': [],
                'required_paths': [], 'health_checks': [],
                'service_health_checks': {'mariadb': [{'name': 'synthetic adapter', 'argv': ['true']}]}}}
    cfg['paths']['backup_source'] = 'nas.example.invalid:/backups'
    directory = root / 'inputs/mariadb' / ('a' * 64)
    cfg['schema'] = component_guest.CONFIG_SCHEMA
    cfg['deployment'] = {'contract': 3, 'capabilities': ['linux'], 'lifecycle': lifecycle,
        'input_identity': 'a' * 64, 'input_directory': str(directory),
        'runtime_file': str(directory / 'component-runtime.json'), 'protected_guests': [9900],
        'applications': {'mariadb': {'id': 'database', 'adapter': 'mariadb', 'lifecycle': lifecycle,
                                    'runtime_id': 'database'}},
        'payload_phases': {'mariadb': 'database'}, 'phases': ['preparation', 'mariadb']}
    runtime = {'schema': 'homelab-component-runtime-v1', 'guest': {'id': 'mariadb'},
        'applications': {'database': {'id': 'database', 'adapter': 'mariadb', 'lifecycle': lifecycle,
            'identity': {'phase': 'mariadb', 'runtime_id': 'database', 'services': {}, 'networks': {}},
            'settings': {}, 'storage_paths': {}}}}
    packet = {'schema': component_guest.PACKET_SCHEMA, 'guest': 'mariadb', 'enabled': True,
        'identity': 'a' * 64, 'files': {'site.json': io.encoded(cfg).decode(),
            'component-runtime.json': io.encoded(runtime).decode(), 'homelab.cnf': 'retained listener\n'}}
    return cfg, packet


def initialize(root, *, workspace=None, revision=None, fresh=False):
    root = Path(root).resolve(); root.chmod(0o700)
    for relative in ('state', 'state/808', 'inputs', 'inputs/mariadb'):
        (root / relative).mkdir(mode=0o700)
    io.write_new(root / 'ca', b'fixture public CA\n')
    cfg, packet = configuration(root,fresh=fresh)
    io.write_new(root / 'packet.json', io.encoded(packet))
    if revision is None:
        # A bare synthetic backend for explicit missing/unowned-state negatives.
        io.write_new(root / 'state/808/terraform.tfstate', backend_bytes())
    else:
        if fresh or workspace is None:raise AssertionError('Choose explicit fresh or genuine prior fixture')
        seed(root,workspace,revision)
    return cfg


def prepare(root):
    root = Path(root).resolve()
    cfg, site = component_inputs.prepare(root / 'packet.json', root / 'inputs', create=True)
    return cfg, component_inputs.binding(cfg, site)


def payload(cfg):
    runtime = io.read_json(Path(cfg['deployment']['runtime_file']), private=True)
    app = runtime['applications']['database']
    parent = component_inputs.app_directory(cfg, create=True)
    return component_payload.prepare(parent, cfg['deployment']['input_identity'], 'database', {
        'application.json': io.encoded(app), 'owned-app.json': io.encoded(component_ownership.identity(cfg, app)),
        component_continuity.FILE:io.encoded(component_continuity.document(app,{}))})


def seed(root, workspace, revision, *, run_id='1', identity='e'*64):
    """Use real deploy/attempt/static/payload writers; only guest bodies are fake.

    The prior input namespace is separate from active identity a. This does not
    mock current/previous readers or write a bare canonical success by hand.
    """
    import deploy
    root=Path(root).resolve()
    packet=copy.deepcopy(io.read_json(root/'packet.json',private=True))
    cfg=json.loads(packet['files']['site.json'])
    runtime=json.loads(packet['files']['component-runtime.json'])
    first=not(root/'state/808/ordinary-complete.json').exists()
    lifecycle='fresh' if first else 'retained'
    directory=root/'inputs/mariadb'/identity
    cfg['deployment'].update(lifecycle=lifecycle,input_identity=identity,input_directory=str(directory),runtime_file=str(directory/'component-runtime.json'))
    cfg['deployment']['applications']['mariadb']['lifecycle']=lifecycle
    runtime['applications']['database']['lifecycle']=lifecycle
    packet.update(identity=identity)
    packet['files']['site.json']=io.encoded(cfg).decode()
    packet['files']['component-runtime.json']=io.encoded(runtime).decode()
    selected=root/('seed-'+identity+'.json');io.write_new(selected,io.encoded(packet))
    def infrastructure(*args,**kwargs):
        state=root/'state/808/terraform.tfstate'
        if not state.exists():io.write_new(state,backend_bytes())
        return {'status':'passed','changed':False,'created':first,'state_sha256':io.sha(state)}
    def application(*args,**kwargs):return {'status':'passed','changed':False}
    def app_inputs(value,app,environment,*,attempt):
        if app!='database' or environment!={}:raise AssertionError('Unexpected seeded app role')
        return payload(value)
    metadata={'GITHUB_RUN_ID':str(run_id),'GITHUB_RUN_ATTEMPT':'1','GITHUB_RUN_NUMBER':str(run_id),
        'GITHUB_SHA':revision,'GITHUB_WORKSPACE':str(workspace),'GITHUB_REPOSITORY':'example/private-site',
        'HOMELAB_DEPLOYMENT_WORKFLOW':'example/private-site/.github/workflows/deploy.yml@refs/heads/main'}
    with patch.dict(os.environ,metadata),patch('deployment_inputs.source_hash',return_value='b'*64),\
         patch.object(deploy,'bootstrap_closed'),\
         patch.object(deploy.proxmox_guest,'infrastructure',side_effect=infrastructure),\
         patch('component_ansible.run_phase',side_effect=application),\
         patch('component_prepare.prepare',side_effect=app_inputs):
        for phase in ['infrastructure',*component_guest.phases(cfg)]:
            deploy.run(phase,selected,inputs=root/'inputs',environment={})
    return io.regular(root/'state/808/ordinary-complete.json',private=True)
