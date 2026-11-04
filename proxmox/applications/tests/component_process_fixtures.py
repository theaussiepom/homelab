"""Synthetic current receiver packets and real static/payload publication for OS tests."""
from pathlib import Path
import component_guest
import component_inputs
import component_ownership
import component_payload
import private_io as io


def configuration(root):
    root = Path(root).resolve()
    cfg = {'site': {'node': 'fixture-pve', 'api_endpoint': 'https://192.0.2.10:8006/'},
        'guest': {'vmid': 808, 'hostname': 'fixture', 'memory_mib': 1024,
                  'interfaces': [{'ipv4': '198.18.25.8/24', 'mac': '02:00:00:00:00:08',
                                  'bridge': 'example0', 'vlan': None}]},
        'ssh_public_keys': ['ssh-ed25519 fixture-public-key'],
        'paths': {name: str(root / leaf) for name, leaf in (
            ('state_root', 'state'), ('backup_mount', 'nas'), ('backup_directory', 'nas/backups'),
            ('ca_file', 'ca'), ('api_token', 'api'), ('private_key', 'key'), ('known_hosts', 'hosts'))},
        'app': {'kind': 'mariadb', 'vmid': 808, 'hostname': 'fixture', 'memory_mib': 1024,
                'address': '198.18.25.8', 'mac': '02:00:00:00:00:08', 'packages': [],
                'required_paths': [], 'health_checks': [],
                'service_health_checks': {'mariadb': [{'name': 'synthetic adapter', 'argv': ['true']}]}}}
    cfg['paths']['backup_source'] = 'nas.example.invalid:/backups'
    directory = root / 'inputs/mariadb' / ('a' * 64)
    cfg['schema'] = component_guest.CONFIG_SCHEMA
    cfg['deployment'] = {'contract': 3, 'capabilities': ['linux'], 'lifecycle': 'retained',
        'input_identity': 'a' * 64, 'input_directory': str(directory),
        'runtime_file': str(directory / 'component-runtime.json'), 'protected_guests': [9900],
        'applications': {'mariadb': {'id': 'database', 'adapter': 'mariadb', 'lifecycle': 'retained',
                                    'runtime_id': 'database'}},
        'payload_phases': {'mariadb': 'database'}, 'phases': ['preparation', 'mariadb']}
    runtime = {'schema': 'homelab-component-runtime-v1', 'guest': {'id': 'mariadb'},
        'applications': {'database': {'id': 'database', 'adapter': 'mariadb', 'lifecycle': 'retained',
            'identity': {'phase': 'mariadb', 'runtime_id': 'database', 'services': {}, 'networks': {}},
            'settings': {}, 'storage_paths': {}}}}
    packet = {'schema': component_guest.PACKET_SCHEMA, 'guest': 'mariadb', 'enabled': True,
        'identity': 'a' * 64, 'files': {'site.json': io.encoded(cfg).decode(),
            'component-runtime.json': io.encoded(runtime).decode(), 'homelab.cnf': 'retained listener\n'}}
    return cfg, packet


def initialize(root):
    root = Path(root).resolve(); root.chmod(0o700)
    for relative in ('state', 'state/808', 'inputs', 'inputs/mariadb'):
        (root / relative).mkdir(mode=0o700)
    io.write_new(root / 'state/808/terraform.tfstate', b'authoritative backend')
    io.write_new(root / 'ca', b'fixture public CA\n')
    cfg, packet = configuration(root)
    io.write_new(root / 'packet.json', io.encoded(packet))
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
        'application.json': io.encoded(app), 'owned-app.json': io.encoded(component_ownership.identity(cfg, app))})
