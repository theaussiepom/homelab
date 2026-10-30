"""Entirely synthetic retained commissioning records; no native resources."""

import copy
from pathlib import Path
import private_io as io
from fixtures import guest
from coordinated_contract import SCHEMA, ROLES
from plan_policy import RESOURCES


def save(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else io.encoded(value))
    path.chmod(0o600)
    return io.digest(path.read_bytes())


def backend(vmid, serial=2):
    return {
        "version": 4, "lineage": f"fixture-{vmid}", "serial": serial,
        "resources": [
            {"module": address.rsplit('.', 2)[0], "type": address.split('.')[-2],
             "name": address.split('.')[-1], "mode": "managed",
             "instances": [{"attributes": {key: vmid, "node_name": "fixture-pve", "id": f"fixture/{vmid}/{key}"}}]}
            for address, key in RESOURCES.items()
        ],
    }


class CompletedGroup:
    def __init__(self, root, *, postgres=False):
        self.root = Path(root).resolve()
        self.root.chmod(0o700)
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.nas = self.root / 'nas'
        self.nas.mkdir(mode=0o700)
        self.backups = self.nas / 'backups'
        self.backups.mkdir(mode=0o700)
        self.schema = 'homelab-postgresql-cutover-v1' if postgres else 'homelab-database-server-cutover-v1'
        self.roles = ROLES[self.schema]
        engine = self.roles[0]
        self.operation = engine + '-fixture'
        self.directory = ('database-network-cutover-' if postgres else 'database-server-cutover-') + self.operation
        self.local = self.state / self.directory
        self.remote = self.backups / self.directory
        self.catalogue = {'schema': 'homelab-database-networks-v1', 'networks': {r: {} for r in ('postgresql', 'mariadb', 'influxdb')}}
        self.catalogue_raw = io.encoded(self.catalogue)
        self.cfgs, members, requested = {}, {}, {}
        for index, role in enumerate(self.roles):
            vmid = 808 + index
            cfg = guest(self.root)
            cfg['guest']['vmid'] = cfg['app']['vmid'] = vmid
            cfg['app']['kind'] = role
            cfg['deployment']['capabilities'] = ['linux'] if role == engine else ['linux', 'docker']
            if role != engine:
                cfg['app']['exclusive_writer_confirmed'] = True
            self.cfgs[role] = cfg
            work = self.state / str(vmid)
            work.mkdir(mode=0o700)
            installed = self.root / ('installed-' + role + '.json')
            ca_hash = save(self.root / 'ca', b'fixture public CA\n')
            save(self.root / 'hosts', b'198.18.25.8 ssh-ed25519 fixture\n')
            source_hash = 'a' * 64
            input_hashes = {str(self.root / 'ca'): ca_hash}
            files = {
                'site': save(installed, cfg),
                'plan.json': save(work / 'plan.json', {'source_sha256': source_hash, 'input_hashes': input_hashes}),
                'ssh-trust.json': save(work / 'ssh-trust.json', {'address': cfg['app']['address'], 'keys': [['ssh-ed25519', 'fixture']]}),
                'terraform.tfstate': io.digest(io.encoded(backend(vmid, 1))),
                'tfvars': save(work / 'tofu/site.auto.tfvars.json', {'fixture': True}),
            }
            original = {'files': files, 'source_sha256': source_hash, 'input_hashes': input_hashes,
                        'state_lineage': f'fixture-{vmid}', 'state_serial': 1}
            plan_directory = 'database-network-plan-fixture'
            request_hash = save(work / plan_directory / 'request.json', {'original': original})
            candidate = 'b' * 64
            review_hash = save(work / plan_directory / 'review-packet.json', {'candidate_guest_sha256': candidate})
            packet = {'schema': 'homelab-database-network-apply-v1', 'vmid': vmid,
                      'request_sha256': request_hash, 'review_packet_sha256': review_hash,
                      'apply_helper_sha256': 'c' * 64, 'allow_guest_restart': True}
            requested[role] = {'vmid': vmid, 'installer_revision': 'd' * 40, 'adapter_revision': 'e' * 40,
                               'plan_directory': plan_directory, 'network_packet': packet,
                               'runtime_packet': {'fixture': True},
                               'startup': {'gate_sha256': 'f' * 64, 'dependency_sha256': '1' * 64}}
            overlay_dir = 'database-network-apply-' + review_hash
            overlay = {'schema': 'homelab-database-network-overlay-v1', 'status': 'network_overlay_verified',
                       'packet_sha256': io.digest(io.encoded(packet)), 'request_sha256': request_hash,
                       'review_packet_sha256': review_hash, 'candidate_guest_sha256': candidate,
                       'original': original, 'state_sha256': io.digest(io.encoded(backend(vmid))),
                       'state_lineage': f'fixture-{vmid}', 'state_serial': 2, 'vmid': vmid}
            overlay_hash = save(work / overlay_dir / 'overlay.json', overlay)
            save(self.backups / str(vmid) / overlay_dir / 'overlay.json', overlay)
            later = postgres and role != engine
            current_hash = save(work / 'terraform.tfstate', backend(vmid, 3 if later else 2))
            initial = None
            if later:
                baseline = {'status': 'passed', 'binding': {'vmid': vmid, 'source_sha256': source_hash},
                            'state_sha256': current_hash, 'result': {'status': 'passed'}}
                initial_hash = save(work / 'ordinary-100-1/complete.json', baseline)
                save(work / 'ordinary-complete.json', baseline)
                initial = {'operation': 'ordinary-100-1', 'sha256': initial_hash, 'source_sha256': source_hash}
            members[role] = {'vmid': vmid, 'node': 'fixture-pve', 'installed_site': str(installed),
                             'overlay': {'directory': overlay_dir, 'sha256': overlay_hash},
                             'initial_state_sha256': current_hash, 'initial_ordinary': initial}
        self.request = {'schema': self.schema, 'operation': self.operation,
                        'catalogue_sha256': io.digest(self.catalogue_raw), 'members': requested}
        request_hash = self.record('request.json', self.request)
        self.record('claim.json', self.request)
        complete_hash = self.record('complete.json', {'status': 'passed', 'operation': self.operation,
                                                     'packet_sha256': request_hash, 'roles': list(self.roles)})
        if postgres:
            acceptance = {k: None for k in ('observed_utc', 'scope', 'automatic_cd', 'NAS_parity',
                                           'password_restore_receipt_sha256', 'browser', 'remaining_scope')}
            acceptance.update(status='network31_group_and_saved_credential_SQL_accepted',
                              qualified_request_sha256=request_hash, qualified_completion_sha256=complete_hash)
        else:
            acceptance = {'schema': 'homelab-database-server-cutover-selection-v1', 'mode': 'apply',
                          'helper_revision': 'e' * 40, 'installer_revision': 'd' * 40,
                          'catalogue_sha256': io.digest(self.catalogue_raw), 'packet': self.request}
        self.acceptance_raw = io.encoded(acceptance)
        self.group = {'directory': self.directory, 'schema': self.schema, 'operation': self.operation,
                      'records': {'request.json': request_hash, 'claim.json': request_hash, 'complete.json': complete_hash},
                      'catalogue': {'file': 'catalogue.json', 'sha256': io.digest(self.catalogue_raw)},
                      'acceptance': {'file': 'acceptance.json', 'sha256': io.digest(self.acceptance_raw)},
                      'recovery': {'mount': str(self.nas), 'directory': str(self.backups), 'source': 'nas.example.invalid:/backups'},
                      'members': members}
        for role, cfg in self.cfgs.items():
            cfg['coordinated_custody'] = {'schema': SCHEMA, 'group': copy.deepcopy(self.group)}
            inputs = self.root / 'inputs' / role / ('9' * 64)
            cfg['paths']['coordinated_custody_inputs'] = str(inputs)
            save(inputs / 'catalogue.json', self.catalogue_raw)
            save(inputs / 'acceptance.json', self.acceptance_raw)
            save(inputs / 'site.json', cfg)

    def record(self, name, value):
        value_hash = save(self.local / name, value)
        save(self.remote / name, value)
        return value_hash

    def work(self, role):
        return self.state / str(self.group['members'][role]['vmid'])

    def site(self, role):
        return Path(self.cfgs[role]['paths']['coordinated_custody_inputs']) / 'site.json'

    def files(self):
        return {'catalogue.json': self.catalogue_raw.decode(), 'acceptance.json': self.acceptance_raw.decode()}

    def resolved(self):
        return {r: (cfg, None, self.files()) for r, cfg in self.cfgs.items()}
