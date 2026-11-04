"""Historical anchors→actual component deploy/attempt; app/native engines are fakes.

These explicit packet fixtures test the receiver and admission boundary. They do
not invoke a legacy compiler or claim renderer/native/service acceptance. The
source→packet contract is exercised separately by current component integrations.
"""
import copy
from contextlib import contextmanager, ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

F = Path(Path(__file__).resolve().parents[3])
sys.path[:0] = [str(F / 'blueprints'), str(F / 'proxmox/applications'),
                str(F / 'proxmox/applications/tests')]
import component_guest
import component_inputs
import component_ownership
import component_payload
import coordinated_contract
import coordinated_generation
import custody_records
import deploy
import initial_ordinary
import private_io as io
from application_contract import ADAPTERS
from custody_fixtures import CompletedGroup, backend, legacy_canonical, legacy_immutable, save
from fixtures import guest, github_source

CASES = ('postgresql', 'identity', 'db-tools', 'mariadb', 'influxdb', 'automation', 'zigbee2mqtt')
ADAPTER = {'identity': 'authentik', 'db-tools': 'cloudbeaver', 'automation': 'homeassistant'}


class HistoricalCase:
    """Conforming historical files and component packet; no source/compiler fake."""
    def __init__(self, test, root, role, *, group=None, phase=None):
        self.test, self.root, self.role = test, root, role
        self.root.chmod(0o700)
        self.adapter = ADAPTER.get(role, role)
        if role in ('postgresql', 'identity', 'db-tools', 'mariadb'):
            self.group = group if group is not None else CompletedGroup(root, postgres=role != 'mariadb')
            self.cfg = copy.deepcopy(self.group.cfgs[role])
            self.work = self.group.work(role)
            self.missing_evidence = self.group.local / 'complete.json'
            self.proofs = self.group.files()
        else:
            self.group = None
            self.cfg = guest(root)
            self.cfg['app']['kind'] = role
            (root / 'state').mkdir(mode=0o700)
            self.work = root / 'state/808'; self.work.mkdir(mode=0o700)
            self.cfg['paths']['backup_directory'] = str(root / 'nas/backups')
            (root / 'nas').mkdir(mode=0o700)
            (root / 'nas/backups').mkdir(mode=0o700)
            save(root / 'ca', b'synthetic public CA\n')
            save(root / 'hosts', b'198.18.25.8 ssh-ed25519 fixture\n')
            save(self.work / 'ssh-trust.json', {'address': self.cfg['app']['address'],
                                               'keys': [['ssh-ed25519', 'fixture']]})
            if role == 'zigbee2mqtt':
                self.cfg['guest']['serial_device'] = {'path': '/dev/serial/by-id/usb-fixture'}
                save(root / 'helper-key', b'synthetic helper credential\n')
                save(root / 'helper-hosts', b'fixture host trust\n')
                self.cfg['paths'].update(host_device_key=str(root / 'helper-key'),
                                         host_known_hosts=str(root / 'helper-hosts'))
            installed = root / 'installed.json'
            installed_hash = save(installed, self.cfg)
            state_hash = save(self.work / 'terraform.tfstate', backend(808))
            record = {'status': 'passed', 'binding': {'vmid': 808, 'source_sha256': 'a' * 64,
                'site_sha256': installed_hash, 'input_hashes': {str(root / 'ca'): io.sha(root / 'ca')}},
                'state_sha256': state_hash, 'result': {'status': 'passed', 'changed': False}}
            operation = 'ordinary-100-3'
            immutable = self.work / operation / 'complete.json'
            selected = {'schema': {'influxdb': initial_ordinary.SCHEMA,
                'automation': initial_ordinary.AUTOMATION_SCHEMA,
                'zigbee2mqtt': initial_ordinary.ZIGBEE_SCHEMA}[role],
                'vmid': 808, 'node': 'fixture-pve', 'installed_site': str(installed),
                'installed_site_sha256': installed_hash, 'initial_state_sha256': state_hash,
                'receipt': {'operation': operation, 'source_sha256': 'a' * 64,
                    'sha256': save(self.work / 'ordinary-complete.json', legacy_canonical(record)),
                    'immutable_sha256': save(immutable, legacy_immutable(record))}}
            if role in ('automation', 'zigbee2mqtt'):
                selected['incomplete_operations'] = ['ordinary-99-1']
                save(self.work / 'ordinary-99-1/failure.log', b'preserved pre-anchor failed attempt\n')
            self.cfg['initial_ordinary'] = selected
            self.missing_evidence = immutable
            self.proofs = {}
        self.installed = Path(self.cfg.get('initial_ordinary', {}).get('installed_site',
            self.group.group['members'][role]['installed_site'] if self.group else ''))
        # The source/root binding is deliberately separate from phase app inputs.
        self.inputs = root / 'component-inputs'
        self.identity = '9' * 64
        self.guest_id, self.app_id, self.phase = 'retained-guest', 'owned-application', phase or 'application'
        directory = self.inputs / self.guest_id / self.identity
        self.cfg['schema'] = component_guest.CONFIG_SCHEMA
        self.cfg['deployment'] = {'contract': 3, 'capabilities': ['linux', 'docker']
            if ADAPTERS[self.adapter]['services'] else ['linux'], 'input_identity': self.identity,
            'input_directory': str(directory), 'runtime_file': str(directory / 'component-runtime.json'),
            'lifecycle': 'retained', 'protected_guests': [9900],
            'applications': {}, 'payload_phases': {self.phase: self.app_id},
            'phases': ['preparation', self.phase]}
        self.cfg['app'].update(service_health_checks={self.phase: [{'name': 'fake adapter', 'argv': ['true']}]},
                               exclusive_writer_confirmed=True)
        if self.group:
            self.cfg['paths']['coordinated_custody_inputs'] = str(directory)
        roles = ADAPTERS[self.adapter]['services']
        names = {name: 'owned-' + name.replace('_', '-') for name in roles}
        app = {'id': self.app_id, 'adapter': self.adapter, 'lifecycle': 'retained',
               'identity': {'runtime_id': 'retained-app', 'phase': self.phase,
                            'services': names, 'networks': {}}, 'storage_paths': {}, 'settings': {}}
        row = {'id': self.app_id, 'adapter': self.adapter, 'lifecycle': 'retained', 'runtime_id': 'retained-app'}
        files = dict(self.proofs)
        if roles:
            app.update(project_name='retained-project', project_file='compose.yml')
            row.update(project='retained-project', compose_file='compose.yml', services=list(names.values()))
            files['compose.yml'] = io.encoded({'services': {name: {'image': 'fixture/image:1'}
                                                           for name in names.values()}}).decode()
        self.cfg['deployment']['applications'][self.phase] = row
        self.runtime = {'schema': 'homelab-component-runtime-v1',
                        'guest': {'id': self.guest_id}, 'applications': {self.app_id: app}}
        self.packet = root / 'component-packet.json'
        self.publish(files)
        self.github, self.revisions = github_source(root)
        self.native_calls, self.app_calls, self.prepared = [], [], []
        # Immutable historical copies, failed attempts and group provenance remain.
        self.history = {p: (p.stat().st_ino, p.read_bytes()) for p in root.rglob('*') if p.is_file()
                        and not p.is_relative_to(self.github) and p != self.packet
                        and p.name not in ('ordinary-complete.json', 'terraform.tfstate')}

    def publish(self, files=None):
        if files is None:
            files = json.loads(self.packet.read_bytes())['files']
        files['site.json'] = io.encoded(self.cfg).decode()
        files['component-runtime.json'] = io.encoded(self.runtime).decode()
        self.packet.write_bytes(io.encoded({'schema': component_guest.PACKET_SCHEMA,
            'guest': self.guest_id, 'enabled': True, 'identity': self.identity, 'files': files}))
        self.packet.chmod(0o600)

    def revise(self):
        """An explicit synthetic source revision gets a new immutable input slot.

        This is test packet construction, not a compatibility compiler. Direct
        publish() still refuses to overwrite an already materialized identity.
        """
        packet = json.loads(self.packet.read_bytes())
        if (packet['files']['site.json'] == io.encoded(self.cfg).decode()
                and packet['files']['component-runtime.json'] == io.encoded(self.runtime).decode()):
            return
        self.identity = io.digest(io.encoded({'prior_identity': self.identity,
                                              'config': self.cfg, 'runtime': self.runtime}))
        directory = self.inputs / self.guest_id / self.identity
        self.cfg['deployment'].update(input_identity=self.identity, input_directory=str(directory),
                                      runtime_file=str(directory/'component-runtime.json'))
        if self.group:
            self.cfg['paths']['coordinated_custody_inputs'] = str(directory)
        self.publish()

    def bind(self, contexts):
        context = {'GITHUB_RUN_ID': '777', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_NUMBER': '777',
            'GITHUB_REPOSITORY': 'example/private-site',
            'HOMELAB_DEPLOYMENT_WORKFLOW': 'example/private-site/.github/workflows/deploy.yml@refs/heads/main',
            'GITHUB_SHA': self.revisions[0], 'GITHUB_WORKSPACE': str(self.github)}
        contexts.enter_context(patch.dict(os.environ, context))
        contexts.enter_context(patch.object(deploy, 'bootstrap_closed'))
        contexts.enter_context(patch('deployment_inputs.source_hash', return_value='7' * 64))
        contexts.enter_context(patch('proxmox_guest.guest_trust'))
        contexts.enter_context(patch.object(custody_records.os.path, 'ismount',
                                            side_effect=lambda value: Path(value) == self.root / 'nas'))
        real_output = subprocess.check_output
        def output(argv, *args, **kwargs):
            if argv[0] == 'findmnt':
                value = 'nfs4 nas.example.invalid:/backups\n'
                return value if kwargs.get('text') else value.encode()
            return real_output(argv, *args, **kwargs)
        contexts.enter_context(patch.object(custody_records.subprocess, 'check_output', side_effect=output))
        self.native = contexts.enter_context(patch('proxmox_guest.infrastructure', side_effect=self.infrastructure))
        self.prepare = contexts.enter_context(patch('component_prepare.prepare', side_effect=self.app_prepare))
        contexts.enter_context(patch('component_ansible.run_phase', side_effect=self.app_run))

    def infrastructure(self, cfg, site, work, operation, binding, **kwargs):
        self.test.assertEqual(work, self.work)
        self.test.assertTrue((work / 'ORDINARY-HOLD.json').exists())
        member = (cfg['coordinated_custody']['group']['members'][self.role] if self.group
                  else initial_ordinary.selection(cfg))
        self.test.assertEqual(kwargs['state_identity'], coordinated_generation.backend(work, member)[1])
        body = json.loads((work / 'terraform.tfstate').read_bytes()); body['serial'] += 1
        save(work / 'terraform.tfstate', body)
        self.native_calls.append(kwargs['state_identity'])
        return {'changed': True, 'created': False, 'state_sha256': io.sha(work / 'terraform.tfstate')}

    def app_prepare(self, cfg, app_id, environment, *, attempt):
        self.test.assertEqual(app_id, self.app_id)
        self.test.assertTrue((self.work / 'ORDINARY-HOLD.json').exists())
        app = self.runtime['applications'][app_id]
        values = {'application.json': io.encoded(app),
                  'owned-app.json': io.encoded(component_ownership.identity(cfg, app))}
        parent = component_inputs.app_directory(cfg, create=True)
        payload = component_payload.prepare(parent, self.identity, app_id, values)
        self.prepared.append(payload.check())
        return payload

    def app_run(self, cfg, site, work, operation, expected, phase, *, payload, previously_owned):
        self.test.assertTrue((work / 'ORDINARY-HOLD.json').exists())
        started = io.read_json(operation / (phase + '-started.json'), private=True)
        if phase == 'preparation':
            self.test.assertIsNone(payload)
        else:
            self.test.assertEqual(phase, self.phase)
            self.test.assertEqual(started['phase_inputs'], payload.check())
            self.test.assertEqual(payload.app, self.app_id)
            self.app_calls.append(previously_owned)
        return {'status': 'passed', 'changed': False, 'target_contacted': False}

    def all_phases(self):
        return [deploy.run(phase, self.packet, inputs=self.inputs, environment={})
                for phase in ['infrastructure', *self.cfg['deployment']['phases']]]

    def history_unchanged(self):
        for path, expected in self.history.items():
            self.test.assertEqual((path.stat().st_ino, path.read_bytes()), expected, str(path))


class ComponentHistoricalTransitionTests(unittest.TestCase):
    @contextmanager
    def case(self, role):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as contexts:
            value = HistoricalCase(self, Path(temporary).resolve(), role)
            value.bind(contexts)
            yield value

    def test_all_four_paths_five_schemas_and_each_group_member_reach_bound_component_phase_and_repeat(self):
        for role in CASES:
            with self.subTest(role=role), self.case(role) as value:
                value.all_phases()
                first = io.read_json(value.work / 'ordinary-complete.json', private=True)
                self.assertEqual(first['schema'], 'homelab-component-ordinary-complete-v1')
                self.assertEqual(first['phase_inputs'][value.phase]['app'], value.app_id)
                proof_key = 'coordinated_custody_sha256' if value.group else initial_ordinary.BINDING
                self.assertEqual(first['binding'][proof_key], coordinated_contract.selection_digest(value.cfg)
                                 if value.group else initial_ordinary.selection_digest(value.cfg))
                value.history_unchanged()
                with patch.dict(os.environ, {'GITHUB_RUN_ID': '778', 'GITHUB_RUN_NUMBER': '778',
                                             'GITHUB_SHA': value.revisions[1]}):
                    value.all_phases()
                    self.assertFalse(deploy.run('infrastructure', value.packet, inputs=value.inputs)['target_contacted'])
                self.assertEqual(len(value.native_calls), 2)
                self.assertEqual(value.native_calls[1], first['state_identity'])
                self.assertEqual(value.app_calls, [False, True])
                self.assertEqual(len(value.prepared), 2)
                self.assertFalse((value.work / 'ORDINARY-HOLD.json').exists())
                value.history_unchanged()

    def test_explicit_source_revision_keeps_old_publication_and_uses_new_immutable_slot(self):
        with self.case('mariadb') as value:
            value.all_phases()
            previous=Path(value.cfg['deployment']['input_directory'])
            before={path:(path.stat().st_ino,path.read_bytes()) for path in previous.rglob('*') if path.is_file()}
            identity=value.identity
            value.cfg['deployment']['prerequisites']=['explicit synthetic source assertion']
            value.revise()
            self.assertNotEqual(value.identity,identity)
            self.assertNotEqual(Path(value.cfg['deployment']['input_directory']),previous)
            with patch.dict(os.environ,{'GITHUB_RUN_ID':'778','GITHUB_RUN_NUMBER':'778','GITHUB_SHA':value.revisions[1]}):
                value.all_phases()
            self.assertEqual(len(value.native_calls),2)
            self.assertEqual(before,{path:(path.stat().st_ino,path.read_bytes()) for path in before})
            value.history_unchanged()

    def test_same_identity_source_edit_refuses_instead_of_rewriting_static_inputs(self):
        with self.case('mariadb') as value:
            value.all_phases()
            previous=Path(value.cfg['deployment']['input_directory'])
            before={path:(path.stat().st_ino,path.read_bytes()) for path in previous.rglob('*') if path.is_file()}
            value.cfg['deployment']['prerequisites']=['changed without a source revision']
            value.publish()
            with patch.dict(os.environ,{'GITHUB_RUN_ID':'778','GITHUB_RUN_NUMBER':'778','GITHUB_SHA':value.revisions[1]}), \
                    self.assertRaisesRegex(ValueError,'differs or was interrupted'):
                value.all_phases()
            self.assertEqual(len(value.native_calls),1)
            self.assertFalse((value.work/'ORDINARY-HOLD.json').exists())
            self.assertEqual(before,{path:(path.stat().st_ino,path.read_bytes()) for path in before})

    def test_missing_foreign_tampered_or_unselected_anchor_and_holds_refuse_before_native_or_app_inputs(self):
        for role in CASES:
            for failure in ('missing', 'foreign-state', 'tampered-site', 'hold', 'unselected'):
                with self.subTest(role=role, failure=failure), self.case(role) as value:
                    if failure == 'missing':
                        value.missing_evidence.unlink()
                    elif failure == 'foreign-state':
                        body = json.loads((value.work / 'terraform.tfstate').read_bytes())
                        body['resources'][0]['instances'][0]['attributes']['node_name'] = 'foreign-node'
                        save(value.work / 'terraform.tfstate', body)
                    elif failure == 'tampered-site':
                        value.installed.write_bytes(value.installed.read_bytes() + b' ')
                    elif failure == 'hold':
                        save(value.work / 'VERIFYING.json', {'status': 'pending'})
                    else:
                        value.cfg.pop('coordinated_custody' if value.group else 'initial_ordinary')
                        if value.group: value.cfg['paths'].pop('coordinated_custody_inputs')
                        value.publish()
                    before = {p: (p.stat().st_ino, p.read_bytes()) for p in value.work.rglob('*')
                              if p.is_file()}
                    with self.assertRaises((ValueError, OSError)):
                        deploy.run('infrastructure', value.packet, inputs=value.inputs, environment={})
                    self.assertEqual(value.native_calls, [])
                    value.prepare.assert_not_called()
                    self.assertEqual(value.app_calls, [])
                    self.assertFalse((Path(value.cfg['deployment']['input_directory']) / 'applications').exists())
                    for path, expected in before.items():
                        self.assertEqual((path.stat().st_ino, path.read_bytes()), expected)


if __name__ == '__main__':
    unittest.main()
