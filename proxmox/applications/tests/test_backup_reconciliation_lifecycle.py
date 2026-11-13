"""Real compiler/attempt/receipt progression; only API, SSH, ToFu and apps are fakes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'blueprints'), str(ROOT/'proxmox/applications')]
import backup_staging
import component_plan
import component_packet
import component_ansible
import commands
import deploy
import proxmox_guest
from private_io import encoded, read_json, sha, write_bytes, write_new
from plan_policy import GUEST_RESOURCE
from test_plan import fixture as fresh_plan
import test_component_deployment as fixture_module
from fixtures import github_source

INFRASTRUCTURE = proxmox_guest.infrastructure
IS_ANCESTOR = commands.is_ancestor


class BackupReconciliationLifecycleTests(unittest.TestCase):
    def setUp(self):
        """Create an isolated real-source fixture with fictional runtime boundaries."""
        self.fixture = fixture_module.DeploymentIntegrationTests(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root; self.work = self.fixture.state/'610'
        self.workspace, self.revisions = github_source(self.root)
        environment = patch.dict(os.environ, {'GITHUB_WORKSPACE': str(self.workspace), 'GITHUB_SHA': self.revisions[0]})
        environment.start(); self.addCleanup(environment.stop)
        ancestry = patch.object(commands, 'is_ancestor', side_effect=IS_ANCESTOR)
        ancestry.start(); self.addCleanup(ancestry.stop)
        self.library = self.root/'complete-backup-source'
        shutil.copytree(ROOT/'docs/examples/backup', self.library)
        self.source = yaml.safe_load((self.library/'site.yaml').read_text())
        context = self.source['contexts']['lab']
        context['paths']['state_root'] = str(self.fixture.state)
        context['trust']['ca_file'] = str(self.root/'ca.pem')
        self.source['secret_sources']['token']['path'] = str(self.root/'token')
        write_new(self.root/'token', b'fixture@pve!deploy=fictional')
        self.source['storage']['local']['pool'] = 'local-zfs'
        self.applies = []; self.remote = []; self.failure = None

    def publish(self, *, backup, data, job=True, protect_data=True):
        """Compile a selected backup variation into the fixture's actual guest packet."""
        source = copy.deepcopy(self.source)
        volumes = source['guests']['resolver']['volumes']
        if data:
            volumes['data'] = {'storage': 'local', 'slot': 0, 'path': '/srv/data', 'size_gib': 8}
            volumes['backup-stage']['slot'] = 1
            if backup and protect_data: volumes['data']['backup'] = None
        if not backup:
            source.pop('backup'); source['guests']['resolver'].pop('backup')
            volumes.pop('backup-stage')
        elif not job:
            source['backup'] = {}; volumes.pop('backup-stage')
        path = self.library/'site.yaml'; path.write_text(yaml.safe_dump(source))
        plan = component_plan.resolve(self.library, path)
        packet = component_packet.lower_plan(plan, inputs=self.fixture.inputs)['resolver']
        self.cfg = self.fixture.cfg = json.loads(packet['files']['site.json'])
        write_bytes(self.fixture.packet, encoded(packet))
        os.environ['GITHUB_SHA'] = self.revisions[1 if backup else 0]

    def allocated(self, cfg):
        """Project declared volume order into fictional provider-allocated identities."""
        return [{'path': cfg['guest']['volumes'][name]['path'],
                 'size': str(cfg['guest']['volumes'][name]['size_gib'])+'G',
                 'volume': 'local-zfs:subvol-610-disk-'+str(index+1),
                 'path_in_datastore': 'local-zfs:subvol-610-disk-'+str(index+1),
                 'backup': cfg['guest']['volumes'][name].get('backup', True), 'replicate': True,
                 'acl': False, 'quota': False, 'read_only': False, 'shared': False, 'mount_options': []}
                for index, name in enumerate(cfg['guest']['volume_order'])]

    def seed(self, cfg, site, work, operation, expected, **kwargs):
        """Complete the fixture infrastructure writer with normalized owned mount state."""
        result = self.fixture.infrastructure(cfg, site, work, operation, expected, **kwargs)
        state = read_json(work/'terraform.tfstate', private=True)
        state['resources'][0]['instances'][0]['attributes']['mount_point'] = self.allocated(cfg)
        write_bytes(work/'terraform.tfstate', encoded(state)); result['state_sha256'] = sha(work/'terraform.tfstate')
        return result

    def ordinary(self):
        """Execute every ordinary deployment phase through the actual attempt machinery."""
        return [deploy.run(phase, self.fixture.packet, inputs=self.fixture.inputs, environment={})
                for phase in ['infrastructure', *self.cfg['deployment']['phases']]]

    def prepare_prior(self, data):
        """Earn and preserve a genuine fixture success before selecting enrollment."""
        self.publish(backup=False, data=data)
        with patch.object(proxmox_guest, 'infrastructure', side_effect=self.seed): self.ordinary()
        self.previous = read_json(self.work/'ordinary-complete.json', private=True)
        self.canonical = (self.work/'ordinary-complete.json').read_bytes()
        self.old_backend = (self.work/'terraform.tfstate').read_bytes()
        self.old_operation = Path(self.previous['operation'])
        self.history = {p: (p.stat().st_ino, p.read_bytes()) for p in self.old_operation.iterdir() if p.is_file()}
        self.publish(backup=True, data=data)

    def plan(self):
        """Return fictional CREATE or refreshed no-op plans for the selected packet."""
        if not (self.work/'terraform.tfstate').exists():
            value = fresh_plan()
            for row in value['resource_changes']:
                row['change']['after']['node_name'] = self.cfg['site']['node']
                row['change']['after']['vm_id' if row['address'] == GUEST_RESOURCE else 'container_id'] = 610
            change = value['resource_changes'][0]['change']
            change['after']['mount_point'] = self.allocated(self.cfg)
            for row in change['after']['mount_point']:
                row['volume'] = 'local-zfs'; row.pop('path_in_datastore')
            change['after_unknown'] = {'mount_point': [{'path_in_datastore': True} for row in change['after']['mount_point']]}
            return value
        state = read_json(self.work/'terraform.tfstate', private=True)
        rows = []
        for native in state['resources']:
            address = '.'.join(native[k] for k in ('module', 'type', 'name'))
            before = copy.deepcopy(native['instances'][0]['attributes']); after = copy.deepcopy(before)
            if address == GUEST_RESOURCE: after['mount_point'] = self.allocated(self.cfg)
            rows.append({'address': address, 'type': native['type'], 'mode': 'managed',
                         'change': {'before': after, 'after': copy.deepcopy(after), 'actions': ['no-op']}})
            if address == GUEST_RESOURCE:
                drift = copy.deepcopy(rows[-1]); drift['change'].update(before=before, after=after, actions=['update'])
        value = {'resource_changes': rows}
        if drift['change']['before'] != drift['change']['after']: value['resource_drift'] = [drift]
        return value

    def tofu(self, argv, environment, log):
        """Simulate saved-plan and state writes without invoking a provider or target."""
        if 'plan' in argv: write_new(log.parent/'guest.tfplan', b'fictional saved provider plan')
        if 'apply' in argv:
            self.applies.append(log.parent.name)
            if (self.work/'terraform.tfstate').exists():
                state = read_json(self.work/'terraform.tfstate', private=True)
            else:
                state = {'version': 4, 'lineage': 'synthetic-owned-lineage', 'serial': 0, 'resources': []}
                for row in self.plan()['resource_changes']:
                    module, kind, name = row['address'].rsplit('.', 2)
                    attrs = copy.deepcopy(row['change']['after']); attrs['id'] = 'fixture-'+kind+'-'+name
                    state['resources'].append({'module': module, 'type': kind, 'name': name, 'mode': 'managed',
                                               'instances': [{'attributes': attrs}]})
            state['serial'] += 1
            state['resources'][0]['instances'][0]['attributes']['mount_point'] = self.allocated(self.cfg)
            write_bytes(self.work/'terraform.tfstate', encoded(state))

    def api(self, path):
        """Serve only the fixed synthetic storage, volume-info and active-config reads."""
        self.remote.append(path)
        mounts = self.allocated(self.cfg)
        if path.endswith('/config?current=1'):
            value = {'rootfs': 'local-zfs:subvol-610-disk-0,size=8G', 'digest': 'fictional'}
            value.update({'mp'+str(i): row['volume']+',mp='+row['path']+',size='+row['size']+
                          ',backup='+str(int(row['backup'])) for i, row in enumerate(mounts)})
            if self.failure == 'api': value['mp'+str(len(mounts)-1)] += ',shared=1'
            return value
        if path == '/storage?type=zfspool':
            return [{'storage': 'local-zfs', 'type': 'lvmthin' if self.failure == 'pool' else 'zfspool', 'pool': 'rpool/data'}]
        self.assertIn('/content/local-zfs%3Asubvol-610-disk-', path)
        row = mounts[-1]
        return {'format': 'subvol', 'path': '/rpool/data/'+row['volume'].split(':')[1],
                'size': self.cfg['app']['backup']['job']['staging']['size_bytes']}

    def ssh(self, argv, environment, target, **kwargs):
        """Emit a closed fictional proof while checking the exact mounted-probe command."""
        self.assertEqual(kwargs['input_bytes'], backup_staging.MOUNTED_SCRIPT)
        first = argv[-1].endswith(' true')
        source = 'rpool/data/'+self.allocated(self.cfg)[-1]['volume'].split(':')[1]
        value = {'device': [0, 17 if target.name.endswith('before.json') else 29],
                 'inode': 34, 'uid': 0, 'gid': 0, 'mode': 0o755, 'mtime_ns': 101, 'ctime_ns': 102,
                 'mount_id': 55 if target.name.endswith('before.json') else 88,
                 'bytes': self.cfg['app']['backup']['job']['staging']['size_bytes'],
                 'source': hashlib.sha256(source.encode()).hexdigest()}
        if self.failure == 'after' and target.name.endswith('after.json'): value['inode'] += 1
        write_new(target, encoded(value))
        self.probes.append((target.name, first))

    def ansible(self, argv, environment, log):
        """Fake PBS configuration while delegating other local fixture app phases."""
        if log.parent.name != 'pbs-agent': return self.fixture.ansible(argv, environment, log)
        write_new(log, b'example: ok=1 changed=0 failed=0\n')

    def boundaries(self):
        """Replace native work while retaining real compiler, policy and ownership readers."""
        from contextlib import ExitStack
        stack = ExitStack(); self.addCleanup(stack.close)
        for target, values in [
            ('proxmox_guest.infrastructure', {'side_effect': INFRASTRUCTURE}),
            ('proxmox_guest.quiet', {'side_effect': self.tofu}),
            ('proxmox_guest.subprocess.check_output', {'side_effect': lambda *a, **k: encoded(self.plan())}),
            ('proxmox_guest.api_get', {'side_effect': lambda cfg, path: self.api(path)}),
            ('proxmox_guest.backup', {}), ('proxmox_guest.host_devices.check', {}),
            ('proxmox_guest.host_devices.attach', {'return_value': False}),
            ('proxmox_guest.guest_identity.pin', {}),
            ('backup_staging.quiet', {'side_effect': self.ssh}),
            ('component_ansible.quiet', {'side_effect': self.ansible})]:
            stack.enter_context(patch(target, **values))
        self.probes = []
        return stack

    def test_empty_prior_mount_first_enrollment_then_owned_nonempty_repeat(self):
        """Enroll from an empty prior mount list and admit a later owned repeat."""
        self.progression(False)

    def test_preserved_data_mount_and_order_first_enrollment_then_repeat(self):
        """Preserve retained data mounts and their order across enrollment and repeat."""
        self.progression(True)

    def test_valid_fresh_allocation_verifies_after_creation_then_owned_repeat(self):
        """Verify a fresh allocated stage after creation and retain ownership on repeat."""
        self.publish(backup=True, data=False)
        with self.boundaries():
            self.ordinary()
            self.assertEqual(self.probes, [('backup-staging-after.json', True)])
            self.assertEqual(len(self.applies), 1)
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '102', 'GITHUB_RUN_NUMBER': '11'}): self.ordinary()
            self.assertEqual(len(self.applies), 1)
            self.assertEqual(self.probes[-2:], [('backup-staging-before.json', False), ('backup-staging-after.json', False)])
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())

    def test_unsupported_pool_refuses_fresh_before_creation_or_apply(self):
        """Refuse unsupported fresh staging storage before resource creation or apply."""
        self.publish(backup=True, data=False); self.failure = 'pool'
        with self.boundaries():
            with self.assertRaises(ValueError): deploy.run('infrastructure', self.fixture.packet, inputs=self.fixture.inputs)
        self.assertFalse((self.work/'terraform.tfstate').exists())
        self.assertEqual(self.applies, [])
        self.assertEqual(self.probes, [])

    def test_unsupported_pool_refuses_existing_before_apply(self):
        """Refuse unsupported retained staging storage without applying a plan."""
        self.failure_case('pool', expected_applies=0)

    def test_backup_bit_only_reconciliation_has_current_operational_proof_then_noop(self):
        """Commit backup-bit-only drift with active stage proof and then admit no-op repeat."""
        self.prepare_prior(True)
        with self.boundaries(), patch.dict(os.environ, {'GITHUB_RUN_ID': '102', 'GITHUB_RUN_NUMBER': '11'}):
            self.ordinary()
            identities = [row['volume'] for row in self.allocated(self.cfg)]
            self.publish(backup=True, data=True, protect_data=False)
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '103', 'GITHUB_RUN_NUMBER': '12'}): self.ordinary()
            self.assertEqual([row['volume'] for row in self.allocated(self.cfg)], identities)
            self.assertFalse(self.allocated(self.cfg)[0]['backup'])
            self.assertEqual(len(self.applies), 2)
            self.assertEqual(self.probes[-2:], [('backup-staging-before.json', False), ('backup-staging-after.json', False)])
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '104', 'GITHUB_RUN_NUMBER': '13'}): self.ordinary()
            self.assertEqual(len(self.applies), 2)

    def test_backup_bit_drift_without_operational_job_retains_prior_refusal(self):
        """Refuse backup-bit drift without broadening the no-job runtime contract."""
        self.prepare_prior(True)
        self.publish(backup=True, data=True, job=False, protect_data=False)
        with self.boundaries(), patch.dict(os.environ, {'GITHUB_RUN_ID': '102', 'GITHUB_RUN_NUMBER': '11'}):
            with self.assertRaisesRegex(ValueError, 'Preserve owned resource identities'):
                deploy.run('infrastructure', self.fixture.packet, inputs=self.fixture.inputs)
        self.assertEqual(self.remote, []); self.assertEqual(self.applies, [])
        self.assertEqual((self.work/'terraform.tfstate').read_bytes(), self.old_backend)
        self.assertEqual((self.work/'ordinary-complete.json').read_bytes(), self.canonical)

    def progression(self, data):
        """Check state-only enrollment success, immutable old evidence and a later repeat."""
        self.prepare_prior(data)
        with self.boundaries(), patch.dict(os.environ, {'GITHUB_RUN_ID': '102', 'GITHUB_RUN_NUMBER': '11'}):
            self.ordinary()
            self.assertEqual(len(self.applies), 1)
            new = read_json(self.work/'ordinary-complete.json', private=True)
            self.assertNotEqual(new['state_sha256'], self.previous['state_sha256'])
            self.assertEqual((self.old_operation/'complete.json').read_bytes(), self.canonical)
            self.assertEqual(self.probes, [('backup-staging-before.json', True), ('backup-staging-after.json', True)])
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '103', 'GITHUB_RUN_NUMBER': '12'}): self.ordinary()
            self.assertEqual(len(self.applies), 1, 'owned no-op repeat must not apply again')
            self.assertEqual(self.probes[-2:], [('backup-staging-before.json', False), ('backup-staging-after.json', False)])
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
        self.assertEqual(self.history, {p: (p.stat().st_ino, p.read_bytes()) for p in self.history})

    def test_failed_first_identity_check_retains_canonical_state_hold_and_no_apply(self):
        """Retain the prior canonical generation and HOLD when pre-apply identity fails."""
        self.failure_case('api', expected_applies=0)

    def test_failed_post_apply_identity_retains_hold_and_never_fabricates_success(self):
        """Preserve failed evidence without a success receipt after post-apply mismatch."""
        self.failure_case('after', expected_applies=1)

    def failure_case(self, failure, expected_applies):
        """Exercise a controlled failure with real attempt and receipt preservation."""
        self.prepare_prior(True); self.failure = failure
        with self.boundaries(), patch.dict(os.environ, {'GITHUB_RUN_ID': '102', 'GITHUB_RUN_NUMBER': '11'}):
            with self.assertRaises(ValueError): deploy.run('infrastructure', self.fixture.packet, inputs=self.fixture.inputs)
            hold = (self.work/'ORDINARY-HOLD.json').read_bytes()
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '103', 'GITHUB_RUN_NUMBER': '12'}):
                before = len(self.remote)
                with self.assertRaises(ValueError): deploy.run('infrastructure', self.fixture.packet, inputs=self.fixture.inputs)
                self.assertEqual(len(self.remote), before)
            self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(), hold)
        self.assertEqual(len(self.applies), expected_applies)
        self.assertEqual((self.work/'ordinary-complete.json').read_bytes(), self.canonical)
        self.assertFalse((self.work/'ordinary-102-1/infrastructure-complete.json').exists())
        self.assertFalse((self.work/'ordinary-102-1/complete.json').exists())
        if not expected_applies: self.assertEqual((self.work/'terraform.tfstate').read_bytes(), self.old_backend)


if __name__ == '__main__': unittest.main()
