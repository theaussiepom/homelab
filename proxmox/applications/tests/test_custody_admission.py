"""Qualified completed groups and evolving ordinary generations, without targets."""

import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import coordinated_contract as contract
import coordinated_evidence as evidence
import coordinated_generation as generation
import custody_records as records
import deployment_inputs as inputs
import deployment_state as state
import deploy
import private_io as io
import proxmox_guest as pve
from fixtures import github_source
from custody_fixtures import CompletedGroup, save, backend


class AdmissionTests(unittest.TestCase):
    def fixture(self, postgres=False):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        value = CompletedGroup(td.name, postgres=postgres)
        mount = patch.object(records.os.path, 'ismount', return_value=True)
        findmnt = patch.object(records.subprocess, 'check_output', return_value='nfs4 nas.example.invalid:/backups\n')
        mount.start(); findmnt.start()
        self.addCleanup(mount.stop); self.addCleanup(findmnt.stop)
        return value

    def runtime(self, value, role='mariadb'):
        cfg, site, work = value.cfgs[role], value.site(role), value.work(role)
        source, revisions = github_source(value.root)
        context = patch.dict(os.environ, {
            'GITHUB_RUN_ID': '777', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_NUMBER': '777',
            'GITHUB_REPOSITORY': 'example/private-site',
            'HOMELAB_DEPLOYMENT_WORKFLOW': 'example/private-site/.github/workflows/deploy.yml@refs/heads/main',
            'GITHUB_SHA': revisions[0], 'GITHUB_WORKSPACE': str(source),
        })
        context.start(); self.addCleanup(context.stop)
        # Only packet transport and native executors are substituted. Evidence,
        # binding, filesystem admission, real local key lookup and receipts run.
        preparation = patch.object(inputs, 'prepare', return_value=(cfg, site))
        source_hash = patch.object(inputs, 'source_hash', return_value='7' * 64)
        preparation.start(); source_hash.start()
        self.addCleanup(preparation.stop); self.addCleanup(source_hash.stop)
        def infrastructure(*args, **kwargs):
            self.assertEqual(kwargs['state_identity'], generation.backend(work, value.group['members'][role])[1])
            body = records.decode((work / 'terraform.tfstate').read_bytes())
            body['serial'] += 1
            save(work / 'terraform.tfstate', body)
            return {'changed': True, 'created': False, 'state_sha256': io.sha(work / 'terraform.tfstate')}
        infra = patch.object(pve, 'infrastructure', side_effect=infrastructure)
        ansible = patch.object(deploy.ansible_guest, 'run_phase', return_value={'status': 'passed', 'changed': False})
        i, a = infra.start(), ansible.start()
        self.addCleanup(infra.stop); self.addCleanup(ansible.stop)
        return SimpleNamespace(cfg=cfg, site=site, work=work, revisions=revisions, infra=i, app=a)

    def all_phases(self, runtime):
        import guest_contract
        for phase in ['infrastructure', *guest_contract.phases(runtime.cfg)]:
            deploy.run(phase, runtime.site)

    def test_complete_local_and_nas_provenance_includes_disabled_members(self):
        value = self.fixture(postgres=True)
        contract.configured_closure(value.resolved())
        for role, cfg in value.cfgs.items():
            proofs, lineage, baseline = evidence.inspect(cfg)
            self.assertEqual(lineage, f"fixture-{cfg['guest']['vmid']}")
            self.assertEqual(baseline is None, role == 'postgresql')
            self.assertIn(str(value.work('db-tools') / 'plan.json'), proofs)
            self.assertIn(str(value.remote / 'complete.json'), proofs)
        for variant in ('missing', 'changed', 'missing-proof', 'changed-proof'):
            resolved = copy.deepcopy(value.resolved())
            if variant == 'missing': resolved.pop('db-tools')
            if variant == 'changed': resolved['db-tools'][0]['coordinated_custody']['group']['members']['db-tools']['initial_state_sha256'] = '4' * 64
            if variant == 'missing-proof': resolved['db-tools'][2].pop('acceptance.json')
            if variant == 'changed-proof': resolved['db-tools'][2]['acceptance.json'] += ' '
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                contract.configured_closure(resolved)
        cfg = value.cfgs['postgresql']
        path = value.work('db-tools') / 'plan.json'
        old = path.read_bytes(); save(path, old + b' ')
        with self.assertRaisesRegex(ValueError, 'original installation record'):
            evidence.inspect(cfg)

    def test_exact_legacy_anchor_runs_new_phases_and_three_future_generations_advance(self):
        for role in ('mariadb', 'identity', 'db-tools'):
            value = self.fixture(postgres=role != 'mariadb')
            # check_output is shared by modules: route only findmnt to its fixture.
            real = subprocess.run
            def output(argv, **kwargs):
                if argv[0] == 'findmnt': return 'nfs4 nas.example.invalid:/backups\n'
                return real(argv, check=True, stdout=subprocess.PIPE, **kwargs).stdout
            with patch.object(subprocess, 'check_output', side_effect=output):
                runtime = self.runtime(value, role)
                originals = {str(p): p.read_bytes() for p in value.state.rglob('*.json')}
                first_overlay = value.group['members'][role]['overlay']['sha256']
                for number in (777, 778, 779):
                    with patch.dict(os.environ, {'GITHUB_RUN_ID': str(number), 'GITHUB_RUN_NUMBER': str(number),
                                                 'GITHUB_SHA': runtime.revisions[0 if number == 777 else 1]}):
                        self.all_phases(runtime)
                        receipt = records.decode((runtime.work / 'ordinary-complete.json').read_bytes())
                        self.assertEqual(receipt['run_number'], number)
                        self.assertEqual(receipt['state_sha256'], io.sha(runtime.work / 'terraform.tfstate'))
                        self.assertEqual((Path(receipt['operation']) / 'complete.json').read_bytes(), (runtime.work / 'ordinary-complete.json').read_bytes())
                        self.assertFalse(deploy.run('infrastructure', runtime.site)['target_contacted'])
                self.assertEqual(runtime.infra.call_count, 3)
                self.assertEqual(first_overlay, value.group['members'][role]['overlay']['sha256'])
                for path, raw in originals.items():
                    if Path(path).name != 'ordinary-complete.json': self.assertEqual(Path(path).read_bytes(), raw)

    def test_unproven_backend_or_receipt_cannot_fall_back_to_initial_anchor(self):
        for variant in ('state', 'absent', 'foreign', 'malformed', 'baseline-copy'):
            value = self.fixture(postgres=True)
            cfg, role = value.cfgs['identity'], 'identity'
            work = value.work(role)
            if variant == 'state': save(work / 'terraform.tfstate', backend(809, 4))
            if variant == 'absent': (work / 'ordinary-complete.json').unlink()
            if variant == 'foreign': save(work / 'ordinary-complete.json', {'status': 'passed', 'binding': {}})
            if variant == 'malformed': save(work / 'ordinary-complete.json', b'{')
            if variant == 'baseline-copy': save(work / 'ordinary-100-1/complete.json', b'changed')
            with self.subTest(variant=variant), self.assertRaises((ValueError, OSError)):
                # Baseline-copy fails immutable inspection before classification.
                proofs, lineage, baseline = evidence.inspect(cfg)
                attempt = self.attempt(value, role, proofs)
                generation.classify(attempt, value.group['members'][role], lineage, baseline)

    def attempt(self, value, role, proofs=None):
        cfg = value.cfgs[role]
        work = value.work(role)
        attempt = state.DeploymentAttempt(cfg, {'vmid': cfg['guest']['vmid'], 'input_hashes': proofs or {},
                                               'coordinated_custody_sha256': contract.selection_digest(cfg)}, ['preparation', 'test'])
        def select():
            attempt.workflow = ['example/private-site', 'example/private-site/.github/workflows/deploy.yml']
            attempt.operation = work / 'ordinary-777-1'
            attempt.marker = {'binding': attempt.binding, 'operation': str(attempt.operation)}
            if hasattr(attempt, 'previous_ordinary_sha256'):
                attempt.marker['previous_ordinary_sha256'] = attempt.previous_ordinary_sha256
        attempt._select_run = select
        return attempt

    def test_latest_success_prevents_pointer_rollback_and_changed_or_uncommitted_history(self):
        for variant in ('old-anchor', 'old-success', 'missing-pointer', 'foreign-history', 'failed-history', 'duplicate-run', 'orphan', 'changed-state', 'changed-copy', 'operation-escape', 'wrong-identity'):
            value = self.fixture()
            cfg = value.cfgs['mariadb']; work = value.work('mariadb')
            attempt = self.attempt(value, 'mariadb')
            state_hash, identity = generation.backend(work, value.group['members']['mariadb'])
            def receipt(number):
                path = work / f'ordinary-{number}-1'
                v = {'status': 'passed', 'binding': attempt.binding, 'state_sha256': state_hash,
                     'state_identity': identity, 'result': {}, 'workflow': ['example/private-site', 'example/private-site/.github/workflows/deploy.yml'],
                     'run_number': number, 'site_revision': 'a' * 40, 'operation': str(path)}
                save(path / 'complete.json', v)
                return io.encoded(v)
            old = receipt(770); latest = receipt(771)
            save(work / 'ordinary-complete.json', latest)
            if variant == 'old-anchor': (work / 'ordinary-complete.json').unlink()
            if variant == 'old-success': save(work / 'ordinary-complete.json', old)
            if variant == 'missing-pointer': (work / 'ordinary-complete.json').unlink()
            if variant == 'foreign-history':
                v = records.decode(latest); v['binding']['coordinated_custody_sha256'] = '0' * 64; save(work / 'ordinary-771-1/complete.json', v)
            if variant == 'failed-history':
                v = records.decode(latest); v['status'] = 'failed'; save(work / 'ordinary-771-1/complete.json', v)
            if variant == 'duplicate-run':
                v = records.decode(latest); v['operation'] = str(work / 'ordinary-772-1'); save(work / 'ordinary-772-1/complete.json', v)
            if variant == 'orphan': (work / 'ordinary-772-1').mkdir(mode=0o700)
            if variant == 'changed-state': save(work / 'terraform.tfstate', backend(808, 3))
            if variant == 'changed-copy': save(work / 'ordinary-complete.json', latest + b' ')
            if variant in ('operation-escape', 'wrong-identity'):
                # Without any later history the canonical value must still prove
                # its own immutable copy and exact identity; no fallback exists.
                for name in ('ordinary-770-1', 'ordinary-771-1'):
                    (work / name / 'complete.json').unlink(); (work / name).rmdir()
                v = records.decode(latest)
                if variant == 'operation-escape': v['operation'] = str(value.root / 'ordinary-771-1')
                else:
                    v['state_identity']['lineage'] = 'foreign'; save(work / 'ordinary-771-1/complete.json', v)
                save(work / 'ordinary-complete.json', v)
            with self.subTest(variant=variant), self.assertRaises((OSError, ValueError)):
                generation.classify(attempt, value.group['members']['mariadb'], 'fixture-808', None)

    def test_own_continuation_requires_exact_predecessor_ready_identity_and_receipt_check(self):
        value = self.fixture(); member = value.group['members']['mariadb']
        attempt = self.attempt(value, 'mariadb')
        attempt.custody_identity = generation.classify(attempt, member, 'fixture-808', None)
        with self.assertRaisesRegex(ValueError, 'receipt provenance'): attempt.begin_infrastructure()
        with self.assertRaisesRegex(ValueError, 'receipt provenance'): attempt.begin_phase('preparation')
        self.assertFalse(attempt.completed(lambda *a: True))
        attempt.begin_infrastructure()
        result = {'changed': False, 'state_sha256': io.sha(attempt.work / 'terraform.tfstate')}
        attempt.infrastructure_complete(result)
        hold = attempt.hold.read_bytes(); ready = (attempt.operation / 'infrastructure-complete.json').read_bytes()
        for variant in ('valid', 'foreign-hold', 'bad-hold', 'ready', 'complete-pending', 'lineage'):
            save(attempt.hold, hold); save(attempt.operation / 'infrastructure-complete.json', ready)
            save(attempt.work / 'terraform.tfstate', backend(808))
            if variant == 'foreign-hold': save(attempt.hold, {'previous_ordinary_sha256': 'f' * 64})
            if variant == 'bad-hold': save(attempt.hold, [])
            if variant == 'ready': save(attempt.operation / 'infrastructure-complete.json', {'binding': {}})
            if variant == 'complete-pending': save(attempt.operation / 'complete.json', {})
            if variant == 'lineage':
                body = backend(808); body['lineage'] = 'changed'; save(attempt.work / 'terraform.tfstate', body)
            next_attempt = self.attempt(value, 'mariadb')
            if variant == 'valid':
                self.assertEqual(generation.classify(next_attempt, member, 'fixture-808', None), attempt.custody_identity or generation.backend(attempt.work, member)[1])
            else:
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    generation.classify(next_attempt, member, 'fixture-808', None)
            if variant == 'complete-pending': (attempt.operation / 'complete.json').unlink()
        attempt.custody_identity = generation.backend(attempt.work, member)[1]
        with self.assertRaisesRegex(ValueError, 'applied backend'):
            attempt.infrastructure_complete(dict(result, state_sha256='f' * 64))

    def test_snapshot_and_mount_refuse_unsafe_or_changed_evidence_without_writes(self):
        value = self.fixture(); path = value.root / 'private.json'; save(path, {'safe': True})
        snapshot = records.Snapshot(); raw = snapshot.read(path); snapshot.finish()
        save(path, raw + b' ')
        with self.assertRaisesRegex(ValueError, 'bytes changed'): snapshot.finish()
        directory = value.root / 'race'; directory.mkdir(mode=0o700); save(directory / 'proof', raw)
        snapshot = records.Snapshot(); snapshot.read(directory / 'proof'); directory.rename(value.root / 'retained'); directory.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'directory or mount changed'): snapshot.finish()
        for variant in ('mode', 'symlink', 'parent-symlink', 'large', 'fifo', 'relative', 'traversal'):
            save(path, raw)
            target = path
            if variant == 'mode': path.chmod(0o644)
            if variant == 'symlink': target = value.root / 'link'; target.symlink_to(path)
            if variant == 'parent-symlink': target = value.root / 'parent-link' / 'proof'; target.parent.symlink_to(value.root / 'retained')
            if variant == 'large': save(path, b'x' * (records.LIMIT + 1))
            if variant == 'fifo': target = value.root / 'fifo'; os.mkfifo(target, 0o600)
            if variant == 'relative': target = Path('relative')
            if variant == 'traversal': target = value.root / '..' / 'private.json'
            with self.subTest(variant=variant), self.assertRaises((OSError, ValueError)):
                records.read_existing(target)
        with patch.object(records.os.path, 'ismount', return_value=False), self.assertRaises(ValueError): records.recovery(value.cfgs['mariadb'])
        for output in ('ext4 /dev/sda', 'nfs4 foreign:/backups', ''):
            with patch.object(records.subprocess, 'check_output', return_value=output), self.assertRaises(ValueError): records.recovery(value.cfgs['mariadb'])
        with self.assertRaises(ValueError): records.decode(b'{"duplicate":1,"duplicate":2}')
        with self.assertRaises(ValueError): records.decode(b'{')

    def test_pending_and_hidden_markers_remain_holds_in_local_nas_nested_and_bootstrap(self):
        value = self.fixture(); cfg = value.cfgs['mariadb']
        for folder in (value.local, value.remote, value.work('mariadb')):
            for name in ('HOLD.json', '.SERVICE-VERIFYING.json', 'ordinary-complete.json.pending', '.ORDINARY-HOLD.json.pending'):
                marker = folder / name; save(marker, {})
                with self.subTest(folder=folder, name=name), self.assertRaises(ValueError):
                    if folder == value.work('mariadb'): records.no_markers(folder, own_ordinary=True)
                    else: evidence.inspect(cfg)
                marker.unlink()
        bootstrap = value.root / 'bootstrap'; bootstrap.mkdir(mode=0o700)
        state.bootstrap_closed(bootstrap)
        for name in ('CONFIGURING', '.CONFIGURING.pending', 'HOLD.json'):
            save(bootstrap / name, {})
            with self.assertRaises(ValueError): state.bootstrap_closed(bootstrap)
            (bootstrap / name).unlink()
        bootstrap.rmdir(); bootstrap.symlink_to(value.root)
        with self.assertRaises(ValueError): state.bootstrap_closed(bootstrap)

    def test_closed_selection_refuses_unknown_waivers_and_missing_initial_disposition(self):
        value = self.fixture(postgres=True); cfg = value.cfgs['postgresql']
        mutations = [
            lambda c: c['coordinated_custody'].update(writers_fenced=True),
            lambda c: c['coordinated_custody'].update(schema='unknown'),
            lambda c: c['coordinated_custody']['group'].update(schema=[]),
            lambda c: c['coordinated_custody']['group'].update(operation='foreign'),
            lambda c: c['coordinated_custody']['group'].update(directory=[]),
            lambda c: c['coordinated_custody']['group']['records'].update(**{'claim.json': '0' * 64}),
            lambda c: c['coordinated_custody']['group']['catalogue'].update(file='../escape'),
            lambda c: c['coordinated_custody']['group']['acceptance'].update(file='catalogue.json'),
            lambda c: c['coordinated_custody']['group']['recovery'].update(directory='/elsewhere'),
            lambda c: c['coordinated_custody']['group']['members']['identity'].update(vmid=808),
            lambda c: c['coordinated_custody']['group']['members']['identity'].update(node=''),
            lambda c: c['coordinated_custody']['group']['members']['identity'].update(installed_site='/x/../y'),
            lambda c: c['coordinated_custody']['group']['members']['identity']['initial_ordinary'].update(operation='ordinary-0-1'),
            lambda c: c['coordinated_custody']['group']['members']['identity']['overlay'].update(directory='arbitrary'),
            lambda c: c['coordinated_custody']['group']['members']['postgresql'].pop('initial_ordinary'),
            lambda c: c['guest'].update(vmid=811),
            lambda c: c['paths'].update(backup_source='elsewhere'),
            lambda c: c['paths'].pop('coordinated_custody_inputs'),
            lambda c: c['coordinated_custody']['group']['records'].update(**{'request.json': 'x'}),
        ]
        for mutate in mutations:
            candidate = copy.deepcopy(cfg); mutate(candidate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): contract.selection(candidate)
        cfg = copy.deepcopy(cfg); cfg.pop('coordinated_custody')
        with self.assertRaises(ValueError): contract.selection(cfg)

    def test_backend_projection_refuses_wrong_id_shape_node_and_plan_identity(self):
        value = self.fixture(); work = value.work('mariadb'); member = value.group['members']['mariadb']
        good = backend(808)
        for mutate in (
            lambda v: v.update(version=3), lambda v: v.update(serial=True), lambda v: v.update(lineage=''),
            lambda v: v['resources'].pop(), lambda v: v['resources'][0].update(mode='data'),
            lambda v: v['resources'][0].update(module='foreign'),
            lambda v: v['resources'][0]['instances'].append({}),
            lambda v: v['resources'][0]['instances'][0].update(deposed='old'),
            lambda v: v['resources'][0]['instances'][0]['attributes'].update(vm_id=809),
            lambda v: v['resources'][0]['instances'][0]['attributes'].update(node_name='foreign'),
            lambda v: v['resources'][0]['instances'][0]['attributes'].update(id=''),
        ):
            bad = copy.deepcopy(good); mutate(bad); save(work / 'terraform.tfstate', bad)
            with self.assertRaises(ValueError): generation.backend(work, member)
        save(work / 'terraform.tfstate', good)
        _, identity = generation.backend(work, member)
        plan = {'resource_changes': [{'address': a, 'change': {'before': {'id': row['id']}, 'after': {'id': row['id']}}} for a, row in identity['resources'].items()]}
        generation.plan_identity(plan, identity)
        for side in ('before', 'after', 'after_unknown'):
            bad = copy.deepcopy(plan)
            if side == 'after_unknown': bad['resource_changes'][0]['change'][side] = {'id': True}
            else: bad['resource_changes'][0]['change'][side]['id'] = 'foreign'
            with self.assertRaises(ValueError): generation.plan_identity(bad, identity)

    def test_packet_proofs_are_checked_before_materialization_and_cannot_escape_its_directory(self):
        value = self.fixture(); cfg = value.cfgs['mariadb']
        identity = '8' * 64
        destination = value.root / 'fresh-inputs' / 'mariadb' / identity
        cfg['paths']['coordinated_custody_inputs'] = str(destination)
        packet = {'schema': deploy.guest_contract.SCHEMA, 'kind': 'mariadb', 'enabled': True,
                  'identity': identity, 'files': dict(value.files(), **{'site.json': io.encoded(cfg).decode()})}
        path = value.root / 'packet.json'
        for variant in ('missing-proof', 'changed-proof', 'wrong-directory', 'valid'):
            v = copy.deepcopy(packet)
            if variant == 'missing-proof': v['files'].pop('acceptance.json')
            if variant == 'changed-proof': v['files']['catalogue.json'] += ' '
            if variant == 'wrong-directory':
                c = copy.deepcopy(cfg); c['paths']['coordinated_custody_inputs'] = str(value.root / 'elsewhere')
                v['files']['site.json'] = io.encoded(c).decode()
            save(path, v)
            if variant == 'valid':
                observed, site = inputs.prepare(path, value.root / 'fresh-inputs')
                self.assertEqual(observed, cfg); self.assertEqual(site, destination / 'site.json')
                self.assertEqual((destination / 'acceptance.json').read_bytes(), value.acceptance_raw)
            else:
                with self.subTest(variant=variant), self.assertRaises(ValueError): inputs.prepare(path, value.root / 'fresh-inputs')
                self.assertFalse(destination.exists())

    def test_plan_identity_is_enforced_before_apply_and_missing_trust_is_never_created(self):
        from test_plan import existing_fixture
        value = self.fixture(); cfg = value.cfgs['mariadb']; work = value.work('mariadb')
        trust = work / 'ssh-trust.json'; trust.unlink()
        with self.assertRaisesRegex(ValueError, 'existing commissioned guest trust'):
            pve.guest_trust(cfg, work, persist=False)
        self.assertFalse(trust.exists())
        cfg['site']['node'] = 'pve-lab'; cfg['guest']['vmid'] = cfg['app']['vmid'] = 6100
        save(value.root / 'api', b'fixture@pve!deploy=synthetic')
        plan = existing_fixture()
        for row in plan['resource_changes']:
            row['change']['before']['id'] = row['change']['after']['id'] = 'original'
        identity = {'resources': {r['address']: {'id': 'foreign'} for r in plan['resource_changes']}}
        operation = value.root / 'attempt'; operation.mkdir(mode=0o700)
        def quiet(argv, env, log):
            self.assertNotIn('apply', argv)
            if 'plan' in argv: save(operation / 'guest.tfplan', b'fixture plan')
        with patch.object(inputs, 'binding', return_value={}), patch.object(pve, 'backup'), \
             patch.object(pve, 'quiet', side_effect=quiet) as command, \
             patch.object(pve.subprocess, 'check_output', return_value=io.encoded(plan)), \
             self.assertRaisesRegex(ValueError, 'admitted backend resource ID'):
            pve.infrastructure(cfg, value.root / 'site', work, operation, {}, state_identity=identity)
        self.assertTrue(command.called)
        self.assertFalse((operation / 'apply-window.json').exists())

    def test_actual_dependency_cases_keep_all_configured_copies_and_only_enable_valid_subsets(self):
        import importlib.util
        path = Path(__file__).resolve().parents[3] / 'blueprints/compile.py'
        spec = importlib.util.spec_from_file_location('custody_blueprints', path)
        compiler = importlib.util.module_from_spec(spec); spec.loader.exec_module(compiler)
        value = self.fixture(postgres=True)
        deps = {'dns': [], 'ingress': ['dns'], 'postgresql': ['dns'], 'mariadb': ['dns'], 'influxdb': ['dns'],
                'identity': ['postgresql', 'ingress'], 'db-tools': ['postgresql', 'ingress', 'identity'],
                'automation': ['ingress', 'identity', 'mariadb', 'influxdb'], 'bitwarden': ['ingress', 'mariadb'],
                'pegaprox': ['dns'], 'zigbee2mqtt': ['automation']}
        manifest = {'guests': {r: {'depends_on': d, 'prerequisites': []} for r, d in deps.items()}, 'routes': {}, 'values': {}}
        resolved = value.resolved()
        for index, role in enumerate(deps):
            if role not in resolved: resolved[role] = ({'guest': {'vmid': 6000 + index}}, {}, {})
        for role in value.roles: resolved[role] = (resolved[role][0], {}, resolved[role][2])
        overlay = {'schema': 'homelab-site-v3', 'routes': {}, 'values': {}, 'common': {}, 'guests': {}, 'images': {}, 'accepted': {}}
        def compile_guest(name, cfg, stack, files, enabled):
            return cfg, {'enabled': name in enabled}
        cases = [(None, 11), (['db-tools'], 10), (['identity'], None), (['identity', 'db-tools'], None),
                 (['identity', 'automation'], None), (['identity', 'db-tools', 'automation'], None),
                 (['identity', 'db-tools', 'automation', 'zigbee2mqtt'], 7), (['pegaprox'], 10),
                 (['bitwarden'], 10), (['dns'], None)]
        with patch.object(compiler, 'manifest', return_value=manifest), \
             patch.object(compiler, '_resolve_guest', side_effect=lambda root, overlay, name, spec: resolved[name]), \
             patch.object(compiler, '_compile_guest', side_effect=compile_guest), \
             patch.object(compiler.routes, 'bind', return_value={}), patch.object(compiler.service_bindings, 'bind'), \
             patch.object(compiler.connections, 'validate'):
            for disabled, expected in cases:
                with self.subTest(disabled=disabled):
                    if expected is None:
                        with self.assertRaises(ValueError): compiler.compile_stack(value.root, overlay, disabled)
                    else:
                        packets = compiler.compile_stack(value.root, overlay, disabled)
                        self.assertEqual(len(packets), 11)
                        self.assertEqual(sum(p['enabled'] for p in packets.values()), expected)
            # Disabled source copy remains mandatory, and no target executors are
            # part of compile. Remove just that copy to prove refusal is early.
            resolved['db-tools'][0].pop('coordinated_custody')
            with self.assertRaisesRegex(ValueError, 'Custody inputs|provenance copies'):
                compiler.compile_stack(value.root, overlay, ['db-tools'])

    def test_other_pending_paths_and_changed_immutable_inputs_refuse_before_native_executor(self):
        value = self.fixture()
        member = value.group['members']['mariadb']
        for folder, name in ((value.local, 'complete.json.pending'),
                             (value.remote, '.claim.json.pending'),
                             (value.work('mariadb') / member['overlay']['directory'], 'overlay.json.pending'),
                             (value.backups / '808' / member['overlay']['directory'], '.HOLD.json'),
                             (value.work('mariadb') / 'database-network-plan-fixture', 'request.json.pending')):
            save(folder / name, {})
            with self.subTest(folder=folder), self.assertRaises(ValueError): evidence.inspect(value.cfgs['mariadb'])
            (folder / name).unlink()
        for leaf in ('database-unexpected', 'database-file'):
            child = value.work('mariadb') / leaf
            if leaf.endswith('unexpected'): child.symlink_to(value.root / 'absent')
            else: save(child, b'retained unrelated record')
            # A non-directory database-* record is ignored, while symlinked
            # nested custody cannot bypass the directory/marker examination.
            expected, _, _ = evidence.inspect(value.cfgs['mariadb'])
            a = self.attempt(value, 'mariadb', expected)
            with patch.object(pve, 'guest_trust'), patch.object(generation, 'classify', return_value={}), \
                 patch.object(pve, 'infrastructure') as native:
                if leaf.endswith('unexpected'):
                    with self.assertRaises(ValueError): a.__enter__()
                else:
                    with a: pass
                native.assert_not_called()
            child.unlink()

    def test_real_packet_compiler_resolves_input_slot_before_runtime_validation(self):
        import importlib.util
        path = Path(__file__).resolve().parents[3] / 'blueprints/compile.py'
        spec = importlib.util.spec_from_file_location('custody_slot_blueprints', path)
        compiler = importlib.util.module_from_spec(spec); spec.loader.exec_module(compiler)
        value = self.fixture(); cfg = value.cfgs['mariadb']
        cfg['paths']['coordinated_custody_inputs'] = '${inputs}'
        with self.assertRaisesRegex(ValueError, 'absolute custody paths'):
            contract.selection(cfg)
        contract.configured_closure(value.resolved())
        result, packet = compiler._compile_guest('mariadb', cfg, None, value.files(), ['mariadb'])
        directory = '/var/lib/homelab-inputs/ordinary/mariadb/' + packet['identity']
        self.assertEqual(result['paths']['coordinated_custody_inputs'], directory)
        self.assertEqual(contract.selection_digest(result), contract.selection_digest(cfg))
        self.assertEqual(packet['files']['catalogue.json'], value.catalogue_raw.decode())
        self.assertEqual(packet['files']['acceptance.json'], value.acceptance_raw.decode())
        self.assertEqual(contract.selection(result), cfg['coordinated_custody']['group'])
        # Exercise real source resolution too: public profile placeholders carry
        # private proof bytes through existing central values, not a new adapter.
        source = value.root / 'stack-source'
        base = copy.deepcopy(cfg)
        base.pop('deployment'); selected = base.pop('coordinated_custody')
        base['paths'].pop('coordinated_custody_inputs')
        base['guest'].update(dns_servers=[], rules=[])
        save(source / 'common.json', {})
        save(source / 'guests/mariadb/profile.json', {'config': base, 'stack': None,
             'files': {'catalogue.json': '${custody.catalogue}', 'acceptance.json': '${custody.acceptance}'}})
        save(source / 'stack.json', {'schema': 'homelab-stack-v2', 'values': {}, 'routes': {},
             'guests': {'mariadb': {'depends_on': [], 'prerequisites': []}}})
        overlay = {'schema': 'homelab-site-v3', 'common': {}, 'images': {}, 'accepted': {}, 'routes': {},
                   'values': {'custody.catalogue': value.catalogue_raw.decode(), 'custody.acceptance': value.acceptance_raw.decode()},
                   'guests': {'mariadb': {'config': {'coordinated_custody': selected,
                       'paths': {'coordinated_custody_inputs': '${inputs}'}}}}}
        with patch.object(compiler, 'CATALOGUE', {'mariadb': compiler.CATALOGUE['mariadb']}):
            packets = compiler.compile_stack(source, overlay)
        self.assertTrue(packets['mariadb']['enabled'])
        self.assertEqual(packets['mariadb']['files']['acceptance.json'], value.acceptance_raw.decode())
        self.assertEqual(records.decode(packets['mariadb']['files']['site.json'])['coordinated_custody'], selected)
        cfg['paths']['coordinated_custody_inputs'] = '${other}'
        with self.assertRaises(ValueError): contract.configured_closure(value.resolved())
