"""Qualified completed groups and evolving ordinary generations, without targets."""

import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[3]/'blueprints')]
import coordinated_contract as contract
import coordinated_evidence as evidence
import coordinated_generation as generation
import custody_records as records
import deployment_inputs as inputs
import deployment_state as state
import deploy
import private_io as io
import proxmox_guest as pve
import ordinary_failure
import component_guest
import component_inputs
import component_payload
import component_evidence
from test_component_historical_transition import HistoricalCase
from fixtures import github_source
from custody_fixtures import CompletedGroup, save, backend


class AdmissionTests(unittest.TestCase):
    def fixture(self, postgres=False, proof_literal=None, legacy_serializers=True):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        value = CompletedGroup(td.name, postgres=postgres, proof_literal=proof_literal, legacy_serializers=legacy_serializers)
        mount = patch.object(records.os.path, 'ismount', return_value=True)
        real_output=subprocess.check_output
        def output(argv,*args,**kwargs):
            if argv[0]=='findmnt':
                value='nfs4 nas.example.invalid:/backups\n'
                return value if kwargs.get('text') else value.encode()
            return real_output(argv,*args,**kwargs)
        findmnt = patch.object(records.subprocess, 'check_output', side_effect=output)
        mount.start(); findmnt.start()
        self.addCleanup(mount.stop); self.addCleanup(findmnt.stop)
        return value

    def runtime(self, value, role='mariadb'):
        case = HistoricalCase(self, value.root, role, group=value, phase=role)
        contexts = ExitStack();self.addCleanup(contexts.close);case.bind(contexts)
        # Only app/native executors are fakes. Packet/static/AppPayload/binding,
        # attempt locks, local Git ancestry and historical evidence stay real.
        app = contexts.enter_context(patch('component_ansible.run_phase',
            return_value={'status':'passed','changed':False}))
        def agent(cfg, environment):
            return component_payload.prepare(component_inputs.app_directory(cfg,create=True),
                cfg['deployment']['input_identity'],'agent',
                {'application.json':io.encoded({'id':'agent','adapter':'zabbix-agent'})})
        contexts.enter_context(patch('component_prepare.prepare_agent',side_effect=agent))
        runtime = SimpleNamespace(cfg=case.cfg,site=case.packet,work=case.work,
            revisions=case.revisions,infra=case.native,app=app,case=case)
        def run(phase):
            case.revise()
            return deploy.run(phase,case.packet,inputs=case.inputs,environment={})
        runtime.run=run
        return runtime


    def all_phases(self, runtime):
        for phase in ['infrastructure', *component_guest.phases(runtime.cfg)]:
            runtime.run(phase)


    def test_exact_reviewed_failed_infrastructure_can_advance_without_fabricating_application_success(self):
        value = self.fixture()
        real = subprocess.run
        def output(argv, **kwargs):
            if argv[0] == 'findmnt': return 'nfs4 nas.example.invalid:/backups\n'
            return real(argv, check=True, stdout=subprocess.PIPE, **kwargs).stdout
        with patch.object(subprocess, 'check_output', side_effect=output):
            runtime = self.runtime(value)
            self.all_phases(runtime)
            previous = (runtime.work / 'ordinary-complete.json').read_bytes()
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '778', 'GITHUB_RUN_NUMBER': '778',
                                         'GITHUB_SHA': runtime.revisions[1]}):
                runtime.run('infrastructure')
                runtime.run('preparation')
                runtime.app.side_effect = RuntimeError('synthetic missing sudo before account writes')
                with self.assertRaises(RuntimeError): runtime.run('mariadb')
                runtime.app.side_effect = None
            operation = runtime.work / 'ordinary-778-1'
            hold = (runtime.work / 'ORDINARY-HOLD.json').read_bytes()
            log = operation / 'mariadb/application.log'
            save(log, b'synthetic fixed failure before account writes\n')
            row = {'operation': operation.name, 'phase': 'mariadb', 'hold_sha256': io.digest(hold),
                   'infrastructure_sha256': io.sha(operation / 'infrastructure-complete.json'),
                   'log_sha256': io.sha(log), 'previous_ordinary_sha256': io.digest(previous),
                   'state_sha256': io.sha(runtime.work / 'terraform.tfstate')}
            runtime.cfg['reviewed_ordinary_failures'] = [row]
            self.assertEqual((runtime.work / 'ordinary-complete.json').read_bytes(), previous)
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '779', 'GITHUB_RUN_NUMBER': '779',
                                         'GITHUB_SHA': runtime.revisions[1]}):
                with self.assertRaises((ValueError, OSError)): runtime.run('infrastructure')
                # Operator preservation is explicit, never performed by CD.
                (runtime.work / 'ORDINARY-HOLD.json').rename(operation / 'preserved-failed-hold.json')
                for change in ('log', 'started', 'infra', 'foreign', 'complete', 'nested-hold', 'unselected'):
                    originals = {p: p.read_bytes() for p in (log, operation / 'mariadb-started.json', operation / 'infrastructure-complete.json')}
                    if change in ('log', 'started', 'infra'):
                        target = {'log': log, 'started': operation / 'mariadb-started.json', 'infra': operation / 'infrastructure-complete.json'}[change]
                        save(target, originals[target] + b' ')
                    if change == 'foreign': row['previous_ordinary_sha256'] = 'f' * 64
                    if change == 'complete': save(operation / 'complete.json', {})
                    if change == 'nested-hold': save(log.parent / '.pending-HOLD.json', {})
                    if change == 'unselected': runtime.cfg.pop('reviewed_ordinary_failures')
                    with self.subTest(change=change), self.assertRaises((ValueError, OSError)):
                        runtime.run('infrastructure')
                    for p, raw in originals.items(): save(p, raw)
                    row['previous_ordinary_sha256'] = io.digest(previous)
                    (operation / 'complete.json').unlink(missing_ok=True)
                    (log.parent / '.pending-HOLD.json').unlink(missing_ok=True)
                    runtime.cfg['reviewed_ordinary_failures'] = [row]
                self.all_phases(runtime)
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '780', 'GITHUB_RUN_NUMBER': '780',
                                         'GITHUB_SHA': runtime.revisions[1]}): self.all_phases(runtime)
            self.assertEqual((operation / 'preserved-failed-hold.json').read_bytes(), hold)
            self.assertFalse((operation / 'complete.json').exists())
            self.assertEqual(records.decode((runtime.work / 'ordinary-complete.json').read_bytes())['run_number'], 780)

    def test_reviewed_failure_source_is_closed_bounded_and_cannot_select_paths_or_unknown_digests(self):
        row = {'operation': 'ordinary-100-1', 'phase': 'postgresql',
               **{k: 'a' * 64 for k in ('hold_sha256', 'infrastructure_sha256', 'log_sha256', 'previous_ordinary_sha256', 'state_sha256')}}
        self.assertEqual(ordinary_failure.selection({}), [])
        for change in ('type', 'bound', 'group', 'extra', 'path', 'duplicate', 'phase', 'digest'):
            cfg = {'coordinated_custody': {}, 'reviewed_ordinary_failures': [copy.deepcopy(row)]}
            selected = cfg['reviewed_ordinary_failures']
            if change == 'type': cfg['reviewed_ordinary_failures'] = {}
            if change == 'bound': cfg['reviewed_ordinary_failures'] = [row] * 17
            if change == 'group': cfg.pop('coordinated_custody')
            if change == 'extra': selected[0]['unknown'] = True
            if change == 'path': selected[0]['operation'] = '../ordinary-100-1'
            if change == 'duplicate': selected.append(copy.deepcopy(row))
            if change == 'phase': selected[0]['phase'] = '../postgresql'
            if change == 'digest': selected[0]['hold_sha256'] = 'unknown'
            with self.subTest(change=change), self.assertRaises(ValueError): ordinary_failure.selection(cfg)

    def test_exact_final_agent_phase_can_be_selected_without_admitting_other_hyphenated_paths(self):
        row = {'operation': 'ordinary-100-1', 'phase': component_guest.AGENT_PHASE,
               **{k: 'a' * 64 for k in ('hold_sha256', 'infrastructure_sha256', 'log_sha256',
                                       'previous_ordinary_sha256', 'state_sha256')}}
        cfg = {'coordinated_custody': {}, 'reviewed_ordinary_failures': [row]}
        self.assertEqual(ordinary_failure.selection(cfg), [row])
        for phase in ('foreign-phase', 'zabbix-agent/..', '../zabbix-agent', 'zabbix-agent\n'):
            changed = copy.deepcopy(cfg); changed['reviewed_ordinary_failures'][0]['phase'] = phase
            with self.subTest(phase=phase), self.assertRaises(ValueError): ordinary_failure.selection(changed)

    def test_exact_reviewed_agent_failure_keeps_old_hold_and_requires_a_new_successful_run(self):
        import monitoring_inputs
        value = self.fixture(); real = subprocess.run
        def output(argv, **kwargs):
            if argv[0] == 'findmnt': return 'nfs4 nas.example.invalid:/backups\n'
            return real(argv, check=True, stdout=subprocess.PIPE, **kwargs).stdout
        with patch.object(subprocess, 'check_output', side_effect=output), patch.object(monitoring_inputs, 'source_files', return_value=[]):
            runtime = self.runtime(value)
            selected = {'hostname':'fixture-808','psk_identity':'fixture-808',
                'server_active':'198.18.25.36:10051','server_vmid':816,'server_hostname':'zabbix',
                'profiles':['linux','mysql'],'database_uri':'tcp://127.0.0.1:3306'}
            selected.update(hostname=runtime.cfg['site']['node']+'-'+str(runtime.cfg['guest']['vmid']))
            selected['psk_identity'] = selected['hostname']
            selected['credential_file'] = str(value.root/'agent.json')
            selected['database_password_file'] = str(value.root/'agent-database-password')
            save(Path(selected['credential_file']), {'psk':'b'*64})
            save(Path(selected['database_password_file']), b'c'*64)
            runtime.cfg['app']['monitoring'] = selected
            runtime.cfg['deployment']['phases'].append(component_guest.AGENT_PHASE)
            runtime.cfg['deployment']['payload_phases'][component_guest.AGENT_PHASE]='agent'
            self.all_phases(runtime)
            previous = (runtime.work/'ordinary-complete.json').read_bytes()
            phase = component_guest.AGENT_PHASE
            with patch.dict(os.environ, {'GITHUB_RUN_ID':'778','GITHUB_RUN_NUMBER':'778','GITHUB_SHA':runtime.revisions[1]}):
                for name in ('infrastructure','preparation','mariadb'): runtime.run(name)
                runtime.app.side_effect = RuntimeError('synthetic final agent refusal')
                with self.assertRaises(RuntimeError):runtime.run(phase)
                runtime.app.side_effect = None
            operation=runtime.work/'ordinary-778-1'; hold=(runtime.work/'ORDINARY-HOLD.json').read_bytes()
            log=operation/phase/'application.log';save(log,b'original agent failure remains\n')
            row={'operation':operation.name,'phase':phase,'hold_sha256':io.digest(hold),
                 'infrastructure_sha256':io.sha(operation/'infrastructure-complete.json'),'log_sha256':io.sha(log),
                 'previous_ordinary_sha256':io.digest(previous),'state_sha256':io.sha(runtime.work/'terraform.tfstate')}
            runtime.cfg['reviewed_ordinary_failures']=[row]
            with patch.dict(os.environ, {'GITHUB_RUN_ID':'779','GITHUB_RUN_NUMBER':'779','GITHUB_SHA':runtime.revisions[1]}):
                with self.assertRaises((ValueError,OSError)):runtime.run('infrastructure')
                self.assertEqual((runtime.work/'ordinary-complete.json').read_bytes(),previous)
                # Only the explicit fixture operator preserves the old active hold.
                (runtime.work/'ORDINARY-HOLD.json').rename(operation/'preserved-failed-hold.json')
                self.all_phases(runtime)
            self.assertEqual((operation/'preserved-failed-hold.json').read_bytes(),hold)
            self.assertEqual(log.read_bytes(),b'original agent failure remains\n')
            self.assertFalse((operation/'complete.json').exists())
            self.assertEqual(records.decode((runtime.work/'ordinary-complete.json').read_bytes())['run_number'],779)

    def test_component_failed_app_and_agent_proofs_are_closed_immutable_and_owned(self):
        import monitoring_inputs
        for agent in (False,True):
            value=self.fixture()
            with patch.object(monitoring_inputs,'source_files',return_value=[]):
                runtime=self.runtime(value)
                if agent:
                    runtime.cfg['app']['monitoring']={'hostname':'fixture-pve-808',
                        'psk_identity':'fixture-pve-808','server_active':'198.18.25.36:10051',
                        'server_vmid':816,'server_hostname':'zabbix','profiles':['linux','mysql'],
                        'credential_file':str(value.root/'agent.json')}
                    runtime.cfg['deployment']['phases'].append(component_guest.AGENT_PHASE)
                    runtime.cfg['deployment']['payload_phases'][component_guest.AGENT_PHASE]='agent'
                self.all_phases(runtime)
                phase=component_guest.AGENT_PHASE if agent else 'mariadb'
                with patch.dict(os.environ,{'GITHUB_RUN_ID':'778','GITHUB_RUN_NUMBER':'778',
                                           'GITHUB_SHA':runtime.revisions[1]}):
                    for name in ['infrastructure','preparation']+(['mariadb'] if agent else []):runtime.run(name)
                    runtime.app.side_effect=RuntimeError('synthetic selected phase refusal')
                    with self.assertRaises(RuntimeError):runtime.run(phase)
                    runtime.app.side_effect=None
                operation=runtime.work/'ordinary-778-1';row={'phase':phase}
                hold=runtime.work/'ORDINARY-HOLD.json';raw=hold.read_bytes();held=records.decode(raw)
                hold.rename(operation/'preserved-failed-hold.json')
                started_path=operation/(phase+'-started.json');started_raw=started_path.read_bytes()
                started=records.decode(started_raw);proof=started['phase_inputs']
                payload=Path(held['binding']['app_inputs_directory'])/proof['app']
                manifest=payload/'selected-app.json';application=payload/'application.json'
                prior_site=Path(held['binding']['app_inputs_directory']).parent/'site.json'
                before={path:path.read_bytes() for path in (manifest,application,prior_site)}
                attempt=SimpleNamespace(cfg=runtime.cfg)
                ordinary_failure.phase_start(attempt,operation,row,held,raw)
                for variant in ('missing-proof','foreign-app','wrong-input-identity','noncanonical-start','noncanonical-hold',
                                'payload-tamper','missing-manifest','foreign-old-guest','foreign-old-phase-map'):
                    bad=copy.deepcopy(started);owner=copy.deepcopy(held)
                    if variant=='missing-proof':bad.pop('phase_inputs')
                    elif variant=='foreign-app':bad['phase_inputs']['app']='foreign'
                    elif variant=='wrong-input-identity':bad['phase_inputs']['identity']='0'*64
                    elif variant=='payload-tamper':application.write_bytes(before[application]+b' ')
                    elif variant=='missing-manifest':manifest.unlink()
                    elif variant in ('foreign-old-guest','foreign-old-phase-map'):
                        cfg=records.decode(before[prior_site])
                        if variant=='foreign-old-guest':cfg['guest']['hostname']='foreign'
                        else:cfg['deployment']['payload_phases'][phase]='foreign'
                        save(prior_site,cfg);owner['binding']['site_sha256']=io.sha(prior_site)
                        bad['binding']=copy.deepcopy(owner['binding'])
                    save(started_path,io.encoded(bad)+(b' ' if variant=='noncanonical-start' else b''))
                    with self.subTest(agent=agent,variant=variant),self.assertRaises((ValueError,OSError)):
                        ordinary_failure.phase_start(attempt,operation,row,owner,
                            io.encoded(owner)+(b' ' if variant=='noncanonical-hold' else b''))
                    save(started_path,started_raw)
                    for path,content in before.items():save(path,content)
                ordinary_failure.phase_start(attempt,operation,row,held,raw)
                self.assertEqual((operation/'preserved-failed-hold.json').read_bytes(),raw)
                self.assertEqual(started_path.read_bytes(),started_raw)
                self.assertFalse((operation/'complete.json').exists())
                self.assertFalse((runtime.work/'ORDINARY-HOLD.json').exists())
                self.assertEqual(runtime.infra.call_count,2)

    def test_complete_local_and_nas_provenance_includes_disabled_members(self):
        value = self.fixture(postgres=True)
        component_evidence.bind(self.source_evidence(value))
        for role, cfg in value.cfgs.items():
            proofs, lineage, baseline = evidence.inspect(cfg)
            self.assertEqual(lineage, f"fixture-{cfg['guest']['vmid']}")
            self.assertEqual(baseline is None, role == 'postgresql')
            self.assertIn(str(value.work('db-tools') / 'plan.json'), proofs)
            self.assertIn(str(value.remote / 'complete.json'), proofs)
        # Current component closure runs before execution selection; a disabled
        # member's document and exact raw assets remain configured source inputs.
        for variant in ('missing', 'changed', 'missing-proof', 'changed-proof'):
            source = self.source_evidence(value)
            if variant == 'missing':
                source.guests.pop('db-tools'); source.apps.pop('db-tools')
            elif variant == 'changed':
                changed = copy.deepcopy(source.site['evidence']['group'])
                changed['document']['group']['members']['db-tools']['initial_state_sha256'] = '4' * 64
                source.site['evidence']['changed-group'] = changed
                source.guests['db-tools']['admission']['coordinated_custody']['evidence'] = 'changed-group'
            elif variant == 'missing-proof':
                source.guests['db-tools']['admission']['assets'].pop('acceptance')
            else:
                source.site['evidence']['changed-acceptance'] = {
                    'text': source.site['evidence']['acceptance']['text'] + ' '}
                source.guests['db-tools']['admission']['assets']['acceptance'] = 'changed-acceptance'
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                component_evidence.bind(source)
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
                        self.assertFalse(runtime.run('infrastructure')['target_contacted'])
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

    def test_component_packet_proof_tamper_is_preserved_as_static_evidence_but_never_reaches_native(self):
        for variant in ('missing-proof','changed-proof','wrong-directory','valid'):
            value=self.fixture();case=HistoricalCase(self,value.root,'mariadb',group=value,phase='mariadb')
            packet=records.decode(case.packet.read_bytes())
            if variant=='missing-proof':packet['files'].pop('acceptance.json')
            if variant=='changed-proof':packet['files']['catalogue.json']+=' '
            if variant=='wrong-directory':
                cfg=records.decode(packet['files']['site.json'])
                cfg['paths']['coordinated_custody_inputs']=str(value.root/'elsewhere')
                packet['files']['site.json']=io.encoded(cfg).decode()
            save(case.packet,packet)
            destination=Path(case.cfg['deployment']['input_directory'])
            with ExitStack() as contexts:
                case.bind(contexts)
                if variant=='valid':
                    deploy.run('infrastructure',case.packet,inputs=case.inputs,environment={})
                    observed=records.decode((destination/'site.json').read_bytes())
                    self.assertEqual(observed,case.cfg)
                    self.assertEqual((destination/'acceptance.json').read_bytes(),value.acceptance_raw)
                else:
                    with self.subTest(variant=variant),self.assertRaises((ValueError,OSError)):
                        deploy.run('infrastructure',case.packet,inputs=case.inputs,environment={})
                    self.assertEqual(case.native_calls,[]);case.prepare.assert_not_called()
                    self.assertFalse((case.work/'ORDINARY-HOLD.json').exists())
                    self.assertFalse((destination/'applications').exists())
                    # Versioned receiver keeps only the refused static witness.
                    self.assertFalse((value.root/'elsewhere').exists())
                    self.assertTrue((destination/'component-prepared.json').is_file())
                    for name,raw in packet['files'].items():
                        self.assertEqual((destination/name).read_bytes(),raw.encode())


    def test_plan_identity_is_enforced_before_apply_and_missing_trust_is_never_created(self):
        from test_plan import existing_fixture
        value = self.fixture(); cfg = value.cfgs['mariadb']; work = value.work('mariadb')
        trust = work / 'ssh-trust.json'; trust.unlink()
        with patch.object(pve.subprocess,'run',return_value=SimpleNamespace(
                returncode=0,stdout=cfg['app']['address']+' ssh-ed25519 fixture\n')) as lookup, \
                self.assertRaisesRegex(ValueError, 'existing commissioned guest trust'):
            pve.guest_trust(cfg, work, persist=False)
        self.assertEqual(lookup.call_args.args[0][0],'ssh-keygen')
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

    def test_component_evidence_keeps_every_configured_member_independent_of_execution_selection(self):
        value=self.fixture(postgres=True)
        source=self.source_evidence(value)
        result=component_evidence.bind(source)
        self.assertEqual(set(result),set(value.roles))
        self.assertTrue(all(row['coordinated_custody']==value.cfgs[role]['coordinated_custody']
                            for role,row in result.items()))
        # A disabled/otherwise unexecuted copy is still part of source closure.
        source.guests['db-tools'].pop('admission')
        with self.assertRaisesRegex(ValueError,'evidence-closure'):component_evidence.bind(source)


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
            # The completed group remains historical input; a new ordinary
            # attempt uses the current closed common binding and guest schema.
            a.cfg = dict(a.cfg, schema='homelab-component-guest-v1',
                         deployment=dict(a.cfg['deployment'], lifecycle='retained'))
            a.binding = dict(a.binding, schema=state.BINDING_SCHEMA, site_sha256='a'*64,
                source_sha256='b'*64, input_identity='c'*64,
                app_inputs_directory=str(value.work('mariadb')/'applications'))
            with patch.object(pve, 'guest_trust'), patch.object(generation, 'classify', return_value={}), \
                 patch.object(pve, 'infrastructure') as native:
                if leaf.endswith('unexpected'):
                    with self.assertRaises(ValueError): a.__enter__()
                else:
                    with a: pass
                native.assert_not_called()
            child.unlink()

    def source_evidence(self,value):
        first=next(iter(value.cfgs.values()))
        context={'node':first['site']['node'],'paths':{key:first['paths'][key] for key in
                 ('state_root','backup_mount','backup_directory','backup_source')}}
        source=SimpleNamespace(site={'contexts':{'selected':context},'evidence':{
            'group':{'document':copy.deepcopy(first['coordinated_custody'])},
            'catalogue':{'text':value.catalogue_raw.decode()},
            'acceptance':{'text':value.acceptance_raw.decode()}}},guests={},apps={})
        for role,cfg in value.cfgs.items():
            source.guests[role]={'context':'selected','identity':{'vmid':cfg['guest']['vmid']},
                'admission':{'coordinated_custody':{'evidence':'group','member':role},
                             'assets':{'catalogue':'catalogue','acceptance':'acceptance'}}}
            source.apps[role]={'guest':role,'adapter':{'identity':'authentik','db-tools':'cloudbeaver'}.get(role,role)}
        return source

    def lower_evidence_packet(self,value,*,literal='ordinary ${inputs} and ${literal.name}'):
        """Packet unit: conforming component collaborators, real proof/slot builder."""
        import component_packet
        source=self.source_evidence(value);selected=component_evidence.bind(source)['mariadb']
        cfg=value.cfgs['mariadb'];app_id='database'
        runtime={'schema':'homelab-component-runtime-v1','guest':{'id':'database'},'applications':{app_id:{
            'id':app_id,'adapter':'mariadb','lifecycle':'retained','identity':{'phase':'mariadb',
            'runtime_id':'database','services':{},'networks':{}},'settings':{},'storage_paths':{}}}}
        context={**copy.deepcopy(source.site['contexts']['selected']),
            'trust':{'ca_file':cfg['paths']['ca_file'],'known_hosts':cfg['paths']['known_hosts']},
            'credentials':{'api_token':'api','ssh_private_key':'ssh'},'protected_guests':[9900]}
        guest={'context':'selected','lifecycle':'retained','identity':copy.deepcopy(cfg['guest']),
            'resources':{'memory_mib':cfg['guest']['memory_mib']},
            'control':{'address':cfg['app']['address'],'mac':cfg['app']['mac']},
            'software_selection':{'packages':[],'repositories':[]}}
        plan=SimpleNamespace(check=lambda:None,site={'secret_sources':{
            'api':{'type':'file','path':cfg['paths']['api_token']},
            'ssh':{'type':'file','path':cfg['paths']['private_key']}}},library={'assets':{}},
            resolved={'guests':{'database':guest},'contexts':{'selected':context},
                      'evidence':{'database':selected},'enabled':['database']})
        provider={key:copy.deepcopy(cfg[key]) for key in ('site','guest','ssh_public_keys')}
        with patch.object(component_packet,'provider_config',return_value=provider), \
             patch.object(component_packet,'runtime_config',return_value=runtime), \
             patch.object(component_packet.component_runtime,'artifacts',return_value={'ordinary.txt':literal.encode()}), \
             patch.object(component_packet.component_routes,'provider_routes',return_value=[]), \
             patch.object(component_packet,'application_order',return_value=[app_id]), \
             patch.object(component_packet.component_checks,'checks',return_value=[{'name':'fake native','argv':['true']}]), \
             patch.object(component_packet,'INPUTS',value.root/'packet-inputs'):
            return component_packet.lower_guest(plan,'database',inputs=value.root/'packet-inputs')

    def test_component_packet_binds_only_declared_slots_and_never_interpolates_proof_or_ordinary_text(self):
        value=self.fixture(proof_literal='retain ${inputs} and ${literal.name} exactly')
        selected=component_evidence.bind(self.source_evidence(value))['mariadb']
        with self.assertRaisesRegex(ValueError,'absolute custody paths'):contract.selection(selected)
        packet=self.lower_evidence_packet(value)
        cfg=records.decode(packet['files']['site.json'])
        directory=value.root/'packet-inputs/database'/packet['identity']
        self.assertEqual(cfg['paths']['coordinated_custody_inputs'],str(directory))
        self.assertEqual(cfg['deployment']['input_directory'],str(directory))
        self.assertEqual(contract.selection_digest(cfg),contract.selection_digest(selected))
        self.assertEqual(packet['files']['catalogue.json'].encode(),value.catalogue_raw)
        self.assertEqual(packet['files']['acceptance.json'].encode(),value.acceptance_raw)
        self.assertEqual(packet['files']['ordinary.txt'],'ordinary ${inputs} and ${literal.name}')
        component_guest.packet(packet,value.root/'packet-inputs')


    def test_literal_proof_bytes_survive_component_source_binding_lowering_and_preparation(self):
        value=self.fixture(proof_literal='retain ${inputs} and ${literal.name} exactly')
        source=self.source_evidence(value)
        for key in ('catalogue','acceptance'):
            raw=source.site['evidence'][key]['text'];source.site['evidence'][key]['text']+=' '
            with self.subTest(asset=key),self.assertRaisesRegex(ValueError,'evidence-asset'):
                component_evidence.bind(source)
            source.site['evidence'][key]['text']=raw
        self.assertFalse((value.root/'packet-inputs').exists())
        packet=self.lower_evidence_packet(value)
        self.assertEqual(packet['files']['catalogue.json'].encode(),value.catalogue_raw)
        self.assertEqual(packet['files']['acceptance.json'].encode(),value.acceptance_raw)
        packet_path=value.root/'packet.json';save(packet_path,packet)
        observed,site=component_inputs.prepare(packet_path,value.root/'packet-inputs',create=True)
        destination=value.root/'packet-inputs/database'/packet['identity']
        self.assertEqual(site,destination/'site.json')
        proofs,_,_=evidence.inspect(observed)
        self.assertEqual(proofs[str(destination/'catalogue.json')],value.group['catalogue']['sha256'])
        self.assertEqual((destination/'acceptance.json').read_bytes(),value.acceptance_raw)
        before={path:path.read_bytes() for path in destination.iterdir()}
        bad=copy.deepcopy(packet);bad['files']['acceptance.json']+=' '
        save(value.root/'changed-packet.json',bad)
        with self.assertRaisesRegex(ValueError,'differs or was interrupted'):
            component_inputs.prepare(value.root/'changed-packet.json',value.root/'packet-inputs',create=True)
        self.assertEqual(before,{path:path.read_bytes() for path in destination.iterdir()})
