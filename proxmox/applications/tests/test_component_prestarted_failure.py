"""Closed pre-STARTED read-only admission with actual attempt/static/payload files.

Native/application executors and mount/provider boundaries are synthetic. The
reader, local Git ancestry, sealed publications, phase receipts and payloads are
real. HOLD preservation below is an explicit test-operator action, never CD.
"""
import copy
import ast
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[3]/'blueprints')]
import component_guest
import component_inputs
import component_payload
import coordinated_generation
import deploy
import initial_ordinary
import ordinary_failure
import private_io as io
import proxmox_guest
from deployment_state import DeploymentAttempt
from test_component_historical_transition import HistoricalCase


class PrestartedFailureTests(unittest.TestCase):
    def fixture(self, *, preparation_failure=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        case = HistoricalCase(self, root, 'zigbee2mqtt', phase='radio')
        contexts = ExitStack()
        self.addCleanup(contexts.close)
        case.bind(contexts)
        contexts.enter_context(patch('monitoring_inputs.source_files', return_value=[]))
        cfg = case.cfg
        cfg['app']['monitoring'] = {'profiles': ['linux']}
        cfg['app']['service_health_checks']['telemetry'] = [{'name': 'synthetic telemetry', 'argv': ['true']}]
        cfg['deployment']['applications']['telemetry'] = {
            'id': 'telemetry-app', 'adapter': 'winet', 'lifecycle': 'retained',
            'runtime_id': 'telemetry', 'project': 'retained-project',
            'compose_file': 'compose.yml', 'services': ['owned-winet']}
        cfg['deployment']['payload_phases'].update(telemetry='telemetry-app', **{'zabbix-agent': 'agent'})
        cfg['deployment']['phases'] = ['preparation', 'radio', 'telemetry', 'zabbix-agent']
        case.runtime['applications']['telemetry-app'] = {
            'id': 'telemetry-app', 'adapter': 'winet', 'lifecycle': 'retained',
            'identity': {'runtime_id': 'telemetry', 'phase': 'telemetry',
                         'services': {'winet': 'owned-winet'}, 'networks': {},
                         'runtime_directory': '/opt/homelab-app/runtime/telemetry'},
            'project_name': 'retained-project', 'project_file': 'compose.yml',
            'storage_paths': {}, 'settings': {}}
        files = json.loads(case.packet.read_bytes())['files']
        compose = json.loads(files['compose.yml'])
        compose['services']['owned-winet'] = {'image': 'fixture/winet:1'}
        files['compose.yml'] = io.encoded(compose).decode()
        case.publish(files)
        # A no-change infrastructure result keeps the genuine initial backend;
        # the failed run never gains a fabricated ordinary success.
        case.native.side_effect = lambda cfg, site, work, *args, **kwargs: {
            'changed': False, 'created': False, 'state_sha256': io.sha(work/'terraform.tfstate')}
        for phase in (('infrastructure',) if preparation_failure else ('infrastructure', 'preparation', 'radio')):
            deploy.run(phase, case.packet, inputs=case.inputs, environment={})
        if preparation_failure:
            with patch('component_ansible.run_phase', side_effect=RuntimeError('synthetic preparation refusal')), \
                 self.assertRaises(RuntimeError):
                deploy.run('preparation', case.packet, inputs=case.inputs, environment={})
        operation = case.work/'ordinary-777-1'
        # Match the installed infrastructure writer without invoking OpenTofu.
        (operation/'tofu').mkdir(mode=0o700)
        for phase in (('preparation',) if preparation_failure else ('preparation', 'radio')):
            folder = operation/phase
            folder.mkdir(mode=0o700)
            io.write_new(folder/'application.log', b'synthetic passed prefix\n')
        hold = case.work/'ORDINARY-HOLD.json'
        raw = hold.read_bytes()
        row = {'operation': operation.name, 'phase': 'telemetry', 'boundary': 'before-started',
            'hold_sha256': io.digest(raw),
            'infrastructure_sha256': io.sha(operation/'infrastructure-complete.json'),
            'previous_ordinary_sha256': io.sha(case.work/'ordinary-complete.json'),
            'state_sha256': io.sha(case.work/'terraform.tfstate'),
            'preceding_completions_sha256': {name: io.sha(operation/(name+'-complete.json'))
                                            for name in (() if preparation_failure else ('preparation', 'radio'))}}
        if preparation_failure:
            row.pop('boundary'); row.pop('preceding_completions_sha256')
            row.update(phase='preparation', log_sha256=io.sha(operation/'preparation/application.log'))
        cfg['reviewed_ordinary_failures'] = [row]
        case.revise()
        current, site = component_inputs.prepare(case.packet, case.inputs, create=True)
        binding = component_inputs.binding(current, site)
        contexts.enter_context(patch.dict(os.environ, {'GITHUB_RUN_ID': '778', 'GITHUB_RUN_NUMBER': '778',
                                                        'GITHUB_SHA': case.revisions[1]}))
        attempt = DeploymentAttempt(current, binding, component_guest.phases(current))
        attempt._select_run()
        return SimpleNamespace(case=case, attempt=attempt, member=initial_ordinary.selection(current),
            row=current['reviewed_ordinary_failures'][0], operation=operation, hold=hold, raw=raw,
            old_binding=io.decode_json(raw)['binding'], binding_key=initial_ordinary.BINDING)

    def inspect(self, value):
        return ordinary_failure.inspect_record(value.attempt, value.member, value.binding_key,
                                               value.row, value.raw)

    def files(self, value):
        return {p: (p.stat().st_ino, p.read_bytes()) for p in value.case.root.rglob('*')
                if p.is_file() and not p.is_relative_to(value.case.github)}

    def historical(self, value):
        cfg, _ = ordinary_failure._sealed_component(value.old_binding)
        held = io.decode_json(value.raw)
        return SimpleNamespace(cfg=cfg, binding=value.old_binding, work=value.case.work,
            receipt=value.case.work/'ordinary-complete.json', operation=value.operation,
            workflow=held['workflow'], run_number=held['run_number'], site_revision=held['site_revision'])

    def test_supplied_exact_hold_reader_is_read_only_and_default_reader_has_no_active_fallback(self):
        value = self.fixture()
        module = ast.parse(Path(proxmox_guest.__file__).read_text())
        writer = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == 'infrastructure')
        copies = [node for node in ast.walk(writer) if isinstance(node, ast.Call)
                  and ast.unparse(node.func) == 'shutil.copytree']
        self.assertEqual([ast.unparse(node.args[1]) for node in copies], ["operation / 'tofu'"])
        before = self.files(value)
        with patch('private_io.private_writer', side_effect=AssertionError('No writer')), \
             patch('component_payload.prepare', side_effect=AssertionError('No payload writer')):
            result = self.inspect(value)
            with self.assertRaises(FileNotFoundError):
                ordinary_failure.inspect(value.attempt, value.member, value.binding_key)
        self.assertEqual(result['identity'], coordinated_generation.backend(value.case.work, value.member)[1])
        self.assertEqual(before, self.files(value))
        self.assertEqual(value.hold.read_bytes(), value.raw)
        self.assertFalse((value.operation/'complete.json').exists())

    def test_actual_normal_caller_refuses_active_hold_then_reads_operator_preserved_failure(self):
        value = self.fixture()
        previous = (value.case.work/'ordinary-complete.json').read_bytes()
        with self.assertRaises((ValueError, OSError)):
            deploy.run('infrastructure', value.case.packet, inputs=value.case.inputs, environment={})
        self.assertEqual(value.hold.read_bytes(), value.raw)
        self.assertFalse((value.case.work/'ordinary-778-1').exists())
        # Explicit local synthetic operator action; no production writer exists.
        value.hold.rename(value.operation/'preserved-failed-hold.json')
        found = ordinary_failure.inspect(value.attempt, value.member, value.binding_key)
        self.assertEqual(set(found), {value.operation.name})
        deploy.run('infrastructure', value.case.packet, inputs=value.case.inputs, environment={})
        self.assertEqual((value.case.work/'ordinary-complete.json').read_bytes(), previous)
        self.assertEqual((value.operation/'preserved-failed-hold.json').read_bytes(), value.raw)
        self.assertFalse((value.operation/'complete.json').exists())
        self.assertTrue((value.case.work/'ordinary-778-1/infrastructure-complete.json').is_file())

    def test_successful_recovery_then_advanced_state_and_next_run_keep_old_failure_history(self):
        value = self.fixture()
        value.hold.rename(value.operation/'preserved-failed-hold.json')
        old = {p: (p.stat().st_ino, p.read_bytes()) for p in value.operation.rglob('*') if p.is_file()}
        def infrastructure(cfg, site, work, *args, **kwargs):
            path = work/'terraform.tfstate'
            state = io.read_json(path); state['serial'] += 1
            path.write_bytes(io.encoded(state))
            return {'changed': True, 'created': False, 'state_sha256': io.sha(path)}
        value.case.native.side_effect = infrastructure
        def prepare(cfg, app_id, environment, *, attempt):
            runtime = io.read_json(Path(cfg['deployment']['runtime_file']))
            return component_payload.prepare(component_inputs.app_directory(cfg, create=True),
                cfg['deployment']['input_identity'], app_id,
                {'application.json': io.encoded(runtime['applications'][app_id])})
        value.case.prepare.side_effect = prepare
        def agent(cfg, environment):
            return component_payload.prepare(component_inputs.app_directory(cfg, create=True),
                cfg['deployment']['input_identity'], 'agent', {'application.json': b'{"id":"agent"}'})
        with patch('component_prepare.prepare_agent', side_effect=agent), \
             patch('component_ansible.run_phase', return_value={'status': 'passed', 'changed': False}):
            for run in (778, 779):
                with patch.dict(os.environ, {'GITHUB_RUN_ID': str(run), 'GITHUB_RUN_NUMBER': str(run)}):
                    for phase in ['infrastructure', *value.case.cfg['deployment']['phases']]:
                        deploy.run(phase, value.case.packet, inputs=value.case.inputs, environment={})
                complete = io.read_json(value.case.work/'ordinary-complete.json')
                self.assertEqual(complete['run_number'], run)
                self.assertNotEqual(complete['state_sha256'], value.row['state_sha256'])
                self.assertTrue(coordinated_generation.component_success(complete, Path(complete['operation'])))
        self.assertEqual(old, {p: (p.stat().st_ino, p.read_bytes()) for p in old})
        self.assertFalse(value.hold.exists())
        for path in (value.attempt.receipt, value.case.work/'terraform.tfstate'):
            original = path.read_bytes(); path.write_bytes(original+b' ')
            calls = value.case.native.call_count
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '780', 'GITHUB_RUN_NUMBER': '780'}), \
                 self.subTest(path=path.name), self.assertRaises(ValueError):
                deploy.run('infrastructure', value.case.packet, inputs=value.case.inputs, environment={})
            self.assertEqual(value.case.native.call_count, calls)
            self.assertFalse(value.hold.exists())
            path.write_bytes(original)
        # Operator-time exact preimage checks may now refuse legitimately; normal
        # reviewed history above remains admissible through the real classifier.
        context = self.historical(value)
        with self.assertRaisesRegex(ValueError, 'pre-preservation'):
            ordinary_failure.inspect_historical(context, value.member, value.binding_key, value.row, value.raw)

    def test_original_operator_context_needs_no_future_selection_and_mutable_preimages_remain_exact(self):
        value = self.fixture()
        context = self.historical(value)
        self.assertNotIn('reviewed_ordinary_failures', context.cfg)
        before = self.files(value)
        result = ordinary_failure.inspect_historical(context, value.member, value.binding_key, value.row, value.raw)
        self.assertEqual(result['identity'], coordinated_generation.backend(context.work, value.member)[1])
        self.assertEqual(before, self.files(value))
        for path in (context.receipt, context.work/'terraform.tfstate'):
            original = path.read_bytes(); path.write_bytes(original+b' ')
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, 'pre-preservation'):
                ordinary_failure.inspect_historical(context, value.member, value.binding_key, value.row, value.raw)
            path.write_bytes(original)
        self.assertEqual(value.hold.read_bytes(), value.raw)

    def test_original_started_preparation_operator_contract_and_wrong_context_refuse(self):
        value = self.fixture(preparation_failure=True)
        context = self.historical(value)
        original = self.files(value)
        self.assertNotIn('reviewed_ordinary_failures', context.cfg)
        result = ordinary_failure.inspect_historical(context, value.member, value.binding_key, value.row, value.raw)
        self.assertEqual(result['phase'], 'preparation')
        for key, changed in (('operation', value.case.work/'ordinary-999-1'),
                             ('run_number', 999), ('workflow', ['other', 'workflow']),
                             ('site_revision', 'f'*40), ('binding', {})):
            previous = getattr(context, key); setattr(context, key, changed)
            with self.subTest(key=key), self.assertRaises(ValueError):
                ordinary_failure.inspect_historical(context, value.member, value.binding_key, value.row, value.raw)
            setattr(context, key, previous)
        with self.assertRaises(ValueError):
            ordinary_failure.inspect_historical(context, {**value.member, 'vmid': 999},
                                                value.binding_key, value.row, value.raw)
        self.assertEqual(original, self.files(value))

    def test_prefix_work_logs_are_optional_but_prefix_receipts_and_payloads_remain_required(self):
        value = self.fixture()
        (value.operation/'radio/application.log').unlink()
        (value.operation/'radio').rmdir()
        self.inspect(value)

    def test_three_native_started_preparation_records_keep_original_operator_contract(self):
        for role in ('postgresql', 'mariadb', 'influxdb'):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temporary, ExitStack() as contexts:
                case = HistoricalCase(self, Path(temporary).resolve(), role, phase='database')
                case.bind(contexts)
                case.all_phases()
                with patch.dict(os.environ, {'GITHUB_RUN_ID': '778', 'GITHUB_RUN_NUMBER': '778',
                                             'GITHUB_SHA': case.revisions[1]}):
                    case.native.side_effect = lambda cfg, site, work, *args, **kwargs: {
                        'changed': False, 'created': False, 'state_sha256': io.sha(work/'terraform.tfstate')}
                    deploy.run('infrastructure', case.packet, inputs=case.inputs, environment={})
                    with patch('component_ansible.run_phase', side_effect=RuntimeError('synthetic DB preparation failure')), \
                         self.assertRaises(RuntimeError):
                        deploy.run('preparation', case.packet, inputs=case.inputs, environment={})
                operation = case.work/'ordinary-778-1'
                (operation/'preparation').mkdir(mode=0o700)
                log = operation/'preparation/application.log'
                io.write_new(log, b'synthetic fixed preparation guard refusal\n')
                raw = (case.work/'ORDINARY-HOLD.json').read_bytes(); held = io.decode_json(raw)
                cfg, _ = ordinary_failure._sealed_component(held['binding'])
                context = SimpleNamespace(cfg=cfg, binding=held['binding'], work=case.work,
                    operation=operation, receipt=case.work/'ordinary-complete.json',
                    workflow=held['workflow'], run_number=held['run_number'], site_revision=held['site_revision'])
                member = (case.group.group['members'][role] if case.group else initial_ordinary.selection(cfg))
                key = 'coordinated_custody_sha256' if case.group else initial_ordinary.BINDING
                row = {'operation': operation.name, 'phase': 'preparation', 'hold_sha256': io.digest(raw),
                    'infrastructure_sha256': io.sha(operation/'infrastructure-complete.json'),
                    'log_sha256': io.sha(log), 'previous_ordinary_sha256': io.sha(context.receipt),
                    'state_sha256': io.sha(case.work/'terraform.tfstate')}
                before = {p: (p.stat().st_ino, p.read_bytes()) for p in operation.rglob('*') if p.is_file()}
                actual = ordinary_failure.inspect_historical(context, member, key, row, raw)
                self.assertEqual(set(row), {'operation', 'phase', 'hold_sha256', 'infrastructure_sha256',
                    'log_sha256', 'previous_ordinary_sha256', 'state_sha256'})
                self.assertEqual(actual['identity'], coordinated_generation.backend(case.work, member)[1])
                self.assertEqual(before, {p: (p.stat().st_ino, p.read_bytes()) for p in before})
                self.assertEqual((case.work/'ORDINARY-HOLD.json').read_bytes(), raw)

    def test_row_union_rejects_wrong_boundaries_unclosed_shapes_and_unselected_raw_records(self):
        value = self.fixture()
        self.assertEqual(ordinary_failure.selection(value.attempt.cfg), [value.row])
        mutations = [lambda r: r.update(boundary='other'), lambda r: r.update(log_sha256='a'*64),
            lambda r: r.update(preceding_completions_sha256=[]),
            lambda r: r.update(preceding_completions_sha256={}),
            lambda r: r.update(preceding_completions_sha256={'other': 'a'*64}),
            lambda r: r.update(preceding_completions_sha256={'preparation': 'wrong'}),
            lambda r: r['preceding_completions_sha256'].update({'bad/name': 'a'*64}),
            lambda r: r['preceding_completions_sha256'].update(telemetry='a'*64),
            lambda r: r['preceding_completions_sha256'].update({str(i): 'a'*64 for i in range(129)})]
        for phase in ('preparation', 'infrastructure', 'zabbix-agent'):
            mutations.append(lambda r, phase=phase: r.update(phase=phase))
        for mutate in mutations:
            cfg = copy.deepcopy(value.attempt.cfg)
            mutate(cfg['reviewed_ordinary_failures'][0])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                ordinary_failure.selection(cfg)
        cfg = copy.deepcopy(value.attempt.cfg)
        cfg.pop('schema')
        with self.assertRaises(ValueError): ordinary_failure.selection(cfg)
        row = copy.deepcopy(value.row); row['operation'] = 'ordinary-666-1'
        with self.assertRaisesRegex(ValueError, 'exact selected'): ordinary_failure.inspect_record(
            value.attempt, value.member, value.binding_key, row, value.raw)
        for raw in (value.raw+b' ', io.encoded({}), b'null'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ordinary_failure.inspect_record(value.attempt, value.member, value.binding_key, value.row, raw)

    def test_selected_later_unknown_markers_worklogs_payloads_and_links_refuse(self):
        value = self.fixture()
        operation = value.operation
        applications = Path(value.old_binding['app_inputs_directory'])
        candidates = [(operation/name, False) for name in ('telemetry-started.json',
            'telemetry-complete.json', 'zabbix-agent-started.json', 'zabbix-agent-complete.json',
            'unknown-started.json', 'unknown-complete.json', 'complete.json', 'unknown.log')]
        candidates += [(operation/name, True) for name in ('telemetry', 'zabbix-agent', 'unknown', 'infrastructure')]
        candidates += [(applications/name, True) for name in ('telemetry-app', 'agent', 'unknown-app')]
        for path, directory in candidates:
            with self.subTest(path=path.name):
                if directory: path.mkdir(mode=0o700)
                else: io.write_new(path, b'{}')
                with self.assertRaises(ValueError): self.inspect(value)
                if directory: path.rmdir()
                else: path.unlink()
        # A partial leaf and a dangling symlink also count as present effects.
        for path in (operation/'telemetry', applications/'telemetry-app'):
            io.write_new(path, b'partial')
            with self.assertRaises(ValueError): self.inspect(value)
            path.unlink(); path.symlink_to(value.case.root/'absent')
            with self.assertRaises(ValueError): self.inspect(value)
            path.unlink()
        nested = operation/'radio/.pending-HOLD.json'
        io.write_new(nested, b'{}')
        with self.assertRaises(ValueError): self.inspect(value)
        nested.unlink()
        self.inspect(value)

    def test_prefix_started_completion_and_payload_proofs_are_whole_and_exact(self):
        value = self.fixture()
        # For hypothetical reviewed-row variants, mock only the current sealed
        # source collaborator. Old source, STARTED/completions and payload reads
        # remain real; the positive integration methods use both real sources.
        sealed = ordinary_failure._sealed_component
        def selected_source(binding):
            cfg, runtime = sealed(binding)
            if binding == value.attempt.binding:
                cfg['reviewed_ordinary_failures'] = copy.deepcopy(value.attempt.cfg['reviewed_ordinary_failures'])
            return cfg, runtime
        context = patch.object(ordinary_failure, '_sealed_component', side_effect=selected_source)
        context.start(); self.addCleanup(context.stop)
        for name in ('preparation', 'radio'):
            for suffix in ('-started.json', '-complete.json'):
                path = value.operation/(name+suffix)
                original = path.read_bytes()
                path.write_bytes(original+b' ')
                with self.subTest(name=name, suffix=suffix), self.assertRaises(ValueError): self.inspect(value)
                path.unlink()
                with self.assertRaises((ValueError, OSError)): self.inspect(value)
                io.write_new(path, original)
        saved = copy.deepcopy(value.row['preceding_completions_sha256'])
        value.row['preceding_completions_sha256'].pop('radio')
        with self.assertRaisesRegex(ValueError, 'old phase prefix'): self.inspect(value)
        value.row['preceding_completions_sha256'] = copy.deepcopy(saved)
        complete = value.operation/'radio-complete.json'; original = complete.read_bytes()
        for mutate in (lambda c: c.update(extra=True), lambda c: c.update(binding={}),
                       lambda c: c['result'].update(status='failed'), lambda c: c['result'].update(changed=None),
                       lambda c: c['phase_inputs'].update(app='foreign')):
            changed = io.decode_json(original); mutate(changed)
            complete.write_bytes(io.encoded(changed))
            value.row['preceding_completions_sha256']['radio'] = io.sha(complete)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.inspect(value)
        complete.write_bytes(original); value.row['preceding_completions_sha256'] = copy.deepcopy(saved)
        payload = Path(value.old_binding['app_inputs_directory'])/value.case.app_id/'application.json'
        original = payload.read_bytes(); payload.write_bytes(original+b' ')
        with self.assertRaises(ValueError): self.inspect(value)
        payload.write_bytes(original)
        self.inspect(value)

    def test_current_state_canonical_source_and_persistent_runtime_owner_drift_refuse(self):
        value = self.fixture()
        for path in (Path(value.old_binding['app_inputs_directory']).parent/'site.json',
                     Path(value.old_binding['app_inputs_directory']).parent/'component-runtime.json'):
            original = path.read_bytes(); path.write_bytes(original+b' ')
            with self.subTest(path=path.name), self.assertRaises(ValueError): self.inspect(value)
            path.write_bytes(original)
        original_runtime = ordinary_failure._sealed_component
        def changed_sealed(binding):
            cfg, runtime = original_runtime(binding)
            if binding == value.attempt.binding:
                runtime['applications']['telemetry-app']['identity']['runtime_id'] = 'foreign-owner'
            return cfg, runtime
        with patch.object(ordinary_failure, '_sealed_component', side_effect=changed_sealed), \
             self.assertRaisesRegex(ValueError, 'persistent runtime owner'):
            self.inspect(value)
        for mutate in (lambda a: setattr(a, 'site_revision', 'f'*40),
                       lambda a: setattr(a, 'run_number', 777),
                       lambda a: setattr(a, 'workflow', ['foreign', 'workflow'])):
            before = (value.attempt.site_revision, value.attempt.run_number, value.attempt.workflow)
            mutate(value.attempt)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.inspect(value)
            value.attempt.site_revision, value.attempt.run_number, value.attempt.workflow = before
        self.inspect(value)


if __name__ == '__main__':
    unittest.main()
