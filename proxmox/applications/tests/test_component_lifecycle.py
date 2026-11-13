"""Current component lifecycle guards; guest/native execution is a conforming fake.

Static receiver inputs, binding7, AppPayload publication, locks, holds, receipts,
and local Git ancestry remain real. This is no native or CD acceptance claim.
"""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

F = Path(os.environ.get('HOMELAB_FRAMEWORK', Path(__file__).resolve().parents[3])).resolve()
sys.path[:0] = [str(F/'proxmox/applications'), str(F/'proxmox/applications/tests')]
import component_guest as contract
import component_inputs
import component_payload
import component_prepare
import component_ansible
import component_process_fixtures as fixtures
import deployment_inputs
import deploy
import deployment_state as state
import monitoring_inputs
import private_io as io
import proxmox_guest as pve
from fixtures import github_source


class ComponentLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source, self.revisions = github_source(self.root)
        self.cfg = fixtures.initialize(self.root,workspace=self.source,revision=self.revisions[0])
        self.work = self.root/'state/808'
        self.site = self.root/'packet.json'
        context = patch.dict(os.environ, {
            'GITHUB_RUN_ID':'777', 'GITHUB_RUN_ATTEMPT':'1', 'GITHUB_RUN_NUMBER':'777',
            'GITHUB_SHA':self.revisions[0], 'GITHUB_WORKSPACE':str(self.source),
            'GITHUB_REPOSITORY':'example/private-site',
            'HOMELAB_DEPLOYMENT_WORKFLOW':'example/private-site/.github/workflows/deploy.yml@refs/heads/main'})
        context.start(); self.addCleanup(context.stop)
        for context in (patch.object(deploy, 'bootstrap_closed'),
                        patch.object(deployment_inputs, 'source_hash', return_value='b'*64),
                        patch.object(component_prepare, 'prepare', side_effect=self.prepare_app),
                        patch.object(component_prepare, 'prepare_agent', side_effect=self.prepare_agent)):
            context.start(); self.addCleanup(context.stop)
        context = patch.object(pve, 'infrastructure', side_effect=lambda *args, **kwargs: {
            'changed':False, 'created':False, 'state_sha256':io.sha(self.work/'terraform.tfstate')})
        self.infra = context.start(); self.addCleanup(context.stop)
        context = patch.object(component_ansible, 'run_phase', side_effect=self.application)
        self.app = context.start(); self.addCleanup(context.stop)

    def fresh(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve()
        self.cfg=fixtures.initialize(self.root,fresh=True)
        self.work=self.root/'state/808';self.site=self.root/'packet.json'

    def publish(self):
        packet = io.read_json(self.site, private=True)
        packet['files']['site.json'] = io.encoded(self.cfg).decode()
        packet['identity'] = self.cfg['deployment']['input_identity']
        io.write_bytes(self.site, io.encoded(packet))

    @property
    def expected(self):
        cfg, binding = fixtures.prepare(self.root)
        self.assertEqual(cfg, self.cfg)
        self.assertEqual(binding['schema'], component_payload.BINDING_SCHEMA)
        self.assertEqual(len(binding), 7)
        return binding

    def prepare_app(self, cfg, app_id, environment, *, attempt):
        self.assertEqual(app_id, 'database')
        self.assertEqual(environment, {})
        return fixtures.payload(cfg)

    def prepare_agent(self, cfg, environment):
        self.assertEqual(environment, {})
        return component_payload.prepare(component_inputs.app_directory(cfg, create=True),
            cfg['deployment']['input_identity'], 'agent',
            {'application.json':io.encoded({'schema':'homelab-component-agent-input-v1',
                'monitoring':cfg['app']['monitoring']})})

    def application(self, cfg, site, work, operation, binding, phase, *, payload, previously_owned):
        self.assertEqual(binding['schema'], component_payload.BINDING_SCHEMA)
        self.assertEqual(len(binding), 7)
        started = io.read_json(operation/(phase+'-started.json'), private=True)
        if phase == 'preparation':
            self.assertIsNone(payload)
            self.assertNotIn('phase_inputs', started)
        else:
            self.assertIsInstance(payload, component_payload.AppPayload)
            self.assertEqual(payload.app, cfg['deployment']['payload_phases'][phase])
            self.assertEqual(started['phase_inputs'], payload.check())
        return {'status':'passed', 'changed':False}

    def phase(self, phase):
        return deploy.run(phase, self.site, inputs=self.root/'inputs', environment={})

    def run_all(self):
        for phase in ['infrastructure', *contract.phases(self.cfg)]:
            self.phase(phase)

    def test_preparation_precedes_app_and_unchanged_repeat_contacts_no_target(self):
        self.phase("infrastructure")
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.phase("mariadb")
        self.app.assert_not_called()
        self.phase("preparation")
        self.phase("mariadb")
        for phase in ["infrastructure", "preparation", "mariadb"]:
            self.assertFalse(self.phase(phase)["target_contacted"])
        self.assertEqual(self.infra.call_count, 1)
        self.assertEqual(self.app.call_count, 2)
        self.assertFalse((self.work / "ORDINARY-HOLD.json").exists())

    def test_monitoring_is_one_final_phase_and_cannot_be_skipped_or_replayed(self):
        directory = Path(self.cfg['deployment']['input_directory'])
        self.cfg['app']['monitoring'] = {
            'hostname':'fixture-pve-808', 'psk_identity':'fixture-pve-808',
            'server_active':'198.18.25.36:10051', 'server_vmid':816,
            'server_hostname':'zabbix', 'profiles':['linux'],
            'credential_file':str(directory/'applications/agent/monitoring-agent.json')}
        self.cfg['deployment']['phases'].append('zabbix-agent')
        self.cfg['deployment']['payload_phases']['zabbix-agent'] = 'agent'
        provider = self.root/'provider'; provider.mkdir(mode=0o700)
        for leaf, value in (
            ('owner.json', {'schema':'homelab-zabbix-access-v1',
                'endpoint':self.cfg['site']['api_endpoint'], 'node':self.cfg['site']['node'],
                'address':'198.18.25.36', 'backup_source':'example.invalid:/backups'}),
            ('READY.json', {'identity':monitoring_inputs.TOKEN_ID, 'read_only':True}),
            ('token.json', {'identity':monitoring_inputs.TOKEN_ID,
                           'token':monitoring_inputs.TOKEN_ID+'=synthetic-token'})):
            io.write_new(provider/leaf, io.encoded(value))
        context = patch.object(monitoring_inputs, 'PROVIDER', provider/'token.json')
        context.start(); self.addCleanup(context.stop)
        self.publish()
        self.assertEqual(contract.phases(self.cfg), ['preparation', 'mariadb', 'zabbix-agent'])
        previous=self.work/'ordinary-complete.json'
        previous_bytes,previous_inode=previous.read_bytes(),previous.stat().st_ino
        self.phase('infrastructure')
        self.phase('preparation')
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.phase('zabbix-agent')
        self.phase('mariadb')
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())
        self.assertEqual(previous.read_bytes(),previous_bytes)
        self.assertEqual(previous.stat().st_ino,previous_inode)
        self.phase('zabbix-agent')
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
        self.assertEqual([call.args[-1] for call in self.app.call_args_list],
                         ['preparation', 'mariadb', 'zabbix-agent'])
        self.assertFalse(self.phase('zabbix-agent')['target_contacted'])

    def test_unmonitored_agent_is_explicitly_unselected_and_contacts_no_target(self):
        result = self.phase('zabbix-agent')
        self.assertEqual(result, {'status':'not_selected', 'vmid':808, 'changed':False, 'target_contacted':False})
        self.infra.assert_not_called(); self.app.assert_not_called()
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())

    def test_infrastructure_and_preparation_failures_hold_and_never_replay(self):
        self.infra.side_effect = ValueError("native failure")
        with self.assertRaises(ValueError):
            self.phase("infrastructure")
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.phase("infrastructure")
        self.assertEqual(self.infra.call_count, 1)
        self.app.assert_not_called()

    def test_interrupted_application_is_durable_even_for_same_run(self):
        self.phase("infrastructure")
        self.app.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.phase("preparation")
        with self.assertRaises(ValueError):
            self.phase("preparation")
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.phase("mariadb")
        self.assertEqual(self.app.call_count, 1)
        self.assertTrue((self.work / "ORDINARY-HOLD.json").exists())

    def test_another_run_and_input_state_drift_cannot_advance_an_attempt(self):
        self.phase("infrastructure")
        held = (self.work / "ORDINARY-HOLD.json").read_bytes()
        with (
            patch.dict(
                os.environ, {"GITHUB_RUN_ID": "778", "GITHUB_RUN_NUMBER": "778"}
            ),
            self.assertRaises(ValueError),
        ):
            self.phase("preparation")
        prepared = Path(self.cfg['deployment']['input_directory'])/'site.json'
        before = prepared.read_bytes()
        prepared.write_bytes(before+b'\n')
        with self.assertRaises(ValueError):
            self.phase("preparation")
        prepared.write_bytes(before)
        (self.work / "terraform.tfstate").write_text("changed state")
        with self.assertRaises(ValueError):
            self.phase("preparation")
        self.assertEqual((self.work / "ORDINARY-HOLD.json").read_bytes(), held)
        self.app.assert_not_called()

    def test_existing_and_group_holds_include_dangling_symlinks(self):
        for folder, name in [
            (self.work, "FOUNDATION-HOLD.json"),
            (self.root / "state/database-network-cutover-held", "HOLD.json"),
        ]:
            folder.mkdir(mode=0o700, exist_ok=True)
            hold = folder / name
            hold.symlink_to(folder / "absent")
            with self.assertRaises(ValueError):
                self.phase("infrastructure")
            self.infra.assert_not_called()
            hold.unlink()

    def test_state_change_during_phase_preserves_the_hold_and_unfinished_phase(self):
        self.phase("infrastructure")

        def change(*args, **kwargs):
            (self.work / "terraform.tfstate").write_text(
                "external change during application"
            )
            return {"status": "passed", "changed": False}

        self.app.side_effect = change
        with self.assertRaises(ValueError):
            self.phase("preparation")
        self.assertTrue((self.work / "ORDINARY-HOLD.json").exists())
        self.assertFalse(
            (self.work / "ordinary-777-1/preparation-complete.json").exists()
        )

    def test_missing_backend_with_completed_custody_cannot_recreate_on_new_inputs(self):
        self.run_all()
        (self.work / "terraform.tfstate").unlink()
        old_directory = Path(self.cfg['deployment']['input_directory'])
        new_directory = old_directory.parent/('b'*64)
        self.cfg['deployment'].update(input_identity='b'*64,
            input_directory=str(new_directory), runtime_file=str(new_directory/'component-runtime.json'))
        self.publish()
        self.infra.side_effect = None
        self.infra.return_value = {
            "created": True,
            "changed": True,
            "state_sha256": "unwanted new backend",
        }
        with (
            patch.dict(
                os.environ, {"GITHUB_RUN_ID": "778", "GITHUB_RUN_NUMBER": "778"}
            ),
            self.assertRaises(ValueError),
        ):
            self.phase("infrastructure")
        self.assertEqual(self.infra.call_count, 1)
        self.assertFalse((self.work / "ordinary-778-1").exists())

    def test_symlinked_backend_is_not_an_authoritative_state_file(self):
        (self.work / "terraform.tfstate").unlink()
        target = self.root / "other-state"
        target.write_text("unrelated backend")
        (self.work / "terraform.tfstate").symlink_to(target)
        with self.assertRaises(ValueError):
            self.phase("infrastructure")
        self.infra.assert_not_called()
        self.assertEqual(target.read_text(), "unrelated backend")

    def test_missing_backend_preserves_each_kind_of_prior_custody(self):
        self.fresh()
        (self.work / "terraform.tfstate").unlink()
        for name in [
            "ordinary-complete.json",
            "ordinary-776-1",
            "ssh-trust.json",
            "host-key-evidence.json",
            "plan.json",
            "applied.json",
            "started.json",
            "rollout-complete.json",
            "foundation-complete.json",
            "terraform.tfstate.backup",
        ]:
            with self.subTest(name=name):
                evidence = self.work / name
                evidence.symlink_to(self.work / "absent")
                with self.assertRaises(ValueError):
                    with state.DeploymentAttempt(self.cfg, self.expected, []):
                        pass
                self.assertTrue(evidence.is_symlink())
                evidence.unlink()
        self.infra.assert_not_called()

    def test_empty_guest_custody_allows_first_creation_but_directory_backend_refuses(
        self,
    ):
        self.fresh()
        backend = self.work / "terraform.tfstate"
        backend.unlink()
        with state.DeploymentAttempt(self.cfg, self.expected, []):
            pass
        backend.mkdir()
        with self.assertRaises(ValueError):
            self.phase("infrastructure")
        self.infra.assert_not_called()
        self.assertTrue(backend.is_dir())

    def test_locks_are_exclusive_and_released_after_exception(self):
        with state.DeploymentAttempt(
            self.cfg, self.expected, ["preparation", "mariadb"]
        ):
            with self.assertRaises(BlockingIOError):
                with state.DeploymentAttempt(
                    self.cfg, self.expected, ["preparation", "mariadb"]
                ):
                    pass
        with state.DeploymentAttempt(
            self.cfg, self.expected, ["preparation", "mariadb"]
        ):
            pass

    def test_changed_state_invalidates_a_completed_noop_and_retains_old_install_records(
        self,
    ):
        install = self.work / "rollout-complete.json"
        install.write_text("original installation evidence")
        install_inode=install.stat().st_ino
        self.run_all()
        io.write_bytes(self.work / "terraform.tfstate", fixtures.backend_bytes(serial=3))
        with patch.dict(
            os.environ, {"GITHUB_RUN_ID": "778", "GITHUB_RUN_NUMBER": "778"}
        ), self.assertRaisesRegex(ValueError, "backend changed"):
            self.phase("infrastructure")
        self.assertEqual(self.infra.call_count, 1)
        self.assertEqual(install.read_text(), "original installation evidence")
        self.assertEqual(install.stat().st_ino,install_inode)

    def test_new_merges_reconcile_and_older_or_replayed_runs_cannot_roll_back(self):
        self.run_all()
        old = (self.work / "ordinary-777-1/complete.json").read_bytes()
        with patch.dict(
            os.environ,
            {
                "GITHUB_RUN_ID": "778",
                "GITHUB_RUN_NUMBER": "778",
                "GITHUB_SHA": self.revisions[1],
            },
        ):
            self.run_all()
        self.assertEqual(self.infra.call_count, 2)
        self.assertEqual(self.app.call_count, 4)
        self.assertEqual((self.work / "ordinary-777-1/complete.json").read_bytes(), old)
        receipt = (self.work / "ordinary-complete.json").read_bytes()
        for metadata in (
            {"GITHUB_RUN_ID": "776", "GITHUB_RUN_NUMBER": "776"},
            {
                "GITHUB_RUN_ID": "778",
                "GITHUB_RUN_NUMBER": "778",
                "GITHUB_RUN_ATTEMPT": "2",
            },
            {
                "GITHUB_RUN_ID": "780",
                "GITHUB_RUN_NUMBER": "780",
                "GITHUB_SHA": self.revisions[0],
            },
            {
                "GITHUB_RUN_ID": "779",
                "GITHUB_RUN_NUMBER": "779",
                "HOMELAB_DEPLOYMENT_WORKFLOW": "other/site/.github/workflows/deploy.yml@refs/heads/main",
            },
        ):
            with patch.dict(os.environ, metadata), self.assertRaises(ValueError):
                self.phase("infrastructure")
        self.assertEqual((self.work / "ordinary-complete.json").read_bytes(), receipt)
        self.assertEqual(self.infra.call_count, 2)
        self.assertFalse((self.work / "ORDINARY-HOLD.json").exists())

    def test_missing_workflow_sequence_cannot_select_an_attempt(self):
        for metadata in (
            {"GITHUB_RUN_NUMBER": ""},
            {"GITHUB_SHA": ""},
            {"GITHUB_WORKSPACE": ""},
            {"GITHUB_REPOSITORY": ""},
            {"HOMELAB_DEPLOYMENT_WORKFLOW": ""},
        ):
            with patch.dict(os.environ, metadata), self.assertRaises(ValueError):
                self.phase("infrastructure")
        self.infra.assert_not_called()
        self.assertFalse((self.work / "ORDINARY-HOLD.json").exists())

    def test_changed_backend_cannot_replay_a_completed_run(self):
        self.run_all()
        io.write_bytes(self.work / "terraform.tfstate", fixtures.backend_bytes(serial=3))
        with self.assertRaisesRegex(ValueError, "backend changed"):
            self.phase("infrastructure")
        self.assertEqual(self.infra.call_count, 1)
        self.assertFalse((self.work / "ORDINARY-HOLD.json").exists())


if __name__ == '__main__': unittest.main()
