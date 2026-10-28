"""One merge admits one fresh saved plan; later runs never reinstall a guest."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import foundation_cd as cd

GUESTS = {'ingress': (212, 'traefik'), 'identity': (211, 'security'), 'db-tools': (202, 'db-tools')}
SITE = {'node': 'pve-lab', 'api_endpoint': 'https://10.88.25.10:8006/'}


class Deployment:
    hold_name = 'FOUNDATION-HOLD.json'
    def __init__(self):
        self.calls, self.checked = [], []
        self.source = 'a' * 64
        self.fail = None
        self.interrupt = False
        self.tamper_json = False
        self.actions = ['create']
        self.before = None

    def validate(self, cfg):
        return cfg['guest']['vmid']

    def source_hash(self):
        return self.source

    def input_hashes(self, cfg):
        stack = json.loads(Path(cfg['app']['stack_config']).read_text())
        paths = [cfg['app']['stack_config'], cfg['paths']['ca_file']]
        paths += list(stack['foundation']['secret_files'].values())
        return {path: cd.digest(Path(path).read_bytes()) for path in sorted(paths)}

    def check_merge_create_plan(self, value, node, vmid):
        self.checked.append((value, node, vmid))
        if any(row['change']['actions'] != ['create'] or row['change']['before'] is not None
               for row in value['resource_changes']):
            raise ValueError('Strict public policy refused an existing target or destruction')

    def execute(self, action, site, approved=None):
        self.calls.append((action, site, approved))
        cfg = json.loads(site.read_text())
        vmid = cfg['guest']['vmid']
        work = Path(cfg['paths']['state_root']) / str(vmid)
        marker = json.loads((work / self.hold_name).read_text())
        if marker['step'] != action:
            raise AssertionError('Adapter hold must precede the shared operation')
        if self.fail == action:
            if self.interrupt:
                raise KeyboardInterrupt
            raise ValueError('Synthetic child failure must not become a retry')
        if action == 'plan':
            binary = b'synthetic-existing-saved-plan'
            value = {'resource_changes': [{'address': 'module.guest.' + name,
                     'change': {'before': self.before, 'actions': self.actions,
                                'after': {'node_name': cfg['site']['node'], 'vm_id': vmid}}}
                     for name in ('container', 'firewall_options', 'firewall_rules')]}
            raw = cd.encoded(value)
            plan = {'vmid': vmid, 'creates_guest': self.before is None and self.actions == ['create'],
                    'site_sha256': cd.digest(site.read_bytes()), 'source_sha256': self.source,
                    'input_hashes': self.input_hashes(cfg), 'plan_sha256': cd.digest(binary),
                    'plan_json_sha256': cd.digest(raw)}
            cd.write_new(work / 'guest.tfplan', binary)
            cd.write_new(work / 'guest.tfplan.json', raw if not self.tamper_json else b'{"modified": true}')
            cd.write_new(work / 'plan.json', cd.encoded(plan))
            return plan
        if action == 'deploy':
            if cd.digest((work / 'guest.tfplan').read_bytes()) != approved:
                raise AssertionError('Deploy must receive the original binary-plan fingerprint')
            result = {'step': 'deploy', 'status': 'passed', 'vmid': vmid, 'plan_sha256': approved}
            cd.write_new(work / 'applied.json', cd.encoded({'plan_sha256': approved}))
            cd.write_new(work / 'rollout-complete.json', cd.encoded(result))
            return result
        if action == 'verify':
            return {'step': 'verify', 'status': 'passed', 'vmid': vmid}
        raise AssertionError(action)


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inputs = self.root / 'inputs'; self.inputs.mkdir(mode=0o700)
        self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.bundles = self.root / 'bundles'; self.bundles.mkdir()
        (self.bundles / 'bindings.json').write_bytes(cd.encoded({'site': SITE, 'guests': GUESTS}))
        self.ca = self.root / 'pve-ca.pem'; self.ca.write_text('synthetic public CA')
        self.provider = self.root / 'provider.json'
        cd.write_new(self.provider, cd.encoded({'schema': 'homelab-service-discovery-v1',
            'identity': 'root@pam!homelab-traefik-212', 'token': 'root@pam!homelab-traefik-212=synthetic-token-value'}))
        self.env = {'AUTHENTIK_SECRET_KEY': 'synthetic-authentik-key', 'AUTHENTIK_POSTGRES_PASSWORD': 'synthetic-db-password',
                    'PGADMIN_OAUTH_SECRET': 'synthetic-oauth-secret', 'CLOUDFLARE_DNS_TOKEN': 'synthetic-cf-token'}
        for name, (vmid, hostname) in GUESTS.items():
            directory = self.bundles / name; directory.mkdir()
            destination = self.inputs / ('foundation-' + name)
            secrets = {key: str(destination / cd.SECRETS[name][key][0]) for key in cd.REQUIRED[name]}
            foundation = {'version': 1, 'secret_files': secrets}
            if name == 'ingress':
                foundation.update({'proxmox_token_id': 'root@pam!homelab-traefik-212',
                                   'proxmox_url': SITE['api_endpoint'], 'pve_ca_file': str(self.ca)})
            cfg = {'site': SITE, 'guest': {'vmid': vmid, 'hostname': hostname},
                   'app': {'vmid': vmid, 'hostname': hostname, 'kind': name, 'stack_config': str(destination / 'stack.json')},
                   'paths': {'state_root': str(self.state), 'ca_file': str(self.ca)}}
            (directory / 'site.json').write_bytes(cd.encoded(cfg))
            (directory / 'stack.json').write_bytes(cd.encoded({'kind': name, 'foundation': foundation}))
        self.selection = {'schema': cd.SCHEMA, 'targets': {name: {'vmid': value[0], 'policy': 'merge-create-only-v1'}
                                                         for name, value in GUESTS.items()}}
        (self.bundles / 'rollout.json').write_bytes(cd.encoded(self.selection))
        self.deployment = Deployment()

    def run_cd(self, name='identity'):
        return cd.run(name, self.deployment, self.bundles, self.inputs, self.state, self.provider, self.env)

    def test_initial_run_passes_one_saved_plan_to_deploy_without_replanning(self):
        result = self.run_cd()
        self.assertEqual([call[0] for call in self.deployment.calls], ['plan', 'deploy'])
        work = self.state / '211'
        self.assertEqual(self.deployment.calls[-1][2], cd.digest((work / 'guest.tfplan').read_bytes()))
        self.assertEqual(result['plan_sha256'], self.deployment.calls[-1][2])
        self.assertEqual(self.deployment.checked[0][1:], ('pve-lab', 211))
        self.assertFalse((work / 'FOUNDATION-HOLD.json').exists())

    def test_completed_run_only_verifies_and_does_not_rewrite_inputs_or_plan(self):
        self.run_cd()
        files = list((self.inputs / 'foundation-identity').iterdir()) + list((self.state / '211').glob('guest.tfplan*'))
        stamps = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in files}
        self.deployment.calls.clear()
        result = self.run_cd()
        self.assertEqual(result['step'], 'verify')
        self.assertEqual([call[0] for call in self.deployment.calls], ['verify'])
        self.assertEqual({path: (path.read_bytes(), path.stat().st_mtime_ns) for path in files}, stamps)

    def test_failed_or_interrupted_deploy_keeps_hold_and_never_replays(self):
        for interrupt in (False, True):
            with self.subTest(interrupt=interrupt), tempfile.TemporaryDirectory() as temporary:
                original = self.state
                self.state = Path(temporary) / 'state'; self.state.mkdir(mode=0o700)
                cfg_path = self.bundles / 'identity/site.json'
                cfg = json.loads(cfg_path.read_text()); cfg['paths']['state_root'] = str(self.state)
                cfg_path.write_bytes(cd.encoded(cfg))
                self.deployment = Deployment(); self.deployment.fail = 'deploy'; self.deployment.interrupt = interrupt
                # Use a distinct input root because selected site bytes changed.
                old_inputs = self.inputs
                self.inputs = Path(temporary) / 'inputs'; self.inputs.mkdir(mode=0o700)
                cfg['app']['stack_config'] = str(self.inputs / 'foundation-identity/stack.json')
                cfg_path.write_bytes(cd.encoded(cfg))
                stack_path = self.bundles / 'identity/stack.json'
                stack = json.loads(stack_path.read_text())
                stack['foundation']['secret_files'] = {key: str(self.inputs / 'foundation-identity' / cd.SECRETS['identity'][key][0])
                                                       for key in cd.REQUIRED['identity']}
                stack_path.write_bytes(cd.encoded(stack))
                with self.assertRaises(KeyboardInterrupt if interrupt else ValueError): self.run_cd()
                hold = self.state / '211/FOUNDATION-HOLD.json'
                self.assertEqual(json.loads(hold.read_text())['step'], 'deploy')
                calls = list(self.deployment.calls)
                data = (self.inputs / 'foundation-identity/postgresql-password').read_bytes()
                with self.assertRaisesRegex(ValueError, 'no automatic retry'): self.run_cd()
                self.assertEqual(self.deployment.calls, calls)
                self.assertEqual((self.inputs / 'foundation-identity/postgresql-password').read_bytes(), data)
                self.state, self.inputs = original, old_inputs

    def test_changed_secret_refuses_without_overwriting_the_original(self):
        self.run_cd()
        path = self.inputs / 'foundation-identity/postgresql-password'
        original = path.read_bytes()
        self.env['AUTHENTIK_POSTGRES_PASSWORD'] = 'changed-value'
        self.deployment.calls.clear()
        with self.assertRaisesRegex(ValueError, 'inputs changed'): self.run_cd()
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.deployment.calls, [])

    def test_empty_environment_secret_stops_before_private_bundle_or_plan(self):
        self.env['AUTHENTIK_SECRET_KEY'] = ''
        with self.assertRaisesRegex(ValueError, 'secret is missing'): self.run_cd()
        self.assertFalse((self.inputs / 'foundation-identity').exists())
        self.assertEqual(self.deployment.calls, [])

    def test_provider_value_is_split_only_from_the_expected_retained_identity(self):
        self.run_cd('ingress')
        path = self.inputs / 'foundation-ingress/proxmox-token'
        self.assertEqual(path.read_text(), 'synthetic-token-value')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_unknown_provider_identity_and_arbitrary_secret_selection_are_refused(self):
        original = self.provider.read_bytes()
        value = json.loads(original); value['identity'] = 'root@pam!some-other-token'
        self.provider.write_bytes(cd.encoded(value))
        with self.assertRaisesRegex(ValueError, 'declared discovery credential'): self.run_cd('ingress')
        self.provider.write_bytes(original)
        stack_path = self.bundles / 'ingress/stack.json'
        stack = json.loads(stack_path.read_text())
        stack['foundation']['secret_files']['other'] = str(self.root / 'any-secret')
        stack_path.write_bytes(cd.encoded(stack))
        with self.assertRaisesRegex(ValueError, 'fixed foundation secret'): self.run_cd('ingress')
        self.assertEqual(self.deployment.calls, [])

    def test_unknown_existing_phase_receipt_is_never_adopted(self):
        work = self.state / '211'; work.mkdir(mode=0o700)
        cd.write_new(work / 'applied.json', b'{}')
        with self.assertRaisesRegex(ValueError, 'no adoption'): self.run_cd()
        self.assertFalse((self.inputs / 'foundation-identity').exists())
        self.assertEqual(self.deployment.calls, [])

    def test_destroy_replace_and_existing_target_plans_never_reach_deploy(self):
        for actions, before in [(['delete', 'create'], {}), (['delete'], {}), (['update'], {}), (['no-op'], {})]:
            with self.subTest(actions=actions), tempfile.TemporaryDirectory() as temporary:
                # Planning failures hold the attempt, so each policy case uses
                # a fresh synthetic fixture instead of clearing a failed hold.
                test = FoundationTests('test_initial_run_passes_one_saved_plan_to_deploy_without_replanning')
                test.setUp()
                try:
                    test.deployment.actions, test.deployment.before = actions, before
                    with test.assertRaises(ValueError): test.run_cd()
                    test.assertEqual([call[0] for call in test.deployment.calls], ['plan'])
                    test.assertTrue((test.state / '211/FOUNDATION-HOLD.json').exists())
                finally:
                    test.doCleanups()

    def test_saved_json_tampering_is_refused_before_the_strict_policy_and_deploy(self):
        self.deployment.tamper_json = True
        with self.assertRaisesRegex(ValueError, 'single saved foundation plan'): self.run_cd()
        self.assertEqual([call[0] for call in self.deployment.calls], ['plan'])
        self.assertEqual(self.deployment.checked, [])

    def test_source_or_trust_input_change_prevents_repeat_even_with_same_profile(self):
        self.run_cd()
        self.deployment.source = 'b' * 64
        self.deployment.calls.clear()
        with self.assertRaisesRegex(ValueError, 'Completed foundation rollout'): self.run_cd()
        self.assertEqual(self.deployment.calls, [])
        self.deployment.source = 'a' * 64
        self.ca.write_text('changed trust input')
        with self.assertRaisesRegex(ValueError, 'Completed foundation rollout'): self.run_cd()
        self.assertEqual(self.deployment.calls, [])

    def test_verification_failure_is_held_without_reinstall_or_automatic_replay(self):
        self.run_cd()
        self.deployment.calls.clear(); self.deployment.fail = 'verify'
        with self.assertRaises(ValueError): self.run_cd()
        self.assertEqual([call[0] for call in self.deployment.calls], ['verify'])
        with self.assertRaisesRegex(ValueError, 'no automatic retry'): self.run_cd()
        self.assertEqual([call[0] for call in self.deployment.calls], ['verify'])

    def test_unrelated_host_or_guest_identity_is_refused_before_installing_inputs(self):
        path = self.bundles / 'identity/site.json'
        cfg = json.loads(path.read_text()); cfg['site']['api_endpoint'] = 'https://10.88.25.99:8006/'
        path.write_bytes(cd.encoded(cfg))
        with self.assertRaisesRegex(ValueError, 'rendered foundation identity'): self.run_cd()
        self.assertFalse((self.inputs / 'foundation-identity').exists())
        self.assertEqual(self.deployment.calls, [])

    def test_result_and_receipts_do_not_print_or_contain_secret_values(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output): result = self.run_cd()
        visible = output.getvalue() + json.dumps(result)
        for path in (self.state / '211').glob('*.json'):
            visible += path.read_text()
        for secret in self.env.values(): self.assertNotIn(secret, visible)


if __name__ == '__main__':
    unittest.main()
