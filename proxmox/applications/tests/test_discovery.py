"""The first CD merge can create only the declared new guest and public routes."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_deploy import deploy, fixture as site_fixture
from test_foundation import fixture as foundation_fixture
from test_plan import fixture as plan_fixture


def site(root):
    cfg = site_fixture(Path(root))
    cfg['guest']['interfaces'].append({'ipv4': '10.77.30.20/24', 'mac': '02:00:00:00:30:20'})
    cfg['app']['discovery_routes'] = [{'name': 'identity', 'host': 'sso.example.invalid',
                                      'url': 'http://10.77.30.20:9000'}]
    return cfg


class DiscoveryTests(unittest.TestCase):
    def test_legacy_hostname_alias_retains_the_same_backend_and_login(self):
        cfg = site(Path('/synthetic'))
        cfg['app']['discovery_routes'][0]['aliases'] = ['sso.legacy.invalid']
        labels = deploy.discovery.labels(cfg)
        self.assertEqual(labels['traefik.http.routers.identity.rule'],
                         '(Host(`sso.example.invalid`) || Host(`sso.legacy.invalid`))')
        cfg['app']['discovery_routes'][0]['aliases'].append('sso.example.invalid')
        with self.assertRaisesRegex(ValueError, 'unique'): deploy.discovery.labels(cfg)

    def test_native_node_red_authentik_login_does_not_get_a_second_proxy_login(self):
        cfg = {'app': {'kind': 'automation', 'node_red_authentication': 'authentik-oidc', 'discovery_routes': [
            {'name': 'homeassistant', 'host': 'ha.example.invalid', 'url': 'http://10.88.30.21:8123'},
            {'name': 'node-red', 'host': 'flows.example.invalid', 'url': 'http://10.88.30.21:1880', 'login': 'oidc'}]},
            'guest': {'interfaces': [{'ipv4': '10.88.30.21/24'}]}}
        labels = deploy.discovery.labels(cfg)
        self.assertEqual(labels['traefik.http.routers.node-red.middlewares'], 'security-headers@file')
        cfg['app'].pop('node_red_authentication')
        with self.assertRaises(ValueError): deploy.discovery.labels(cfg)

    def test_automation_notes_require_node_red_auth_and_leave_ha_login_alone(self):
        cfg = {'app': {'kind': 'automation', 'ingress_foundation': {'authentik_url':'http://10.88.30.20:9000'}, 'discovery_routes': [
            {'name':'homeassistant', 'host':'ha.example.invalid', 'url':'http://10.88.30.21:8123'},
            {'name':'node-red', 'host':'flows.example.invalid', 'url':'http://10.88.30.21:1880', 'login':'authentik'}]},
            'guest': {'interfaces':[{'ipv4':'10.88.30.21/24'}]}}
        labels = deploy.discovery.labels(cfg)
        self.assertEqual(labels['traefik.http.routers.node-red.middlewares'], 'security-headers@file,authentik@file')
        self.assertEqual(labels['traefik.http.routers.homeassistant.middlewares'], 'security-headers@file')
        self.assertEqual(labels['traefik.http.routers.node-red.priority'], '10')
        for login in (None, 'own', 'arbitrary@file', [], True):
            bad = copy.deepcopy(cfg)
            if login is None: bad['app']['discovery_routes'][1].pop('login')
            else: bad['app']['discovery_routes'][1]['login'] = login
            with self.subTest(login=login), self.assertRaises(ValueError): deploy.discovery.labels(bad)
        cfg['app']['discovery_routes'][0]['login'] = 'authentik'
        with self.assertRaises(ValueError): deploy.discovery.labels(cfg)
        cfg['app']['discovery_routes'][0].pop('login')
        cfg['app']['discovery_routes'][1]['name'] = 'unclassified-editor'
        cfg['app']['discovery_routes'][1]['login'] = 'own'
        with self.assertRaises(ValueError): deploy.discovery.labels(cfg)

    def test_node_red_requires_the_declared_ingress_authentik_middleware(self):
        cfg = {'app': {'kind': 'automation', 'discovery_routes': [
            {'name':'homeassistant', 'host':'ha.example.invalid', 'url':'http://10.88.30.21:8123'},
            {'name':'node-red', 'host':'flows.example.invalid', 'url':'http://10.88.30.21:1880', 'login':'authentik'}]},
            'guest': {'interfaces':[{'ipv4':'10.88.30.21/24'}]}}
        for settings in (None, {}, {'authentik_url':''}, {'authentik_url':'http://8.8.8.8:9000'}):
            bad = copy.deepcopy(cfg)
            if settings is not None: bad['app']['ingress_foundation'] = settings
            with self.subTest(settings=settings), self.assertRaisesRegex(ValueError, 'Authenti'):
                deploy.discovery.labels(bad)
        cfg['app']['ingress_foundation'] = {'authentik_url':'http://10.88.30.20:9000'}
        self.assertIn('authentik@file', deploy.discovery.labels(cfg)['traefik.http.routers.node-red.middlewares'])

    def test_outpost_notes_are_only_the_fixed_callback_on_the_identity_guest(self):
        cfg = {'app': {'kind':'identity', 'discovery_routes': [
            {'name':'node-red-outpost', 'host':'flows.example.invalid',
             'url':'http://10.88.30.20:9000', 'login':'outpost'}]},
            'guest': {'interfaces':[{'ipv4':'10.88.30.20/24'}]}}
        labels = deploy.discovery.labels(cfg)
        self.assertEqual(labels['traefik.http.routers.node-red-outpost.rule'],
                         'Host(`flows.example.invalid`) && PathPrefix(`/outpost.goauthentik.io/`)')
        self.assertEqual(labels['traefik.http.routers.node-red-outpost.priority'], '100')
        self.assertEqual(labels['traefik.http.routers.node-red-outpost.middlewares'], 'security-headers@file')
        for url in ('http://10.88.30.20:1880', 'http://10.88.30.20'):
            bad = copy.deepcopy(cfg); bad['app']['discovery_routes'][0]['url'] = url
            with self.subTest(url=url), self.assertRaises(ValueError): deploy.discovery.labels(bad)
        bad = copy.deepcopy(cfg); bad['app']['discovery_routes'][0].pop('login')
        with self.assertRaises(ValueError): deploy.discovery.labels(bad)
        cfg['app']['kind'] = 'automation'
        with self.assertRaises(ValueError): deploy.discovery.labels(cfg)

    def test_labels_expose_only_the_selected_guest_backend_and_standard_tls(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = site(root); before = copy.deepcopy(cfg)
            labels = deploy.discovery.labels(cfg)
            self.assertEqual(cfg, before)
            self.assertEqual(labels['traefik.http.services.identity.loadbalancer.server.url'], 'http://10.77.30.20:9000')
            self.assertEqual(labels['traefik.http.routers.identity.rule'], 'Host(`sso.example.invalid`)')
            self.assertEqual(labels['traefik.http.routers.identity.entrypoints'], 'websecure')
            self.assertEqual(labels['traefik.http.routers.identity.tls.certresolver'], 'letsencrypt')
            self.assertEqual(labels['traefik.http.routers.identity.middlewares'], 'security-headers@file')
            self.assertNotIn('forwardauth', json.dumps(labels))
            # NX211v0.7 checks ':' before '='. Colon syntax preserves http://.
            notes = '\n'.join(f'{key}: {value}' for key, value in sorted(labels.items()))
            parsed = dict(line.split(':', 1) for line in notes.splitlines())
            self.assertEqual({key: value.strip() for key, value in parsed.items()}, labels)

    def test_routes_reject_secret_fields_and_unselected_or_non_private_origins(self):
        bad_urls = ('http://10.77.30.21:9000', 'http://8.8.8.8:9000', 'http://127.0.0.1:9000',
                    'http://backend.example.invalid:9000', 'http://user:password@10.77.30.20:9000',
                    'https://10.77.30.20:9000', 'http://10.77.30.20:9000/private',
                    'http://10.77.30.20:9000?secret=bad', 'http://10.77.30.20:99999',
                    'http://10.77.30.20:9000\ntraefik.secret: bad')
        with tempfile.TemporaryDirectory() as root:
            for url in bad_urls:
                cfg = site(root); cfg['app']['discovery_routes'][0]['url'] = url
                with self.subTest(url=url), self.assertRaises(ValueError): deploy.validate(cfg)
            cfg = site(root); cfg['app']['discovery_routes'][0]['password'] = 'forbidden'
            with self.assertRaisesRegex(ValueError, 'only name, host and url'): deploy.validate(cfg)
            cfg = site(root); cfg['guest']['routing_labels'] = {'traefik.enable': 'true'}
            with self.assertRaisesRegex(ValueError, 'never arbitrary'): deploy.validate(cfg)

    def test_route_names_hosts_duplicates_and_unbounded_lists_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            for field, value in (('name', 'bad\nname'), ('host', 'Host(`injected`)'),
                                 ('host', '*.example.invalid'), ('name', ''), ('host', 'localhost')):
                cfg = site(root); cfg['app']['discovery_routes'][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError): deploy.validate(cfg)
            cfg = site(root); cfg['app']['discovery_routes'] *= 2
            with self.assertRaisesRegex(ValueError, 'unique'): deploy.validate(cfg)
            cfg = site(root); cfg['app']['discovery_routes'] *= 17
            with self.assertRaisesRegex(ValueError, 'at most 16'): deploy.validate(cfg)

    def test_legacy_guest_has_no_labels(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(deploy.discovery.labels(site_fixture(Path(root))), {})

    def test_merge_policy_accepts_only_three_fresh_known_creates(self):
        deploy.check_merge_create_plan(plan_fixture(), 'pve-lab', 6100)
        for action in ('update', 'no-op', 'delete'):
            value = plan_fixture(); value['resource_changes'][0]['change']['actions'] = [action]
            with self.subTest(action=action), self.assertRaises(ValueError):
                deploy.check_merge_create_plan(value, 'pve-lab', 6100)
        # A create action cannot disguise adoption of an existing target.
        value = plan_fixture()
        value['resource_changes'][0]['change']['before'] = copy.deepcopy(value['resource_changes'][0]['change']['after'])
        with self.assertRaisesRegex(ValueError, 'fresh creates'):
            deploy.check_merge_create_plan(value, 'pve-lab', 6100)

    def test_merge_policy_refuses_import_move_deferred_or_unknown_identity(self):
        alterations = (
            lambda v: v['resource_changes'][0]['change'].update(importing={'id': 'already-exists'}),
            lambda v: v['resource_changes'][0].update(previous_address='module.other.guest'),
            lambda v: v['resource_changes'][0]['change'].update(after_unknown={'vm_id': True}),
            lambda v: v.update(deferred_changes=[{'reason': 'unknown'}]),
            lambda v: v.update(complete=False),
            lambda v: v.update(errored=True),
            lambda v: v.update(resource_drift=[{'address': 'other'}]),
            lambda v: v['resource_changes'][0].update(type='unrelated_resource'),
            lambda v: v['resource_changes'][0].update(mode='data'),
        )
        for index, alter in enumerate(alterations):
            value = plan_fixture(); alter(value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                deploy.check_merge_create_plan(value, 'pve-lab', 6100)
        # Legacy reviewed convergence still accepts updates, as before.
        value = plan_fixture()
        for row in value['resource_changes']:
            row['change']['actions'] = ['update']
            row['change']['before'] = copy.deepcopy(row['change']['after'])
        deploy.check_plan(value, 'pve-lab', 6100)

    def test_external_secret_and_ca_changes_invalidate_plan_input_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cfg = site_fixture(root)
            (root / 'ca').write_text('synthetic PVE CA')
            stack = foundation_fixture(root, 'ingress')
            path = root / 'stack.json'; path.write_text(json.dumps(stack))
            cfg['app']['stack_config'] = str(path)
            baseline = deploy.input_hashes(cfg)
            self.assertIn(stack['foundation']['pve_ca_file'], baseline)
            self.assertIn(stack['foundation']['secret_files']['proxmox_token'], baseline)
            Path(stack['foundation']['secret_files']['proxmox_token']).write_text('changed synthetic token')
            self.assertNotEqual(deploy.input_hashes(cfg), baseline)

    def test_planning_persists_full_plan_and_compiles_notes_into_the_same_tfvars(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cfg = site(root)
            cfg['guest']['vmid'] = cfg['app']['vmid'] = 6100
            cfg['site']['node'] = 'pve-lab'
            cfg['ssh_public_keys'] = ['ssh-ed25519 AAAAsynthetic']
            config = root / 'site.json'; config.write_text(json.dumps(cfg))
            (root / 'api').write_text('synthetic-token'); (root / 'ca').write_text('synthetic-ca')
            value = plan_fixture()
            def quiet(command, *args):
                for argument in command:
                    if argument.startswith('-out='):
                        Path(argument.removeprefix('-out=')).write_bytes(b'synthetic-saved-plan')
            with patch.object(deploy, 'backup'), patch.object(deploy, 'quiet', side_effect=quiet), \
                    patch.object(deploy.subprocess, 'check_output', return_value=json.dumps(value).encode()):
                receipt = deploy.execute('plan', config)
            work = root / 'state' / '6100'
            self.assertEqual(json.loads((work / 'guest.tfplan.json').read_text()), value)
            self.assertEqual(receipt['plan_json_sha256'], deploy.sha(work / 'guest.tfplan.json'))
            self.assertEqual(receipt['plan_sha256'], deploy.sha(work / 'guest.tfplan'))
            variables = json.loads((work / 'tofu' / 'site.auto.tfvars.json').read_text())
            self.assertEqual(variables['guest']['routing_labels'], deploy.discovery.labels(cfg))
            self.assertEqual((work / 'guest.tfplan.json').stat().st_mode & 0o777, 0o600)

    def test_foundation_cannot_listen_on_an_address_outside_its_guest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cfg = site_fixture(root)
            stack = foundation_fixture(root, 'identity')
            path = root / 'stack.json'; path.write_text(json.dumps(stack))
            cfg['app'].update(kind='identity', stack_config=str(path))
            with self.assertRaisesRegex(ValueError, 'assigned to this guest'): deploy.validate(cfg)
            cfg['guest']['interfaces'].append({'ipv4': '198.18.30.20/24', 'mac': '02:00:00:00:30:20'})
            self.assertEqual(deploy.validate(cfg), 6101)


if __name__ == '__main__':
    unittest.main()
