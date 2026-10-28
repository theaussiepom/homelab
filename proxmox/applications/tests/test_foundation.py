"""File-based configuration contracts; no real identity, DNS or Proxmox calls."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_render import render, fixture as legacy_fixture, image


def fixture(directory, kind):
    root = Path(directory)
    names = {'identity': ['secret_key', 'postgresql_password', 'smtp_password'],
             'db-tools': ['oauth_client_secret'],
             'ingress': ['proxmox_token', 'cloudflare_dns_token']}[kind]
    paths = {}
    for name in names:
        path = root / (name + '.secret')
        path.write_text('synthetic-$' + name)
        path.chmod(0o600)
        paths[name] = str(path)
    cfg = legacy_fixture(kind) if kind != 'db-tools' else {
        'kind': kind, 'guest_memory_mib': 1024, 'services': {'pgadmin': image()},
        'pgadmin_bind_address': '198.18.30.32'}
    selected = {'version': 1, 'secret_files': paths}
    if kind == 'identity':
        for key in ('authentik_secret_key', 'postgresql_password', 'postgresql_host', 'postgresql_user', 'postgresql_database'):
            cfg.pop(key)
        selected.update(bind_address='198.18.30.20', postgresql_host='198.18.30.23',
                        postgresql_user='authentik', postgresql_database='authentik')
        for name in ('server', 'worker'):
            cfg['services'][name]['environment'] = {'AUTHENTIK_EMAIL__HOST': 'smtp.example.invalid',
                'AUTHENTIK_EMAIL__FROM': 'sso@example.invalid', 'AUTHENTIK_EMAIL__USE_TLS': 'true'}
    elif kind == 'db-tools':
        selected.update(public_url='https://pgadmin.example.invalid',
                        identity_url='https://sso.example.invalid', oauth_client_id='same-client',
                        oauth_name='authentik', provider_slug='pgadmin4')
    else:
        ca = root / 'pve-ca.pem'
        ca.write_text('-----BEGIN CERTIFICATE-----\nsynthetic-public-fixture\n-----END CERTIFICATE-----\n')
        selected.update(bind_address='198.18.40.33', proxmox_url='https://198.18.25.10:8006',
                        proxmox_token_id='root@pam!traefik-provider', acme_email='operator@example.invalid',
                        acme_dns_resolvers=['198.18.40.2:53', '198.18.100.4:53'],
                        pve_ca_file=str(ca))
    cfg['foundation'] = selected
    return cfg


class FoundationTests(unittest.TestCase):
    def test_optional_node_red_middleware_uses_the_selected_private_identity_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = fixture(directory, 'ingress')
            cfg['foundation']['authentik_url'] = 'http://10.88.30.20:9000'
            shared = json.loads(next(a['content'] for a in render.foundation_files(cfg) if a['path'] == 'shared.yml'))
            auth = shared['http']['middlewares']['authentik']['forwardAuth']
            self.assertEqual(auth['address'], 'http://10.88.30.20:9000/outpost.goauthentik.io/auth/traefik')
            self.assertFalse(auth['trustForwardHeader'])
            for url in ('http://8.8.8.8:9000', 'http://127.0.0.1:9000',
                        'http://user:password@10.88.30.20:9000', 'http://10.88.30.20:9000/private'):
                cfg['foundation']['authentik_url'] = url
                with self.subTest(url=url), self.assertRaises(ValueError): render.foundation_files(cfg)

    def test_authentik_origin_rejects_empty_query_and_fragment_delimiters(self):
        with tempfile.TemporaryDirectory() as directory:
            for suffix in ('?', '#', '/?', '/#'):
                cfg = fixture(directory, 'ingress')
                cfg['foundation']['authentik_url'] = 'http://10.88.30.20:9000' + suffix
                with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                    render.foundation_files(cfg)

    def test_identity_references_files_and_binds_only_the_selected_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = fixture(directory, 'identity'); before = copy.deepcopy(cfg)
            services = render.compose(cfg)['services']
            self.assertEqual(cfg, before)
            for name in ('server', 'worker'):
                service = services[name]
                self.assertEqual(service['environment']['AUTHENTIK_SECRET_KEY'],
                                 'file:///run/secrets/authentik-secret-key')
                self.assertEqual(service['environment']['AUTHENTIK_POSTGRESQL__PASSWORD'],
                                 'file:///run/secrets/postgresql-password')
                self.assertEqual(service['environment']['AUTHENTIK_EMAIL__PASSWORD'],
                                 'file:///run/secrets/smtp-password')
                self.assertEqual(service['user'], '1000')
                self.assertEqual(service['depends_on'], {'redis': {'condition': 'service_healthy'}})
            self.assertEqual(services['server']['ports'], ['198.18.30.20:9000:9000'])
            self.assertNotIn('ports', services['worker'])
            self.assertNotIn('ports', services['redis'])
            self.assertNotIn('synthetic-$', json.dumps(services))
            artifacts = render.foundation_files(cfg)
            self.assertEqual({a['path'] for a in artifacts},
                             {'authentik-secret-key', 'postgresql-password', 'smtp-password'})
            self.assertTrue(all((a['uid'], a['gid'], a['mode']) == (1000, 1000, '0400') for a in artifacts))
            self.assertEqual(artifacts[0]['content'], 'synthetic-$secret_key')

    def test_pgadmin_config_uses_original_client_with_new_https_origins(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = fixture(directory, 'db-tools')
            services = render.compose(cfg)['services']
            service = services['pgadmin']
            self.assertEqual(service['ports'], ['198.18.30.32:80:80'])
            self.assertEqual(service['environment']['PGADMIN_LISTEN_ADDRESS'], '0.0.0.0')
            self.assertEqual(service['user'], '5050')
            self.assertNotIn('synthetic-$', json.dumps(services))
            artifacts = {a['path']: a for a in render.foundation_files(cfg)}
            self.assertTrue(all((a['uid'], a['gid'], a['mode']) == (5050, 5050, '0400')
                                for a in artifacts.values()))
            namespace = {}
            with patch('pathlib.Path.read_text', return_value='synthetic-private-client-secret'):
                exec(compile(artifacts['pgadmin-config.py']['content'], '<generated>', 'exec'), namespace)
            self.assertIs(namespace['SERVER_MODE'], True)
            self.assertEqual(namespace['AUTHENTICATION_SOURCES'], ['oauth2'])
            provider = namespace['OAUTH2_CONFIG'][0]
            self.assertEqual(provider['OAUTH2_CLIENT_ID'], 'same-client')
            self.assertEqual(provider['OAUTH2_CLIENT_SECRET'], 'synthetic-private-client-secret')
            self.assertTrue(provider['OAUTH2_SSL_CERT_VERIFICATION'])
            self.assertEqual(provider['OAUTH2_SERVER_METADATA_URL'],
                             'https://sso.example.invalid/application/o/pgadmin4/.well-known/openid-configuration')
            self.assertNotIn('synthetic-private-client-secret', artifacts['pgadmin-config.py']['content'])

    def test_traefik_uses_pinned_provider_trusted_api_and_file_token_without_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = fixture(directory, 'ingress')
            service = render.compose(cfg)['services']['traefik']
            self.assertEqual(service['network_mode'], 'host')
            self.assertEqual(service['environment']['CF_DNS_API_TOKEN_FILE'], '/run/secrets/cloudflare-dns-token')
            self.assertNotIn('docker.sock', json.dumps(service))
            self.assertNotIn('synthetic-$', json.dumps(service))
            artifacts = {a['path']: a for a in render.foundation_files(cfg)}
            static = json.loads(artifacts['traefik.yml']['content'])
            provider = static['providers']['plugin']['traefik-proxmox-provider']
            self.assertEqual(provider['apiToken'], 'synthetic-$proxmox_token')
            self.assertEqual(provider['apiValidateSSL'], 'true')
            self.assertEqual(static['experimental']['plugins']['traefik-proxmox-provider']['version'], 'v0.7.0')
            self.assertEqual(static['experimental']['plugins']['traefik-proxmox-provider']['hash'],
                             '9e3b91e0ba79fc27dd2587e8b92db725a424a9c21cb17cfcf07b1ef6e354efd7')
            self.assertTrue(static['experimental']['abortOnPluginFailure'])
            challenge = static['certificatesResolvers']['letsencrypt']['acme']['dnsChallenge']
            self.assertEqual(challenge['resolvers'], ['198.18.40.2:53', '198.18.100.4:53'])
            self.assertEqual(challenge['propagation'], {'disableANSChecks': True, 'requireAllRNS': True})
            self.assertNotIn('disableChecks', challenge['propagation'])
            self.assertNotIn('docker', static['providers'])
            self.assertEqual(static['entryPoints']['websecure']['address'], '198.18.40.33:443')
            self.assertEqual(static['entryPoints']['health']['address'], '127.0.0.1:8082')
            self.assertEqual(static['ping']['entryPoint'], 'health')
            self.assertFalse(static['api']['dashboard'])
            self.assertTrue(all((a['uid'], a['gid'], a['mode']) == (0, 0, '0400') for a in artifacts.values()))
            self.assertEqual(set(render.foundation_source_files(cfg)),
                             set(cfg['foundation']['secret_files'].values()) | {cfg['foundation']['pve_ca_file']})

    def test_acme_requires_explicit_unique_recursive_dns_addresses_on_port_53(self):
        with tempfile.TemporaryDirectory() as directory:
            for value in (None, [], '198.18.40.2:53', ['dns.example.invalid:53'],
                          ['127.0.0.1:53'], ['0.0.0.0:53'], ['198.18.40.2:853'],
                          ['198.18.40.2:53', '198.18.40.2:53'],
                          ['198.18.40.2:53', '198.18.40.3:53', '198.18.40.4:53', '198.18.40.5:53']):
                cfg = fixture(directory, 'ingress')
                if value is None:
                    cfg['foundation'].pop('acme_dns_resolvers')
                else:
                    cfg['foundation']['acme_dns_resolvers'] = value
                with self.subTest(value=value), self.assertRaises(ValueError):
                    render.compose(cfg)
            cfg = fixture(directory, 'ingress')
            cfg['foundation']['acme_dns_resolvers'] = ['198.18.40.2:53']
            artifacts = {item['path']: item for item in render.foundation_files(cfg)}
            static = json.loads(artifacts['traefik.yml']['content'])
            self.assertEqual(static['certificatesResolvers']['letsencrypt']['acme']['dnsChallenge']['resolvers'],
                             ['198.18.40.2:53'])

    def test_closed_schema_rejects_inline_secret_listener_and_tls_bypasses(self):
        with tempfile.TemporaryDirectory() as directory:
            for kind in ('identity', 'db-tools', 'ingress'):
                cfg = fixture(directory, kind)
                cfg['foundation']['disable_tls_verification'] = True
                with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'closed foundation'):
                    render.compose(cfg)
            cfg = fixture(directory, 'identity'); cfg['authentik_secret_key'] = 'inline-forbidden'
            with self.assertRaisesRegex(ValueError, 'inline credentials'): render.compose(cfg)
            cfg = fixture(directory, 'db-tools')
            cfg['services']['pgadmin']['environment']['PGADMIN_CONFIG_SERVER_MODE'] = 'False'
            with self.assertRaisesRegex(ValueError, 'inline overrides'): render.compose(cfg)
            cfg = fixture(directory, 'ingress'); cfg['foundation']['proxmox_url'] = 'http://api.example.invalid'
            with self.assertRaisesRegex(ValueError, 'HTTPS'): render.compose(cfg)
            cfg = fixture(directory, 'identity'); cfg['foundation']['bind_address'] = '0.0.0.0'
            with self.assertRaisesRegex(ValueError, 'selected IPv4'): render.compose(cfg)

    def test_secret_inputs_refuse_symlinks_permissions_empty_values_and_newlines(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = fixture(directory, 'db-tools')
            path = Path(cfg['foundation']['secret_files']['oauth_client_secret'])
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'private'): render.foundation_files(cfg)
            path.chmod(0o600)
            for value in ('', '\n', 'two\nlines', 'nul\0byte'):
                path.write_text(value)
                with self.subTest(value=value), self.assertRaises(ValueError): render.foundation_files(cfg)
            path.write_text('synthetic-preserved-$secret\n')
            self.assertEqual(render.foundation_files(cfg)[1]['content'], 'synthetic-preserved-$secret')
            link = Path(directory) / 'link'; link.symlink_to(path)
            cfg['foundation']['secret_files']['oauth_client_secret'] = str(link)
            with self.assertRaises(OSError): render.foundation_files(cfg)

    def test_cli_writes_private_artifacts_and_metadata_without_secret_output(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = fixture(directory, 'ingress')
            source = Path(directory) / 'stack.json'; source.write_text(json.dumps(cfg)); source.chmod(0o600)
            output = Path(directory) / 'rendered'
            result = subprocess.run([sys.executable, str(Path(render.__file__)), '--config', str(source),
                                     '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, '')
            self.assertFalse((output / 'routes.yml').exists())
            manifest = json.loads((output / 'runtime-files.json').read_text())
            self.assertEqual(len(manifest), 4)
            for item in manifest:
                self.assertNotIn('content', item)
                self.assertEqual((output / item['path']).stat().st_mode & 0o777, 0o600)
                self.assertTrue((output / item['path']).is_file())
            self.assertEqual((output / 'compose.yml').stat().st_mode & 0o777, 0o600)
            # Re-rendering must also tighten an existing file, not merely pass
            # mode0600 to O_CREAT (which leaves pre-existing modes unchanged).
            (output / 'traefik.yml').chmod(0o644)
            repeated = subprocess.run([sys.executable, str(Path(render.__file__)), '--config', str(source),
                                       '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(repeated.returncode, 0, repeated.stderr)
            self.assertEqual((output / 'traefik.yml').stat().st_mode & 0o777, 0o600)

    def test_legacy_stack_has_no_new_external_files(self):
        cfg = legacy_fixture('identity')
        self.assertEqual(render.foundation_files(cfg), [])
        self.assertEqual(render.foundation_source_files(cfg), [])


if __name__ == '__main__':
    unittest.main()
