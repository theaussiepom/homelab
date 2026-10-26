"""Exercise service placement, credential isolation and restored-image rules."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('app_render', ROOT / 'render.py')
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)


def image():
    """Provide invented but well-formed pinned image input."""
    return {'image': 'example.invalid/service@sha256:' + '1' * 64,
            'memory_mib': 256, 'cpus': 1, 'pids_limit': 128,
            'environment': {}, 'extra_mounts': []}


def fixture(kind):
    """Provide only synthetic configuration and deliberately non-real routes."""
    cfg = {'kind': kind, 'data_root': '/srv/homelab/data', 'guest_memory_mib': 4096,
           'timezone': 'Etc/UTC', 'services': {}}
    names = {'automation': ['homeassistant', 'node_red', 'mqtt'],
             'identity': ['server', 'worker', 'redis'],
             'dns': ['pihole', 'unbound'], 'ingress': ['traefik']}[kind]
    cfg['services'] = {name: image() for name in names}
    if kind == 'identity':
        cfg.update(postgresql_host='pg.example.invalid', authentik_secret_key='synthetic-only-key',
                   postgresql_user='authentik', postgresql_password='synthetic-only-password', postgresql_database='authentik')
    if kind == 'ingress':
        cfg.update(homeassistant_host='ha.example.invalid', node_red_host='flows.example.invalid',
                   identity_host='auth.example.invalid', homeassistant_url='http://198.18.100.20:8123',
                   node_red_url='http://198.18.100.20:1880', identity_url='http://198.18.30.20:9000')
    return cfg


class RenderTests(unittest.TestCase):
    """Check application behaviour and guard against the incidents already seen."""

    def test_capture_mounts_use_a_directory_inside_the_data_disk(self):
        """A freshly formatted volume may already contain filesystem recovery files."""
        cfg = fixture('dns')
        del cfg['data_root']
        services = render.compose(cfg)['services']
        self.assertEqual(services['pihole']['volumes'], ['/srv/homelab/data/pihole:/etc/pihole'])
        self.assertEqual(services['unbound']['volumes'], ['/srv/homelab/data/unbound:/opt/unbound/etc/unbound'])

    def test_automation_shares_one_guest_and_keeps_discovery(self):
        """HA, Node-RED and authenticated MQTT remain together, without radio moves."""
        result = render.compose(fixture('automation'))
        self.assertEqual(set(result['services']), {'homeassistant', 'node_red', 'mqtt'})
        self.assertEqual(result['services']['homeassistant']['network_mode'], 'host')
        self.assertNotIn('privileged', result['services']['homeassistant'])
        self.assertEqual(result['services']['homeassistant']['restart'], 'no')
        self.assertGreaterEqual(int(result['services']['homeassistant']['stop_grace_period'][:-1]), 60)
        self.assertFalse(any('avahi' in str(s) for s in result['services'].values()))

    def test_container_budgets_cannot_exceed_the_guest_budget(self):
        """Sharing a guest cannot hide memory overcommit inside it."""
        cfg = fixture('automation'); cfg['guest_memory_mib'] = 512
        with self.assertRaises(ValueError): render.compose(cfg)
        for invalid in (0, -1, True, '256'):
            cfg = fixture('automation'); cfg['services']['mqtt']['memory_mib'] = invalid
            with self.assertRaises(ValueError): render.compose(cfg)

    def test_images_require_a_digest_or_a_verified_archive_contract(self):
        """Do not replace existing custom images with floating vendor tags."""
        cfg = fixture('automation'); cfg['services']['homeassistant']['image'] = 'homeassistant:latest'
        with self.assertRaises(ValueError): render.compose(cfg)
        cfg['services']['homeassistant']['image'] = 'sha256:' + '2' * 64
        with self.assertRaises(ValueError): render.compose(cfg)
        cfg['services']['homeassistant'].update(archive='/private/ha.tar', archive_sha256='3' * 64)
        result = render.compose(cfg)
        self.assertEqual(result['services']['homeassistant']['pull_policy'], 'never')

    def test_extra_mounts_preserve_helpers_without_host_control_sockets(self):
        """The frozen startup helper can be retained without the broken Avahi dependency."""
        cfg = fixture('automation')
        cfg['services']['homeassistant']['extra_mounts'] = [
            {'source': '/srv/homelab/data/ha-startup', 'target': '/startup', 'read_only': True}]
        self.assertIn('/srv/homelab/data/ha-startup:/startup:ro', render.compose(cfg)['services']['homeassistant']['volumes'])
        for path in ('/run/avahi-daemon/socket', '/var/run/docker.sock', '/etc/shadow'):
            bad = copy.deepcopy(cfg); bad['services']['homeassistant']['extra_mounts'][0]['source'] = path
            with self.assertRaises(ValueError): render.compose(bad)

    def test_identity_keeps_its_postgresql_and_redis_dependencies(self):
        """A migration of the installed Authentik version must not silently drop Redis."""
        result = render.compose(fixture('identity'))
        self.assertEqual(set(result['services']), {'server', 'worker', 'redis'})
        self.assertEqual(result['services']['server']['environment']['AUTHENTIK_POSTGRESQL__HOST'], 'pg.example.invalid')
        self.assertEqual(result['services']['worker']['environment']['AUTHENTIK_REDIS__HOST'], 'redis')
        # Server/worker may bind the same internal metrics ports: isolate their networks.
        for service in result['services'].values():
            self.assertNotIn('network_mode', service)
        self.assertNotIn('ports', result['services']['redis'])
        self.assertNotIn('ports', result['services']['worker'])

    def test_only_node_red_gets_authentik_forward_auth(self):
        """HA uses its own login; Node-RED requires Authentik, including its outpost route."""
        result = render.ingress(fixture('ingress'))
        routers = result['http']['routers']
        self.assertNotIn('middlewares', routers['homeassistant'])
        self.assertEqual(routers['node_red']['middlewares'], ['authentik'])
        self.assertNotIn('middlewares', routers['outpost'])
        self.assertEqual(routers['outpost']['service'], 'identity')

    def test_dns_does_not_replace_the_routers_dhcp_authority(self):
        """Pi-hole provides DNS while the current router continues to own DHCP."""
        result = render.compose(fixture('dns'))
        self.assertEqual(result['services']['pihole']['environment']['FTLCONF_dhcp_active'], 'false')
        self.assertEqual(result['services']['unbound']['ports'], ['127.0.0.1:5335:53/tcp', '127.0.0.1:5335:53/udp'])

    def test_database_and_radio_containers_are_not_added_to_the_app_stack(self):
        """Native database and physical radio ownership stay separate."""
        for kind in ('mariadb', 'postgresql', 'influxdb', 'radio'):
            with self.assertRaises(ValueError): render.compose({'kind': kind})

    def test_literal_dollars_are_preserved_for_compose(self):
        """Compose interpolation must not rewrite restored passwords or settings."""
        cfg = fixture('automation'); cfg['services']['mqtt']['environment']['EXAMPLE'] = 'synthetic-$literal'
        self.assertEqual(render.compose(cfg)['services']['mqtt']['environment']['EXAMPLE'], 'synthetic-$$literal')

    def test_mdns_helper_capability_and_mount_are_explicit(self):
        cfg = fixture('automation'); ha = cfg['services']['homeassistant']
        ha['environment']['HOMELAB_HA_IPV4'] = '198.18.100.20'
        with self.assertRaises(ValueError): render.compose(cfg)
        ha['cap_add'] = ['NET_ADMIN']
        ha['extra_mounts'] = [{'source': '/srv/homelab/data/ha-startup', 'target': '/startup', 'read_only': True}]
        self.assertEqual(render.compose(cfg)['services']['homeassistant']['cap_add'], ['NET_ADMIN'])
        cfg['services']['mqtt']['cap_add'] = ['NET_ADMIN']
        with self.assertRaises(ValueError): render.compose(cfg)

    def test_preserved_commands_keep_container_variables_literal(self):
        cfg = fixture('automation'); node = cfg['services']['node_red']
        node.update(command=['sh', '-c', 'echo $CONTAINER_VALUE'], entrypoint=None, user='${LITERAL_USER}')
        result = render.compose(cfg)['services']['node_red']
        self.assertEqual(result['command'][-1], 'echo $$CONTAINER_VALUE')
        self.assertIsNone(result['entrypoint']); self.assertEqual(result['user'], '$${LITERAL_USER}')
        for field, value in [('user', ['root']), ('command', [1]), ('entrypoint', True)]:
            bad = fixture('automation'); bad['services']['node_red'][field] = value
            with self.assertRaises(ValueError): render.compose(bad)


if __name__ == '__main__':
    unittest.main()
