"""Actual file boundaries, metadata preservation and one-use route activation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_browser as component
import component_image as shared
from test_ingress_browser import browser, settings


def update_packet(original=b'{"http":{}}', vmid=712):
    route = settings()
    return {'schema': 'homelab-ingress-browser-update-v1', 'revision': 'a'*40, 'vmid': vmid,
            'plan_sha256': 'b'*64, 'state_sha256': 'c'*64, 'foundation_complete_sha256': 'd'*64,
            'compose_sha256': 'e'*64, 'runtime_sha256': 'f'*64,
            'shared_before_sha256': hashlib.sha256(original).hexdigest(),
            'shared_after_sha256': hashlib.sha256(browser.candidate(original, route)).hexdigest(),
            'image': 'traefik@sha256:' + '1'*64, 'route': route,
            'startup': {'gate_sha256':'4'*64,'docker_dependency_sha256':'5'*64,
                        'routing_unit_sha256':'6'*64,'routing_dependency_sha256':'7'*64,
                        'interfaces':['eth0','eth1','eth2','eth3']},
            'network_evidence': {'path': f'/var/lib/homelab-applications/{vmid}/admission/network.json', 'sha256': '2'*64},
            'policy_evidence': {'path': f'/var/lib/homelab-applications/{vmid}/admission/policy.json', 'sha256': '3'*64}}


class PacketTests(unittest.TestCase):
    def test_exact_packet_rejects_missing_prerequisites_widening_and_mutable_source(self):
        value = update_packet()
        self.assertEqual(browser.packet(value), value)
        for key, bad in [('revision', 'main'), ('image', 'traefik:latest'), ('vmid', 900),
                         ('network_evidence', {'path': '/etc/passwd', 'sha256': '2'*64}),
                         ('policy_evidence', {'path': '/var/lib/homelab-applications/999/admission/a', 'sha256': '2'*64})]:
            with self.subTest(key=key), self.assertRaises(ValueError): browser.packet({**value, key: bad})
        with self.assertRaises(ValueError): browser.packet({**value, 'allow_restart': True})


@unittest.skipUnless(os.geteuid() == 0, 'Actual ownership checks run in the isolated Linux fixture')
class ComponentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name); self.config = root/'shared.yml'; self.static = root/'traefik.yml'
        self.compose, self.identity = root/'compose.yml', root/'identity.json'
        self.original = b'{"tls":{"options":{"default":{"minVersion":"VersionTLS12"}}},"http":{}}\n'
        self.selected = update_packet(self.original)
        self.config.write_bytes(self.original); self.config.chmod(0o400)
        self.static.write_text(json.dumps({'providers': {'file': {'filename': '/etc/traefik/shared.yml', 'watch': True}},
            'entryPoints': {'websecure': {'address': '10.88.40.33:443'}},
            'certificatesResolvers': {'letsencrypt': {'acme': {'storage': '/private/unchanged'}}}}))
        self.static.chmod(0o400)
        self.compose.write_text(json.dumps({'name': 'homelab-ingress', 'services': {'traefik': {
            'image': self.selected['image'], 'volumes': [
                {'source': str(self.config), 'target': '/etc/traefik/shared.yml', 'read_only': True},
                {'source': str(self.static), 'target': '/etc/traefik/traefik.yml', 'read_only': True}]}}}))
        self.compose.chmod(0o600)
        self.identity.write_text('{"vmid":712,"kind":"ingress"}'); self.identity.chmod(0o600)
        self.selected.update(compose_sha256=component.digest(self.compose.read_bytes()),
                             runtime_sha256=component.digest(self.static.read_bytes()))
        self.commands = []; self.started = 'same-start'
        self.units={name:root/name for name in ('gate','docker_dependency','routing_unit','routing_dependency')}
        for name,path in self.units.items():
            path.write_text('fixture '+name);path.chmod(0o644)
            self.selected['startup'][name+'_sha256']=component.digest(path.read_bytes())
        for p in (patch.multiple(component, CONFIG=self.config, STATIC=self.static, STATE=root/'state'),
                  patch.object(component,'STARTUP_FILES',self.units),
                  patch.multiple(shared, COMPOSE=self.compose, IDENTITY=self.identity, command=self.command),
                  patch.object(component, 'backend_ready'), patch.object(component, 'route_ready')):
            obj = p.start(); self.addCleanup(p.stop)
        self.before = {p: p.read_bytes() for p in (self.compose, self.static)}

    def command(self, argv):
        self.commands.append(argv)
        if 'ps' in argv: return ('a'*64 + '\n').encode()
        if 'inspect' in argv: return json.dumps({'State': {'Running': True, 'StartedAt': self.started},
                                               'Config': {'Image': self.selected['image']}}).encode()
        if argv[:2]==['systemctl','show']:
            value='Requires=homelab-network-ready.service\nAfter=homelab-network-ready.service\nActiveState=active\nNeedDaemonReload=no\nMainPID=123\nActiveEnterTimestampMonotonic=456\n'
            if argv[2]=='homelab-network-ready.service':
                value+='ExecStart={ argv[]=/usr/lib/systemd/systemd-networkd-wait-online --ipv4 --timeout=30 --interface=eth0:routable --interface=eth1:routable --interface=eth2:routable --interface=eth3:routable ; }\n'
            return value.encode()
        raise AssertionError('No mutating subprocess may be issued')

    def test_install_preserves_inode_metadata_and_other_configs_then_verifies_only(self):
        os.setxattr(self.config, 'user.route-fixture', b'preserve')
        before = self.config.stat()
        self.assertTrue(component.run(self.selected)['changed'])
        after = self.config.stat()
        self.assertEqual((before.st_ino, before.st_uid, before.st_gid, before.st_mode),
                         (after.st_ino, after.st_uid, after.st_gid, after.st_mode))
        self.assertEqual(os.getxattr(self.config, 'user.route-fixture'), b'preserve')
        self.assertEqual(self.config.read_bytes(), browser.candidate(self.original, self.selected['route']))
        self.assertFalse(component.run(self.selected, True)['changed'])
        for path, data in self.before.items(): self.assertEqual(path.read_bytes(), data)
        self.assertFalse(any(any(x in argv for x in ('up', 'pull', 'restart', 'stop')) for argv in self.commands))
        with self.assertRaises(FileExistsError): component.run(self.selected)

    def test_failure_after_write_retains_hold_and_original_and_cannot_replay(self):
        with patch.object(component, 'route_ready', side_effect=ValueError('synthetic redirect failure')):
            with self.assertRaises(ValueError): component.run(self.selected)
        operation = component.STATE/'influx-browser-v1'
        self.assertEqual((operation/'shared-before.json').read_bytes(), self.original)
        self.assertTrue((operation/'HOLD.json').is_file())
        self.assertFalse((operation/'complete.json').exists())
        altered = {**self.selected, 'revision': 'f'*40}
        with self.assertRaises(FileExistsError): component.run(altered)
        with self.assertRaises(OSError): component.run(self.selected, True)

    def test_healthy_but_restarted_container_is_not_accepted(self):
        with patch.object(component, 'route_ready', side_effect=lambda route: setattr(self, 'started', 'different')):
            with self.assertRaises(ValueError): component.run(self.selected)
        self.assertTrue((component.STATE/'influx-browser-v1/HOLD.json').is_file())

    def test_static_drift_refuses_before_any_file_change(self):
        self.selected['runtime_sha256'] = '0'*64
        with self.assertRaises(ValueError): component.run(self.selected)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(component.STATE.exists())

    def test_network_not_ready_holds_before_changing_the_watched_file(self):
        with patch.object(component, 'backend_ready', side_effect=ValueError('No admitted interface')):
            with self.assertRaises(ValueError): component.run(self.selected)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertTrue((component.STATE/'influx-browser-v1/HOLD.json').is_file())

    def test_prior_three_interface_startup_gate_refuses_before_route_write(self):
        original=self.command
        def prior_gate(argv):return original(argv).replace(b' --interface=eth3:routable',b'')
        with patch.object(shared,'command',side_effect=prior_gate):
            with self.assertRaises(ValueError):component.run(self.selected)
        self.assertEqual(self.config.read_bytes(),self.original)
        self.assertFalse(component.STATE.exists())

    def test_startup_file_drift_is_not_repaired_by_route_installation(self):
        path=self.units['gate'];path.write_text('unreviewed gate')
        with self.assertRaises(ValueError):component.run(self.selected)
        self.assertEqual(path.read_text(),'unreviewed gate')
        self.assertEqual(self.config.read_bytes(),self.original)


if __name__ == '__main__': unittest.main()
