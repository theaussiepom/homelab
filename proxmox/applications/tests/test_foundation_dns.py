"""Narrow foundation DNS admission, preservation and fail-closed tests."""
import copy
import json
import sys
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import foundation_dns as cd
import site_config

SETTINGS = site_config.render(site_config.read(site_config.ROOT / 'examples/foundation.site.example.json'))['dns-settings.json']
cd.configure(SETTINGS)


UNBOUND_SOURCE = ('remote-control:\n    control-enable: yes\nserver:\n    # keep this comment exactly\n'
    + ''.join(f'    local-zone: "{name}" redirect\n' for name in (*cd.REDIRECTS, *cd.UNCHANGED))
    + ''.join(f'    local-data: "{name} A {address}"\n' for name, address in {
        'old.example.org': '192.168.200.254', 'lab.example.org': '192.168.200.254', **cd.UNCHANGED}.items()))


class MergeTests(unittest.TestCase):
    def test_additional_broker_host_keeps_other_aliases_and_redirects(self):
        settings = copy.deepcopy(SETTINGS)
        settings['extra_records'] = {'broker.mqtt': '10.88.40.21'}
        try:
            cd.configure(settings)
            before = ['192.168.200.240 broker.mqtt old-broker.example.org', '10.88.25.2 nas']
            after = cd.merge_hosts(before)
            self.assertIn('192.168.200.240 old-broker.example.org', after)
            self.assertIn('10.88.40.21 broker.mqtt', after)
            self.assertEqual(cd.ACME_EXCEPTIONS, tuple(SETTINGS['acme_exceptions']))
            bad = copy.deepcopy(settings); bad['extra_records'] = {next(iter(SETTINGS['unchanged'])): '10.88.40.21'}
            with self.assertRaises(ValueError): cd.configure(bad)
        finally:
            cd.configure(SETTINGS)

    def test_exact_pinned_ftl_unquoted_array_output_and_json_are_supported(self):
        records = ['10.1.2.3 sample.example.invalid sample-alias', '2001:db8::1 ipv6.example.invalid']
        actual = '[ 10.1.2.3 sample.example.invalid sample-alias, 2001:db8::1 ipv6.example.invalid ]\n'
        self.assertEqual(cd.parse_hosts(actual), records)
        self.assertEqual(cd.parse_hosts(json.dumps(records)), records)
        self.assertEqual(cd.parse_hosts('[ ]\n'), [])
        for value in ('warning\n[ 10.1.2.3 host ]', '[ 10.1.2.3 host, ]', '[ 10.1.2.3 host;evil ]', '{}'):
            with self.subTest(value=value), self.assertRaises(ValueError): cd.parse_hosts(value)

    def test_changes_only_selected_names_and_preserves_shared_line_aliases(self):
        before = ['192.168.200.5   sso.lab.example.org old-proxy.lab.example.org',
                  '192.168.200.5 pgadmin.lab.example.org other.lab.example.org',
                  '10.88.25.2\tnas.lab.example.org nas',
                  '2001:db8::1 untouched.lab.example.org']
        original = copy.deepcopy(before)
        after = cd.merge_hosts(before)
        self.assertEqual(before, original)
        self.assertEqual(after, ['192.168.200.5 old-proxy.lab.example.org',
                                '192.168.200.5 other.lab.example.org',
                                before[2], before[3], '10.88.40.33 sso.lab.example.org',
                                '10.88.40.33 pgadmin.lab.example.org'])
        self.assertEqual(cd.merge_hosts(after), after)

    def test_already_correct_shared_aliases_whitespace_and_order_remain_exact(self):
        before = ['10.88.25.2 nas.lab.example.org',
                  '10.88.40.33\tSSO.lab.example.org.\tpgadmin.lab.example.org proxy-alias.lab.example.org']
        self.assertEqual(cd.merge_hosts(before), before)

    def test_duplicate_selected_records_and_ipv6_are_removed_without_dropping_aliases(self):
        before = ['10.88.40.33 sso.lab.example.org',
                  '192.168.200.5 SSO.lab.example.org other',
                  '2001:db8::5 pgadmin.lab.example.org ipv6-only']
        self.assertEqual(cd.merge_hosts(before), ['192.168.200.5 other', '2001:db8::5 ipv6-only',
                         '10.88.40.33 sso.lab.example.org', '10.88.40.33 pgadmin.lab.example.org'])

    def test_invalid_record_arrays_are_refused_instead_of_silently_repaired(self):
        for value in (None, {}, [None], ['garbage'], ['not-an-ip host'],
                      ['10.1.2.3 sso.lab.example.org\ninjected'], ['10.1.2.3 name;command'],
                      ['10.1.2.3 valid'] * 4097):
            with self.subTest(value=str(value)[:70]), self.assertRaises(ValueError): cd.merge_hosts(value)


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.identity = self.root / 'identity.json'; self.compose = self.root / 'compose.json'
        self.identity.write_text(json.dumps({'vmid': 6101, 'hostname': 'dns', 'kind': 'dns'}))
        self.compose.write_text(json.dumps({'name': 'homelab-dns', 'services': {'pihole': {}, 'unbound': {'volumes': ['/srv/homelab/data/unbound:/opt/unbound/etc/unbound']}}}))
        self.identity.chmod(0o600); self.compose.chmod(0o600)
        self.state = self.root / 'evidence'
        self.hosts = ['192.168.200.5 sso.lab.example.org old-alias', '10.88.25.2 nas']
        self.commands = []; self.failure = None; self.override = False
        self.unbound = UNBOUND_SOURCE
        read, directory = cd.private_read, cd.owned_directory
        self.patches = patch.multiple(cd, REMOTE_ROOT=self.state, IDENTITY=self.identity, COMPOSE=self.compose,
            private_read=lambda path, owner=None: read(path, owner=os.getuid()),
            owned_directory=lambda path, owner=None: directory(path, owner=os.getuid()), command=self.command,
            read_unbound=lambda: (self.unbound, {}), stage_unbound=lambda *args: None,
            apply_unbound=self.apply_unbound, verify_unbound=lambda *args: None)
        self.patches.start(); self.addCleanup(self.patches.stop)
        self.uid = patch.object(cd.os, 'geteuid', return_value=0); self.uid.start(); self.addCleanup(self.uid.stop)

    def apply_unbound(self, before, metadata, after, candidate):
        changed = self.unbound != after
        self.unbound = after
        return changed

    def command(self, argv):
        self.commands.append(argv)
        if argv[:3] == ['docker', 'inspect', '--format']:
            return json.dumps(['FTLCONF_dns_hosts=override'] if self.override else ['FTLCONF_dns_dnssec=false'])
        suffix = argv[len(cd.COMPOSE_ARGV):]
        if suffix == ['ps', '-q', 'pihole']: return 'a' * 64 + '\n'
        if suffix[:6] == ['exec', '-T', 'pihole', 'pihole-FTL', '--config', 'dns.hosts']:
            if len(suffix) == 6: return json.dumps(self.hosts)
            # The durable marker and private recovery evidence must precede
            # the first FTL configuration write, not an exception handler.
            self.assertTrue((self.state / 'HOLD.json').is_file())
            backups = list(self.state.glob('*/hosts-before.json'))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
            if self.failure == 'write': raise ValueError('synthetic FTL failure')
            self.hosts = json.loads(suffix[-1]); return ''
        if suffix == ['exec', '-T', 'pihole', 'pihole', 'reloaddns']:
            if self.failure == 'reload': raise ValueError('synthetic reload failure')
            return ''
        if suffix[:4] == ['exec', '-T', 'pihole', 'dig']:
            return ('192.168.200.5' if self.failure == 'verify' else cd.RECORDS[suffix[-2]]) + '\n'
        raise AssertionError('Unexpected synthetic command')

    def mutations(self):
        return [a for a in self.commands if 'dns.hosts' in a and len(a) > len(cd.COMPOSE_ARGV) + 6]

    def test_success_backs_up_updates_reloads_and_then_becomes_verify_only(self):
        before = list(self.hosts)
        result = cd.remote_run()
        self.assertTrue(result['changed']); self.assertTrue(result['verified'])
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(json.loads(next(self.state.glob('*/hosts-before.json')).read_text())['hosts'], before)
        self.assertFalse((self.state / 'HOLD.json').exists())
        self.commands.clear()
        result = cd.remote_run()
        self.assertFalse(result['changed']); self.assertEqual(self.mutations(), [])
        self.assertFalse(any('reloaddns' in argv for argv in self.commands))
        self.assertEqual(sum('dig' in argv for argv in self.commands), 2)

    def test_each_mutation_or_verification_failure_keeps_hold_and_prevents_replay(self):
        for failure in ('write', 'reload', 'verify'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                self.state = Path(temp) / 'state'
                with patch.object(cd, 'REMOTE_ROOT', self.state):
                    self.failure = failure; self.commands.clear()
                    self.hosts = ['192.168.200.5 sso.lab.example.org old-alias']
                    with self.assertRaises(ValueError): cd.remote_run()
                    self.assertTrue((self.state / 'HOLD.json').exists())
                    count = len(self.mutations())
                    with self.assertRaisesRegex(ValueError, 'no automatic retry'): cd.remote_run()
                    self.assertEqual(len(self.mutations()), count)

    def test_environment_control_or_wrong_guest_prevents_any_change(self):
        self.override = True
        with self.assertRaisesRegex(ValueError, 'controlled by environment'): cd.remote_run()
        self.assertEqual(self.mutations(), []); self.assertFalse(self.state.exists())
        self.override = False; self.commands.clear()
        self.identity.write_text(json.dumps({'vmid': 900, 'hostname': 'deploy', 'kind': 'dns'}))
        with self.assertRaisesRegex(ValueError, 'not the commissioned'): cd.remote_run()
        self.assertEqual(self.commands, [])

    def test_unbound_candidate_or_reload_failure_keeps_combined_hold_before_pihole_write(self):
        for phase in ('candidate', 'reload'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                self.state = Path(temporary) / 'state'
                self.hosts = ['192.168.200.5 sso.lab.example.org old-alias']
                self.unbound = UNBOUND_SOURCE
                self.commands.clear()
                def fail_reload(*args):
                    self.apply_unbound(*args)
                    raise ValueError('synthetic Unbound reload failure')
                replacement = {'stage_unbound': Mock(side_effect=ValueError('synthetic candidate rejected'))} if phase == 'candidate' else {
                    'apply_unbound': fail_reload}
                with patch.object(cd, 'REMOTE_ROOT', self.state), patch.multiple(cd, **replacement), self.assertRaises(ValueError):
                    cd.remote_run()
                self.assertEqual(self.mutations(), [])
                hold = json.loads((self.state / 'HOLD.json').read_text())
                self.assertEqual(hold['remote_closure'], 'unconfirmed')
                if phase == 'reload':
                    evidence = Path(hold['evidence'])
                    self.assertTrue((evidence / 'unbound-apply-started.json').exists())
                    self.assertFalse((evidence / 'unbound-apply-completed.json').exists())

    def test_host_edit_during_unbound_is_not_overwritten_by_pihole(self):
        for phase in ('stage', 'apply'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                self.state = Path(temporary) / 'state'
                self.hosts = ['192.168.200.5 sso.lab.example.org old-alias']
                self.unbound = UNBOUND_SOURCE
                self.commands.clear()
                def drift_stage(*args):
                    if phase == 'stage': self.hosts.append('10.88.25.9 newly-added-unrelated')
                    return None
                def drift_apply(*args):
                    changed = self.apply_unbound(*args)
                    if phase == 'apply': self.hosts.append('10.88.25.9 newly-added-unrelated')
                    return changed
                with patch.object(cd, 'REMOTE_ROOT', self.state), patch.multiple(cd,
                        stage_unbound=drift_stage, apply_unbound=drift_apply), self.assertRaisesRegex(ValueError, 'changed'):
                    cd.remote_run()
                self.assertIn('10.88.25.9 newly-added-unrelated', self.hosts)
                self.assertEqual(self.mutations(), [])
                hold = json.loads((self.state / 'HOLD.json').read_text())
                self.assertTrue((Path(hold['evidence']) / 'unbound-apply-completed.json').exists())

    def test_concurrent_host_edit_is_preserved_and_held_before_any_write(self):
        calls = 0
        original = self.command
        def drifting(argv):
            nonlocal calls
            if argv[-2:] == ['--config', 'dns.hosts']:
                calls += 1
                if calls == 2: self.hosts.append('10.88.25.9 newly-added-unrelated')
            return original(argv)
        with patch.object(cd, 'command', side_effect=drifting), self.assertRaisesRegex(ValueError, 'changed during admission'):
            cd.remote_run()
        self.assertIn('10.88.25.9 newly-added-unrelated', self.hosts)
        self.assertEqual(self.mutations(), []); self.assertTrue((self.state / 'HOLD.json').exists())


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.work = self.root / '6101'; self.work.mkdir(mode=0o700)
        self.inputs = self.root / 'inputs'; self.inputs.mkdir(mode=0o700)
        self.input = self.inputs / 'dns.json'; self.hosts = self.inputs / 'hosts'; self.key = self.inputs / 'key'
        self.cfg = {'site': {'node': 'pve-lab', 'api_endpoint': 'https://10.88.25.10:8006/'},
            'guest': {'vmid': 6101, 'hostname': 'dns'},
            'app': {'vmid': 6101, 'hostname': 'dns', 'kind': 'dns', 'mac': '02:40:00:00:61:01'},
            'paths': {'known_hosts': str(self.hosts), 'private_key': str(self.key), 'state_root': str(self.root)}}
        for path, value in ((self.input, json.dumps(self.cfg)), (self.hosts, cd.ADDRESS + ' ssh-ed25519 AAAAsynthetic\n'),
                (self.key, 'synthetic-only-key'), (self.work / 'started.json', '{}'),
                (self.work / 'ssh-trust.json', json.dumps({'address': cd.ADDRESS, 'keys': [['ssh-ed25519', 'AAAAsynthetic']]}))):
            path.write_text(value); path.chmod(0o600)
        self.patches = patch.multiple(cd, INPUT=self.input, HOSTS=self.hosts, KEY=self.key, WORK=self.work)
        self.patches.start(); self.addCleanup(self.patches.stop)
        self.shared = SimpleNamespace(validate=Mock(), application_address=Mock(return_value=cd.ADDRESS),
            guest_identity=SimpleNamespace(pin=Mock()), api_get=Mock(), write=Mock())
        self.outcome = {'status': 'passed', 'vmid': 6101, 'records': cd.RECORDS, 'changed': True,
                        'verified': True, 'remote_closure': 'completed', 'unbound_redirects': cd.REDIRECTS,
                        'preserved_redirects': cd.UNCHANGED, 'acme_transparent': list(cd.ACME_EXCEPTIONS)}
        self.fail_ssh = False; self.timeout = False

    def subprocess(self, argv, **kwargs):
        if argv[0] == 'ssh-keygen':
            return SimpleNamespace(returncode=0, stdout=self.hosts.read_text(), stderr='')
        self.assertEqual(argv[0], 'ssh')
        self.assertEqual(argv[-2], 'root@10.88.40.2')
        self.assertTrue(argv[-1].startswith('python3 - --remote '))
        payload = argv[-1].removeprefix('python3 - --remote ')
        import base64
        self.assertEqual(json.loads(base64.urlsafe_b64decode(payload)), cd.SETTINGS)
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn('GlobalKnownHostsFile=/dev/null', argv)
        self.assertIn('ProxyCommand=none', argv)
        self.assertIn('UserKnownHostsFile=' + str(self.hosts), argv)
        self.assertIn(b'def merge_hosts', kwargs['input'])
        self.assertTrue((self.work / 'DNS-FOUNDATION-HOLD.json').exists())
        if self.timeout: raise subprocess.TimeoutExpired(argv, 150)
        return SimpleNamespace(returncode=1 if self.fail_ssh else 0,
                               stdout=json.dumps(self.outcome).encode(), stderr=b'')

    def test_existing_pve_and_ssh_identity_are_anchored_before_one_remote_script(self):
        with patch.object(cd.subprocess, 'run', side_effect=self.subprocess):
            self.assertEqual(cd.run(self.shared), self.outcome)
        self.shared.validate.assert_called_once_with(self.cfg)
        self.shared.guest_identity.pin.assert_called_once()
        self.assertFalse((self.work / 'DNS-FOUNDATION-HOLD.json').exists())
        self.assertEqual(len(list(self.work.glob('foundation-dns-*/result.json'))), 1)

    def test_failure_timeout_or_incomplete_receipt_never_replays(self):
        for failure in ('ssh', 'timeout', 'receipt'):
            with self.subTest(failure=failure):
                self.fail_ssh = failure == 'ssh'; self.timeout = failure == 'timeout'
                self.outcome['verified'] = failure != 'receipt'
                hold = self.work / 'DNS-FOUNDATION-HOLD.json'
                if hold.exists(): hold.unlink()
                with patch.object(cd.subprocess, 'run', side_effect=self.subprocess), \
                        self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    cd.run(self.shared)
                self.assertTrue(hold.exists())
                with patch.object(cd.subprocess, 'run') as remote, self.assertRaisesRegex(ValueError, 'no automatic retry'):
                    cd.run(self.shared)
                remote.assert_not_called()

    def test_changed_identity_stops_without_an_ssh_operation(self):
        self.cfg['guest']['vmid'] = 900
        self.input.write_text(json.dumps(self.cfg))
        with patch.object(cd.subprocess, 'run') as remote, self.assertRaisesRegex(ValueError, 'Unexpected commissioned'):
            cd.run(self.shared)
        remote.assert_not_called(); self.shared.guest_identity.pin.assert_not_called()


class UnboundMergeTests(unittest.TestCase):
    def test_only_two_apex_addresses_and_two_narrow_children_change(self):
        after = cd.merge_unbound(UNBOUND_SOURCE)
        for domain in cd.REDIRECTS:
            self.assertIn(f'local-data: "{domain} A 10.88.40.33"', after)
        for domain, address in cd.UNCHANGED.items():
            self.assertIn(f'local-zone: "{domain}" redirect', after)
            self.assertIn(f'local-data: "{domain} A {address}"', after)
        for name in cd.ACME_EXCEPTIONS:
            self.assertIn(f'local-zone: "{name}." transparent', after)
        recovered = after
        for name in cd.ACME_EXCEPTIONS:
            recovered = recovered.replace(f'    local-zone: "{name}." transparent\n', '')
        for name in cd.REDIRECTS:
            recovered = recovered.replace(f'local-data: "{name} A 10.88.40.33"',
                                           f'local-data: "{name} A 192.168.200.254"')
        self.assertEqual(recovered, UNBOUND_SOURCE)
        self.assertEqual(cd.merge_unbound(after), after)

    def test_unexpected_addresses_or_challenge_local_data_fail_closed(self):
        for changed in (UNBOUND_SOURCE.replace('192.168.200.254', '192.168.200.99', 1),
                        UNBOUND_SOURCE.replace('kept-one.example.org" redirect', 'kept-one.example.org" transparent'),
                        UNBOUND_SOURCE + '    local-data: "_acme-challenge.sso.lab.example.org TXT injected"\n',
                        UNBOUND_SOURCE + '    local-zone: "_acme-challenge.sso.lab.example.org" redirect\n'):
            with self.assertRaises(ValueError): cd.merge_unbound(changed)


@unittest.skipUnless(hasattr(os, 'listxattr'), 'Linux ACL/xattr fixture runs in Docker')
class UnboundMetadataTests(unittest.TestCase):
    def test_in_place_write_preserves_inode_owner_mode_and_xattrs_and_refuses_drift(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as directory:
            root = Path(directory); conf = root / 'unbound.conf'
            conf.write_text(UNBOUND_SOURCE); conf.chmod(0o640)
            os.setxattr(conf, 'user.foundation-fixture', b'preserve-this-attribute')
            import struct
            acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in
                  ((1, 6, 0xffffffff), (2, 4, 12345), (4, 4, 0xffffffff), (16, 4, 0xffffffff), (32, 0, 0xffffffff)))
            os.setxattr(conf, 'system.posix_acl_access', acl)
            with patch.object(cd, 'UNBOUND', conf), patch.object(cd, 'command') as command:
                before, metadata = cd.read_unbound()
                after = cd.merge_unbound(before)
                self.assertTrue(cd.apply_unbound(before, metadata, after, root / 'candidate'))
                updated, attributes = cd.read_unbound()
                self.assertEqual(updated, after)
                for key in ('device', 'inode', 'uid', 'gid', 'mode', 'xattrs'):
                    self.assertEqual(attributes[key], metadata[key])
                command.assert_called_once()
                self.assertEqual(command.call_args.args[0][-1], 'reload')
                self.assertFalse(cd.apply_unbound(after, attributes, after, None))
                conf.write_text(after + '# unexpected edit\n')
                with self.assertRaisesRegex(ValueError, 'drifted'):
                    cd.apply_unbound(after, attributes, after + '# desired change\n', root / 'candidate')


if __name__ == '__main__':
    unittest.main()
