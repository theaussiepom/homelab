"""One narrow device listener boundary and shared, strictly pinned SSH custody."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import re
import runpy
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_web_firewall as w

ROOT = Path(w.__file__).parent
DOC_MAP = {'docs/reference/device-web-firewall.md': {
    'source': 'proxmox/bootstrap/device-web-firewall.example.yaml',
    'fields': ('schema', 'target.address', 'target.hostname', 'target.user',
               'web.interface', 'web.mac', 'web.address', 'web.proxy', 'web.port'),
    'validator': 'device_web_firewall.validate',
    'positive': 'test_example_cli_and_documented_fields',
    'negative': 'test_closed_input_rejects_missing_wrong_and_unsafe_values'}}


def config():
    """Load the complete fictional input through the actual authored reader."""
    return w.authored_config.read(ROOT/'device-web-firewall.example.yaml')


def file_stat(mode):
    """Describe a regular owned file without probing the test host."""
    return {'isreg': True, 'islnk': False, 'uid': 0, 'gid': 0, 'nlink': 1, 'mode': mode}


def facts(owned=False):
    """Project pristine or exactly owned synthetic state for real admission."""
    c = config()
    f = {'uid': 0, 'hostname': 'radio', 'addresses': [
        {'ifname': 'eth0.25', 'address': c['web']['mac'],
         'addr_info': [{'family': 'inet', 'local': c['target']['address']}]},
        {'ifname': 'eth0.40', 'address': c['web']['mac'],
         'addr_info': [{'family': 'inet', 'local': c['web']['address']}]}],
         'parent_stat': {'exists': False}, 'config_stat': {'exists': False}, 'config': None,
         'unit_stat': {'exists': False}, 'unit': None, 'ruleset': {'nftables': []},
         'fragment': '', 'dropins': '', 'active': 'inactive', 'enabled': ''}
    if owned:
        f.update(parent_stat={'isdir': True, 'islnk': False, 'uid': 0, 'gid': 0, 'mode': '0755'},
                 config_stat=file_stat('0600'), config=w.render(c), unit_stat=file_stat('0644'),
                 unit=w.UNIT, ruleset={'nftables': w.rules(c)}, fragment=w.UNIT_PATH,
                 active='active', enabled='enabled')
    return f


class DeviceWebFirewallTests(unittest.TestCase):
    def refuses(self, fn, *args, **kwargs):
        """Require the sanitized contract refusal instead of incidental failures."""
        with self.assertRaisesRegex(ValueError, '^'+w.ERROR+'$'):
            fn(*args, **kwargs)

    def test_example_cli_and_documented_fields(self):
        """Check every CLI mode and bind complete public examples and field records."""
        c = config()
        self.assertIs(w.validate(c), c)
        for flag in ['--check', '--emit', '--observe']:
            with patch('sys.stdout', new_callable=io.StringIO) as out, patch('sys.stdin', io.StringIO(json.dumps(facts()))):
                w.main(['--config', str(ROOT/'device-web-firewall.example.yaml'), flag])
            if flag == '--check':
                self.assertEqual(out.getvalue().strip(), 'Device web firewall configuration accepted')
            else:
                self.assertEqual(json.loads(out.getvalue()), c if flag == '--emit' else w.inspect(c, facts()))
        with patch('sys.stdout', new_callable=io.StringIO), patch('sys.stdin', io.StringIO(json.dumps(facts(True)))):
            w.main(['--config', str(ROOT/'device-web-firewall.example.yaml'), '--observe', '--final'])
        for args in [['--config', '/absent/source.yaml', '--check'],
                     ['--config', str(ROOT/'device-web-firewall.example.yaml'), '--emit', '--final']]:
            with patch('sys.stderr', new_callable=io.StringIO) as err, self.assertRaises(SystemExit) as e:
                w.main(args)
            self.assertEqual(e.exception.code, 1)
            self.assertEqual(err.getvalue(), w.ERROR+'\n')
        with patch('sys.argv', [str(ROOT/'device_web_firewall.py'), '--config', str(ROOT/'device-web-firewall.example.yaml'), '--check']), patch('sys.stdout', new_callable=io.StringIO):
            runpy.run_path(str(ROOT/'device_web_firewall.py'), run_name='__main__')
        guide = (ROOT.parents[1]/'docs/reference/device-web-firewall.md').read_text()
        excerpt = re.findall(r'```yaml\n(.*?)\n```', guide, re.S)
        self.assertEqual(len(excerpt), 1)
        self.assertEqual(w.authored_config.parse(excerpt[0].encode(), '.yaml'), c)
        for field in DOC_MAP['docs/reference/device-web-firewall.md']['fields']:
            self.assertIn('`'+field+'`', guide)

    def test_closed_input_rejects_missing_wrong_and_unsafe_values(self):
        """Exercise required types, unknown keys and unsafe identities for each field."""
        original = config()
        for section in [None, 'target', 'web']:
            selected = original if section is None else original[section]
            for name in selected:
                for kind in ['missing', 'null', 'container']:
                    bad = deepcopy(original); target = bad if section is None else bad[section]
                    if kind == 'missing':
                        del target[name]
                    else:
                        target[name] = None if kind == 'null' else []
                    self.refuses(w.validate, bad)
            bad = deepcopy(original); (bad if section is None else bad[section])['extra'] = True
            self.refuses(w.validate, bad)
        cases = {'schema': ['wrong'], 'target.hostname': ['-bad', 'bad\nname', 'a'*64],
                 'target.user': ['root;id', 'UPPER', 'a'*33],
                 'web.interface': ['lo', 'bad/name', 'a'*16],
                 'web.mac': ['00:00:00:00:00:00', '01:00:00:00:00:01', '02:AA:00:00:00:01'],
                 'web.port': [True, 0, 65536, '8080']}
        for key, values in cases.items():
            for value in values:
                bad = deepcopy(original); parts = key.split('.')
                if len(parts) == 1:
                    bad[key] = value
                else:
                    bad[parts[0]][parts[1]] = value
                self.refuses(w.validate, bad)
        for section, name in [('target', 'address'), ('web', 'address'), ('web', 'proxy')]:
            for value in ['host.example.org', '198.18.40.4/32', '127.0.0.1', '0.0.0.0',
                          '169.254.1.1', '224.0.0.1', '255.255.255.255', '01.2.3.4']:
                bad = deepcopy(original); bad[section][name] = value
                self.refuses(w.validate, bad)
        bad = config(); bad['web']['proxy'] = bad['web']['address']; self.refuses(w.validate, bad)

    def test_exact_listener_scope_and_independent_persistence(self):
        """Permit only proxy and local health traffic to the exact IPv4 listener."""
        c = config(); text = w.render(c)
        self.assertEqual(w.previous(text), c)
        self.assertEqual(text.count('ip daddr 198.18.40.4 tcp dport 8080'), 3)
        self.assertIn('iifname "eth0.40" ip saddr 198.18.40.33 ip daddr 198.18.40.4 tcp dport 8080 accept', text)
        self.assertIn('iifname "lo" ip daddr 198.18.40.4 tcp dport 8080 accept', text)
        self.assertIn('ip daddr 198.18.40.4 tcp dport 8080 drop', text)
        self.assertNotIn(c['target']['address'], text.split('\n', 1)[1])
        for forbidden in ['flush', 'include ', 'hook output', 'hook forward', 'policy drop', 'ct state', '8081', '5580']:
            self.assertNotIn(forbidden, text)
        self.assertIn('After=nftables.service\nBefore=docker.service', w.UNIT)
        self.assertNotIn('ExecStop', w.UNIT)
        for invalid in ['', w.HEADER+'null\n', w.HEADER+'{\n', text+'# foreign\n']:
            self.refuses(w.previous, invalid)
        observed = [{'metainfo': {'version': 'observed-version'}}]
        for row in w.rules(c):
            key, body = next(iter(row.items())); observed.append({key: dict(body, handle=27)})
        self.assertEqual(w.kernel({'nftables': observed}), w.rules(c))
        for value in [None, {'extra': []}, {'nftables': None}, {'nftables': [None]},
                      {'nftables': [{'unexpected': {}}]}, {'nftables': [{'rule': []}]}]:
            self.refuses(w.kernel, value)

    def test_first_repeat_update_and_final_actual_ownership(self):
        """Distinguish first ownership, repeat, proxy update and real final refusal."""
        c = config()
        self.assertTrue(w.inspect(c, facts())['changed'])
        self.assertFalse(w.inspect(c, facts(True))['changed'])
        self.assertFalse(w.inspect(c, facts(True), final=True)['changed'])
        new = deepcopy(c); new['web']['proxy'] = '198.18.40.34'
        self.assertTrue(w.inspect(new, facts(True))['changed'])
        self.refuses(w.inspect, new, facts(True), final=True)
        f = facts(); f['enabled'] = 'not-found'; self.assertTrue(w.inspect(c, f)['changed'])
        self.refuses(w.inspect, c, facts(), final=True)
        for owned in [False, True]:
            original = facts(owned)
            for name, value in [('uid', 1000), ('uid', False), ('hostname', 'foreign'), ('addresses', None),
                                ('addresses', [None]), ('parent_stat', None), ('config_stat', None),
                                ('unit_stat', None), ('dropins', '/foreign'), ('fragment', '/foreign'),
                                ('active', 'failed'), ('enabled', 'disabled')]:
                f = deepcopy(original); f[name] = value
                self.refuses(w.inspect, c, f)
            for value in [{'isdir': True, 'islnk': True, 'uid': 0, 'gid': 0, 'mode': '0755'},
                          {'isdir': True, 'islnk': False, 'uid': 0, 'gid': 0, 'mode': '0777'}]:
                f = deepcopy(original); f['parent_stat'] = value; self.refuses(w.inspect, c, f)
            for name, value in [('address', None), ('address', '02:00:00:00:40:05'), ('master', 'br0'), ('flags', ['SLAVE']),
                                ('addr_info', [None]), ('addr_info', []), ('addr_info', 'wrong')]:
                f = deepcopy(original); f['addresses'][1][name] = value
                self.refuses(w.inspect, c, f)
            f = deepcopy(original); f['addresses'].append(deepcopy(f['addresses'][1])); self.refuses(w.inspect, c, f)
            f = deepcopy(original); f['addresses'][0]['addr_info'] = []; self.refuses(w.inspect, c, f)
        for field in ['config_stat', 'unit_stat']:
            for key, value in [('isreg', False), ('islnk', True), ('uid', 1000), ('gid', 1000), ('nlink', 2), ('mode', '0666')]:
                f = facts(True); f[field][key] = value; self.refuses(w.inspect, c, f)
        f = facts(); f['unit_stat'] = file_stat('0644'); self.refuses(w.inspect, c, f)
        f = facts(); f['ruleset'] = {'nftables': w.rules(c)}; self.refuses(w.inspect, c, f)
        f = facts(True); f['unit'] += '# foreign\n'; self.refuses(w.inspect, c, f)
        f = facts(True); f['ruleset']['nftables'][-1]['rule']['expr'] = [{'accept': None}]; self.refuses(w.inspect, c, f)
        for field, value in [('port', 80), ('address', '198.18.40.5')]:
            bad = config(); bad['web'][field] = value
            if field == 'address':
                f = facts(True); f['addresses'][1]['addr_info'][0]['local'] = value
            else:
                f = facts(True)
            self.refuses(w.inspect, bad, f)

    def test_transport_reuses_shared_custody_and_preserves_refusals(self):
        """Keep both callers on one custody check and sanitize its diagnostics."""
        c = config(); options = {'synthetic': True}
        with patch.object(w.bootstrap_ssh, 'trust') as check:
            w.trust(c, options)
        check.assert_called_once_with({'address': c['target']['address'], 'hostname': c['target']['hostname']}, options)
        with patch.object(w.bootstrap_ssh, 'trust', side_effect=ValueError('private diagnostic')):
            self.refuses(w.trust, c, options)

    def test_playbook_has_precontact_guards_and_no_application_or_network_writer(self):
        """Bind the stock playbook to source, transport and exact native readback."""
        play = yaml.safe_load((ROOT/'ansible/device-web-firewall.yml').read_text())[0]
        self.assertFalse(play['gather_facts']); self.assertTrue(play['become'])
        guard = play['pre_tasks'][0]
        self.assertEqual(guard['delegate_to'], 'localhost'); self.assertFalse(guard['become'])
        text = (ROOT/'ansible/device-web-firewall.yml').read_text()
        self.assertIn("lookup('ansible.builtin.config', 'use_tty'", text)
        self.assertIn('bootstrap_closed()', text)
        self.assertIn('w.trust(', text)
        self.assertIn('validate: /usr/sbin/nft -c -f %s', text)
        self.assertIn('--observe, --final', text)
        reads = yaml.safe_load((ROOT/'ansible/device-web-firewall-read.yml').read_text())
        address_read = next(task for task in reads if task.get('register') == 'web_addresses')
        # iproute2 omits the link MAC with -4; admission needs both link and IP identity.
        self.assertEqual(address_read['ansible.builtin.command']['argv'], ['ip', '-j', 'address', 'show'])
        for forbidden in ['apt:', 'docker compose', 'authorized_keys', 'reboot:', 'nft flush', 'nftables.service\n']:
            self.assertNotIn(forbidden, text)

    def test_actual_ansible_rejects_unsafe_transport_before_a_ssh_spy(self):
        """Run the real playbook/plugin and distinguish precontact refusal from contact."""
        executable = Path(sys.executable).with_name('ansible-playbook')
        if not executable.exists():
            self.skipTest('The locked Ansible environment is required')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); key = root/'key'; known = root/'known_hosts'; spy = root/'contacted'
            key.write_text('fictional input'); key.chmod(0o600)
            known.write_text('198.18.25.4 ssh-ed25519 AAAAfixture\n'); known.chmod(0o644)
            fake = root/'ssh'; fake.write_text('#!/bin/sh\nprintf called >> '+shlex.quote(str(spy))+'\nexit 99\n'); fake.chmod(0o755)
            inventory = root/'inventory.json'
            inventory.write_text(json.dumps({'all': {'children': {'device_web': {'hosts': {'radio': {
                'ansible_host': '198.18.25.4', 'ansible_user': 'operator', 'ansible_connection': 'ssh'}}}}}}))
            cfg = root/'ansible.cfg'; cfg.write_text('[defaults]\n')
            env = {**os.environ, 'PATH': str(root)+os.pathsep+os.environ['PATH'],
                   'ANSIBLE_CONFIG': str(cfg), 'ANSIBLE_LOCAL_TEMP': str(root/'local'),
                   'ANSIBLE_SSH_ARGS': '-F /dev/null -o ControlMaster=no',
                   'ANSIBLE_HOST_KEY_CHECKING': 'true', 'ANSIBLE_SSH_USETTY': 'False', 'LC_ALL': 'C.UTF-8'}
            common = '-o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o UserKnownHostsFile='+str(known)+' -o BatchMode=yes -o IdentitiesOnly=yes -o ControlMaster=no'
            base = [str(executable), '-i', str(inventory), str(ROOT/'ansible/device-web-firewall.yml'),
                    '-e', 'device_web_firewall_config='+str(ROOT/'device-web-firewall.example.yaml'),
                    '--private-key', str(key), '--ssh-common-args', common]
            for changes, stage in [({'ANSIBLE_SSH_USETTY': 'True'}, 'Bind the one selected inventory identity'),
                                   ({'ANSIBLE_HOST_KEY_CHECKING': 'false'}, 'Admit actual SSH options and protected file custody')]:
                result = subprocess.run(base, env={**env, **changes}, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(stage, result.stdout, result.stdout+result.stderr)
                self.assertFalse(spy.exists(), result.stdout+result.stderr)
            result = subprocess.run(base, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Read the effective remote identity', result.stdout, result.stdout+result.stderr)
            self.assertTrue(spy.exists(), result.stdout+result.stderr)
            self.assertIn('unreachable=1', result.stdout)
            self.assertIn('failed=0', result.stdout)

    def test_script_isolation_and_namespace_imports_keep_the_shared_helper_available(self):
        """The extraction must preserve prior PBS imports and isolated CLI use."""
        for filename, example in [('pbs_firewall.py', 'pbs-firewall.example.yaml'),
                                  ('device_web_firewall.py', 'device-web-firewall.example.yaml')]:
            result=subprocess.run([sys.executable,'-I',str(ROOT/filename),'--config',str(ROOT/example),'--check'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        root=ROOT.parents[1]
        result=subprocess.run([sys.executable,'-c',
            'import proxmox.bootstrap.pbs_firewall,proxmox.bootstrap.device_web_firewall'],
            cwd=root,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__ == '__main__':
    unittest.main()
