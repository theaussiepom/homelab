"""Closed PBS policy, exact ownership and native-input guards; no target contact."""
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
import pbs_firewall as p

ROOT = Path(p.__file__).parent
DOC_MAP = {'docs/reference/pbs-firewall.md': {
    'source': 'proxmox/bootstrap/pbs-firewall.example.yaml',
    'fields': ('schema', 'target.address', 'target.hostname', 'apps.interface', 'apps.mac', 'apps.address', 'apps.proxy'),
    'validator': 'pbs_firewall.validate', 'positive': 'test_example_cli_and_canonical_documentation',
    'negative': 'test_all_fields_closed_required_and_typed'}}


def config():
    """Read the maintained fictional complete input through the actual loader."""
    return p.authored_config.read(ROOT / 'pbs-firewall.example.yaml')


def file_stat(mode='0600'):
    """Model ordinary root-owned regular file metadata, never host stat data."""
    return {'isreg': True, 'islnk': False, 'uid': 0, 'gid': 0, 'nlink': 1, 'mode': mode}


def observed(owned=False):
    """Supply a complete synthetic current-state projection for the real validator."""
    c = config()
    f = {'hostname': 'backup', 'uid': 0, 'distribution': 'Debian', 'release': '13',
         'nft_version': '1.1.3-1', 'pbs_installed': True,
         'addresses': [{'ifname': 'ens3', 'address': '02:00:00:00:25:03', 'link_type': 'ether',
                        'addr_info': [{'family': 'inet', 'local': c['target']['address']}]},
                       {'ifname': 'ens4', 'address': '02:00:00:00:20:03', 'link_type': 'ether',
                        'addr_info': [{'family': 'inet', 'local': '198.18.20.3'}]},
                       {'ifname': 'ens5', 'address': c['apps']['mac'], 'link_type': 'ether', 'addr_info': []}],
         'routes': [{'dst': 'default', 'dev': 'ens3', 'gateway': '198.18.25.1'},
                    {'dst': '198.18.25.0/24', 'dev': 'ens3', 'scope': 'link'}],
         'storage_routes': [[{'dst': '198.18.20.2', 'dev': 'ens4'}]],
         'unit_stat': file_stat('0644'), 'config_stat': file_stat('0755'),
         'dropin_stat': {'exists': False}, 'unit': p.STOCK_UNIT,
         'config': p.STOCK_CONFIG, 'dropin': '',
         'fragment': '/usr/lib/systemd/system/nftables.service', 'reload_needed': 'no',
         'dropins': '', 'active': 'inactive', 'enabled': 'disabled',
         'ruleset': {'nftables': [{'metainfo': {'version': '1.1.3'}}]}}
    if owned:
        f.update(config=p.render(c), config_stat=file_stat(), dropin=p.DROPIN,
                 dropin_stat=file_stat('0644'), dropins=p.DROPIN_PATH, active='active',
                 enabled='enabled',
                 ruleset={'nftables': [{'metainfo': {'version': '1.1.3'}}] + p.rules(c)})
    return f


class PBSFirewallTests(unittest.TestCase):
    """Exercise shape, ownership, policy ordering and standard Ansible wiring."""
    def refused(self, fn, *args):
        """Require the sanitized contract refusal, rather than an incidental exception."""
        with self.assertRaisesRegex(ValueError, '^' + p.ERROR + '$'):
            fn(*args)

    def test_example_cli_and_canonical_documentation(self):
        """Both pure CLI modes and exact public example use the authoritative validator."""
        c = config()
        self.assertIs(p.validate(c), c)
        for flag in ('--check', '--emit'):
            with patch('sys.stdout', new_callable=io.StringIO) as out:
                p.main(['--config', str(ROOT / 'pbs-firewall.example.yaml'), flag])
            self.assertEqual(json.loads(out.getvalue()) if flag == '--emit' else out.getvalue().strip(),
                             c if flag == '--emit' else 'PBS firewall configuration accepted')
        with patch('sys.stderr', new_callable=io.StringIO) as err, self.assertRaises(SystemExit) as e:
            p.main(['--config', '/absent/pbs-firewall.yaml', '--check'])
        self.assertEqual(e.exception.code, 1)
        self.assertEqual(err.getvalue(), p.ERROR + '\n')
        with patch('sys.argv', [str(ROOT / 'pbs_firewall.py'), '--config', str(ROOT / 'pbs-firewall.example.yaml'), '--check']), patch('sys.stdout', new_callable=io.StringIO):
            runpy.run_path(str(ROOT / 'pbs_firewall.py'), run_name='__main__')
        guide = (ROOT.parents[1] / 'docs/reference/pbs-firewall.md').read_text()
        excerpt = re.findall(r'```yaml\n(.*?)\n```', guide, re.S)
        self.assertEqual(len(excerpt), 1)
        self.assertEqual(p.authored_config.parse(excerpt[0].encode(), '.yaml'), c)
        for field in DOC_MAP['docs/reference/pbs-firewall.md']['fields']:
            self.assertIn('`' + field + '`', guide)
        self.assertNotIn('publickey', guide)

    def test_all_fields_closed_required_and_typed(self):
        """Every public field rejects omission/null/types/extensions and injection shapes."""
        original = config()
        for section in (None, 'target', 'apps'):
            for key in original if section is None else original[section]:
                c = deepcopy(original)
                obj = c if section is None else c[section]
                del obj[key]
                self.refused(p.validate, c)
            c = deepcopy(original)
            (c if section is None else c[section])['unexpected'] = True
            self.refused(p.validate, c)
        for path in [(), ('target',), ('apps',)]:
            for bad in (None, False, [], '', 1):
                c = deepcopy(original)
                if path:
                    c[path[0]] = bad
                else:
                    c = bad
                self.refused(p.validate, c)
        fields = [('schema', None), *[(k, 'target') for k in original['target']],
                  *[(k, 'apps') for k in original['apps']]]
        for key, section in fields:
            for bad in (None, False, [], {}, 1, '', 'bad\n; flush ruleset'):
                c = deepcopy(original)
                (c if section is None else c[section])[key] = bad
                self.refused(p.validate, c)
        for path in [('target', 'address'), ('apps', 'address'), ('apps', 'proxy')]:
            for bad in ('::1', '127.0.0.1', '0.0.0.0', '169.254.1.2', '224.0.0.1',
                        '240.0.0.1', '198.18.40.0/24', '01.2.3.4', 'host.invalid'):
                c = deepcopy(original); c[path[0]][path[1]] = bad
                self.refused(p.validate, c)
        for field, values in [('mac', ['ff:ff:ff:ff:ff:ff', '01:00:00:00:00:01',
                                      '00:00:00:00:00:00', '02:AA:00:00:00:01']),
                              ('interface', ['lo', '-ens5', 'a' * 16])]:
            for value in values:
                c = deepcopy(original); c['apps'][field] = value; self.refused(p.validate, c)
        for value in ('-host', 'host-', 'a' * 64):
            c = deepcopy(original); c['target']['hostname'] = value; self.refused(p.validate, c)
        c = deepcopy(original); c['apps']['proxy'] = c['target']['address']; self.refused(p.validate, c)
        self.assertEqual(original, config())

    def test_shared_loader_refuses_duplicate_alias_sibling_and_missing_source(self):
        """Use existing authored-reader security behavior, without another parser."""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'firewall.yaml'
            for raw in ('schema: a\nschema: b\n', 'a: &x 1\nb: *x\n'):
                path.write_text(raw)
                with self.assertRaises(ValueError): p.authored_config.read(path)
            path.write_text(yaml.safe_dump(config()))
            self.assertEqual(p.validate(p.authored_config.read(path)), config())
            path.with_suffix('.json').write_text('{}')
            with self.assertRaises(ValueError): p.authored_config.read(path)

    def test_first_repeat_and_proxy_update_preserve_network_identity(self):
        """Pristine first ownership, actual owned repeat and proxy-only updates are distinct."""
        c = config(); f = observed()
        self.assertTrue(p.inspect(c, f)['changed'])
        f = observed(True); self.assertFalse(p.inspect(c, f)['changed'])
        self.assertFalse(p.inspect(c, f, final=True)['changed'])
        c['apps']['proxy'] = '198.18.40.34'
        self.assertTrue(p.inspect(c, f)['changed'])
        self.refused(p.inspect, c, f, True)
        for section, key, value in [('target', 'hostname', 'other'), ('target', 'address', '198.18.25.4'),
                                    ('apps', 'interface', 'ens6'), ('apps', 'mac', '02:00:00:00:40:04'),
                                    ('apps', 'address', '198.18.40.4')]:
            old = config(); old[section][key] = value; f = observed(True)
            f['config'] = p.render(old)
            f['ruleset'] = {'nftables': p.rules(old)}
            self.refused(p.inspect, config(), f)

    def test_file_kernel_service_and_first_ownership_refusals(self):
        """Foreign or uncertain persistence/rules never authorize replacing the policy."""
        for owned in (False, True):
            base = observed(owned)
            for field in ('unit_stat', 'config_stat', *(['dropin_stat'] if owned else [])):
                for key, value in [('isreg', False), ('islnk', True), ('uid', 1), ('gid', 1),
                                   ('nlink', 2), ('mode', '0666')]:
                    f = deepcopy(base); f[field][key] = value; self.refused(p.inspect, config(), f)
            for key, value in [('unit', p.STOCK_UNIT + '# changed\n'), ('fragment', '/foreign/unit'),
                               ('reload_needed', 'yes'), ('dropins', '/foreign.conf'),
                               ('active', 'failed'), ('enabled', 'masked')]:
                f = deepcopy(base); f[key] = value; self.refused(p.inspect, config(), f)
        for key, value in [('config', p.STOCK_CONFIG + '# foreign\n'), ('dropin_stat', file_stat('0644')),
                           ('ruleset', {'nftables': p.rules(config())})]:
            f = observed(); f[key] = value; self.refused(p.inspect, config(), f)
        self.refused(p.inspect, config(), observed(), True)
        for key, value in [('config', p.HEADER + '{}\n'), ('dropin', p.DROPIN + '#foreign'),
                           ('config_stat', file_stat('0644'))]:
            f = observed(True); f[key] = value; self.refused(p.inspect, config(), f)
        for text in ('', p.HEADER + '{', p.render(config()) + 'flush ruleset\n'):
            self.refused(p.previous, text)
        for value in (None, {}, {'nftables': None}, {'nftables': [None]},
                      {'nftables': [{'table': {}, 'chain': {}}]},
                      {'nftables': [{'metainfo': {'version': 'other'}}]},
                      {'nftables': [{'set': {}}]}, {'nftables': [{'rule': []}]}):
            self.refused(p.kernel, value)
        good = {'nftables': deepcopy(p.rules(config()))}
        good['nftables'][0]['table']['handle'] = 7
        self.assertEqual(p.kernel(good), p.rules(config()))
        for mutate in (lambda r: r.reverse(), lambda r: r.append({'table': {'family': 'ip', 'name': 'foreign'}}),
                       lambda r: r[3]['rule']['expr'].pop(), lambda r: r[2]['chain'].update(policy='drop')):
            f = observed(True); mutate(f['ruleset']['nftables']); self.refused(p.inspect, config(), f)

    def test_native_network_separation_and_unchanged_probe_inputs(self):
        """Wrong host/NIC/global/default/storage use is refused before any policy write."""
        c = config(); base = observed()
        for key, value in [('hostname', 'other'), ('uid', 1000), ('distribution', 'other'),
                           ('release', '12'), ('nft_version', '1.0'), ('pbs_installed', False),
                           ('addresses', None), ('routes', None), ('storage_routes', None)]:
            f = deepcopy(base); f[key] = value; self.refused(p.inspect, c, f)
        mutations = [lambda f: f['addresses'].pop(),
                     lambda f: f['addresses'].append(deepcopy(f['addresses'][-1])),
                     lambda f: f['addresses'][2].update(address='02:00:00:00:40:04'),
                     lambda f: f['addresses'][2].update(link_type='loopback'),
                     lambda f: f['addresses'][2].update(master='br0'),
                     lambda f: f['addresses'][2].update(flags=['UP', 'SLAVE']),
                     lambda f: f['addresses'][1].update(address=c['apps']['mac']),
                     lambda f: f['addresses'][0].update(addr_info=[]),
                     lambda f: f['addresses'][2].update(addr_info=[{'local': c['target']['address']}]),
                     lambda f: f['addresses'][2].update(addr_info=[{'family': 'inet', 'local': '198.18.20.3'}]),
                     lambda f: f['addresses'][2].update(addr_info=[{'family': 'inet6', 'scope': 'global', 'local': '2001:db8::1'}]),
                     lambda f: f['routes'].append({'dst': 'default', 'dev': 'ens5'}),
                     lambda f: f['routes'].append({'dst': 'default', 'nexthops': [{'dev': 'ens5'}, {'dev': 'ens3'}]}),
                     lambda f: f['routes'].append({'dst': 'default', 'nhid': 17}),
                     lambda f: f['routes'].append({'dst': 'default', 'dev': 'ens3', 'nexthops': []}),
                     lambda f: f['routes'].append({'dst': '::/0', 'dev': 'ens5'}),
                     lambda f: f['storage_routes'].append([]),
                     lambda f: f['storage_routes'].append([{}]),
                     lambda f: f['storage_routes'].append([{'dev': 'ens5'}])]
        for mutate in mutations:
            f = deepcopy(base); mutate(f); self.refused(p.inspect, c, f)
        f = deepcopy(base)
        f['addresses'][2]['addr_info'] = [{'family': 'inet', 'local': c['apps']['address']},
                                         {'family': 'inet6', 'scope': 'link', 'local': 'fe80::1'}]
        saved = deepcopy(f); p.inspect(c, f); self.assertEqual(saved, f)

    def test_exact_delegated_snippets_roundtrip_and_refuse_changed_network(self):
        """Execute actual admission/final subprocess code through its real JSON boundary."""
        tasks = yaml.safe_load((ROOT / 'ansible/pbs-firewall.yml').read_text())[0]['tasks']
        scripts = [t['ansible.builtin.command']['argv'][2] for t in tasks
                   if t.get('delegate_to') == 'localhost']
        self.assertEqual(len(scripts), 2)
        def invoke(code, value):
            return subprocess.run([sys.executable, '-c', code, str(ROOT)], input=json.dumps(value),
                                  text=True, capture_output=True)
        first = invoke(scripts[0], {'config': config(), 'facts': observed()})
        self.assertEqual(first.returncode, 0, first.stderr)
        admission = json.loads(first.stdout)
        self.assertIs(type(admission['network']), list)
        payload = {'config': config(), 'facts': observed(True), 'network': admission['network']}
        final = invoke(scripts[1], payload)
        self.assertEqual(final.returncode, 0, final.stderr)
        payload['facts']['addresses'][1]['addr_info'][0]['local'] = '198.18.20.4'
        bad = invoke(scripts[1], payload)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn(p.ERROR, bad.stderr)

    def test_explicit_ssh_trust_never_reads_the_private_key(self):
        """Inspect explicit key metadata and the exact public pin; refuse unsafe options/files."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve(); key = root / 'key'; known = root / 'known_hosts'
            key.write_text('fictional private input; must never be read'); key.chmod(0o600)
            known.write_text('198.18.25.3,backup ssh-ed25519 AAAAfixture\n'); known.chmod(0o644)
            args = '-o StrictHostKeyChecking=yes -o ControlMaster=no -o BatchMode=yes -o IdentitiesOnly=yes -o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o UserKnownHostsFile=' + shlex.quote(str(known))
            options = {'private_key_file': str(key), 'host_key_checking': True, 'inline_key_absent': True,
                       'password_absent': True, 'ssh_executable': 'ssh', 'ssh_args': '-C -F /dev/null -o ControlMaster=no',
                       'ssh_common_args': args, 'ssh_extra_args': '', 'sftp_extra_args': '', 'scp_extra_args': ''}
            c = config()
            with patch.object(p.os, 'open', wraps=p.os.open) as opened:
                p.trust(c, options)
            self.assertEqual(opened.call_count, 1, str(opened.call_args_list))
            self.assertEqual(opened.call_args.args[0], known)
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
            for field, value in [('host_key_checking', False), ('inline_key_absent', False), ('password_absent', False),
                                 ('ssh_executable', 'wrapper'), ('ssh_extra_args', '-o ProxyCommand=unsafe'),
                                 ('sftp_extra_args', '-x'), ('scp_extra_args', '-x'), ('private_key_file', None),
                                 ('private_key_file', 'relative'), ('ssh_common_args', '"'), ('ssh_common_args', None),
                                 ('ssh_args', '-F /unreviewed'), ('ssh_args', ''), ('ssh_args', '-o'),
                                 ('ssh_common_args', args + ' -o StrictHostKeyChecking=no'),
                                 ('ssh_common_args', args + ' -o ProxyCommand=unsafe'),
                                 ('ssh_common_args', args + ' -o VerifyHostKeyDNS=yes'),
                                 ('ssh_common_args', args + ' -o UpdateHostKeys=yes'),
                                 ('ssh_common_args', args + ' -o malformed')]:
                self.refused(p.trust, config(), {**options, field: value})
            for field in ('ssh_args', 'private_key_file'):
                bad = dict(options); del bad[field]; self.refused(p.trust, config(), bad)
            key.chmod(0o644); self.refused(p.trust, config(), options); key.chmod(0o600)
            known.chmod(0o666); self.refused(p.trust, config(), options); known.chmod(0o644)
            linked = root / 'linked'; linked.symlink_to(key)
            self.refused(p.trust, config(), {**options, 'private_key_file': str(linked)})
            os.link(key, root / 'hardlink'); self.refused(p.trust, config(), options); (root / 'hardlink').unlink()
            with patch.object(p.os, 'geteuid', return_value=os.geteuid() + 10): self.refused(p.trust, config(), options)
            for body in ('', '# no actual key\n', '198.18.25.4 ssh-ed25519 AAAA\n',
                         '*.invalid ssh-ed25519 AAAA\n', '@cert-authority 198.18.25.3 ssh-ed25519 AAAA\n',
                         '198.18.25.3 unknown AAAA\n', '198.18.25.3 ssh-ed25519 ***\n', '\uffff'):
                known.write_text(body); self.refused(p.trust, config(), options)
            known.write_bytes(b'x' * 65537); self.refused(p.trust, config(), options)
            known.write_text('198.18.25.3 ssh-ed25519 AAAA\n')
            real_open = os.fdopen
            class ChangedRead:
                """Change the actual owned public file after read to exercise its identity guard."""
                def __init__(self, fd, mode): self.stream = real_open(fd, mode)
                def __enter__(self): return self
                def __exit__(self, *args): self.stream.close()
                def fileno(self): return self.stream.fileno()
                def read(self, bound):
                    raw = self.stream.read(bound); known.write_text('changed\n'); return raw
            with patch.object(p.os, 'fdopen', ChangedRead): self.refused(p.trust, config(), options)

    def test_actual_playbook_precontact_refusal_precedes_any_ssh_execution(self):
        """Resolve actual CLI options; owned SSH spy proves unsafe inputs fail before contact."""
        if not Path(sys.executable).with_name('ansible-playbook').exists():
            self.skipTest('Use locked Ansible tools for this actual playbook control')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve(); key = root / 'key'; known = root / 'known_hosts'; spy = root / 'ssh-called'
            key.write_text('fictional private input'); key.chmod(0o600)
            known.write_text('198.18.25.3 ssh-ed25519 AAAAfixture\n'); known.chmod(0o644)
            ssh = root / 'ssh'
            ssh.write_text('#!/bin/sh\nprintf called >> ' + shlex.quote(str(spy)) + '\nexit 99\n'); ssh.chmod(0o755)
            inventory = {'all': {'children': {'pbs': {'hosts': {'backup': {
                'ansible_host': '198.18.25.3', 'ansible_user': 'root', 'ansible_connection': 'ssh'}}}}}}
            inv = root / 'inventory.json'; inv.write_text(json.dumps(inventory))
            cfg = root / 'ansible.cfg'; cfg.write_text('[defaults]\n')
            env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                   'ANSIBLE_LOCAL_TEMP': str(root / 'local'), 'ANSIBLE_SSH_ARGS': '-F /dev/null -o ControlMaster=no',
                   'ANSIBLE_HOST_KEY_CHECKING': 'true', 'ANSIBLE_CONFIG': str(cfg), 'LC_ALL': 'en_US.UTF-8'}
            args = '-o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o UserKnownHostsFile=' + str(known) + ' -o BatchMode=yes -o IdentitiesOnly=yes -o ControlMaster=no'
            base = [str(Path(sys.executable).with_name('ansible-playbook')), '-i', str(inv),
                    str(ROOT / 'ansible/pbs-firewall.yml'), '-e', 'pbs_firewall_config=' + str(ROOT / 'pbs-firewall.example.yaml')]
            cases = [([], args, {}), (['--private-key', str(key)], args + ' -o StrictHostKeyChecking=no', {}),
                     (['--private-key', str(key)], args, {'ANSIBLE_HOST_KEY_CHECKING': 'false'}),
                     (['--private-key', str(key), '-e', 'ansible_ssh_private_key_file=' + str(root / 'absent')], args, {}),
                     (['--private-key', str(key)], args, {'ANSIBLE_PRIVATE_KEY': 'fictional-inline-value'}),
                     (['--private-key', str(key)], args.replace(str(known), str(root / 'missing_known')), {}),
                     (['--private-key', str(root / 'absent')], args, {})]
            for extra, common, changes in cases:
                result = subprocess.run(base + extra + ['--ssh-common-args', common], env={**env, **changes}, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(spy.exists(), result.stdout + result.stderr)
                self.assertIn('Verify explicit key and strict pinned SSH options before contact', result.stdout, result.stdout + result.stderr)
            result = subprocess.run(base + ['--private-key', str(key), '--ssh-common-args', args], env=env, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(spy.exists(), result.stdout + result.stderr)
            self.assertIn('TASK [Read existing host facts without package or network changes]', result.stdout)
            self.assertIn('unreachable=1', result.stdout)
            self.assertIn('failed=0', result.stdout)

    def test_storage_literals_are_exact_and_dns_ambiguity_refuses(self):
        """Only explicit mounted NFS sources become bounded stock route queries."""
        self.assertEqual(p.storage_servers({'filesystems': []}), [])
        self.assertEqual(p.storage_servers({'filesystems': [
            {'source': '198.18.20.2:/export'}, {'source': '198.18.20.2:/other'},
            {'source': '[2001:db8::2]:/export'}]}), ['198.18.20.2', '2001:db8::2'])
        for value in (None, {}, {'filesystems': None}, {'filesystems': [{}]},
                      {'filesystems': [{'source': None}]}, {'filesystems': [{'source': 'nas:/export'}]},
                      {'filesystems': [{'source': '198.18.20.2:relative'}]}):
            self.refused(p.storage_servers, value)

    def test_render_matches_template_and_exact_ordered_family_direction_policy(self):
        """Generated rules have no global flush, output/forward chain or broad established grant."""
        c = config(); policy = p.render(c)
        template = (ROOT / 'ansible/pbs-firewall.nft.j2').read_text()
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'ANSIBLE_LOCAL_TEMP': d}):
            from ansible.template import Templar, trust_as_template
            rendered = Templar(variables={'pbs_firewall_admission': {'policy': policy}}).template(
                trust_as_template(template))
        self.assertEqual(rendered, policy)
        self.assertNotIn('flush ruleset', policy)
        self.assertNotIn('include ', policy)
        self.assertNotIn('hook output', policy); self.assertNotIn('hook forward', policy)
        self.assertLess(policy.index('nfproto ipv6 drop'), policy.index('ct direction reply'))
        self.assertIn('ct direction reply ct state { established, related } accept', policy)
        self.assertEqual(len(p.rules(c)), 7)

    def test_stock_ansible_precontact_and_mutation_order_without_local_sudo(self):
        """Actual playbook validates locally, mutates only owned files/service, then reads back."""
        play = yaml.safe_load((ROOT / 'ansible/pbs-firewall.yml').read_text())[0]
        self.assertEqual((play['hosts'], play['become'], play['gather_facts']), ('pbs', False, False))
        pre = play['pre_tasks'][0]
        self.assertEqual((pre['delegate_to'], pre['become'], pre['vars']['ansible_connection']), ('localhost', False, 'local'))
        self.assertIn('bootstrap_closed()', repr(pre['block'][0]))
        self.assertIn('--emit', repr(pre['block'][2]))
        self.assertIn('hostvars[inventory_hostname].ansible_connection', repr(pre['block'][3]))
        tasks = play['tasks']; names = [t['name'] for t in tasks]
        admission = names.index('Validate current ownership and interface separation locally')
        mutation = names.index('Prepare only the owned stock-service override directory')
        self.assertLess(admission, mutation)
        for t in tasks:
            if t.get('delegate_to') == 'localhost':
                self.assertFalse(t['become']); self.assertFalse(t['vars']['ansible_become'])
        self.assertNotIn('restarted', repr(play)); self.assertNotIn('ansible.builtin.apt', repr(play))
        copy = tasks[names.index('Syntax-check and install only the declared own-table policy')]['ansible.builtin.template']
        self.assertEqual(copy['validate'], '/usr/sbin/nft --check --file %s')
        self.assertEqual(copy['mode'], '0600')
        self.assertIn('final=True', repr(tasks[-1]))
        self.assertIn('r["network"]==v["network"]', repr(tasks[-1]))


if __name__ == '__main__':
    unittest.main()
