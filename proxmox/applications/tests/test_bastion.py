"""Synthetic bastion policy, preserved administration and shared CD boundaries."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import bastion
import deploy
from test_deploy import fixture as base


def fixture(root):
    key = root / 'operator.pub'
    key.write_text('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n')
    cfg = base(root)
    cfg['guest'].update(cpu=1, root_gib=4, nesting=False, keyctl=False, volumes={}, rules=[])
    cfg['guest']['interfaces'] = [
        {'ipv4':'198.18.15.15/24', 'gateway':'198.18.15.1', 'mac':'02:00:00:00:15:15', 'ipv6':'manual'},
        {'ipv4':'198.18.25.15/24', 'mac':'02:00:00:00:25:15', 'ipv6':'manual'}]
    cfg['app'].update(kind='bastion', address='198.18.25.15', mac='02:00:00:00:25:15',
        packages=['openssh-server=1:10.0p1-1', 'nftables=1.1.3-1'],
        bastion={'entry_address':'198.18.15.15', 'management_address':'198.18.25.15',
                 'runner_source':'198.18.25.11/32', 'maintenance':[], 'roles':[
                     {'name':'operator', 'uid':1000, 'gid':1000,
                      'sources':['198.18.10.2/32'], 'public_key_file':str(key),
                      'permit_open':['198.18.25.10:8006', '198.18.25.2:31722']}]})
    cfg['guest']['rules'] = bastion.access_rules(cfg['app']['bastion'])
    return cfg


class BastionTests(unittest.TestCase):
    def test_positive_native_kind_has_exact_rules_and_no_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = fixture(Path(tmp))
            self.assertEqual(deploy.validate(cfg), 6101)
            self.assertFalse(deploy.needs_capture(cfg['app']))
            files = bastion.render(cfg['app']['bastion'])
            ssh = files['sshd_config']
            self.assertIn('ListenAddress 198.18.15.15:22', ssh)
            self.assertIn('Match LocalAddress 198.18.25.15\n    AllowUsers root@198.18.25.11/32', ssh)
            self.assertIn('PermitOpen 198.18.25.10:8006 198.18.25.2:31722', ssh)
            self.assertIn('MaxSessions 0', ssh)
            for value in ['AllowAgentForwarding no', 'AllowStreamLocalForwarding no', 'PermitListen none',
                          'PermitTunnel no', 'X11Forwarding no', 'PasswordAuthentication no',
                          'KbdInteractiveAuthentication no', 'PermitUserRC no']:
                self.assertIn(value, ssh)
            self.assertNotIn('Include ', ssh)
            self.assertIn('net.ipv4.ip_forward=0', files['sysctl'])

    def test_refuses_wildcards_injection_broad_sources_and_nonmanagement_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = fixture(Path(tmp))
            for field, values in {'sources':[['198.18.10.0/24'], ['*'], ['198.18.10.2/32\nAllowUsers root']],
                                  'permit_open':[['*:22'], ['198.18.25.0/24:22'], ['198.18.40.33:443'],
                                                 ['198.18.25.10:*'], ['198.18.25.10:8006\nPermitTunnel yes']],
                                  'name':['root', 'operator\nMatch all'], 'uid':[0, True], 'gid':[0, True]}.items():
                for value in values:
                    bad = copy.deepcopy(good); bad['app']['bastion']['roles'][0][field] = value
                    with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                        deploy.validate(bad)

    def test_refuses_address_account_and_network_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = fixture(Path(tmp))
            for change in ['ipv6', 'missing_rule', 'extra_rule', 'extra_interface', 'capture', 'nesting', 'same_address', 'management_gateway', 'duplicate_role']:
                bad = copy.deepcopy(good)
                if change == 'ipv6': bad['guest']['interfaces'][0]['ipv6'] = 'auto'
                elif change == 'missing_rule': bad['guest']['rules'].pop()
                elif change == 'extra_rule': bad['guest']['rules'].append({'direction':'out','proto':'tcp','port':'443','destination':'0.0.0.0/0','comment':'broad'})
                elif change == 'extra_interface': bad['guest']['interfaces'].append(bad['guest']['interfaces'][0])
                elif change == 'capture': bad['app']['capture'] = {}
                elif change == 'nesting': bad['guest']['nesting'] = True
                elif change == 'same_address': bad['app']['bastion']['entry_address'] = '198.18.25.15'
                elif change == 'management_gateway':
                    bad['guest']['interfaces'][0].pop('gateway');bad['guest']['interfaces'][1]['gateway']='198.18.25.1'
                else: bad['app']['bastion']['roles'].append(bad['app']['bastion']['roles'][0])
                with self.subTest(change=change), self.assertRaises(ValueError): deploy.validate(bad)

    def test_public_operator_key_is_bound_into_saved_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = fixture(root); (root/'ca').write_text('synthetic CA')
            before = deploy.input_hashes(cfg)
            self.assertIn(str(root/'operator.pub'), before)
            (root/'operator.pub').write_text('different public key')
            self.assertNotEqual(deploy.input_hashes(cfg), before)
            with self.assertRaises(ValueError): bastion.render(cfg['app']['bastion'])

    def test_account_receipt_and_numeric_collisions_hold_without_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = fixture(Path(tmp))['app']['bastion']
            user = SimpleNamespace(pw_name='operator',pw_uid=1000,pw_gid=1000,pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')
            group = SimpleNamespace(gr_name='operator',gr_gid=1000,gr_mem=[])
            receipt = [{'name':'operator','uid':1000,'gid':1000}]
            with patch.object(bastion.pwd,'getpwall',return_value=[]), patch.object(bastion.grp,'getgrall',return_value=[]):
                bastion.account_preflight(policy)
                with self.assertRaises(ValueError): bastion.account_preflight(policy,receipt)
            with patch.object(bastion.pwd,'getpwall',return_value=[user]), patch.object(bastion.grp,'getgrall',return_value=[group]):
                with self.assertRaises(ValueError): bastion.account_preflight(policy)
                bastion.account_preflight(policy,receipt)
                user.pw_uid = 1001
                with self.assertRaises(ValueError): bastion.account_preflight(policy,receipt)
                user.pw_uid = 1000
            foreign = SimpleNamespace(gr_name='sudo',gr_gid=27,gr_mem=['operator'])
            with patch.object(bastion.pwd,'getpwall',return_value=[user]), patch.object(bastion.grp,'getgrall',return_value=[group,foreign]):
                with self.assertRaises(ValueError): bastion.account_preflight(policy,receipt)

    def test_native_bastion_runs_the_shared_pipeline_without_a_capture(self):
        from test_rollout import RolloutTests
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            _, site, work, plan = RolloutTests().prepare(root)
            cfg=fixture(root)
            site.write_text(json.dumps(cfg))
            receipt=json.loads((work/'plan.json').read_text())
            receipt.update(site_sha256=deploy.sha(site),input_hashes=deploy.input_hashes(cfg))
            deploy.write(work/'plan.json',receipt)
            with patch.object(deploy,'_execute_step',return_value={'status':'passed'}) as step, patch.object(deploy.guest_identity,'pin',return_value={'fingerprint':'synthetic'}):
                result=deploy.execute('deploy',site,plan)
            self.assertEqual([call.args[0] for call in step.call_args_list],['apply','stage','start','verify'])
            self.assertEqual(result['status'],'passed')
            self.assertEqual(json.loads((work/'rollout-complete.json').read_text())['plan_sha256'],plan)
            self.assertFalse((work/'ROLLOUT-HOLD.json').exists())

    def test_daemon_defaults_cannot_override_the_selected_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'ssh-defaults'
            path.write_text('# vendor default\nSSHD_OPTS=\n')
            bastion.daemon_preflight(path)
            for content in ['SSHD_OPTS="-f /etc/ssh/other.conf"', '. /etc/other', 'SSHD_OPTS=-oPermitTunnel=yes']:
                path.write_text(content)
                with self.assertRaises(ValueError):bastion.daemon_preflight(path)

    def test_runtime_verifier_rejects_forwarding_bridging_nat_and_policy_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = fixture(Path(tmp))['app']['bastion']
            expected = bastion.render(policy)['sshd_config']
            self.assertTrue(expected)
            bastion.check_transit(dict(bastion.SYSCTLS), [{'ifname':'lo'}, {'ifname':'eth0','linkinfo':{'info_kind':'veth'}}, {'ifname':'eth1'}], {'nftables':[]})
            for sysctls, links, rules in [({'net.ipv4.ip_forward':'1'}, [], {'nftables':[]}),
                                         ({}, [{'linkinfo':{'info_kind':'bridge'}}], {'nftables':[]}),
                                         ({}, [], {'nftables':[{'chain':{'type':'nat'}}]})]:
                with self.subTest(sysctls=sysctls, links=links, rules=rules), self.assertRaises(ValueError):
                    bastion.check_transit(sysctls, links, rules)


if __name__ == '__main__': unittest.main()
