"""Synthetic saved plans and disposable local files; no PVE or credentials used."""
import copy
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_network_maintenance as maintenance
from test_database_network_server import contract

OP = dict(phase='cutover', client_vmids=[211, 202], legacy_server_address='10.88.30.23')


def cfg(vmid=208):
    value = contract(); net = value['networks']['postgresql']
    member = next(g for g in [net['server'], *net['clients']] if g['vmid'] == vmid)
    end = member['address'].split('.')[-1]
    rules = [dict(direction='in', proto='tcp', port='22', source='10.88.25.11/32', comment='runner only')]
    rules.append(dict(direction='in' if vmid == 208 else 'out', proto='tcp', port='5432',
                      destination='10.88.30.23/32', comment='old SQL'))
    if vmid == 208: rules[-1]['source'] = '10.88.30.0/24'
    rules.append(dict(direction='out', proto='tcp', port='80,443', destination='0.0.0.0/0', comment='packages'))
    return {'site': {'node': 'pve-test', 'api_endpoint': 'https://10.88.25.10:8006/'},
            'guest': {'vmid': vmid, 'hostname': member['hostname'], 'cpu': 2, 'memory_mib': 2048,
                'volumes': {'database': {'path': '/var/lib/postgresql', 'size_gib': 16}},
                'interfaces': [dict(bridge='vmbr0', vlan=25, mac='02:25:00:00:00:' + format(vmid - 100, '02x'),
                    ipv4='10.88.25.' + end + '/24', ipv6='manual', gateway='10.88.25.1'),
                    dict(bridge='vmbr30', vlan=None, mac='02:30:00:00:00:' + format(vmid - 100, '02x'),
                    ipv4='10.88.30.' + end + '/24', ipv6='manual')], 'rules': rules},
            'app': {'kind': 'postgresql' if vmid == 208 else 'identity', 'vmid': vmid}, 'ssh_public_keys': ['synthetic public key']}


def desired(original):
    """Independent expected operation, not the implementation under test."""
    guest = copy.deepcopy(original['guest']); net = contract()['networks']['postgresql']
    member = next(g for g in [net['server'], *net['clients']] if g['vmid'] == guest['vmid'])
    nic = dict(bridge='vmbr31', vlan=None, mac=member['mac'], ipv4=member['address'] + '/24', ipv6='manual')
    if guest['vmid'] == 208: guest['interfaces'][1] = nic
    else: guest['interfaces'].append(nic)
    guest['rules'].pop(1)
    selected = [g for g in net['clients'] if g['vmid'] in OP['client_vmids']]
    if guest['vmid'] != 208: selected = [member]
    for client in sorted(selected, key=lambda g: g['vmid']):
        guest['rules'].append(dict(direction='in' if guest['vmid'] == 208 else 'out', proto='tcp', port='5432',
            source=client['address'] + '/32', destination=net['server']['address'] + '/32',
            comment='postgresql approved client ' + client['hostname']))
    return guest


def raw_container(guest):
    return {'vm_id': guest['vmid'], 'node_name': 'pve-test', 'cpu': [{'cores': 2}], 'protection': True,
            'started': True, 'disk': [{'datastore_id': 'local-zfs', 'size': 4}],
            'mount_point': [{'volume': 'preserve-existing-data', 'path': '/var/lib/postgresql'}],
            'network_interface': [dict(name='eth' + str(i), bridge=n['bridge'], vlan_id=n['vlan'],
                mac_address=n['mac'], firewall=True, rate_limit=None, enabled=True) for i, n in enumerate(guest['interfaces'])],
            'initialization': [{'hostname': guest['hostname'], 'user_account': [{'keys': ['original-key']}],
                'dns': [{'servers': ['10.88.40.2']}], 'ip_config': [dict(ipv4=[dict(address=n['ipv4'], gateway=n.get('gateway'))],
                ipv6=[dict(address=n['ipv6'], gateway=None)]) for n in guest['interfaces']]}]}


def raw_rules(guest):
    return {'container_id': guest['vmid'], 'node_name': 'pve-test', 'rule': [dict(type=r['direction'], action='ACCEPT',
            proto=r['proto'], dport=r['port'], source=r.get('source'), dest=r.get('destination'), comment=r['comment'],
            enabled=True, log='nolog', macro=None) for r in guest['rules']]}


def saved_plan(original):
    guest = desired(original)
    values = [(maintenance.CONTAINER, raw_container(original['guest']), raw_container(guest)),
              (maintenance.OPTIONS, {'container_id': guest['vmid'], 'node_name': 'pve-test', 'enabled': True,
               'input_policy': 'DROP', 'output_policy': 'DROP'}, None),
              (maintenance.RULES, raw_rules(original['guest']), raw_rules(guest))]
    rows = []
    for address, before, after in values:
        after = copy.deepcopy(before) if after is None else after
        rows.append({'address': address, 'mode': 'managed', 'change': {'actions': ['no-op'] if before == after else ['update'],
                     'before': before, 'after': after, 'after_unknown': {}, 'replace_paths': []}})
    return {'resource_changes': rows, 'resource_drift': []}


def observed_provider_plan(original):
    """Synthetic values with the exact retained BPG0.117 refresh/plan shapes."""
    value = saved_plan(original); change = value['resource_changes'][0]['change']
    for side in ('before','after'):
        raw = change[side]
        raw.update(tags=[],environment_variables={},features=[dict(nesting=True,keyctl=False,mount=[])],
                   ipv4={'eth0':'10.88.25.20','eth1':'10.88.30.20','docker0':'172.17.0.1'},
                   ipv6={'eth0':'fe80::1','veth123':'fe80::2'})
        for field in ('disk','mount_point'):
            for block in raw[field]: block['mount_options'] = []
        for index,ip in enumerate(raw['initialization'][0]['ip_config']):
            if index < len(original['guest']['interfaces']):
                ip['ipv4'][0]['gateway'] = ip['ipv4'][0]['gateway'] or ''
                ip['ipv6'][0]['gateway'] = ''
    for row in value['resource_changes'][2]['change'].values():
        if isinstance(row,dict) and 'rule' in row:
            for index,rule in enumerate(row['rule']):
                rule['pos'] = index
                for key in ('source','dest'): rule[key] = rule[key] or ''
    refreshed = copy.deepcopy(change['before']); old = copy.deepcopy(refreshed)
    old.update(tags=None,environment_variables=None)
    old['ipv4'].pop('docker0'); old['ipv6'].pop('veth123')
    for field in ('disk','mount_point'):
        for block in old[field]: block['mount_options'] = None
    old['features'][0]['mount'] = None
    value['resource_drift'] = [dict(address=maintenance.CONTAINER,mode='managed',
        change=dict(actions=['update'],before=old,after=refreshed,after_unknown={}))]
    return value


def observed_appended_rule_plan(original):
    """The new BPG rule beyond the old list has unset optional defaults/pos."""
    value = observed_provider_plan(original); value['resource_drift'] = []
    change = value['resource_changes'][2]['change']
    for side in ('before','after'):
        for row in change[side]['rule']:
            row.update({name:'' for name in ('iface','log','macro','security_group','sport')})
    change['after']['rule'][-1].update({name:None for name in
        ('iface','log','macro','security_group','sport','pos')})
    return value


class PureTests(unittest.TestCase):
    def test_new_appended_sql_rule_accepts_only_fixed_omitted_provider_defaults(self):
        value = observed_appended_rule_plan(cfg()); saved = copy.deepcopy(value)
        self.assertEqual(maintenance.check_plan(value,cfg(),contract(),'postgresql',**OP)['candidate_guest'],desired(cfg()))
        self.assertEqual(value,saved)

    def test_new_sql_rule_omissions_do_not_admit_nonempty_fields_or_different_ports(self):
        for field,bad in [('iface','eth1'),('log','info'),('macro','SSH'),('security_group','new-group'),
                          ('sport','12345'),('source','0.0.0.0/0'),('dest','0.0.0.0/0'),('dport','5432,443')]:
            value = observed_appended_rule_plan(cfg()); value['resource_changes'][2]['change']['after']['rule'][-1][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                maintenance.check_plan(value,cfg(),contract(),'postgresql',**OP)

    def test_only_the_rule_beyond_the_old_list_may_omit_its_planned_position(self):
        for side,index,pos in [('before',0,None),('after',0,None),('after',2,None),('after',3,99),('after',3,True)]:
            value = observed_appended_rule_plan(cfg()); value['resource_changes'][2]['change'][side]['rule'][index]['pos'] = pos
            with self.subTest(side=side,index=index,pos=pos), self.assertRaises(ValueError):
                maintenance.check_plan(value,cfg(),contract(),'postgresql',**OP)
        value = observed_appended_rule_plan(cfg())
        rows = value['resource_changes'][2]['change']['after']['rule']; rows[2],rows[3] = rows[3],rows[2]
        for index,row in enumerate(rows): row['pos'] = index
        with self.assertRaises(ValueError): maintenance.check_plan(value,cfg(),contract(),'postgresql',**OP)

    def test_later_read_requires_known_positions_while_comparing_to_the_saved_plan(self):
        planned = observed_appended_rule_plan(cfg())['resource_changes'][2]['change']['after']
        actual = copy.deepcopy(planned)
        for index,row in enumerate(actual['rule']):
            row['pos'] = index
            for name in ('iface','log','macro','security_group','sport'):
                row[name] = row[name] or ''
        maintenance.validate_rule_positions(actual)
        self.assertTrue(maintenance.provider_values_equal(maintenance.RULES,actual,planned))
        with self.assertRaises(ValueError): maintenance.validate_rule_positions(planned)
        for pos in (99,True):
            bad = copy.deepcopy(actual); bad['rule'][-1]['pos'] = pos
            with self.subTest(pos=pos), self.assertRaises(ValueError):
                maintenance.validate_rule_positions(bad)
            with self.subTest(pos=pos), self.assertRaises(ValueError):
                maintenance.provider_values_equal(maintenance.RULES,bad,planned)

    def test_observed_empty_refresh_and_computed_address_maps_preserve_exact_nic_sql_scope(self):
        for vmid in (208,211,202):
            original = cfg(vmid); value = observed_provider_plan(original); saved = copy.deepcopy(value)
            result = maintenance.check_plan(value,original,contract(),'postgresql',**OP)
            self.assertEqual(result['candidate_guest'],desired(original))
            self.assertEqual(value,saved)  # Raw failed evidence is never rewritten.

    def test_empty_gateway_and_firewall_omissions_do_not_allow_real_addresses(self):
        value = observed_provider_plan(cfg(211)); value['resource_drift'] = []
        value['resource_changes'][0]['change']['before']['initialization'][0]['ip_config'][1]['ipv4'][0]['gateway'] = '10.88.30.1'
        with self.assertRaises(ValueError): maintenance.check_plan(value,cfg(211),contract(),'postgresql',**OP)

    def test_material_refresh_changes_remain_held_even_when_plan_before_matches_refresh(self):
        mutations = [lambda v:v.update(tags=['new-tag']),lambda v:v.update(environment_variables={'NEW':'value'}),
            lambda v:v['disk'][0].update(mount_options=['discard']),
            lambda v:v['mount_point'][0].update(mount_options=['ro']),
            lambda v:v['mount_point'][0].update(read_only=True),lambda v:v['features'][0].update(mount=['nfs']),
            lambda v:v['features'][0].update(keyctl=True),lambda v:v.update(unprivileged=False),
            lambda v:v['disk'][0].update(size=99),lambda v:v['network_interface'][0].update(bridge='vmbr99')]
        for mutate in mutations:
            value = observed_provider_plan(cfg(211)); drift = value['resource_drift'][0]['change']
            mutate(drift['after']); value['resource_changes'][0]['change']['before'] = copy.deepcopy(drift['after'])
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                maintenance.check_plan(value,cfg(211),contract(),'postgresql',**OP)

    def test_material_planned_changes_and_unknowns_remain_held_with_compatible_refresh(self):
        for mutate in (lambda p:p['resource_changes'][0]['change']['after'].update(tags=['new']),
                       lambda p:p['resource_changes'][0]['change']['after']['features'][0].update(mount=['nfs']),
                       lambda p:p['resource_changes'][0]['change'].update(after_unknown={'ipv4':True}),
                       lambda p:p['resource_drift'][0]['change'].update(after_unknown={'ipv6':True}),
                       lambda p:p['resource_drift'][0].update(address=maintenance.RULES)):
            value = observed_provider_plan(cfg(211)); mutate(value)
            with self.assertRaises(ValueError): maintenance.check_plan(value,cfg(211),contract(),'postgresql',**OP)

    def test_ordered_firewall_positions_must_follow_the_exact_selected_rule_list(self):
        for side,index in [('before',0),('after',2)]:
            value = observed_provider_plan(cfg(211))
            value['resource_changes'][2]['change'][side]['rule'][index]['pos'] = 99
            with self.subTest(side=side), self.assertRaises(ValueError):
                maintenance.check_plan(value,cfg(211),contract(),'postgresql',**OP)

    def test_provider_equality_ignores_only_fixed_empty_forms_and_valid_computed_maps(self):
        first = observed_provider_plan(cfg(211))['resource_drift'][0]['change']['before']
        second = observed_provider_plan(cfg(211))['resource_drift'][0]['change']['after']
        self.assertTrue(maintenance.provider_values_equal(maintenance.CONTAINER,first,second))
        for update in ({'tags':['new']},{'environment_variables':{'NEW':'value'}},{'protection':1}):
            changed = dict(second,**update)
            self.assertFalse(maintenance.provider_values_equal(maintenance.CONTAINER,first,changed))
        self.assertTrue(maintenance.provider_values_equal(maintenance.RULES,
            {'rule':[{'source':None,'dest':None,'action':'ACCEPT'}]},
            {'rule':[{'source':'','dest':'','action':'ACCEPT'}]}))
        self.assertFalse(maintenance.provider_values_equal(maintenance.RULES,
            {'rule':[{'source':None,'dest':None,'action':'ACCEPT'}]},
            {'rule':[{'source':'0.0.0.0/0','dest':'','action':'ACCEPT'}]}))

    def test_computed_maps_are_typed_address_observations_only(self):
        for field,bad in [('ipv4',{'eth0':'not-an-IP'}),('ipv4',{'eth0':'::1'}),
                          ('ipv6',{'eth0':'127.0.0.1'}),('ipv4',None),('ipv6',['fe80::1'])]:
            value = observed_provider_plan(cfg(211)); value['resource_drift'][0]['change']['after'][field] = bad
            value['resource_changes'][0]['change']['before'][field] = copy.deepcopy(bad)
            with self.subTest(field=field,bad=bad), self.assertRaises(ValueError):
                maintenance.check_plan(value,cfg(211),contract(),'postgresql',**OP)

    def test_pg_server_replaces_same_index_and_only_two_clients_are_granted(self):
        original = cfg(); before = copy.deepcopy(original); catalogue = contract()
        candidate = maintenance.candidate_guest(original['guest'], catalogue, 'postgresql', **OP)
        self.assertEqual(candidate, desired(original))
        self.assertEqual(candidate['interfaces'][0], original['guest']['interfaces'][0])
        self.assertEqual(len(candidate['interfaces']), 2)
        self.assertNotIn('vmbr30', str(candidate['interfaces']))
        self.assertNotIn('10.88.30.', str(candidate['rules']))
        self.assertNotIn('10.88.31.27', str(candidate))
        self.assertEqual(original, before); self.assertEqual(catalogue, contract())

    def test_clients_keep_http_backend_and_append_private_sql(self):
        for vmid in (211, 202):
            original = cfg(vmid); candidate = maintenance.candidate_guest(original['guest'], contract(), 'postgresql', **OP)
            self.assertEqual(candidate, desired(original))
            self.assertEqual(candidate['interfaces'][:2], original['guest']['interfaces'])
            self.assertEqual(candidate['interfaces'][2]['bridge'], 'vmbr31')
            self.assertNotIn('10.88.30.23', str(candidate['rules']))
            self.assertEqual(maintenance.check_plan(saved_plan(original), original, contract(), 'postgresql', **OP)['vmid'], vmid)

    def test_unselected_future_client_or_ambiguous_old_paths_are_held(self):
        variants = [cfg(213)]
        bad = cfg(); bad['guest']['interfaces'][1]['gateway'] = '10.88.30.1'; variants.append(bad)
        bad = cfg(); bad['guest']['rules'][1]['port'] = '5432,443'; variants.append(bad)
        bad = cfg(); bad['guest']['rules'].append(copy.deepcopy(bad['guest']['rules'][1])); variants.append(bad)
        bad = cfg(); bad['guest']['interfaces'].append(copy.deepcopy(bad['guest']['interfaces'][1])); variants.append(bad)
        for original in variants:
            with self.subTest(original=original), self.assertRaises(ValueError):
                maintenance.candidate_guest(original['guest'], contract(), 'postgresql', **OP)
        with self.assertRaises(ValueError):
            maintenance.candidate_guest(cfg()['guest'], contract(), 'postgresql', **dict(OP, legacy_server_address='10.88.30.24'))

    def test_exact_server_saved_plan_is_only_a_review_candidate(self):
        result = maintenance.check_plan(saved_plan(cfg()), cfg(), contract(), 'postgresql', **OP)
        self.assertEqual(result['status'], 'review_required')
        self.assertFalse(result['apply_supported'])
        self.assertFalse(result['lifecycle_effects_verified'])
        self.assertFalse(hasattr(maintenance, 'apply'))

    def test_unrelated_or_computed_resource_changes_are_refused(self):
        mutations = [lambda p: p['resource_changes'][0]['change']['after']['cpu'][0].update(cores=8),
            lambda p: p['resource_changes'][0]['change']['after']['disk'][0].update(size=64),
            lambda p: p['resource_changes'][0]['change']['after'].update(protection=False),
            lambda p: p['resource_changes'][0]['change']['after']['initialization'][0]['ip_config'][0]['ipv4'][0].update(gateway='10.88.25.254'),
            lambda p: p['resource_changes'][0]['change']['after']['network_interface'][1].update(name='eth9'),
            lambda p: p['resource_changes'][1]['change']['after'].update(input_policy='ACCEPT'),
            lambda p: p['resource_changes'][2]['change']['after']['rule'][0].update(source='0.0.0.0/0'),
            lambda p: p['resource_changes'][2]['change']['after']['rule'][-1].update(enabled=False),
            lambda p: p['resource_changes'][0]['change'].update(after_unknown={'network_interface': [True]}),
            lambda p: p.update(resource_drift=[{'address': maintenance.CONTAINER}]),
            lambda p: p['resource_changes'][0].update(previous_address='an-old-resource'),
            lambda p: p['resource_changes'][0]['change'].update(importing={'id': '208'}),
            lambda p: p['resource_changes'][0]['change']['after'].update(vm_id=209),
            lambda p: p['resource_changes'][0]['change']['after'].update(node_name='different-node')]
        for mutate in mutations:
            plan = saved_plan(cfg()); mutate(plan)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                maintenance.check_plan(plan, cfg(), contract(), 'postgresql', **OP)

    def test_create_delete_replace_import_other_resources_or_missing_resources_are_held(self):
        for actions in (['create'], ['delete'], ['delete', 'create'], ['read'], ['forget']):
            value = saved_plan(cfg()); value['resource_changes'][0]['change']['actions'] = actions
            with self.subTest(actions=actions), self.assertRaises(ValueError):
                maintenance.check_plan(value, cfg(), contract(), 'postgresql', **OP)
        for mutate in (lambda p: p['resource_changes'].pop(),
                       lambda p: p['resource_changes'].append(copy.deepcopy(p['resource_changes'][0])),
                       lambda p: p['resource_changes'][0].update(address='other.guest')):
            value = saved_plan(cfg()); mutate(value)
            with self.assertRaises(ValueError): maintenance.check_plan(value, cfg(), contract(), 'postgresql', **OP)

    def test_untagged_zero_provider_representation_is_preserved(self):
        value = saved_plan(cfg())
        for side in ('before', 'after'):
            value['resource_changes'][0]['change'][side]['network_interface'][1]['vlan_id'] = 0
        maintenance.check_plan(value, cfg(), contract(), 'postgresql', **OP)

    def test_other_engines_remain_additive_and_retain_old_paths(self):
        for engine in ('mariadb', 'influxdb'):
            value = contract(); member = value['networks'][engine]['server']; guest = copy.deepcopy(cfg()['guest'])
            guest.update(vmid=member['vmid'], hostname=member['hostname'])
            guest['rules'][1]['port'] = str(maintenance.networks.PORTS[engine])
            candidate = maintenance.candidate_guest(guest, value, engine, phase='additive', client_vmids=[200])
            self.assertEqual(candidate['interfaces'][:2], guest['interfaces'])
            self.assertTrue(all(rule in candidate['rules'] for rule in guest['rules']))
            self.assertEqual(candidate['interfaces'][-1]['bridge'], value['networks'][engine]['bridge'])


class ReadOnlyPlannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.work = self.state / '208'; self.work.mkdir(mode=0o700)
        (self.work / 'tofu').mkdir(mode=0o700)
        self.site = self.root / 'site.json'; self.catalogue = self.root / 'catalogue.json'
        self.evidence = self.work / 'database-network-plan-test'
        self.cfg = cfg(); self.cfg['paths'] = {'state_root': str(self.state), 'ca_file': str(self.root / 'ca'),
            'api_token': str(self.root / 'token')}
        self.source = self.root / 'source'; (self.source / 'tofu').mkdir(parents=True)
        (self.source / 'tofu/main.tf').write_text('# synthetic unchanged original source\n')
        maintenance.write_new(self.site, maintenance.encoded(self.cfg))
        maintenance.write_new(self.catalogue, maintenance.encoded(contract()))
        maintenance.write_new(self.root / 'token', b'SYNTHETIC_TOKEN_NEVER_LOG')
        maintenance.write_new(self.root / 'ca', b'synthetic CA')
        self.labels = {'managed-by': 'original-source'}
        variables = {key: copy.deepcopy(self.cfg[key]) for key in ('site', 'guest', 'ssh_public_keys')}
        variables['guest']['routing_labels'] = self.labels
        maintenance.write_new(self.work / 'tofu/site.auto.tfvars.json', maintenance.encoded(variables))
        for name, data in {'guest.tfplan': b'ORIGINAL_SAVED_PLAN', 'guest.tfplan.json': b'{"original":true}',
                           'terraform.tfstate': b'{"lineage":"original-lineage","serial":7}', 'ssh-trust.json': b'{"original":"trust"}'}.items():
            maintenance.write_new(self.work / name, data)
        self.input_hashes = {str(self.root / 'ca'): maintenance.digest(b'synthetic CA')}
        receipt = {'vmid': 208, 'site_sha256': maintenance.digest(self.site.read_bytes()), 'source_sha256': 'a' * 64,
                   'input_hashes': self.input_hashes, 'plan_sha256': maintenance.digest(b'ORIGINAL_SAVED_PLAN'),
                   'plan_json_sha256': maintenance.digest(b'{"original":true}')}
        for name in ('plan.json', 'applied.json', 'started.json'): maintenance.write_new(self.work / name, maintenance.encoded(receipt))
        maintenance.write_new(self.work / 'rollout-complete.json', maintenance.encoded(
            {'status': 'passed', 'vmid': 208, 'plan_sha256': receipt['plan_sha256']}))
        self.deployment = types.SimpleNamespace(SOURCE=self.source, validate=Mock(return_value=208),
            source_hash=Mock(return_value='a' * 64), input_hashes=Mock(return_value=self.input_hashes),
            discovery=types.SimpleNamespace(labels=Mock(return_value=self.labels)), execute=Mock())
        self.originals = {p: p.read_bytes() for p in self.work.rglob('*') if p.is_file()}
        self.originals[self.site] = self.site.read_bytes()
        for name, value in (('STATE', self.state), ('BOOTSTRAP_HOLD', self.root / 'CONFIGURING')):
            patcher = patch.object(maintenance, name, value); patcher.start(); self.addCleanup(patcher.stop)

    def invoke(self):
        return maintenance.plan(self.deployment, self.site, self.catalogue, self.evidence, 'postgresql', **OP)

    def fake_tofu(self, command, environment, log, output=None):
        self.assertEqual(environment['PROXMOX_VE_API_TOKEN'], 'SYNTHETIC_TOKEN_NEVER_LOG')
        if 'plan' in command: maintenance.write_new(self.evidence / 'guest.tfplan', b'CANDIDATE_SAVED_PLAN')
        if output: maintenance.write_new(output, maintenance.encoded(saved_plan(self.cfg)))

    def test_plan_uses_original_backend_locks_isolated_evidence_and_never_installer_execute(self):
        with patch.object(maintenance, 'tofu', side_effect=self.fake_tofu) as tofu:
            result = self.invoke()
        self.assertFalse(result['apply_supported']); self.assertEqual(result['status'], 'review_required')
        self.assertEqual(len(tofu.call_args_list), 3)
        self.assertIn('-backend-config=path=' + str(self.work / 'terraform.tfstate'), tofu.call_args_list[0].args[0])
        self.assertIn('-out=' + str(self.evidence / 'guest.tfplan'), tofu.call_args_list[1].args[0])
        self.assertTrue(all('apply' not in call.args[0] for call in tofu.call_args_list))
        self.deployment.execute.assert_not_called()
        for path, content in self.originals.items(): self.assertEqual(path.read_bytes(), content)
        for path in self.evidence.rglob('*'):
            if path.is_file() and path.name not in {'main.tf'}: self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('SYNTHETIC_TOKEN', str(result))
        self.assertNotIn('SYNTHETIC_TOKEN', (self.evidence / 'request.json').read_text())
        self.assertEqual(result['original']['state_lineage'], 'original-lineage')
        self.assertEqual(result['original']['state_serial'], 7)
        with self.assertRaises(ValueError): self.invoke()  # One evidence directory is never replayed.

    def test_holds_or_original_source_input_receipt_drift_refuse_before_commands(self):
        for name in ('HOLD.json', 'ROLLOUT-HOLD.json', 'FOUNDATION-HOLD.json'):
            path = self.work / name; maintenance.write_new(path, b'{}')
            with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(ValueError): self.invoke()
            tofu.assert_not_called(); path.unlink()
        self.deployment.source_hash.return_value = 'b' * 64
        with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(ValueError): self.invoke()
        tofu.assert_not_called(); self.assertFalse(self.evidence.exists())

    def test_existing_workflow_lock_blocks_plan(self):
        with (self.work / 'workflow.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(BlockingIOError): self.invoke()
            tofu.assert_not_called()

    def test_failed_plan_retains_private_evidence_and_cannot_reuse_directory(self):
        with patch.object(maintenance, 'tofu', side_effect=RuntimeError('synthetic planning failure')) as tofu:
            with self.assertRaises(RuntimeError): self.invoke()
            self.assertEqual(tofu.call_count, 1)
            with self.assertRaises(ValueError): self.invoke()
            self.assertEqual(tofu.call_count, 1)
        self.assertFalse((self.evidence / 'review-packet.json').exists())
        self.assertFalse(json.loads((self.evidence / 'HOLD.json').read_bytes())['automatic_retry'])
        for path, content in self.originals.items(): self.assertEqual(path.read_bytes(), content)

    def test_new_run_identity_does_not_replay_a_failed_read_only_plan(self):
        with patch.object(maintenance, 'tofu', side_effect=RuntimeError('synthetic planning failure')) as tofu:
            with self.assertRaises(RuntimeError): self.invoke()
            old = self.evidence
            self.evidence = old.with_name(old.name + '-different-run')
            with self.assertRaisesRegex(ValueError, 'failed planning hold'): self.invoke()
            self.assertEqual(tofu.call_count, 1)
            self.assertTrue((old / 'HOLD.json').is_file())
            self.assertFalse(self.evidence.exists())

    def test_interrupted_request_without_exception_marker_blocks_a_new_plan(self):
        interrupted = self.work / 'database-network-plan-interrupted'; interrupted.mkdir(mode=0o700)
        maintenance.write_new(interrupted / 'request.json', b'{}')
        with patch.object(maintenance, 'tofu') as tofu, self.assertRaisesRegex(ValueError, 'planning hold'):
            self.invoke()
        tofu.assert_not_called()
        self.assertFalse(self.evidence.exists())

    def assert_drift_is_held(self, target):
        def changed(command, environment, log, output=None):
            self.fake_tofu(command, environment, log, output)
            if output:
                data = json.loads(target.read_bytes())
                if target == self.catalogue: data['networks']['postgresql']['description'] += ' changed'
                else: data['serial'] += 1
                target.write_bytes(maintenance.encoded(data))
        with patch.object(maintenance, 'tofu', side_effect=changed), self.assertRaises(ValueError): self.invoke()
        self.assertTrue((self.evidence / 'HOLD.json').exists())

    def test_state_drift_during_plan_is_held(self):
        self.assert_drift_is_held(self.work / 'terraform.tfstate')

    def test_catalogue_drift_during_plan_is_held(self):
        self.assert_drift_is_held(self.catalogue)

    def test_symlinked_private_inputs_are_refused(self):
        self.site.unlink(); self.site.symlink_to(self.catalogue)
        with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(OSError): self.invoke()
        tofu.assert_not_called()

    def test_catalogue_accepts_owned_git_mode_without_weakening_private_inputs(self):
        self.catalogue.chmod(0o644)
        with patch.object(maintenance, 'tofu', side_effect=self.fake_tofu):
            self.assertEqual(self.invoke()['status'], 'review_required')
        self.evidence = self.evidence.with_name(self.evidence.name + '-next')
        self.site.chmod(0o644)
        with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(ValueError): self.invoke()
        tofu.assert_not_called()

    def test_commissioned_database_installer_without_discovery_keeps_its_original_variables(self):
        # The actual DB pin f313136 predates the foundation discovery API.
        del self.deployment.discovery
        path = self.work / 'tofu/site.auto.tfvars.json'
        variables = json.loads(path.read_bytes()); variables['guest'].pop('routing_labels')
        path.write_bytes(maintenance.encoded(variables))
        (self.work / 'guest.tfplan.json').unlink()
        for name in ('plan.json','applied.json','started.json'):
            receipt = json.loads((self.work / name).read_bytes()); receipt.pop('plan_json_sha256')
            (self.work / name).write_bytes(maintenance.encoded(receipt))
        before = path.read_bytes()
        with patch.object(maintenance, 'tofu', side_effect=self.fake_tofu):
            self.assertEqual(self.invoke()['status'], 'review_required')
        candidate = json.loads((self.evidence / 'tofu/site.auto.tfvars.json').read_bytes())
        self.assertNotIn('routing_labels', candidate['guest'])
        self.assertEqual(path.read_bytes(), before)

    def test_modern_installer_cannot_drop_its_json_receipt_binding(self):
        for name in ('plan.json','applied.json','started.json'):
            receipt = json.loads((self.work / name).read_bytes()); receipt.pop('plan_json_sha256')
            (self.work / name).write_bytes(maintenance.encoded(receipt))
        with patch.object(maintenance, 'tofu') as tofu:
            with self.assertRaisesRegex(ValueError,'JSON plan binding'): self.invoke()
        tofu.assert_not_called()


if __name__ == '__main__':
    unittest.main()
