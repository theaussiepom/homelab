"""Selected IP filters extend owned state without widening firewall custody."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

APP = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(APP), str(APP/'tests')]
import plan_policy as policy
import component_generation as generation
from component_generation_fixtures import backend, save
from test_plan import fixture, existing_fixture


def attributes(slot=1):
    return {'container_id': 6100, 'node_name': 'fixture-pve', 'name': f'ipfilter-net{slot}',
            'comment': policy.IP_FILTER_COMMENT, 'cidr': [], 'vm_id': None, 'id': f'ipfilter-net{slot}'}


def planned(*, existing=True, owned=False):
    value = existing_fixture() if existing else fixture()
    for row in value['resource_changes']:
        key = policy.RESOURCES[row['address']]
        for side in ('before', 'after'):
            if row['change'][side] is not None:
                row['change'][side].update(node_name='fixture-pve', id=f'fixture/6100/{key}')
    after = attributes()
    if not owned: after['id'] = None
    value['resource_changes'].append({'address': policy.IP_FILTER_RESOURCE+'["1"]',
        'type': 'proxmox_virtual_environment_firewall_ipset', 'change': {
            'actions': ['no-op'] if owned else ['create'],
            'before': copy.deepcopy(after) if owned else None, 'after': after,
            'after_unknown': {} if owned else {'id': True}}})
    return value


def admit(value, *, existing=True, slots=(1,)):
    policy.check_plan(value, 'fixture-pve', 6100, existing=existing,
                      protected_guests=[900], ip_filter_slots=slots)


def state_with_filter():
    value = backend(6100)
    module, kind, name = policy.IP_FILTER_RESOURCE.rsplit('.', 2)
    value['resources'].append({'module': module, 'type': kind, 'name': name, 'mode': 'managed',
                              'instances': [{'index_key': '1', 'attributes': attributes()}]})
    return value


class PerNicFilterTests(unittest.TestCase):
    def test_fresh_infrastructure_does_not_read_an_uncreated_guests_ipset_endpoint(self):
        import deployment_inputs
        import proxmox_guest as provider
        from test_component_deployment import DeploymentIntegrationTests
        from private_io import encoded, sha, write_new
        infrastructure = provider.infrastructure
        case = DeploymentIntegrationTests(); case.setUp(); self.addCleanup(case.doCleanups)
        cfg = copy.deepcopy(case.cfg)
        cfg['site']['node'] = 'fixture-pve'; cfg['guest']['vmid'] = cfg['app']['vmid'] = 6100
        cfg['guest']['interfaces'][1]['ip_filter'] = True
        cfg['paths']['api_token'] = str(case.root/'fresh-provider-token')
        write_new(case.root/'fresh-provider-token', b'fixture@pve!deploy=synthetic')
        work = case.root/'fresh-state'; work.mkdir(mode=0o700)
        operation = case.root/'fresh-attempt'; operation.mkdir(mode=0o700)
        applied = []
        def quiet(argv, environment, log):
            if 'plan' in argv: write_new(operation/'guest.tfplan', b'fresh saved plan')
            if 'apply' in argv:
                applied.append(True)
                save(work/'terraform.tfstate', state_with_filter())
        with patch.object(deployment_inputs, 'binding', return_value={}), \
             patch.object(provider, 'backup'), patch.object(provider, 'quiet', side_effect=quiet), \
             patch.object(provider.subprocess, 'check_output', return_value=encoded(planned(existing=False))), \
             patch.object(provider, 'api_get', side_effect=AssertionError('Fresh endpoint does not exist')), \
             patch.object(provider.guest_identity, 'pin') as pin:
            result = infrastructure(cfg, case.root/'site', work, operation, {})
        self.assertEqual(applied, [True]); pin.assert_called_once()
        self.assertTrue(result['created']); self.assertEqual(result['state_sha256'], sha(work/'terraform.tfstate'))

    def test_preflight_refuses_collision_or_missing_evidence_and_skips_owned_repeats(self):
        import proxmox_guest as provider
        cfg = {'site': {'node': 'fixture-pve'}, 'guest': {'vmid': 6100}}
        with patch.object(provider, 'api_get', return_value=[]) as read:
            provider.new_ip_filters_absent(cfg, planned())
            read.assert_called_once_with(cfg, '/nodes/fixture-pve/lxc/6100/firewall/ipset')
        for rows in (None, {}, [None], [{}], [{'name': None}], [{'name': ''}], [{'name': 'ipfilter-net1'}]):
            with self.subTest(rows=rows), patch.object(provider, 'api_get', return_value=rows), self.assertRaises(ValueError):
                provider.new_ip_filters_absent(cfg, planned())
        with patch.object(provider, 'api_get', side_effect=OSError('unavailable')), self.assertRaises(OSError):
            provider.new_ip_filters_absent(cfg, planned())
        with patch.object(provider, 'api_get', return_value=[{'name': 'unrelated'}]):
            provider.new_ip_filters_absent(cfg, planned())
        with patch.object(provider, 'api_get', side_effect=AssertionError('No new filter needs an API read')):
            provider.new_ip_filters_absent(cfg, planned(owned=True))
            provider.new_ip_filters_absent(cfg, existing_fixture())

    def test_real_saved_plan_caller_refuses_a_collision_before_any_apply(self):
        import deployment_inputs
        import proxmox_guest as provider
        from test_component_deployment import DeploymentIntegrationTests
        from private_io import encoded, write_new
        infrastructure = provider.infrastructure
        case = DeploymentIntegrationTests(); case.setUp(); self.addCleanup(case.doCleanups)
        cfg = copy.deepcopy(case.cfg)
        cfg['site']['node'] = 'fixture-pve'; cfg['guest']['vmid'] = cfg['app']['vmid'] = 6100
        cfg['guest']['interfaces'][1]['ip_filter'] = True
        cfg['paths']['api_token'] = str(case.root/'provider-token')
        write_new(case.root/'provider-token', b'fixture@pve!deploy=synthetic')
        work = case.root/'provider-state'; work.mkdir(mode=0o700)
        save(work/'terraform.tfstate', backend(6100))
        _, identity = generation.backend(work, {'vmid': 6100, 'node': 'fixture-pve'})
        operation = case.root/'provider-attempt'; operation.mkdir(mode=0o700)
        def quiet(argv, environment, log):
            self.assertNotIn('apply', argv)
            if 'plan' in argv: write_new(operation/'guest.tfplan', b'fixture saved plan')
        with patch.object(deployment_inputs, 'binding', return_value={}), \
             patch.object(provider, 'backup'), patch.object(provider, 'quiet', side_effect=quiet), \
             patch.object(provider.subprocess, 'check_output', return_value=encoded(planned())), \
             patch.object(provider, 'api_get', return_value=[{'name': 'ipfilter-net1'}]), \
             self.assertRaisesRegex(ValueError, 'already exists'):
            infrastructure(cfg, case.root/'site', work, operation, {}, state_identity=identity)
        self.assertFalse((operation/'apply-window.json').exists())

    def test_genuine_receipts_add_one_filter_then_preserve_it_across_all_phases_and_repeat(self):
        from test_component_deployment import DeploymentIntegrationTests
        import component_packet
        import component_plan
        from private_io import encoded, read_json, sha, write_bytes
        case = DeploymentIntegrationTests(); case.setUp(); self.addCleanup(case.doCleanups)
        case.all_phases()
        receipt = case.state/'610/ordinary-complete.json'
        original = read_json(receipt, private=True)
        source = case.plan.site
        source['guests']['resolver']['interfaces']['backend']['ip_filter'] = True
        authored = case.root/'consumer/site.json'; authored.write_text(json.dumps(source))
        selected = component_plan.resolve(case.root/'library', authored)
        packet = component_packet.lower_plan(selected, inputs=case.inputs)['resolver']
        write_bytes(case.packet, encoded(packet)); case.cfg = json.loads(packet['files']['site.json'])
        def infrastructure(cfg, site, work, operation, binding, **kwargs):
            result = case.infrastructure(cfg, site, work, operation, binding, **kwargs)
            state = work/'terraform.tfstate'; value = read_json(state, private=True)
            module, kind, name = policy.IP_FILTER_RESOURCE.rsplit('.', 2)
            fields = dict(attributes(), container_id=610, node_name=cfg['site']['node'])
            value['resources'].append({'module': module, 'type': kind, 'name': name,
                'mode': 'managed', 'instances': [{'index_key': '1', 'attributes': fields}]})
            write_bytes(state, encoded(value))
            return dict(result, state_sha256=sha(state))
        for run in (11, 12):
            with patch.dict(os.environ, {'GITHUB_RUN_ID': str(100+run), 'GITHUB_RUN_NUMBER': str(run)}), \
                 patch('proxmox_guest.infrastructure', side_effect=infrastructure):
                case.all_phases()
            current = read_json(receipt, private=True)
            self.assertTrue(generation.identity_extension(original['state_identity'],
                                                          current['state_identity'], [1]))
            self.assertFalse((case.state/'610/ORDINARY-HOLD.json').exists())

    def test_only_declared_static_nics_select_sets(self):
        original = [{'ipv4': '198.18.25.10/24'}, {'ipv4': '198.18.30.10/24', 'ipv6': 'manual'}]
        self.assertEqual(policy.ip_filter_slots(original), [])
        selected = copy.deepcopy(original); selected[1]['ip_filter'] = True
        self.assertEqual(policy.ip_filter_slots(selected), [1])
        self.assertEqual(policy.ip_filter_slots([dict(original[1], ip_filter=False)]), [])
        bad = [None, {}, original*17, [None], [dict(original[0], ip_filter='true')]]
        bad += [[{'ip_filter': True, 'ipv4': v}] for v in ('manual', 'dhcp', 'bad', None, '198.18.30.10')]
        bad += [[{'ip_filter': True}], [dict(selected[1], ipv6='auto')]]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError): policy.ip_filter_slots(value)
        for slots in (None, {}, [True], [-1], [32], [1, 1], ['1']):
            with self.subTest(slots=slots), self.assertRaises(ValueError): policy.resource_fields(slots)

    def test_fresh_addition_existing_addition_and_owned_repeat(self):
        for existing, owned in ((False, False), (True, False), (True, True)):
            value = planned(existing=existing, owned=owned); before = copy.deepcopy(value)
            admit(value, existing=existing)
            self.assertEqual(value, before)
        value = planned()
        with self.assertRaises(ValueError): admit(value, slots=())
        with self.assertRaises(ValueError): admit(dict(value, applyable=False))
        mutations = [lambda row: row['change']['after'].update(name='ipfilter-net0'),
            lambda row: row['change']['after'].update(comment='foreign'),
            lambda row: row['change']['after'].update(cidr=[{'name': '0.0.0.0/0'}]),
            lambda row: row['change']['after'].update(vm_id=6100),
            lambda row: row['change']['after'].update(extra=True),
            lambda row: row['change']['after'].update(container_id=6101),
            lambda row: row['change']['after'].update(node_name='foreign'),
            lambda row: row['change'].update(actions=['delete', 'create']),
            lambda row: row['change'].update(actions=['update']),
            lambda row: row['change'].update(after_unknown={'cidr': True}),
            lambda row: row['change'].update(importing={'id': 'foreign'})]
        for mutation in mutations:
            invalid = copy.deepcopy(value); mutation(invalid['resource_changes'][-1])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): admit(invalid)

    def test_backend_and_plan_ids_preserve_core_resources_and_new_filter_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); member = {'vmid': 6100, 'node': 'fixture-pve'}
            save(root/'terraform.tfstate', backend(6100)); _, old = generation.backend(root, member)
            value = planned(); generation.plan_identity(value, old, ip_filter_slots=[1])
            with self.assertRaises(ValueError): generation.plan_identity(value, old)
            save(root/'terraform.tfstate', state_with_filter()); _, current = generation.backend(root, member)
            self.assertTrue(generation.identity_extension(old, current, [1]))
            self.assertTrue(generation.identity_extension(None, current, [1]))
            self.assertTrue(generation.identity_extension(old, old, []))
            self.assertFalse(generation.identity_extension(old, current, []))
            self.assertFalse(generation.identity_extension(old, dict(current, lineage='foreign'), [1]))
            self.assertFalse(generation.identity_extension(old, None, [1]))
            repeat = planned(owned=True); generation.plan_identity(repeat, current, ip_filter_slots=[1])
            invalid = copy.deepcopy(repeat); invalid['resource_changes'][-1]['change']['after']['id'] = 'foreign'
            with self.assertRaises(ValueError): generation.plan_identity(invalid, current, ip_filter_slots=[1])
            for index in (None, 1, '01', '32'):
                bad = state_with_filter(); bad['resources'][-1]['instances'][0]['index_key'] = index
                save(root/'terraform.tfstate', bad)
                with self.subTest(index=index), self.assertRaises(ValueError): generation.backend(root, member)
            mutations = [lambda row: row.update(attributes=dict(attributes(), cidr=[{'name': '0.0.0.0/0'}])),
                lambda row: row.update(attributes=dict(attributes(), container_id=6101)),
                lambda row: row.update(attributes=dict(attributes(), id=''))]
            for mutation in mutations:
                bad = state_with_filter(); mutation(bad['resources'][-1]['instances'][0]); save(root/'terraform.tfstate', bad)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError): generation.backend(root, member)
            bad = state_with_filter(); bad['resources'][-1]['instances'].append(copy.deepcopy(bad['resources'][-1]['instances'][0]))
            save(root/'terraform.tfstate', bad)
            with self.assertRaises(ValueError): generation.backend(root, member)
            bad = state_with_filter(); bad['resources'][0] = copy.deepcopy(bad['resources'][1])
            save(root/'terraform.tfstate', bad)
            with self.assertRaises(ValueError): generation.backend(root, member)


if __name__ == '__main__': unittest.main()
