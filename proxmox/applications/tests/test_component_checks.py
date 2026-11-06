"""Readiness-builder units mock collaborators; one retained public comparison."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

FRAMEWORK = Path(Path(__file__).resolve().parents[3])
sys.path[:0] = [str(FRAMEWORK/'blueprints'), str(FRAMEWORK/'proxmox/applications')]
import component_checks as checks
from component_errors import ComponentError
FIXTURE = json.loads(Path(__file__).with_name('public-retained-health.json').read_text())


def case(adapter):return copy.deepcopy(FIXTURE['cases'][adapter])


class NativeReadinessUnitTests(unittest.TestCase):
    def test_postgresql_uses_fixed_local_read_only_query_and_selected_backend(self):
        v = case('postgresql')
        with patch.object(checks, '_native_address', return_value='198.18.31.91') as address:
            rows = checks.checks(v['app'], {}, compose_file=None)
        address.assert_called_once_with(v['app'])
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[1]['argv'], ['pg_isready','-h','198.18.31.91','-p','5432'])
        self.assertEqual(rows[2]['argv'][-2:], ['-c','SELECT 1'])
        self.assertIn('ON_ERROR_STOP=1', rows[2]['argv'])
        self.assertEqual(rows[2]['expect'], '1')
        self.assertNotIn('password', repr(rows).lower())

    def test_mariadb_reuses_native_version_boundary_and_local_socket(self):
        v = case('mariadb')
        with patch.object(checks, '_native_address', return_value='198.18.32.91'), \
             patch.object(checks, '_native_version', return_value='12.3.3') as version:
            rows = checks.checks(v['app'], {}, compose_file=None)
        version.assert_called_once_with(v['app'])
        self.assertIn('--protocol=socket', rows[1]['argv'])
        self.assertEqual(rows[1]['argv'][-1], 'SELECT VERSION();')
        self.assertEqual(rows[1]['expect'], '12.3.3')

    def test_influxdb_only_reads_fixed_health_without_setup_or_application_query(self):
        v = case('influxdb')
        with patch.object(checks, '_native_address', return_value='198.18.33.91'), \
             patch.object(checks, '_native_version', return_value='2.7.12'):
            rows = checks.checks(v['app'], {}, compose_file=None)
        code = rows[1]['argv'][-1]
        self.assertIn('http://198.18.33.91:8086/health', code)
        self.assertIn("d['version']=='v2.7.12'", code)
        self.assertNotIn('setup', code);self.assertNotIn('Authorization', code)

    def test_unsupported_native_listener_does_not_get_a_false_health_contract(self):
        for adapter in ('postgresql','mariadb','influxdb'):
            with self.subTest(adapter=adapter):
                v=case(adapter);v['app']['listeners']['web']['port']+=1
                with self.assertRaises(ComponentError):checks.checks(v['app'], {}, compose_file=None)

    def test_native_source_helper_refusal_is_redacted_without_execution(self):
        v=case('mariadb')
        with patch.object(checks.component_native,'_version',side_effect=ValueError('SYNTHETIC_PRIVATE_VALUE')):
            with self.assertRaises(ComponentError) as raised:checks.checks(v['app'], {}, compose_file=None)
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', str(raised.exception))


class DNSReadinessUnitTests(unittest.TestCase):
    def test_unbound_uses_owned_compose_and_service_key_not_fixed_project(self):
        v=case('unbound');v['app']['identity']['services']['unbound']='other_recursive'
        row=checks.checks(v['app'], {}, compose_file='/opt/homelab-app/compose-owned-project.yml')[0]
        self.assertEqual(row['argv'], ['docker','compose','-f','/opt/homelab-app/compose-owned-project.yml',
            'exec','-T','other_recursive','unbound-checkconf','/opt/unbound/etc/unbound/unbound.conf'])
        self.assertEqual(row['expect'], '')

    def test_pihole_keeps_all_explicit_dns_probes_using_existing_direct_resolver_helper(self):
        v=case('pihole')
        with patch.object(checks.dns_records,'validate',return_value={
            'z.example.invalid':'198.18.40.91','a.example.invalid':'198.18.40.92'}) as validate:
            rows=checks.checks(v['app'], {}, compose_file=v['compose_file'])
        validate.assert_called_once()
        self.assertEqual(rows[0]['argv'][-2:], ['pihole','status'])
        self.assertEqual([r['argv'][3] for r in rows[1:]], ['a.example.invalid','z.example.invalid'])
        self.assertTrue(all(r['argv'][1:3]==['/opt/homelab-app/dns_records.py','probe'] for r in rows[1:]))
        self.assertTrue(all(r['expect']=='"read_only_dns_check": "passed"' for r in rows[1:]))

    def test_no_records_means_only_pihole_status_not_an_inferred_dns_query(self):
        v=case('pihole');v['app']['settings']['dns_records']={}
        self.assertEqual(len(checks.checks(v['app'], {}, compose_file=v['compose_file'])),1)

    def test_invalid_record_uses_existing_validator_and_refuses_without_network(self):
        v=case('pihole')
        with patch.object(checks.dns_records,'validate',side_effect=ValueError('SYNTHETIC_PRIVATE_VALUE')):
            with self.assertRaises(ComponentError) as raised:checks.checks(v['app'], {}, compose_file=v['compose_file'])
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE',str(raised.exception))

    def test_unowned_relative_control_path_or_option_service_refuses(self):
        for filename in ('compose.yml','/opt/../private/compose.yml','/opt/compose\n.yml','//network/compose.yml'):
            with self.subTest(filename=filename):
                v=case('unbound')
                with self.assertRaises(ComponentError):checks.checks(v['app'], {}, compose_file=filename)
        v=case('pihole');v['app']['identity']['services']['pihole']='--foreign-option'
        with self.assertRaises(ComponentError):checks.checks(v['app'], {}, compose_file=v['compose_file'])


class AutomationReadinessUnitTests(unittest.TestCase):
    def test_retained_helpers_keep_strategy_api_websocket_boundary_modes(self):
        for adapter,mode in [('homeassistant','homeassistant'),('node_red','node_red')]:
            with self.subTest(adapter=adapter):
                v=case(adapter);row=checks.checks(v['app'], {}, compose_file=None)[0]
                self.assertEqual(row['argv'],['python3','/opt/homelab-app/automation-health.py',mode])
                self.assertEqual(row['expect'],'"read_only_probe": "passed"')

    def test_fresh_ha_uses_existing_qualified_onboarding_or_repeat_helper(self):
        v=case('homeassistant');v['app']['lifecycle']='fresh'
        row=checks.checks(v['app'], {}, compose_file=None)[0]
        self.assertEqual(row['argv'][-1],'homeassistant-fresh')
        self.assertIn('onboarding',row['name'])

    def test_fresh_public_node_claims_only_ui_scope_never_retained_auth(self):
        v=case('node_red');v['app']['lifecycle']='fresh'
        row=checks.checks(v['app'], {}, compose_file=None)[0]
        self.assertEqual(row['argv'][-1],'node_red-fresh')
        self.assertEqual(row['expect'],'"scope": "ui_only"')
        self.assertEqual(row['name'],'Node-RED public UI responds')
        self.assertNotIn('strategy',repr(row));self.assertNotIn('unauthenticated',repr(row))

    def test_unknown_lifecycle_and_custom_native_ports_do_not_reuse_fixed_helpers(self):
        for adapter in ('homeassistant','node_red'):
            for key,value in [('lifecycle','unknown'),('port',1234)]:
                with self.subTest(adapter=adapter,key=key):
                    v=case(adapter)
                    if key=='port':v['app']['listeners']['web']['port']=value
                    else:v['app'][key]=value
                    with self.assertRaises(ComponentError):checks.checks(v['app'], {}, compose_file=None)


class SelectionUnitTests(unittest.TestCase):
    def test_undeclared_health_does_not_invent_acceptance_and_unknown_adapter_refuses(self):
        v=case('node_red');v['app']['health']={}
        self.assertEqual(checks.checks(v['app'], {}, compose_file=None),[])
        v['app']['adapter']='unknown'
        with self.assertRaises(ComponentError):checks.checks(v['app'], {}, compose_file=None)

    def test_arbitrary_argv_and_unhonored_source_interface_are_not_silently_accepted(self):
        for record in ({'type':'adapter','check':'readiness','argv':['ssh','arbitrary']},
                       {'type':'adapter','check':'readiness','source_interface':'backend'}):
            with self.subTest(record=record):
                v=case('node_red');v['app']['health']={'ready':record}
                with self.assertRaises(ComponentError):checks.checks(v['app'], {}, compose_file=None)

    def test_checks_dispatches_selected_component_boundary_once(self):
        v=case('node_red')
        with patch.object(checks,'_declared',return_value=True) as selected, \
             patch.dict(checks.HANDLERS,{'node_red':lambda app,file:[{'fixed':'component-output'}]}):
            self.assertEqual(checks.checks(v['app'], {}, compose_file=None),[{'fixed':'component-output'}])
        selected.assert_called_once_with(v['app'])


class RetainedPublicMetadataIntegrationTests(unittest.TestCase):
    def test_all_seven_public_retained_health_arrays_match_exact_old_compilation(self):
        self.assertTrue(FIXTURE['source_is_public_example'])
        count=0
        for adapter,v in FIXTURE['cases'].items():
            with self.subTest(adapter=adapter):
                result=checks.checks(v['app'],v['guest'],compose_file=v['compose_file'])
                self.assertEqual(json.dumps(result,sort_keys=True),json.dumps(v['expected'],sort_keys=True))
                count+=len(result)
        self.assertEqual(count,39) #14 base probes plus25 exposure-derived DNS probes


if __name__=='__main__':unittest.main()
