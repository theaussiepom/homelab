"""Operational settings test their own closed component, without target access."""
import copy
from types import SimpleNamespace
from pathlib import Path
import backup_recovery
import unittest
from unittest.mock import patch

import component_backup_job as subject
from component_errors import ComponentError


def fixture():
    value = {'name': 'example', 'destination': {'endpoint': {'external': 'pbs'}, 'datastore': 'recovery',
        'namespace': 'guests', 'fingerprint': ':'.join(['ab']*32)},
        'schedule': {'calendar': '02:00', 'jitter_seconds': 300},
        'clients': {'one': {'staging_volume': 'stage', 'interface': 'backup'}},
        'capture': {'pause': [], 'database_lock': [], 'influx_tokens': {}},
        'limits': {'max_bytes': 32*1024*1024, 'max_files': 1000, 'timeout_seconds': 300}}
    resolver = SimpleNamespace(guests={'one': {'context': 'lab', 'identity': {'vmid': 610, 'hostname': 'one'},
        'backup': {'configuration': {}, 'applications': {}}, 'interfaces': {'backup': {'slot': 1, 'address': {'mode': 'static', 'value': '192.0.2.10'}}},
        'interface_addresses': {'backup': '192.0.2.10'}, 'volumes': {
        'stage': {'path': '/srv/backup-stage', 'size_gib': 1}}}}, apps={},
        site={'backup': {'recovery_public_key': {'source': 'public.pem'}}, 'contexts': {'lab': {'node': 'example-node', 'api_endpoint': {'external': 'api'},
            'paths': {'state_root': '/example/state'}}}, 'secret_sources': {'password': {'type': 'file', 'path': '/never-read/password'},
                                'key': {'type': 'file', 'path': '/never-read/key'}}},
        endpoint=lambda ref: {'protocol': 'https', 'address': '192.0.2.50', 'port': 8006 if ref == {'external': 'api'} else 8007})
    return value, resolver


class BackupJobTests(unittest.TestCase):
    def setUp(self):
        key = backup_recovery.public_key((Path(__file__).resolve().parents[1] / 'proxmox/applications/tests/backup-synthetic-recovery-public.pem.fixture').read_bytes())
        binding = patch.object(subject.component_backup_key, 'bind', return_value=key)
        binding.start(); self.addCleanup(binding.stop)
        # This component owns reference binding. Capture planners have their own
        # direct tests; the complete library example exercises real composition.
        for name in ('normalize', 'recipes'):
            boundary = patch.object(subject.backup_capture, name)
            boundary.start(); self.addCleanup(boundary.stop)
    def test_valid_job_resolves_only_references_without_reading_private_files(self):
        value, resolver = fixture(); before = copy.deepcopy(value)
        subject.job(value); subject.bind(resolver, value)
        job = resolver.guests['one']['backup']['job']
        self.assertEqual(job['destination']['server'], '192.0.2.50')
        self.assertRegex(job['secrets']['password']['path'], r'^/example/state/pbs-clients/[0-9a-f]{64}/pbs-password$')
        self.assertRegex(job['destination']['auth_id'], r'^hl-[0-9a-f]{32}@pbs!backup$')
        self.assertEqual(value, before)
        for calendar in ('hourly', 'daily', '00:00', '23:59'):
            value['schedule']['calendar'] = calendar; subject.job(value)
        value['clients']['one']['backup_id'] = 'a'*32
        value['destination']['namespace'] = 'a'*32
        subject.job(value)

    def test_invalid_client_identifiers_report_client_diagnostic(self):
        for field in ('staging_volume','interface','backup_id'):
            value,_=fixture();value['clients']['one'][field]='invalid/path'
            with self.subTest(field=field),self.assertRaisesRegex(ComponentError,'component.backup-client'):
                subject.job(value)

    def test_each_closed_field_rejects_unsafe_unknown_or_unbounded_values(self):
        mutations = [lambda v: v.update(command='PRIVATE_SENTINEL'),
            lambda v: v['destination'].update(datastore='nested/path'),
            lambda v: v['destination'].update(namespace='../outside'),
            lambda v: v['destination'].update(namespace='a'*33),
            lambda v: v['clients']['one'].update(backup_id='a'*33),
            lambda v: v['destination'].update(fingerprint='invalid'),
            lambda v: v['destination'].update(endpoint={'app': 'arbitrary'}),
            lambda v: v['clients']['one'].update(auth_id='root@pam'),
            lambda v: v['clients']['one'].update(password='/raw/path'),
            lambda v: v['capture'].update(pause=['one', 'one']),
            lambda v: v['capture'].update(influx_tokens={'db': '/raw/path'}),
            lambda v: v['limits'].update(max_bytes=True),
            lambda v: v['limits'].update(max_files=1000001),
            lambda v: v['limits'].update(timeout_seconds=0),
            lambda v: v['schedule'].update(jitter_seconds=-1)]
        for mutate in mutations:
            value, _ = fixture(); mutate(value)
            with self.subTest(case=mutations.index(mutate)), self.assertRaises(ComponentError) as error:
                subject.job(value)
            self.assertNotIn('PRIVATE_SENTINEL', str(error.exception))
        for calendar in ('24:00', '2:00', '* * * * *', 'daily\nExecStart=bad', None):
            value, _ = fixture(); value['schedule']['calendar'] = calendar
            with self.subTest(calendar=calendar), self.assertRaises(ComponentError): subject.job(value)

    def test_identity_capture_and_secret_reference_mismatches_refuse(self):
        mutations = [lambda v, r: r.guests.update(two={'backup': {}}),
            lambda v, r: v['capture']['pause'].append('foreign'),
            lambda v, r: r.apps.update(db={'adapter': 'mariadb', 'guest': 'one'}),
            lambda v, r: r.apps.update(db={'adapter': 'influxdb', 'guest': 'one'}),
            lambda v, r: setattr(r, 'endpoint', lambda ref: {'protocol': 'http'})]
        for mutate in mutations:
            value, resolver = fixture(); mutate(value, resolver)
            with self.subTest(case=mutations.index(mutate)), self.assertRaises(ComponentError):
                subject.bind(resolver, value)
        value, resolver = fixture(); resolver.guests['two'] = copy.deepcopy(resolver.guests['one'])
        value['clients']['two'] = copy.deepcopy(value['clients']['one'])
        with self.assertRaisesRegex(ComponentError, 'member-identity'): subject.bind(resolver, value)

    def test_unenrolled_guests_and_apps_are_not_added_to_group_or_capture(self):
        value, resolver = fixture()
        resolver.guests['other'] = {'context': 'elsewhere'}
        resolver.apps['other-db'] = {'guest': 'other', 'adapter': 'mariadb'}
        result = subject.bind(resolver, value)
        self.assertEqual(set(result['group']['members']), {'guest-610'})
        self.assertNotIn('backup', resolver.guests['other'])
        resolver.guests['one']['backup']['applications']['consumer'] = {
            'databases': [{'type': 'mariadb', 'target': {'app': 'other-db'}}]}
        with self.assertRaisesRegex(ComponentError, 'backup-database-producer'):
            subject.bind(resolver, value)
        value['capture']['database_lock'] = ['other-db']
        with self.assertRaisesRegex(ComponentError, 'backup-capture-selection'):
            subject.bind(resolver, value)

    def test_operational_external_database_without_a_group_producer_refuses(self):
        value, resolver = fixture()
        resolver.guests['one']['backup']['applications']['consumer'] = {
            'databases': [{'type': 'postgresql', 'target': {'external': 'database'}}]}
        with self.assertRaisesRegex(ComponentError, 'backup-database-producer'): subject.bind(resolver, value)

    def test_related_database_has_to_resolve_to_its_own_native_producer(self):
        value, resolver = fixture()
        resolver.apps['database'] = {'adapter':'postgresql','guest':'one'}
        resolver.guests['one']['backup']['applications']['consumer'] = {
            'databases':[{'type':'postgresql','target':{'app':'database','guest':'one','protocol':'tcp','address':'192.0.2.10','port':5432}}]}
        subject.bind(resolver,value)

    def test_dhcp_and_invalid_staging_bindings_refuse_during_source_resolution(self):
        for change, code in [
            (lambda r: r.guests['one']['interfaces']['backup']['address'].update(mode='dhcp'),
             'component.backup-interface'),
            (lambda r: r.guests['one']['volumes']['stage'].update(path='/srv/_stage'),
             'component.backup-job-binding')]:
            value, resolver = fixture(); change(resolver)
            with self.assertRaises(ComponentError) as caught: subject.bind(resolver,value)
            self.assertEqual(caught.exception.code, code)

    def test_capture_policy_failure_has_a_component_diagnostic(self):
        value, resolver = fixture()
        with patch.object(subject.backup_capture,'recipes',side_effect=ValueError('invalid capture')):
            with self.assertRaisesRegex(ComponentError,'backup-capture-binding'):subject.bind(resolver,value)

    def test_database_capabilities_are_bound_to_their_owning_guest(self):
        value, resolver = fixture()
        resolver.apps = {'db': {'adapter': 'mariadb', 'guest': 'one'},
                         'metrics': {'adapter': 'influxdb', 'guest': 'one'}}
        value['capture'].update(database_lock=['db'], influx_tokens={'metrics': 'password'}, pause=['metrics'])
        subject.bind(resolver, value)
        self.assertEqual(resolver.guests['one']['backup']['job']['capture'], {
            'database_lock': ['db'], 'pause': ['metrics'], 'influx_tokens': {
                'metrics': {'type': 'file', 'path': '/never-read/password'}}})

    def test_export_secret_missing_or_nonfile_refuses_without_opening_it(self):
        for missing in (True, False):
            value, resolver = fixture()
            resolver.apps['metrics'] = {'adapter': 'influxdb', 'guest': 'one'}
            value['capture']['influx_tokens'] = {'metrics': 'password'}
            if missing:
                resolver.site['secret_sources'].pop('password')
            else:
                resolver.site['secret_sources']['password'] = {'type': 'environment', 'name': 'TOKEN'}
            with self.assertRaises(ComponentError): subject.bind(resolver, value)

    def test_removed_manual_client_inputs_are_rejected(self):
        for field in ('auth_id', 'password', 'encryption_key', 'key_password'):
            value, _ = fixture(); value['clients']['one'][field] = 'obsolete'
            with self.subTest(field=field), self.assertRaises(ComponentError): subject.job(value)


if __name__ == '__main__': unittest.main()
