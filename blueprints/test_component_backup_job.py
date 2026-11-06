"""Operational settings test their own closed component, without target access."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import component_backup_job as subject
from component_errors import ComponentError


def fixture():
    value = {'name': 'example', 'destination': {'endpoint': {'external': 'pbs'}, 'datastore': 'recovery',
        'namespace': 'guests', 'fingerprint': ':'.join(['ab']*32)},
        'schedule': {'calendar': '02:00', 'jitter_seconds': 300},
        'clients': {'one': {'auth_id': 'one@pbs!backup', 'password': 'password', 'encryption_key': 'key',
                           'staging_volume': 'stage', 'interface': 'backup'}},
        'capture': {'pause': [], 'database_lock': [], 'influx_tokens': {}},
        'limits': {'max_bytes': 32*1024*1024, 'max_files': 1000, 'timeout_seconds': 300}}
    resolver = SimpleNamespace(guests={'one': {'context': 'lab', 'identity': {'vmid': 610, 'hostname': 'one'},
        'backup': {'configuration': {}, 'applications': {}}, 'interfaces': {'backup': {'slot': 1, 'address': {'mode': 'static', 'value': '192.0.2.10'}}},
        'interface_addresses': {'backup': '192.0.2.10'}, 'volumes': {
        'stage': {'path': '/srv/backup-stage', 'size_gib': 1}}}}, apps={},
        site={'contexts': {'lab': {'node': 'example-node', 'api_endpoint': {'external': 'api'},
            'paths': {'state_root': '/example/state'}}}, 'secret_sources': {'password': {'type': 'file', 'path': '/never-read/password'},
                                'key': {'type': 'file', 'path': '/never-read/key'}}},
        endpoint=lambda ref: {'protocol': 'https', 'address': '192.0.2.50', 'port': 8006 if ref == {'external': 'api'} else 8007})
    return value, resolver


class BackupJobTests(unittest.TestCase):
    def setUp(self):
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
        self.assertEqual(job['secrets']['password']['path'], '/never-read/password')
        self.assertEqual(value, before)
        for calendar in ('hourly', 'daily', '00:00', '23:59'):
            value['schedule']['calendar'] = calendar; subject.job(value)
        value['clients']['one']['key_password'] = 'password'; subject.job(value)

    def test_each_closed_field_rejects_unsafe_unknown_or_unbounded_values(self):
        mutations = [lambda v: v.update(command='PRIVATE_SENTINEL'),
            lambda v: v['destination'].update(datastore='nested/path'),
            lambda v: v['destination'].update(namespace='../outside'),
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
            lambda v, r: r.site['secret_sources'].pop('key'),
            lambda v, r: r.site['secret_sources']['key'].update(type='environment'),
            lambda v, r: v['capture']['pause'].append('foreign'),
            lambda v, r: r.apps.update(db={'adapter': 'mariadb', 'guest': 'one'}),
            lambda v, r: r.apps.update(db={'adapter': 'influxdb', 'guest': 'one'}),
            lambda v, r: setattr(r, 'endpoint', lambda ref: {'protocol': 'http'})]
        for mutate in mutations:
            value, resolver = fixture(); mutate(value, resolver)
            with self.subTest(case=mutations.index(mutate)), self.assertRaises(ComponentError):
                subject.bind(resolver, value)
        value, resolver = fixture(); resolver.guests['two'] = {'backup': {}}
        value['clients']['two'] = copy.deepcopy(value['clients']['one'])
        with self.assertRaisesRegex(ComponentError, 'client-identity'): subject.bind(resolver, value)

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


if __name__ == '__main__': unittest.main()
