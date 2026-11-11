"""Source-suitability units; peer contracts are mocks, not target evidence."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import component_admission as admission
from component_errors import ComponentError


def fixture():
    context = {'node': 'selected-node', 'paths': {key: '/selected/' + key for key in
               ('state_root', 'backup_mount', 'backup_directory', 'backup_source')},
               'api_endpoint': {'external': 'api'}, 'ssh_public_keys': ['ssh-ed25519 selected-public-key']}
    guest = {'context': 'lab', 'identity': {'vmid': 610},
             'provider_interfaces': [{'ipv4': 'selected-address/24', 'gateway': 'selected-gateway'}],
             'dns_servers': ['selected-dns']}
    app = {'id': 'server', 'guest': 'database', 'adapter': 'postgresql', 'lifecycle': 'retained',
           'identity': {'services': {}}, 'resolved_connections': {}, 'software_selection': {'images': {}}}
    r = SimpleNamespace(site={'contexts': {'lab': context}, 'exposures': {},
                             'domains': {'web': 'selected.example.invalid', 'alias': 'alias.example.invalid'}},
                        guests={'database': guest}, apps={'server': app}, api='selected-api',
                        backend='selected-backend')
    def endpoint(ref):
        if ref.get('external') == 'api': return {'address': r.api}
        if ref.get('app') == 'ingress': return {'app': 'ingress'}
        return {'address': r.backend}
    r.endpoint = endpoint
    return r


class SourceSuitabilityReview(unittest.TestCase):
    def run_admit(self, r, enabled=('database',)):
        with patch.object(admission, 'synthetic_binding', side_effect=lambda key, value: isinstance(value, str) and 'synthetic' in value) as classifier:
            admission.admit(r, enabled)
        return classifier

    def test_source_suitability_checks_only_enabled_guests(self):
        r = fixture(); self.run_admit(r)
        r.guests['other'] = copy.deepcopy(r.guests['database'])
        r.guests['other']['identity']['vmid'] = 611
        r.apps['other'] = dict(copy.deepcopy(r.apps['server']), id='other', guest='other')
        r.apps['other']['resolved_connections']['not_selected'] = {'target': {'address': 'synthetic'}}
        self.run_admit(r)
        r.apps['server']['identity']['services'] = {'postgresql': 'owned'}
        self.run_admit(r)
        r.guests['database']['provider_interfaces'][0]['ipv4_endpoint'] = 'selected-address'
        calls = self.run_admit(r).call_args_list
        self.assertIn((('interfaces.selected.ipv4', 'selected-address'), {}), [(call.args, call.kwargs) for call in calls])
        r.api = 'synthetic'; self.run_admit(r, ())

    def test_network_keys_connection_auth_and_image_binding_refusals(self):
        changes = [lambda r: r.guests['database']['provider_interfaces'][0].update(ipv4='synthetic'),
                   lambda r: r.guests['database']['provider_interfaces'][0].update(gateway='synthetic'),
                   lambda r: setattr(r, 'api', 'synthetic'),
                   lambda r: r.guests['database'].update(dns_servers=['synthetic']),
                   lambda r: r.guests['database'].update(ssh_public_keys=[]),
                   lambda r: r.guests['database'].update(ssh_public_keys=['ssh-rsa selected']),
                   lambda r: r.guests['database'].update(ssh_public_keys=['ssh-ed25519 AAAAAAAAAAAAAAAA']),
                   lambda r: r.apps['server']['resolved_connections'].update(db={'target': {'address': 'synthetic'}}),
                   lambda r: r.apps['server'].update(authentication_resolved={'oidc_issuer': 'https://synthetic.invalid'}),
                   lambda r: r.apps['server'].update(authentication_resolved={'identity_url': 'https://synthetic.invalid'}),
                   lambda r: r.apps['server']['software_selection']['images'].update(app={'image': 'image@sha256:' + '0' * 64}),
                   lambda r: r.apps['server']['software_selection']['images'].update(app={'image': 'selected', 'archive_sha256': '0' * 64})]
        for number, change in enumerate(changes):
            r = fixture(); change(r)
            with self.subTest(number=number), self.assertRaises(ComponentError): self.run_admit(r)

    def test_http_and_dns_exposure_checks_follow_active_publishers_without_invented_edges(self):
        for kind in ('http', 'dns'):
            r = fixture(); r.apps['ingress'] = dict(copy.deepcopy(r.apps['server']), id='ingress')
            exposure = {'type': kind, 'target': {'external': 'backend'}, 'domain': 'web', 'aliases': ['alias']}
            if kind == 'http': exposure['ingress'] = {'app': 'ingress', 'endpoint': 'https_endpoint'}
            else: exposure['resolver'] = 'server'
            r.site['exposures']['web'] = exposure; self.run_admit(r)
            for change in ('backend', 'alias'):
                # endpoint closure remains bound to r, so mutate/restore its selected backend directly.
                if change == 'backend': r.backend = 'synthetic'
                else: r.site['domains']['alias'] = 'synthetic.invalid'
                with self.subTest(kind=kind, change=change), self.assertRaises(ComponentError): self.run_admit(r)
                r.backend = 'selected-backend'; r.site['domains']['alias'] = 'alias.example.invalid'
            self.run_admit(r, ())


if __name__=='__main__':unittest.main()
