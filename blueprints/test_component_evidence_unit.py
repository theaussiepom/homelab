"""Evidence mini-component units; historical formats and endpoint peers are mocked."""
import copy
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'proxmox/applications'))
import component_evidence as evidence
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
    r = SimpleNamespace(site={'contexts': {'lab': context}, 'evidence': {}, 'exposures': {},
                             'domains': {'web': 'selected.example.invalid', 'alias': 'alias.example.invalid'}},
                        guests={'database': guest}, apps={'server': app}, evidence={}, api='selected-api',
                        backend='selected-backend')
    def endpoint(ref):
        if ref.get('external') == 'api': return {'address': r.api}
        if ref.get('app') == 'ingress': return {'app': 'ingress'}
        return {'address': r.backend}
    r.endpoint = endpoint
    return r


def group_fixture():
    r = fixture()
    r.guests['console'] = copy.deepcopy(r.guests['database']); r.guests['console']['identity']['vmid'] = 611
    r.apps['console'] = dict(copy.deepcopy(r.apps['server']), id='console', guest='console', adapter='cloudbeaver')
    document = {'group': {'members': {'postgresql': {'node': 'selected-node', 'vmid': 610},
                                    'db-tools': {'node': 'selected-node', 'vmid': 611}}}}
    r.site['evidence']['group'] = {'document': document}
    selected = {}
    for name in ('catalogue', 'acceptance'):
        text = 'synthetic-' + name + '\n'; r.site['evidence'][name] = {'text': text}
        selected[name] = {'file': name + '.json', 'sha256': hashlib.sha256(text.encode()).hexdigest()}
    for name, role in (('database', 'postgresql'), ('console', 'db-tools')):
        r.guests[name]['admission'] = {'coordinated_custody': {'evidence': 'group', 'member': role},
                                     'assets': {'catalogue': 'catalogue', 'acceptance': 'acceptance'}}
    return r, selected


class EvidenceBindingReview(unittest.TestCase):
    def test_no_proof_invented_and_subject_evidence_merges_without_mutating_source(self):
        r = fixture(); result = evidence.bind(r)
        self.assertEqual(result['database']['app']['kind'], 'database')
        self.assertNotIn('coordinated_custody', result['database'])
        r.site['evidence']['writer'] = {'document': {'guest': 'database', 'exclusive_writer_confirmed': True}}
        value = {'source_assertions': {'evidence': 'writer'}}
        r.guests['database']['admission'] = copy.deepcopy(value); r.apps['server']['admission'] = copy.deepcopy(value)
        before = copy.deepcopy((r.site, r.apps, r.guests)); result = evidence.bind(r)
        self.assertEqual(result['database']['source_assertions'], r.site['evidence']['writer']['document'])
        self.assertEqual((r.site, r.apps, r.guests), before)
        r.apps['server']['admission']['source_assertions']['evidence'] = 'different'
        with self.assertRaisesRegex(ComponentError, 'evidence-conflict'): evidence.bind(r)

    def test_completed_group_binds_exact_assets_and_whole_configured_peer_closure(self):
        r, selected = group_fixture(); before = copy.deepcopy((r.site, r.guests, r.apps))
        with patch.object(evidence.coordinated_contract, 'selection', return_value=selected) as selection:
            result = evidence.bind(r)
        self.assertEqual(selection.call_count, 2)
        self.assertTrue(all(call.kwargs == {'allow_input_slot': True} for call in selection.call_args_list))
        self.assertEqual(result['database']['proof_files'], {'catalogue.json': 'synthetic-catalogue\n', 'acceptance.json': 'synthetic-acceptance\n'})
        self.assertEqual(result['database']['paths']['coordinated_custody_inputs'], '${inputs}')
        self.assertEqual(result['console']['app']['kind'], 'db-tools')
        self.assertEqual(r.site, before[0]); self.assertEqual(r.apps, before[2])

    def test_missing_altered_assets_and_missing_duplicate_cross_context_or_foreign_peers_refuse(self):
        for kind in ('missing-asset', 'altered-asset', 'missing-peer', 'duplicate-peer', 'other-context', 'wrong-role', 'different-proof'):
            r, selected = group_fixture()
            if kind == 'missing-asset': r.guests['database']['admission']['assets'].pop('acceptance')
            elif kind == 'altered-asset': r.site['evidence']['acceptance']['text'] += 'altered'
            elif kind == 'missing-peer': del r.guests['console']; del r.apps['console']
            elif kind == 'duplicate-peer': r.guests['duplicate'] = dict(copy.deepcopy(r.guests['console']), admission={})
            elif kind == 'other-context':
                r.site['contexts']['other'] = copy.deepcopy(r.site['contexts']['lab']); r.guests['console']['context'] = 'other'
            elif kind == 'wrong-role':
                r.apps['console']['adapter'] = 'postgresql'; r.guests['console']['admission']['coordinated_custody']['member'] = 'postgresql'
            else:
                r.site['evidence']['different'] = {'document': dict(copy.deepcopy(r.site['evidence']['group']['document']), changed=True)}
                r.guests['console']['admission']['coordinated_custody']['evidence'] = 'different'
            with self.subTest(kind=kind), patch.object(evidence.coordinated_contract, 'selection', return_value=selected), self.assertRaises(ComponentError): evidence.bind(r)

    def test_initial_and_failure_contracts_remain_separate_and_subject_bound(self):
        r = fixture(); r.site['evidence'] = {'initial': {'document': {'schema': 'fixture-initial'}},
                                           'failure': {'document': {'schema': 'fixture-failure'}}}
        r.guests['database']['admission'] = {'initial_ordinary': {'evidence': 'initial'},
                                           'reviewed_ordinary_failures': {'evidence': 'failure'}}
        with patch.object(evidence.initial_ordinary, 'KINDS', {'fixture-initial': 'postgresql'}), \
             patch.object(evidence.initial_ordinary, 'selection') as initial, patch.object(evidence.ordinary_failure, 'selection') as failure:
            result = evidence.bind(r)
        self.assertEqual(initial.call_args.args[0]['app']['kind'], 'postgresql')
        self.assertEqual(failure.call_args.args[0]['reviewed_ordinary_failures'], {'schema': 'fixture-failure'})
        self.assertEqual(result['database']['initial_ordinary'], {'schema': 'fixture-initial'})
        for kind in ('unknown-schema', 'wrong-adapter', 'wrong-subject'):
            r = fixture(); r.site['evidence']['proof'] = {'document': {'schema': 'fixture-initial', 'guest': 'foreign'}}
            r.guests['database']['admission'] = {'source_assertions' if kind == 'wrong-subject' else 'initial_ordinary': {'evidence': 'proof'}}
            if kind == 'unknown-schema': r.site['evidence']['proof']['document']['schema'] = None
            if kind == 'wrong-adapter': r.apps['server']['adapter'] = 'unbound'
            with self.subTest(kind=kind), patch.object(evidence.initial_ordinary, 'KINDS', {'fixture-initial': 'postgresql'}), patch.object(evidence.initial_ordinary, 'selection'), self.assertRaises(ComponentError): evidence.bind(r)


class EvidenceAdmissionReview(unittest.TestCase):
    def run_admit(self, r, enabled=('database',)):
        with patch.object(evidence, 'synthetic_binding', side_effect=lambda key, value: isinstance(value, str) and 'synthetic' in value) as classifier:
            evidence.admit(r, enabled)
        return classifier

    def test_valid_fresh_and_retained_assertions_only_check_enabled_guests(self):
        r = fixture(); self.run_admit(r)
        r.guests['other'] = copy.deepcopy(r.guests['database'])
        r.guests['other']['identity']['vmid'] = 611
        r.apps['other'] = dict(copy.deepcopy(r.apps['server']), id='other', guest='other')
        r.apps['other']['resolved_connections']['not_selected'] = {'target': {'address': 'synthetic'}}
        self.run_admit(r)
        r.apps['server']['identity']['services'] = {'postgresql': 'owned'}
        r.evidence['database'] = {'source_assertions': {'exclusive_writer_confirmed': True}}
        self.run_admit(r)
        r.guests['database']['provider_interfaces'][0]['ipv4_endpoint'] = 'selected-address'
        calls = self.run_admit(r).call_args_list
        self.assertIn((('interfaces.selected.ipv4', 'selected-address'), {}), [(call.args, call.kwargs) for call in calls])
        r.api = 'synthetic'; self.run_admit(r, ())

    def test_network_key_writer_connection_auth_and_image_binding_refusals(self):
        changes = [lambda r: r.guests['database']['provider_interfaces'][0].update(ipv4='synthetic'),
                   lambda r: r.guests['database']['provider_interfaces'][0].update(gateway='synthetic'),
                   lambda r: setattr(r, 'api', 'synthetic'),
                   lambda r: r.guests['database'].update(dns_servers=['synthetic']),
                   lambda r: r.guests['database'].update(ssh_public_keys=[]),
                   lambda r: r.guests['database'].update(ssh_public_keys=['ssh-rsa selected']),
                   lambda r: r.guests['database'].update(ssh_public_keys=['ssh-ed25519 AAAAAAAAAAAAAAAA']),
                   lambda r: r.apps['server']['identity'].update(services={'postgresql': 'owned'}),
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
            exposure = {'type': kind, 'endpoint': {'external': 'backend'}, 'domain': 'web', 'aliases': ['alias']}
            if kind == 'http': exposure['ingress'] = {'app': 'ingress', 'endpoint': 'https'}
            else: exposure['resolver'] = 'server'
            r.site['exposures']['web'] = exposure; self.run_admit(r)
            for change in ('backend', 'alias'):
                # endpoint closure remains bound to r, so mutate/restore its selected backend directly.
                if change == 'backend': r.backend = 'synthetic'
                else: r.site['domains']['alias'] = 'synthetic.invalid'
                with self.subTest(kind=kind, change=change), self.assertRaises(ComponentError): self.run_admit(r)
                r.backend = 'selected-backend'; r.site['domains']['alias'] = 'alias.example.invalid'
            self.run_admit(r, ())


if __name__ == '__main__':
    unittest.main()
