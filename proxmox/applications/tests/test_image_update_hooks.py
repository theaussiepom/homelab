from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'blueprints'), str(ROOT/'proxmox/applications')]
import authentik_releases as releases
import image_update_hooks as hooks
import component_types
import test_authentik_upgrade as fixture


def pin(tag, digest='a'):
    return f'{releases.REPOSITORY}:{tag}@sha256:' + digest*64


class ReleaseTests(unittest.TestCase):
    def test_new_series_follow_published_history_and_last_patch_of_source(self):
        tags = ['2027.7.2','2027.7.1','2027.3.9','2027.3.10','2026.12.3',
                '2026.12.1','2026.8.20','2027.9.1-rc1','latest']
        digest = lambda tag: 'sha256:'+'a'*64
        source = pin('2026.12.1')
        expected = [source,pin('2026.12.3'),pin('2027.3.10'),pin('2027.7.2')]
        self.assertEqual(releases.select(source,tags,digest), expected)
        self.assertEqual(releases.select(source,tags,digest,through=expected[-2]),expected[:-1])
        exact = pin('2027.3.9')
        self.assertEqual(releases.select(source,tags,digest,through=exact), [*expected[:2], exact])
        for unavailable in [pin('2027.3.11'), pin('2027.3.9','b'), pin('2026.8.20')]:
            with self.assertRaises(ValueError):
                releases.select(source,tags,digest,through=unavailable)
        for absent in [[],['2026.12.0']]:
            with self.assertRaises(ValueError):
                releases.select(source,absent,digest)
        self.assertEqual(releases.select(source,['2026.12.1'],digest), [source])
        self.assertEqual(releases.select(pin('2026.12.1','b'),['2026.12.1'],digest),[pin('2026.12.1','b'),source])
        for path in ([source], [pin('2026.12.3'),source], [source,source],
                     [source,pin('2027.3.1'),pin('2027.3.2')], [pin('2025.4.1'),pin('2025.8.1')],
                     [pin('2025.2.1'),pin('2025.4.1')], [source,pin('2027.13.0')]):
            with self.assertRaises(ValueError):
                releases.validate(path)

    def test_only_profile_owner_can_dispatch_special_hook(self):
        standard = dict(profile='resolver',adapter='unbound',image_update='standard',
                        software_selection={'images':{'unbound':{'image':'resolver'}}})
        self.assertEqual(hooks.phase_options(None,'resolver',standard),{})
        self.assertEqual(hooks.phase_options(None,'preparation',None),{})
        self.assertEqual(hooks.phase_options(None,'db',{'software_selection':{'images':{}}}),{})
        for profile,adapter,hook in [('authentik','authentik','standard'),('other','authentik','release-series'),
                                     ('authentik','unbound','release-series'),('other','unbound',None)]:
            with self.assertRaises(ValueError):
                hooks.phase_options(None,'app',dict(standard,profile=profile,adapter=adapter,image_update=hook))
        owner=dict(standard, profile='authentik',adapter='authentik',image_update='release-series')
        with patch.object(hooks.authentik_upgrade,'phase_options',return_value={'hook':'called'}) as call:
            self.assertEqual(hooks.phase_options(None,'id',owner),{'hook':'called'})
            call.assert_called_once_with(None,'id',owner)
        with self.assertRaises(ValueError):
            component_types.app({'profile':'authentik','guest':'identity','lifecycle':'retained',
                                 'interfaces':{},'image_update':'standard'})
        policy={'owner':'authentik','upstream':'goauthentik/authentik',
                'image':releases.REPOSITORY,'roles':['server','worker']}
        self.assertEqual(releases.plugin(policy),policy)
        with self.assertRaises(ValueError):
            releases.plugin(dict(policy,owner='other'))

    def test_new_installation_has_no_update_baseline(self):
        from types import SimpleNamespace
        current = fixture.runtime(False)
        app = current['applications']['id']
        with self.assertRaises(ValueError):
            hooks.authentik_upgrade.plan({'applications':{}},current,'id')
        app['lifecycle'] = 'fresh'
        self.assertIsNone(hooks.authentik_upgrade.plan({'applications':{}},current,'id'))
        self.assertEqual(hooks.authentik_upgrade.phase_options(SimpleNamespace(previous_configuration=None),
                                                              'install', app), {})

    def test_single_hop_still_proves_final_registration_and_creates_no_intermediate(self):
        case = fixture.GuestTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.plan['stages'] = []
        case.plan['images'] = [fixture.REFS[0],fixture.REFS[-1]]
        # Exercise the guest journal here. Compiler coverage checks which paths are admitted.
        from authentik_upgrade_guest import run
        self.assertFalse(run(case.plan,case.canonical)['changed'])
        self.assertEqual(case.start_count,0)
        self.assertEqual(case.final()['completed'],1)
        case.registration = 'drift'
        with self.assertRaises(ValueError):
            case.final()
