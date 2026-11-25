"""Production ordering, native ownership, schema checkpoints, and interrupted maintenance."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'blueprints'), str(ROOT/'proxmox/applications')]
import authentik_upgrade as upgrade
import authentik_upgrade_guest as guest
import component_ansible
import component_ownership
import test_component_deployment as deployment_fixture
import component_foundations
from component_errors import ComponentError
from private_io import encoded, read_json, write_new

REFS = [f'ghcr.io/goauthentik/server:{family}.1@sha256:' + str(i)*64
        for i, family in enumerate(('2025.4','2025.6','2025.8','2025.10','2025.12','2026.2','2026.5','2026.8'), 1)]


def runtime(legacy):
    names = {'server':'web', 'worker':'jobs'}
    storage = {'media':{'target':'/media' if legacy else '/data/media'}}
    if legacy:
        names['redis'] = 'cache'
    else:
        storage['data'] = {'target':'/data'}
    images = {role:{'image':REFS[0 if legacy else -1]} for role in ('server','worker')}
    return {'applications':{'id':dict(adapter='authentik', lifecycle='retained', software_selection={'images':images},
        identity={'services':names}, storage_paths=storage, project_name='auth', project_file='compose.yml',
        properties={'upgrade_path':REFS}, settings={}, secret_bindings={'key':'original'})}}


def render(value):
    app = value['applications']['id']
    services = {name:{'command':role, 'image':app['software_selection']['images'].get(role,{}).get('image')}
                for role,name in app['identity']['services'].items()}
    services['peer'] = {'command':'external'}
    if legacy := app['identity']['services'].get('redis'):
        services[legacy]['image'] = 'redis@sha256:'+'9'*64
        for role in ('server', 'worker'):
            services[app['identity']['services'][role]]['depends_on'] = {legacy: {'condition': 'service_healthy'}}
    return {'auth':{'services':services, 'media':app['storage_paths']['media']['target']}}


class PlanTests(unittest.TestCase):
    def test_release_selection(self):
        component_foundations.validate('authentik', {'upgrade_path':REFS}, partial=True)
        for path in (None, REFS[:2]+REFS[3:], [None]+REFS[1:], [REFS[1]]+REFS[1:], [REFS[0][:-1]]+REFS[1:]):
            with self.subTest(path=path), self.assertRaises(ComponentError):
                component_foundations.validate('authentik', {'upgrade_path':path}, partial=True)

    def test_source_and_target_bound_to_runtime(self):
        old, new = runtime(True), runtime(False)
        with patch.object(upgrade.component_runtime, 'compositions', side_effect=render):
            plan = upgrade.plan(old, new, 'id')
            self.assertEqual([d['services']['web']['image'] for d in plan['stages']], REFS[1:-1])
            self.assertEqual(['cache' in d['services'] for d in plan['stages']], [True,True,False,False,False,False])
            self.assertEqual([d['media'] for d in plan['stages']], ['/media']*3+['/data/media']*3)
            self.assertEqual(plan['peers'], ['peer'])
            self.assertIsNone(upgrade.plan(new,new,'id'))
            patched = copy.deepcopy(new)
            for row in patched['applications']['id']['software_selection']['images'].values():
                row['image'] = REFS[-1].replace('.1@','.2@')
            with self.assertRaisesRegex(ValueError, 'reviewed target'):
                upgrade.plan(new,patched,'id')
            patched['applications']['id']['properties']['upgrade_path'] = [REFS[-1],row['image']]
            self.assertEqual(upgrade.plan(new,patched,'id')['stages'], [])
            for key, value in [('lifecycle','fresh'), ('project_file','other.yml'), ('secret_bindings',{}),
                               ('settings',{'oidc_blueprints':{'pilot':True}})]:
                candidate = copy.deepcopy(new)
                candidate['applications']['id'][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    upgrade.plan(old,candidate,'id')
            for which,ref in [('source',REFS[1]), ('target',REFS[-2])]:
                first, last = copy.deepcopy(old),copy.deepcopy(new)
                app = (first if which == 'source' else last)['applications']['id']
                for row in app['software_selection']['images'].values():
                    row['image'] = ref
                with self.assertRaises(ValueError):
                    upgrade.plan(first,last,'id')
            wrong = copy.deepcopy(new)
            wrong['applications']['id']['software_selection']['images']['worker']['image'] = REFS[0]
            with self.assertRaises(ValueError):
                upgrade.plan(old,wrong,'id')
            with tempfile.TemporaryDirectory() as tmp:
                files = [Path(tmp)/name for name in ('old','new')]
                for f,v in zip(files,(old,new)):
                    write_new(f,encoded(v))
                cfg = lambda f: {'deployment':{'runtime_file':str(f)}}
                attempt = SimpleNamespace(previous_configuration=cfg(files[0]),cfg=cfg(files[1]))
                self.assertEqual(upgrade.prepare(attempt,'id'),plan)
                attempt.previous_configuration = None
                with self.assertRaises(ValueError):
                    upgrade.prepare(attempt,'id')

    def test_seal_before_schema_mutation(self):
        app = runtime(False)['applications']['id']
        app['id'] = 'id'
        with tempfile.TemporaryDirectory() as tmp:
            attempt = SimpleNamespace(operation=Path(tmp), previous_configuration={})
            with patch.object(upgrade,'prepare',return_value=None):
                self.assertEqual(upgrade.phase_options(attempt,'auth',app),{})
            selection = {'images':REFS}
            with patch.object(upgrade,'prepare',return_value=selection):
                with patch.object(upgrade.component_recovery,'enabled',return_value=False), self.assertRaises(ValueError):
                    upgrade.phase_options(attempt,'auth',app)
                self.assertEqual(list(Path(tmp).iterdir()), [])
                with patch.object(upgrade.component_recovery,'enabled',return_value=True):
                    self.assertEqual(upgrade.phase_options(attempt,'auth',app),{'upgrade': selection})
                marker, = attempt.operation.glob('*-rollback-limit.json')
                self.assertEqual(read_json(marker,private=True)['images'],REFS)

    def test_storage_transition(self):
        old = {'services':{'redis':'cache','server':'app','worker':'jobs'},
               'storage':{'redis':{'target':'/data'},'media':{'target':'/media','source':'a'}}}
        new = {'services':{'server':'app','worker':'jobs'}, 'storage':{'media':{'target':'/data/media','source':'a'},
               'data':{'target':'/data','read_only':False,'kind':'directory'}}}
        upgrade.transition(old,new)
        for key,val in [('read_only',True),('kind','file'),('target','/new')]:
            wrong = copy.deepcopy(new)
            wrong['storage']['data'][key] = val
            with self.assertRaises(ValueError):
                upgrade.transition(old,wrong)
        wrong = copy.deepcopy(new)
        wrong['storage']['media']['source'] = 'b'
        with self.assertRaises(ValueError):
            upgrade.transition(old,wrong)


class DeploymentCallerTests(unittest.TestCase):
    def setUp(self):
        self.case = deployment_fixture.DeploymentIntegrationTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def test_ansible_receives_the_sealed_selection_in_the_owned_phase(self):
        selection = {'images':REFS}
        phases = []
        def inspect(argv,environment,log):
            values = read_json(Path(argv[-1][1:]),private=True)
            if 'component_authentik_upgrade' in values:
                self.assertEqual(values['component_authentik_upgrade'], selection)
                phases.append(log.parent.name)
            return self.case.ansible(argv,environment,log)
        with patch.object(component_ansible,'quiet',side_effect=inspect), patch('image_update_hooks.phase_options',
                side_effect=lambda attempt,phase,app: {'upgrade':selection} if app else {}):
            self.case.all_phases()
        self.assertEqual(phases, [self.case.cfg['deployment']['phases'][-1]])

    def test_prior_receipt_namespaces_allow_only_the_declared_transition(self):
        self.case.all_phases()
        attempt = SimpleNamespace(receipt=self.case.state/'610/ordinary-complete.json',cfg=self.case.cfg)
        old,new = [runtime(flag)['applications']['id'] for flag in (True,False)]
        for app in (old,new):
            app.update(id='recursive_a',guest='resolver')
            app['identity'].update(networks={},runtime_id='owned')
            for key,row in app['storage_paths'].items():
                row.update(source='/srv/fixture/'+key,kind='directory',read_only=False)
        old['storage_paths']['redis'] = dict(target='/data',source='/srv/fixture/redis',kind='directory',read_only=False)
        def sealed(path,**kwargs):
            return old if path.name == 'application.json' else read_json(path,**kwargs)
        with patch.object(component_ownership,'read_json',side_effect=sealed):
            self.assertEqual(component_ownership.namespaces(attempt,new),(True,False))
            new['storage_paths']['media']['source'] = '/different'
            with self.assertRaises(ValueError):
                component_ownership.namespaces(attempt,new)
            new['lifecycle'] = 'fresh'
            with self.assertRaises(ValueError):
                component_ownership.namespaces(attempt,new)


class GuestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.canonical = self.root/'compose.yml'
        with patch.object(upgrade.component_runtime, 'compositions', side_effect=render):
            self.plan = upgrade.plan(runtime(True),runtime(False),'id')
        self.journal = self.root/'.authentik-upgrades'/guest.digest(encoded(self.plan))
        write_new(self.canonical,encoded(self.plan['initial']))
        self.current = self.plan['initial']
        self.image = REFS[0]
        self.fail = False
        self.start_count = 0
        self.reclaimed = []
        self.registration = 'example'
        self.cache = {REFS[1].split(':')[0]+'@'+REFS[1].split('@')[1]}
        self.enterContext(patch.object(guest,'APP_ROOT',self.root))
        self.enterContext(patch.object(guest,'docker',side_effect=self.engine))
        self.retire = self.enterContext(patch.object(guest,'retire'))

    def engine(self,*args,**kwargs):
        if args[:2] == ('image','ls'):
            return '\n'.join(self.cache)
        if args[0] == 'ps':
            if '--no-trunc' in args:
                return ('d' if args[-1].endswith('=cache') else 'a')*64
            if '--quiet' in args:
                return ''
            return '\n'.join(self.current['services'])
        if args[0]=='inspect':
            if '.RestartCount' in args[-2]:
                return '2026-01-01T00:00:00Z 0'
            image = self.plan['initial']['services']['cache']['image'] if args[-1] == 'd'*64 else self.image
            return image+' running healthy '+'b'*64
        if args[0]=='exec':
            return 'log line\nAK_UPGRADE='+json.dumps(dict(pending=0,applications=1,registration_hash=self.registration))
        if '--hash' in args:
            return '\n'.join(role+' '+'b'*64 for role in args[-1].split(','))
        if 'up' in args:
            self.start_count += 1
            if self.fail:
                raise subprocess.CalledProcessError(1,'compose')
            self.current = read_json(Path(args[args.index('-f')+1]), private=True)
            self.image = self.current['services']['web']['image']
        if args[:2] == ('image','rm'):
            self.reclaimed.append(args[-1])
        return ''

    def final(self):
        self.current,self.image = self.plan['final'],REFS[-1]
        self.canonical.write_bytes(encoded(self.current))
        return guest.run(self.plan,self.canonical,final=True)

    def test_six_releases_and_repeat_then_final(self):
        result = guest.run(self.plan,self.canonical)
        self.assertEqual((result['changed'], self.start_count), (True,6))
        self.assertEqual(self.reclaimed,REFS[2:6])
        self.retire.assert_called_once()
        self.assertFalse(guest.run(self.plan,self.canonical)['changed'])
        self.assertEqual(self.final()['last_release'], REFS[-1])
        self.assertEqual(self.reclaimed[-1],REFS[-2])
        self.assertEqual(read_json(self.journal/'final.json')['readback']['registration_hash'],'example')

    def test_lost_ack_and_partial_start(self):
        self.fail = True
        with self.assertRaises(subprocess.CalledProcessError):
            guest.run(self.plan,self.canonical)
        self.assertTrue((self.journal/'started-1.json').exists())
        self.fail=False
        with self.assertRaises(ValueError):
            guest.run(self.plan,self.canonical)
        self.assertEqual(self.start_count,1)
        self.current,self.image=self.plan['stages'][0],REFS[1]
        self.assertTrue(guest.run(self.plan,self.canonical,resume=True)['changed'])
        self.assertEqual(self.start_count,6)
        self.final()
        self.assertTrue(guest.run(self.plan,self.canonical,resume=True)['final_installed'])
        self.assertEqual(self.start_count,6)

    def test_resume_cannot_initialize_or_normalize_a_foreign_legacy_dependency(self):
        with self.assertRaises(FileNotFoundError):
            guest.run(self.plan, self.canonical, resume=True)
        self.assertFalse(self.journal.exists())
        self.plan['stages'][0]['services']['jobs']['depends_on'] = {'other': {'condition': 'service_started'}}
        with self.assertRaisesRegex(ValueError, 'Redis dependency'):
            guest.run(self.plan, self.canonical)
        self.assertEqual(self.start_count, 0)

    def test_changed_registration_foreign_services_and_evidence_refused(self):
        self.current=copy.deepcopy(self.current)
        self.current['services']['foreign']={}
        with self.assertRaisesRegex(ValueError,'project services'):
            guest.run(self.plan,self.canonical)
        self.assertEqual(self.start_count,0)
        self.current=self.plan['initial']
        guest.run(self.plan,self.canonical)
        self.registration='changed'
        with self.assertRaisesRegex(ValueError,'registration'):
            self.final()
        self.assertFalse((self.journal/'final.json').exists())
        with self.assertRaisesRegex(ValueError,'immutable'):
            guest.publish(self.journal/'baseline.json',{'other':True})
        with self.assertRaises(ValueError):
            guest.run(self.plan,self.canonical.with_suffix('.txt'))
        with self.assertRaises(ValueError):
            guest.run(self.plan,self.canonical)

    def test_docker_invocation_and_cleanup(self):
        with patch.object(subprocess,'run',return_value=SimpleNamespace(stdout=' result\n')) as run:
            self.assertEqual(self.original_docker('version'),'result')
            run.assert_called_once()
        write_new(self.root/'started-1.json',encoded({'image':REFS[1],'pulled_for_maintenance':True}))
        with patch.object(guest,'docker',side_effect=['',subprocess.CalledProcessError(1,'rm')]):
            guest.release_image(self.root,1)
        with patch.object(guest,'docker',return_value='another-container') as command:
            guest.release_image(self.root,1)
            self.assertEqual(command.call_count,1)

    original_docker = staticmethod(guest.docker)

    def test_cli_returns_only_the_completion_report(self):
        self.addCleanup(os.umask, os.umask(0o077))
        argv = ['maint',str(self.canonical)]
        for mode in ([], ['resume'], ['final']):
            output = io.StringIO()
            with patch.object(sys,'argv',argv + mode), \
                 patch.object(sys,'stdin',io.StringIO(json.dumps(self.plan))), \
                 patch.object(guest,'run',return_value={'completed':6}) as execute, contextlib.redirect_stdout(output):
                guest.main()
            execute.assert_called_once_with(self.plan, self.canonical, final=mode == ['final'], resume=mode == ['resume'])
            self.assertEqual(json.loads(output.getvalue()), {'completed':6})

    def test_cli_rejects_an_invalid_operation(self):
        self.addCleanup(os.umask, os.umask(0o077))
        with patch.object(sys,'argv',['maint','/opt/homelab-app/compose.yml','other']), self.assertRaises(SystemExit):
            runpy.run_path(guest.__file__,run_name='__main__')
