"""Bound Authentik target operations with disposable files and a fake Docker API."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import identity_database_runtime as runtime
from test_identity_database import fixture as compose_fixture, BEFORE, AFTER

APP = {'kind': 'identity', 'vmid': 711, 'hostname': 'security-test',
       'address': '10.88.25.20', 'mac': '02:88:00:00:19:20'}
START = '2026-10-27T01:00:00.000000000Z'


@unittest.skipUnless(os.getuid() == 0, 'Real ownership checks run in the offline Linux container')
class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.compose = self.root / 'compose.json'; self.identity = self.root / 'identity.json'
        self.mapping = self.root / 'uid_map'; self.mapping.write_text('0 100000 65536\n')
        self.identity.write_text(json.dumps({k: APP[k] for k in ('kind','vmid','hostname','address')}))
        self.identity.chmod(0o600)
        self.document = compose_fixture()
        self.rows = {}; self.commands = []; self.fail_up = False
        for i, name in enumerate(runtime.SERVICES, 1):
            service = self.document['services'][name]; service['restart'] = 'unless-stopped'
            if name != 'redis':
                service['volumes'].append({'type':'bind','source':'/synthetic/authentik-secret-key',
                    'target':'/run/secrets/authentik-secret-key','read_only':True})
            mounts = []
            for j, mount in enumerate(service.get('volumes', [])):
                source = self.root / (name + '-mount-' + str(j)); source.mkdir()
                if isinstance(mount, str):
                    target = mount.split(':')[1]; service['volumes'][j] = str(source) + ':' + target
                else:
                    source.rmdir(); source.write_text('synthetic-private-file'); source.chmod(0o400)
                    target = mount['target']; mount['source'] = str(source)
                mounts.append({'Type':'bind','Source':str(source),'Destination':target,
                               'RW':not target.startswith('/run/secrets/'), 'Propagation':'rprivate'})
            ident = format(i, '064x'); env = dict(service.get('environment', {}))
            config = {'Image':service['image'], 'Hostname':ident[:12],
                      'Env':[k+'='+str(v) for k,v in env.items()],
                      'Labels':{'com.docker.compose.project':'homelab-identity',
                                'com.docker.compose.service':name,'com.docker.compose.config-hash':'original'},
                      'Cmd':[name] if name != 'redis' else ['redis-server'], 'User':service.get('user','')}
            self.rows[name] = {'Id':ident,'Image':'sha256:'+format(101 if name in ('server','worker') else 103,'064x'), 'Config':config,
                'HostConfig':{'RestartPolicy':{'Name':'unless-stopped'},'Memory':256*1024*1024},
                'Mounts':mounts, 'State':{'Running':True,'Status':'running','StartedAt':START,
                    'Health':{'Status':'healthy'}}}
        self.original = (json.dumps(self.document,indent=2)+'\n').encode()
        self.compose.write_bytes(self.original); self.compose.chmod(0o600)
        self.patches = patch.multiple(runtime, COMPOSE=self.compose, IDENTITY=self.identity,
                                     UID_MAP=self.mapping, PVE=self.root/'not-pve', command=self.command)
        self.patches.start(); self.addCleanup(self.patches.stop)
        self.inspected = runtime.run('inspect', APP, {'after':AFTER})
        self.catalogue = {'schema':'homelab-database-networks-v1','networks':{'postgresql':{
            'server':{'vmid':708,'hostname':'postgresql','address':AFTER['address'],'mac':'02:88:00:00:31:23'},
            'clients':[{'vmid':711,'hostname':APP['hostname'],'address':'10.88.31.20','mac':'02:88:00:00:31:20'},
                       {'vmid':702,'hostname':'db-tools','address':'10.88.31.32','mac':'02:88:00:00:31:32'}]}}}
        self.request = runtime.prepare(self.catalogue,self.inspected,[711,702],BEFORE['address'])
        self.commands.clear()

    def command(self, argv, data=None, timeout=180):
        self.commands.append((argv,data))
        if 'ps' in argv: return (self.rows[argv[-1]]['Id']+'\n').encode()
        if 'image' in argv and 'inspect' in argv: return b'[]'
        if 'inspect' in argv:
            return json.dumps(next(r for r in self.rows.values() if r['Id']==argv[-1])).encode()
        if 'config' in argv: return b''
        if 'exec' in argv:
            row=next(r for r in self.rows.values() if r['Id']==argv[argv.index('exec')+1])
            if not row['State']['Running'] or row['State']['Health']['Status']!='healthy':
                raise runtime.CommandFailed('synthetic private health failure')
            return b'PONG\n' if argv[-2:]==['redis-cli','ping'] else b''
        if 'stop' in argv:
            self.assertEqual(argv[-2:],['server','worker'])
            for name in ('server','worker'): self.rows[name]['State'].update(Running=False,Status='exited')
        if 'up' in argv:
            if self.fail_up: raise runtime.CommandFailed('synthetic private start failure')
            self.assertEqual(argv[-2:],['server','worker'])
            for i,name in enumerate(('server','worker'),10):
                row=self.rows[name];row['Config']['Labels']['com.docker.compose.replace']=row['Id']
                row['Id']=format(i,'064x');row['Config']['Hostname']=row['Id'][:12]
                env=runtime.environment(row['Config']['Env']);env.update(AUTHENTIK_POSTGRESQL__HOST=AFTER['address'],AUTHENTIK_POSTGRESQL__PORT='5432')
                row['Config']['Env']=[k+'='+v for k,v in env.items()]
                row['Config']['Labels']['com.docker.compose.config-hash']='updated'
                row['State'].update(Running=True,Status='running',StartedAt='2026-10-27T02:00:00.000000000Z')
        return b''

    def mutation_commands(self): return [a for a,d in self.commands if 'stop' in a or 'up' in a or 'pull' in a]

    def test_preflight_and_verify_are_read_only_and_keep_private_values_out_of_results(self):
        self.assertEqual(runtime.run('preflight',APP,self.request)['status'],'passed')
        self.assertEqual(self.mutation_commands(),[]);self.assertEqual(self.compose.read_bytes(),self.original)
        runtime.run('quiesce',APP,self.request);runtime.run('activate',APP,self.request)
        self.commands.clear(); before=self.compose.read_bytes()
        result=runtime.run('verify',APP,self.request)
        self.assertEqual(result['status'],'passed');self.assertFalse(result['changed'])
        self.assertEqual(self.mutation_commands(),[]);self.assertEqual(self.compose.read_bytes(),before)
        self.assertNotIn('synthetic-private-file',json.dumps(result))
        self.assertNotIn('compose',self.request)
        self.assertNotIn('compose',self.inspected)
        self.assertNotIn('AUTHENTIK_POSTGRESQL__PASSWORD',json.dumps(self.request))

    def test_quiesce_and_allowed_guest_cycle_keep_both_clients_stopped(self):
        result=runtime.run('quiesce',APP,self.request)
        self.assertEqual(result['status'],'passed');self.assertEqual(self.compose.read_bytes(),self.original)
        for name in ('server','worker'):
            self.assertEqual(self.rows[name]['HostConfig']['RestartPolicy']['Name'],'unless-stopped')
            self.assertFalse(self.rows[name]['State']['Running'])
        # Fake the provider/Docker cycle: manually stopped unless-stopped clients
        # stay stopped; Redis starts in the same container with unchanged state.
        self.rows['redis']['State']['StartedAt']='2026-10-27T01:30:00.000000000Z'
        self.assertTrue(runtime.run('activate',APP,self.request)['changed'])
        self.assertEqual(len([a for a,d in self.commands if 'up' in a]),1)

    def test_activation_changes_only_two_endpoints_and_preserves_inode_and_redis(self):
        metadata=self.compose.stat();redis=copy.deepcopy(self.rows['redis'])
        runtime.run('quiesce',APP,self.request);result=runtime.run('activate',APP,self.request)
        expected=json.loads(self.original)
        for name in ('server','worker'):
            expected['services'][name]['environment'].update(AUTHENTIK_POSTGRESQL__HOST=AFTER['address'],AUTHENTIK_POSTGRESQL__PORT='5432')
        self.assertEqual(json.loads(self.compose.read_bytes()),expected)
        current=self.compose.stat();self.assertEqual((current.st_ino,current.st_uid,current.st_gid,current.st_mode),
            (metadata.st_ino,metadata.st_uid,metadata.st_gid,metadata.st_mode))
        self.assertEqual(self.rows['redis'],redis)
        up=next(a for a,d in self.commands if 'up' in a)
        for flag in ('--no-deps','--force-recreate','--pull','never','--wait'): self.assertIn(flag,up)
        self.assertNotIn('pull',[a[2] for a,d in self.commands if len(a)>2])
        self.assertEqual(result['status'],'passed')
        mutations=list(self.mutation_commands())
        with self.assertRaises(ValueError):runtime.run('activate',APP,self.request)
        self.assertEqual(self.mutation_commands(),mutations)

    def test_generated_replacement_history_must_name_exact_original_clients(self):
        runtime.run('quiesce',APP,self.request);runtime.run('activate',APP,self.request)
        for name in ('server','worker'):
            self.assertEqual(self.rows[name]['Config']['Labels']['com.docker.compose.replace'],
                             self.request['runtime'][name]['id'])
        before=list(self.mutation_commands())
        for replacement in (None,'f'*64,self.rows['worker']['Id']):
            self.rows['worker']['Config']['Labels']['com.docker.compose.replace']=replacement
            with self.subTest(replacement=replacement),self.assertRaises(ValueError):
                runtime.run('verify',APP,self.request)
        self.assertEqual(self.mutation_commands(),before)

    def test_unstopped_client_or_wrong_policy_is_held_without_file_write(self):
        with self.assertRaises(ValueError):runtime.run('activate',APP,self.request)
        self.assertEqual(self.compose.read_bytes(),self.original);self.assertEqual(self.mutation_commands(),[])
        self.rows['worker']['HostConfig']['RestartPolicy']['Name']='always'
        with self.assertRaises(ValueError):runtime.run('quiesce',APP,self.request)
        self.assertEqual(self.mutation_commands(),[])

    def test_runtime_compose_secret_and_identity_drift_hold_before_stopping(self):
        original=copy.deepcopy(self.rows)
        for mutate in (lambda: self.rows['worker'].update(Image='sha256:'+'f'*64),
                       lambda: self.rows['redis']['Config']['Env'].append('UNDECLARED=drift')):
            mutate()
            with self.assertRaises(ValueError):runtime.run('quiesce',APP,self.request)
            self.assertEqual(self.mutation_commands(),[]);self.rows=copy.deepcopy(original)
        source=Path(self.rows['server']['Mounts'][-1]['Source']);source.write_text('changed-secret')
        with self.assertRaises(ValueError):runtime.run('preflight',APP,self.request)
        self.assertEqual(self.mutation_commands(),[])
        self.compose.write_bytes(self.original+b' ')
        with self.assertRaises(ValueError):runtime.run('quiesce',APP,self.request)

    def test_unapproved_restart_or_restarted_client_after_cycle_is_held(self):
        runtime.run('quiesce',APP,self.request)
        self.rows['server']['State'].update(Running=True,Status='running')
        with self.assertRaises(ValueError):runtime.run('activate',APP,self.request)
        self.assertFalse(any('up' in a for a,d in self.commands))
        self.rows['server']['State'].update(Running=False,Status='exited')
        self.request['allow_guest_restart']=False
        self.rows['redis']['State']['StartedAt']='2026-10-27T01:30:00.000000000Z'
        with self.assertRaises(ValueError):runtime.run('activate',APP,self.request)

    def test_transient_client_restart_and_restop_is_not_accepted_as_guest_lifecycle(self):
        runtime.run('quiesce',APP,self.request)
        self.rows['worker']['State']['StartedAt']='2026-10-27T01:30:00.000000000Z'
        with self.assertRaises(ValueError):runtime.run('activate',APP,self.request)
        self.assertFalse(any('up' in a for a,d in self.commands))
        self.assertEqual(self.compose.read_bytes(),self.original)

    def test_failed_activation_is_not_replayed_or_automatically_rolled_back(self):
        runtime.run('quiesce',APP,self.request);self.fail_up=True
        with self.assertRaises(runtime.CommandFailed):runtime.run('activate',APP,self.request)
        self.assertEqual(hashlib.sha256(self.compose.read_bytes()).hexdigest(),self.request['candidate_sha256'])
        self.fail_up=False;before=list(self.mutation_commands())
        with self.assertRaises(ValueError):runtime.run('activate',APP,self.request)
        self.assertEqual(self.mutation_commands(),before)
        with self.assertRaises(ValueError):runtime.run('verify',APP,self.request)

    def test_closed_request_and_catalogue_group_binding_are_required(self):
        self.assertTrue(runtime.validate_binding(self.request,self.catalogue,[702,711],BEFORE['address']))
        for field,value in [('command',['arbitrary']),('after',BEFORE),('client_vmids',[711]),('app',dict(APP,vmid=999))]:
            request=copy.deepcopy(self.request);request[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                runtime.validate_binding(request,self.catalogue,[702,711],BEFORE['address'])
        with self.assertRaises(ValueError):runtime.run('unsupported',APP,self.request)
        with self.assertRaises(ValueError):runtime.run('verify',APP,{})
        self.assertEqual(self.mutation_commands(),[])

    def test_target_identity_and_namespace_are_not_adopted(self):
        with self.assertRaises(ValueError):runtime.run('inspect',dict(APP,vmid=999),{'after':AFTER})
        self.mapping.write_text('0 0 4294967295\n')
        with self.assertRaises(ValueError):runtime.run('inspect',APP,{'after':AFTER})
        self.assertEqual(self.mutation_commands(),[])


if __name__ == '__main__': unittest.main()
