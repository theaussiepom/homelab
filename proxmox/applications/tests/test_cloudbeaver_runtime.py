"""Real workspace/receipt files with only OS ownership and Docker boundaries replaced."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
SOURCE=Path(__file__).resolve().parents[1]/'cloudbeaver-runtime.py'
spec=importlib.util.spec_from_file_location('cloud_runtime',SOURCE)
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.ws=self.root/'workspace';self.custody=self.root/'custody';self.pg=self.root/'pgadmin'
        self.owner={'node':'fixture-pve','vmid':808,'hostname':'tools'}
        self.config={'workspace':str(self.ws),'project':'homelab-db-tools',
            'retained_pgadmin_image':'dpage/pgadmin4@sha256:'+'a'*64,'bind_address':'198.18.30.32',
            'connections':{'postgresql':{'name':'PostgreSQL','driver':'postgresql','host':'198.18.31.23',
              'port':5432,'database':'postgres','sslmode':'prefer'},
              'mariadb':{'name':'MariaDB','driver':'mariadb','host':'198.18.32.24','port':3306,'database':''}}}
        for name,value in [('WORKSPACE',self.ws),('CUSTODY',self.custody),('PGADMIN',self.pg),('PERMISSIONS',self.root/'permissions.json')]:
            p=patch.object(r,name,value);p.start();self.addCleanup(p.stop)
        original=Path.lstat
        def lstat(path,*a,**kw):
            value=original(path,*a,**kw);rows=list(value)
            rows[4]=8978 if path==self.ws or self.ws in path.parents or path==r.PERMISSIONS else 5050 if path==self.pg else 0
            rows[5]=rows[4]
            return os.stat_result(rows)
        p=patch.object(Path,'lstat',lstat);p.start();self.addCleanup(p.stop)
        p=patch.object(r.os,'chown');self.chown=p.start();self.addCleanup(p.stop)
        p=patch.object(r.os,'fchown');p.start();self.addCleanup(p.stop)
        r.create(r.PERMISSIONS,{name:['user'] for name in self.config['connections']},uid=8978,mode=0o400)

    def own(self):return r.workspace(self.owner)

    def seed_metadata(self):
        import cloudbeaver
        document=cloudbeaver.connection_document(self.config)
        path=self.ws/'GlobalConfiguration/.dbeaver/data-sources.json'
        r.create(path,document,uid=8978,mode=0o600)
        return path,document

    def test_real_private_create_roundtrip_fsync_and_create_only(self):
        self.own();p=self.custody/'proof.json';r.create(p,{'proof':True})
        self.assertEqual(r.private(p),{'proof':True});self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
        with self.assertRaises(FileExistsError):r.create(p,{})
        p.chmod(0o644)
        with self.assertRaises(ValueError):r.private(p)
        p.unlink();p.symlink_to(self.custody/'workspace.json')
        with self.assertRaises(ValueError):r.private(p)
        p.unlink();p.write_bytes(b'x'*(1024*1024+1));p.chmod(0o600)
        with self.assertRaises(ValueError):r.private(p)

    def test_workspace_is_owned_once_and_unknown_data_or_owner_refuses(self):
        self.assertEqual(self.own(),{'workspace':'owned'});self.chown.assert_any_call(self.ws,8978,8978)
        (self.ws/'retained.db').write_bytes(b'retained')
        before=(self.custody/'workspace.json').read_bytes();self.own()
        self.assertEqual((self.custody/'workspace.json').read_bytes(),before)
        with self.assertRaises(ValueError):r.workspace(dict(self.owner,vmid=809))
        with self.assertRaises(ValueError):r.workspace({'vmid':True})
        self.ws.chmod(0o755)
        with self.assertRaises(ValueError):self.own()

    def test_unknown_workspace_symlink_nonempty_or_custody_mode_refuses(self):
        self.ws.mkdir();(self.ws/'unknown').write_bytes(b'keep')
        with self.assertRaises(ValueError):self.own()
        (self.ws/'unknown').unlink();self.ws.rmdir();self.ws.symlink_to(self.root)
        with self.assertRaises(ValueError):self.own()
        self.ws.unlink();self.custody.chmod(0o755)
        with self.assertRaises(ValueError):self.own()

    def container(self):
        self.own();self.pg.mkdir();(self.pg/'retained.sqlite').write_bytes(b'identity-and-state')
        return {'Id':'f'*64,'Config':{'Image':self.config['retained_pgadmin_image'],
            'Labels':{'com.docker.compose.project':'homelab-db-tools','com.docker.compose.service':'pgadmin'}},
            'Mounts':[{'Destination':'/var/lib/pgadmin','Type':'bind','Source':str(self.pg)}],
            'State':{'Running':True}}

    def test_retirement_binds_exact_managed_container_and_preserves_data(self):
        obj=self.container();before=(self.pg/'retained.sqlite').read_bytes();calls=[]
        def docker(args,**kw):
            calls.append(args)
            if args[0]=='ps':return 'f'*12+'\n'
            if args[0]=='inspect':return json.dumps([dict(obj,State={'Running':False}) if len(calls)>3 else obj])
            return ''
        with patch.object(r,'docker',side_effect=docker):
            self.assertEqual(r.prepare(self.config),{'pgadmin':'retired','data':'preserved'})
        self.assertEqual(calls[-1],['rm','f'*64]);self.assertIn(['stop','--time','60','f'*64],calls)
        self.assertFalse(any('--volumes' in a or '--force' in a for a in calls))
        self.assertEqual((self.pg/'retained.sqlite').read_bytes(),before)
        proof=r.private(self.custody/'pgadmin-retirement.json')
        self.assertEqual(proof['container'],'f'*64)
        with patch.object(r,'docker',side_effect=['f'*12,json.dumps([obj]),'',json.dumps([dict(obj,State={'Running':False})]),'']):
            r.retirement(self.config)
        with patch.object(r,'docker',return_value=''):self.assertEqual(r.retirement(self.config),{'pgadmin':'absent'})
        with self.assertRaises(ValueError):r.prepare(dict(self.config,project='foreign'))

    def test_retirement_rejects_foreign_identity_mount_image_running_or_changed_receipt(self):
        obj=self.container()
        for change in [lambda v:v['Config'].update(Image='other'),lambda v:v['Mounts'][0].update(Source='/unknown'),
                       lambda v:v['Config']['Labels'].update({'com.docker.compose.service':'other'})]:
            bad=copy.deepcopy(obj);change(bad)
            with patch.object(r,'docker',side_effect=['f'*12,json.dumps([bad])]) as boundary,self.assertRaises(ValueError):r.retirement(self.config)
            self.assertEqual(boundary.call_count,2)
        with patch.object(r,'docker',return_value='a\nb'),self.assertRaises(ValueError):r.retirement(self.config)
        with patch.object(r,'docker',side_effect=['f'*12,json.dumps([obj]),'',json.dumps([obj])]),self.assertRaises(ValueError):r.retirement(self.config)
        proof=self.custody/'pgadmin-retirement.json';proof.write_text('{}');proof.chmod(0o600)
        with patch.object(r,'docker',side_effect=['f'*12,json.dumps([obj])]),self.assertRaises(ValueError):r.retirement(self.config)

    def health_boundary(self, rows_as_lines=False, change=None):
        names=['cloudbeaver','auth_gateway'];rows=[{'Service':n,'ID':n} for n in names]
        docs={n:{'Config':{'User':'8978:8978' if n=='cloudbeaver' else '65532:65532'},
          'HostConfig':{'PortBindings':{} if n=='cloudbeaver' else {'4180/tcp':[{'HostIp':self.config['bind_address'],'HostPort':'80'}]},
                        'NetworkMode':'homelab-db-tools_database_tools'},
          'NetworkSettings':{'Networks':{'homelab-db-tools_database_tools':{}}},
          'State':{'Running':True,'Health':{'Status':'healthy'}},
          'Mounts':[{'Source':str(self.ws),'Destination':'/opt/cloudbeaver/workspace','Type':'bind','RW':True}]} for n in names}
        current={'forceHttps':True,'configurationMode':False,'anonymousAccessEnabled':False,'enabledAuthProviders':['local','reverseProxy']}
        if change:change(docs,current)
        def docker(args,**kw):
            if args[0]=='ps':return ''
            if args[0]=='inspect':return json.dumps([docs[args[1]]])
            if 'ps' in args:return '\n'.join(json.dumps(row) for row in rows) if rows_as_lines else json.dumps(rows)
            return json.dumps({'data':{'serverConfig':current}})
        return docker

    def test_health_proves_private_bridge_gateway_only_and_setup_closed(self):
        self.own();r.templates(self.config);self.seed_metadata()
        for lines in (False,True):
            with patch.object(r,'docker',side_effect=self.health_boundary(lines)):
                self.assertEqual(r.health(self.config)['cloudbeaver'],'passed')
        for mutation in [lambda d,c:d['auth_gateway']['State'].update(Running=False),
             lambda d,c:d['cloudbeaver']['State']['Health'].update(Status='unhealthy'),
             lambda d,c:c.update(forceHttps=False),lambda d,c:c.update(configurationMode=True),lambda d,c:c.update(anonymousAccessEnabled=True),
             lambda d,c:d['cloudbeaver']['HostConfig'].update(PortBindings={'8978/tcp':[]}),
             lambda d,c:d['cloudbeaver']['HostConfig'].update(NetworkMode='host'),
             lambda d,c:d['auth_gateway']['NetworkSettings'].update(Networks={'other':{}})]:
            with patch.object(r,'docker',side_effect=self.health_boundary(change=mutation)),self.assertRaises(ValueError):r.health(self.config)
        with patch.object(r,'docker',return_value='old'),self.assertRaises(ValueError):r.health(self.config)

    def test_managed_health_refuses_nested_workspace_shadow(self):
        self.own();r.templates(self.config);self.seed_metadata()
        config=dict(self.config,managed_connections={'owned-administrator':{}})
        with patch.object(r,'managed',return_value={'managed_connections':'verified'}), \
                patch.object(r,'database_health',return_value='managed_tls_administrator_verified'):
            with patch.object(r,'docker',side_effect=self.health_boundary()):
                self.assertEqual(r.health(config)['cloudbeaver'],'passed')
            def shadow(docs,current):
                docs['cloudbeaver']['Mounts'].append({'Destination':'/opt/cloudbeaver/workspace/GlobalConfiguration'})
            with patch.object(r,'docker',side_effect=self.health_boundary(change=shadow)),self.assertRaises(ValueError):
                r.health(config)

    def test_managed_metadata_refuses_stale_endpoints_or_saved_shared_credentials_without_writes(self):
        self.own();path,document=self.seed_metadata()
        document['connections']['custom']={'application-owned':'preserved'}
        path.write_text(json.dumps(document));before=path.read_bytes();r.metadata(self.config)
        self.assertEqual(path.read_bytes(),before)
        for change in [lambda d:d['connections']['postgresql']['configuration'].update(host='198.18.31.99'),
             lambda d:d['connections']['postgresql']['configuration']['properties'].update(sslmode='disable'),
             lambda d:d['connections']['mariadb'].update({'auth-properties':{'password':'never-shared'}}),
             lambda d:d['connections']['postgresql']['configuration'].update(user='shared-admin')]:
            wrong=copy.deepcopy(document);change(wrong);path.write_text(json.dumps(wrong));before=path.read_bytes()
            with self.assertRaises(ValueError):r.metadata(self.config)
            self.assertEqual(path.read_bytes(),before)

    def test_template_seed_is_create_only_and_keeps_custom_permissions(self):
        self.own();r.templates(self.config)
        target=self.ws/'GlobalConfiguration/.dbeaver/data-sources-permissions.json'
        current=json.loads(target.read_text());current['custom-connection']=['a-custom-user']
        target.chmod(0o600);target.write_text(json.dumps(current));before=target.read_bytes()
        r.templates(self.config);self.assertEqual(target.read_bytes(),before)
        current['postgresql']=['admin'];target.write_text(json.dumps(current))
        with self.assertRaises(ValueError):r.templates(self.config)
        self.assertEqual(json.loads(target.read_text())['postgresql'],['admin'])
        target.unlink()
        with self.assertRaises(ValueError):r.templates(self.config,seed=False)

    def test_docker_and_cli_boundaries_return_only_safe_summary(self):
        with patch.object(r.subprocess,'run',return_value=type('Done',(),{'stdout':'safe'})()) as run:
            self.assertEqual(r.docker(['inspect','fixture'],input='private'),'safe')
            self.assertTrue(run.call_args.kwargs['capture_output']);self.assertTrue(run.call_args.kwargs['check'])
        self.own();path=self.root/'public.json';r.create(path,self.config)
        for action in ('workspace','templates','prepare','health'):
            args=['tool',action,'--owner',json.dumps(self.owner)] if action=='workspace' else ['tool',action,'--config',str(path)]
            target='workspace' if action=='workspace' else action
            with patch.object(sys,'argv',args),patch.object(r,target,return_value={'safe':True}),patch('sys.stdout',new_callable=io.StringIO) as output:r.main()
            self.assertEqual(json.loads(output.getvalue()),{'safe':True})
        with patch.object(sys,'argv',['tool','invalid']),patch('sys.stderr',new_callable=io.StringIO),self.assertRaises(SystemExit):runpy.run_path(str(SOURCE),run_name='__main__')


if __name__=='__main__':unittest.main()
