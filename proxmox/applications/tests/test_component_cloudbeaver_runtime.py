"""Real private files with virtual UID boundary and finite Docker-only fakes."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

D=Path(__file__).resolve().parents[1]


def load():
    spec=importlib.util.spec_from_file_location('proposed_cloud_runtime',D/'cloudbeaver-runtime.py');value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


class CloudRuntimeComponentTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.r=load();self.owners={};self.original_stat=os.stat;self.original_lstat=os.lstat;self.original_fstat=os.fstat;self.original_open=os.open
        def virtual(value):
            fields={name:getattr(value,name)for name in dir(value)if name.startswith('st_')};uid,gid=self.owners.get((value.st_dev,value.st_ino),(0,0));fields.update(st_uid=uid,st_gid=gid);return SimpleNamespace(**fields)
        def chown(path,uid,gid,*a,**kw):
            info=self.original_lstat(path);self.owners[(info.st_dev,info.st_ino)]=(uid,gid)
        def fchown(fd,uid,gid):
            info=self.original_fstat(fd);self.owners[(info.st_dev,info.st_ino)]=(uid,gid)
        def opening(path,flags,*args,**kwargs):
            fd=self.original_open(path,flags,*args,**kwargs)
            if flags & (os.O_CREAT | os.O_EXCL) == (os.O_CREAT | os.O_EXCL):
                info=self.original_fstat(fd);self.owners[(info.st_dev,info.st_ino)]=(0,0)
            return fd
        for target,value in [('open',opening),('stat',lambda *a,**kw:virtual(self.original_stat(*a,**kw))),('lstat',lambda *a,**kw:virtual(self.original_lstat(*a,**kw))),('fstat',lambda fd:virtual(self.original_fstat(fd))),('chown',chown),('fchown',fchown),('geteuid',lambda:0)]:
            context=patch.object(self.r.os,target,value);context.start();self.addCleanup(context.stop)
        for name,value in [('WORKSPACE',self.root/'legacy-workspace'),('CUSTODY',self.root/'custody'),('PGADMIN',self.root/'pgadmin'),('RUNTIME',self.root/'runtime'),('COMPOSE',str(self.root/'application/compose.yml'))]:
            setattr(self.r,name,value)
        self.r.PERMISSIONS=self.r.RUNTIME/'cloudbeaver-permissions.json';self.r.MANAGED=self.r.RUNTIME/'cloudbeaver-admin-connections.json'
        self.r.CUSTODY.mkdir(mode=0o700);self.r.RUNTIME.mkdir(mode=0o700);Path(self.r.COMPOSE).parent.mkdir(mode=0o700)
        self.owner={'node':'fixture','vmid':808,'hostname':'tools'}
    def test_exclusive_create_reinitializes_a_reused_inode_before_root_receipt_read(self):
        native_open=self.original_open;injected=[]
        def reused(path,flags,*args,**kwargs):
            fd=native_open(path,flags,*args,**kwargs)
            if flags & (os.O_CREAT | os.O_EXCL) == (os.O_CREAT | os.O_EXCL):
                info=self.original_fstat(fd);key=(info.st_dev,info.st_ino)
                self.owners[key]=(8978,8978);injected.append(key)
            return fd
        path=self.root/'root-receipt.json'
        with patch.object(self,'original_open',side_effect=reused):self.r.create(path,{'owned':True})
        # The production owner guard must succeed for the newly root-created
        # receipt, even if this inode identity had belonged to a deleted file.
        self.assertEqual(self.r.private(path),{'owned':True})
        self.assertEqual(len(injected),1);self.assertEqual(self.owners[injected[0]],(0,0))

    def test_exclusive_create_still_allows_the_subsequent_explicit_managed_fchown(self):
        native_open=self.original_open
        def reused(path,flags,*args,**kwargs):
            fd=native_open(path,flags,*args,**kwargs)
            if flags & (os.O_CREAT | os.O_EXCL) == (os.O_CREAT | os.O_EXCL):
                info=self.original_fstat(fd);self.owners[(info.st_dev,info.st_ino)]=(65532,65532)
            return fd
        path=self.root/'managed-identity.json'
        with patch.object(self,'original_open',side_effect=reused):self.r.create(path,{'owned':True},uid=8978)
        self.assertEqual(self.r.managed_bytes(path,8978,(0o600,)),path.read_bytes())
        info=self.original_lstat(path);self.assertEqual(self.owners[(info.st_dev,info.st_ino)],(8978,8978))

    def test_existing_read_nonexclusive_open_and_failed_exclusive_create_never_reset_owner(self):
        path=self.root/'existing-wrong-owner.json';self.r.create(path,{'owned':True},uid=8978);before=path.read_bytes()
        info=self.original_lstat(path);key=(info.st_dev,info.st_ino)
        with self.assertRaises(ValueError):self.r.private(path)
        fd=self.r.os.open(path,os.O_RDONLY | os.O_CREAT)
        try:self.assertEqual(self.r.os.fstat(fd).st_uid,8978)
        finally:self.r.os.close(fd)
        with self.assertRaises(FileExistsError):self.r.create(path,{'foreign':True})
        self.assertEqual(self.owners[key],(8978,8978));self.assertEqual(path.read_bytes(),before)
        with self.assertRaises(ValueError):self.r.private(path)

    def config(self, fresh=True, suffix='one'):
        value={'workspace':str(self.root/('workspace-'+suffix)),'project':'project-'+suffix,
            'project_file':'compose-'+suffix+'.yml','services':{'cloudbeaver':'server-'+suffix,'auth_gateway':'gateway-'+suffix},
            'runtime_directory':str(self.r.RUNTIME/suffix),'custody_directory':str(self.r.CUSTODY/suffix),
            'runtime_id':'cloud-'+suffix,'lifecycle':'fresh'if fresh else'retained','bind_address':'198.18.30.32','connections':{}}
        if not fresh:value['retained_pgadmin_image']='dpage/pgadmin4@sha256:'+'a'*64
        Path(value['runtime_directory']).mkdir(mode=0o700)
        return value
    def legacy(self):
        return {'workspace':str(self.r.WORKSPACE),'project':'homelab-db-tools','retained_pgadmin_image':'dpage/pgadmin4@sha256:'+'a'*64,'bind_address':'198.18.30.32','connections':{}}
    def test_retained_default_context_preserves_all_old_paths_and_service_ids(self):
        ctx=self.r.context(self.legacy());self.assertEqual((ctx.workspace,ctx.custody,ctx.runtime,ctx.compose),(self.r.WORKSPACE,self.r.CUSTODY,self.r.RUNTIME,self.r.COMPOSE));self.assertEqual(ctx.services,{'cloudbeaver':'cloudbeaver','auth_gateway':'auth_gateway'})
    def test_dynamic_context_uses_only_selected_services_runtime_compose_and_custody(self):
        value=self.config();ctx=self.r.context(value)
        self.assertEqual(ctx.services,value['services']);self.assertEqual(ctx.project,value['project']);self.assertEqual(ctx.compose,str(Path(self.r.COMPOSE).parent/value['project_file']));self.assertEqual(ctx.managed,Path(value['runtime_directory'])/'cloudbeaver-admin-connections.json')
    def test_context_path_service_and_lifecycle_drift_refuse(self):
        value=self.config()
        mutations=[lambda v:v.update(project_file='../foreign.yml'),lambda v:v.update(project_file='other.json'),lambda v:v.update(runtime_directory='/foreign/runtime'),lambda v:v.update(custody_directory='/foreign/custody'),lambda v:v.update(services={'cloudbeaver':'same','auth_gateway':'same'}),lambda v:v['services'].update(peer='foreign'),lambda v:v.update(retained_pgadmin_image='foreign'),lambda v:v.update(lifecycle='unknown')]
        for mutate in mutations:
            bad=copy.deepcopy(value);mutate(bad)
            with self.subTest(case=mutations.index(mutate)),self.assertRaises(ValueError):self.r.context(bad)
    def test_fresh_prepare_never_discovers_or_stops_legacy_pgadmin(self):
        value=self.config();self.r.workspace(self.owner,value)
        with patch.object(self.r,'docker',side_effect=AssertionError('No pgAdmin lookup')):
            self.assertEqual(self.r.prepare(value),{'pgadmin':'not_selected'})
    def test_retained_workspace_owner_receipt_bytes_are_not_rewritten(self):
        value=self.legacy();self.r.workspace(self.owner,value);receipt=self.r.CUSTODY/'workspace.json';raw=receipt.read_bytes();self.assertEqual(json.loads(raw),self.owner)
        self.r.workspace(self.owner,value);self.assertEqual(receipt.read_bytes(),raw)
    def test_two_fresh_instances_share_guest_owner_without_namespace_adoption(self):
        first=self.config(suffix='one');second=self.config(suffix='two')
        self.r.workspace(self.owner,first);self.r.workspace(self.owner,second)
        left=Path(first['custody_directory'])/'workspace.json';right=Path(second['custody_directory'])/'workspace.json'
        self.assertNotEqual(left.read_bytes(),right.read_bytes());self.assertEqual(self.r.workspace_owner(first),self.owner);self.assertEqual(self.r.workspace_owner(second),self.owner)
        before=left.read_bytes();self.r.workspace(self.owner,first);self.assertEqual(left.read_bytes(),before)
    def test_existing_context_receipt_rejects_same_owner_path_project_service_and_runtime_drift(self):
        value=self.config();self.r.workspace(self.owner,value);receipt=Path(value['custody_directory'])/'workspace.json';raw=receipt.read_bytes()
        mutations=[lambda v:v.update(project='foreign'),lambda v:v['services'].update(cloudbeaver='foreign'),lambda v:v.update(runtime_id='foreign'),lambda v:v.update(project_file='foreign.yml'),lambda v:v.update(workspace=str(self.root/'foreign-workspace'))]
        for mutate in mutations:
            changed=copy.deepcopy(value);mutate(changed)
            with self.subTest(case=mutations.index(mutate)),self.assertRaises(ValueError):self.r.workspace(self.owner,changed)
            self.assertEqual(receipt.read_bytes(),raw)
    def test_bare_legacy_receipt_is_not_adopted_into_new_context(self):
        value=self.config();Path(value['custody_directory']).mkdir(mode=0o700);self.r.create(Path(value['custody_directory'])/'workspace.json',self.owner)
        with self.assertRaises(ValueError):self.r.workspace(self.owner,value)
    def test_anchored_private_read_rejects_leaf_symlink_hardlink_and_parent_symlink(self):
        folder=self.root/'safe';folder.mkdir();source=folder/'record.json';self.r.create(source,{'owned':True});self.assertEqual(self.r.private(source),{'owned':True})
        linked=folder/'hard.json';os.link(source,linked)
        with self.assertRaises(ValueError):self.r.private(source)
        linked.unlink();linked.symlink_to(source)
        with self.assertRaises(OSError):self.r.private(linked)
        shortcut=self.root/'shortcut';shortcut.symlink_to(folder,target_is_directory=True)
        with self.assertRaises(OSError):self.r.private(shortcut/'record.json')
    def test_anchored_parent_swap_refuses_instead_of_reading_replacement(self):
        folder=self.root/'swap';folder.mkdir();source=folder/'record.json';self.r.create(source,{'owned':True});moved=self.root/'moved';original=self.r.os.open;swapped=False
        def opening(path,*args,**kwargs):
            nonlocal swapped
            if path=='record.json'and kwargs.get('dir_fd')is not None and not swapped:
                swapped=True;folder.rename(moved);folder.mkdir();self.r.create(folder/'record.json',{'foreign':True})
            return original(path,*args,**kwargs)
        with patch.object(self.r.os,'open',side_effect=opening),self.assertRaises(ValueError):self.r.private(source)
    def test_anchored_leaf_swap_during_read_refuses(self):
        folder=self.root/'leaf';folder.mkdir();source=folder/'record.json';self.r.create(source,{'owned':True});original=self.r.os.open;swapped=False
        def opening(path,*args,**kwargs):
            nonlocal swapped
            result=original(path,*args,**kwargs)
            if path=='record.json'and kwargs.get('dir_fd')is not None and not swapped:
                swapped=True;source.rename(folder/'old.json');self.r.create(source,{'foreign':True})
            return result
        with patch.object(self.r.os,'open',side_effect=opening),self.assertRaises(ValueError):self.r.private(source)
    def test_managed_bytes_preserve_private_owner_group_mode_and_content_digest(self):
        source=self.root/'managed.json';self.r.create(source,{'synthetic':'value'},uid=8978,mode=0o600);raw=source.read_bytes();self.assertEqual(self.r.managed_bytes(source,8978,(0o600,)),raw)
        source.chmod(0o644)
        with self.assertRaises(ValueError):self.r.managed_bytes(source,8978,(0o600,))
    def test_managed_only_fresh_metadata_does_not_require_a_legacy_template_file(self):
        value=self.config()
        with patch.object(self.r,'private',side_effect=AssertionError('No nonexistent old template read')):self.assertEqual(self.r.metadata(value),{'connections':'verified'})
    def test_dynamic_database_health_uses_owned_compose_service_and_stdin_password(self):
        value=self.config();value['managed_connections']={'managed':{'driver':'postgresql','host':'198.18.31.23','username':'fixture_admin','owner':{'source_address':'198.18.31.32'}}};source=Path(value['runtime_directory'])/'cloudbeaver-admin-connections.json';self.r.create(source,{'connections':{'managed':{'configuration':{'auth-properties':{'userPassword':'synthetic-password'}}}}},mode=0o400)
        with patch.object(self.r,'docker',return_value=json.dumps({'database_administrator':'verified','encrypted':True,'source_match':True}))as boundary:self.assertEqual(self.r.database_health(value),'managed_tls_administrator_verified')
        args=boundary.call_args.args[0];self.assertEqual(args[2],str(Path(self.r.COMPOSE).parent/value['project_file']));self.assertIn(value['services']['cloudbeaver'],args);self.assertNotIn('synthetic-password',json.dumps(args));self.assertEqual(boundary.call_args.kwargs['input'],'synthetic-password\n')
    def test_first_seed_writer_stops_only_exact_running_owned_server_and_reads_stopped_identity(self):
        value=self.config();value['cloudbeaver_image']='dbeaver/cloudbeaver@sha256:'+'b'*64
        row={'Id':'f'*64,'Config':{'Image':value['cloudbeaver_image'],'Labels':{'com.docker.compose.project':value['project'],'com.docker.compose.service':value['services']['cloudbeaver']}},'Mounts':[{'Destination':'/opt/cloudbeaver/workspace','Type':'bind','Source':value['workspace'],'RW':True}],'State':{'Running':True}}
        stopped=copy.deepcopy(row);stopped['State']['Running']=False
        with patch.object(self.r,'docker',side_effect=['f'*12,json.dumps([row]),'',json.dumps([stopped])])as boundary:self.r.managed_writer(value)
        self.assertEqual(boundary.call_args_list[2].args[0],['stop','--time','30','f'*64]);self.assertEqual(boundary.call_args_list[2].kwargs,{'timeout':45});self.assertEqual(boundary.call_args_list[3].args[0],['inspect','f'*64])
    def test_managed_writer_uses_exact_selected_identity_and_keeps_nested_mount_refusal(self):
        value=self.config();value['cloudbeaver_image']='dbeaver/cloudbeaver@sha256:'+'b'*64;row={'Id':'f'*64,'Config':{'Image':value['cloudbeaver_image'],'Labels':{'com.docker.compose.project':value['project'],'com.docker.compose.service':value['services']['cloudbeaver']}},'Mounts':[{'Destination':'/opt/cloudbeaver/workspace','Type':'bind','Source':value['workspace'],'RW':True}],'State':{'Running':False}}
        with patch.object(self.r,'docker',side_effect=['f'*12,json.dumps([row])])as boundary:self.r.managed_writer(value)
        self.assertIn('label=com.docker.compose.project='+value['project'],boundary.call_args_list[0].args[0]);self.assertIn('label=com.docker.compose.service='+value['services']['cloudbeaver'],boundary.call_args_list[0].args[0])
        row['Mounts'].append({'Destination':'/opt/cloudbeaver/workspace/foreign'})
        with patch.object(self.r,'docker',side_effect=['f'*12,json.dumps([row])]),self.assertRaises(ValueError):self.r.managed_writer(value)

    def healthy(self,value,change=None):
        names=value['services'];project=value['project'];network=project+'_private'
        rows={name:{'Id':name+'-id','Config':{'User':'8978:8978'if role=='cloudbeaver'else'65532:65532','Labels':{'com.docker.compose.project':project,'com.docker.compose.service':name}},'State':{'Running':True,'Health':{'Status':'healthy'}},'HostConfig':{'NetworkMode':network,'PortBindings':{}if role=='cloudbeaver'else{'4180/tcp':[{'HostIp':value['bind_address'],'HostPort':'80'}]}},'NetworkSettings':{'Networks':{network:{}}},'Mounts':[{'Source':value['workspace'],'Destination':'/opt/cloudbeaver/workspace','Type':'bind','RW':True}]}for role,name in names.items()}
        if change:change(rows)
        def docker(args,**kwargs):
            if args[0]=='inspect':return json.dumps([rows[args[1].removesuffix('-id')]])
            if args[0]=='compose'and 'ps'in args:return json.dumps([{'Service':name,'ID':name+'-id'}for name in names.values()])
            if args[0]=='compose'and 'exec'in args:return json.dumps({'data':{'serverConfig':{'forceHttps':True,'configurationMode':False,'anonymousAccessEnabled':False,'enabledAuthProviders':['local','reverseProxy']}}})
            raise AssertionError('No legacy/global container lookup')
        return docker
    def seed_fresh(self,value):
        self.r.workspace(self.owner,value);ctx=self.r.context(value)
        self.r.create(ctx.permissions,{},uid=8978,mode=0o400);self.r.templates(value)
    def test_dynamic_full_health_uses_only_its_project_services_and_unchanged_auth_gate(self):
        value=self.config();self.seed_fresh(value)
        with patch.object(self.r,'docker',side_effect=self.healthy(value))as boundary:
            self.assertEqual(self.r.health(value),{'cloudbeaver':'passed','setup':'closed','gateway_only_listener':True,'database_login':'individual_credentials_required'})
        calls=boundary.call_args_list;self.assertTrue(all(call.args[0][0]in('compose','inspect')for call in calls));self.assertEqual(calls[0].args[0][2],str(Path(self.r.COMPOSE).parent/value['project_file']))
    def test_dynamic_health_rejects_foreign_project_label_without_relaxing_gateway_boundary(self):
        value=self.config();self.seed_fresh(value)
        def change(rows):rows[value['services']['cloudbeaver']]['Config']['Labels']['com.docker.compose.project']='foreign'
        with patch.object(self.r,'docker',side_effect=self.healthy(value,change)),self.assertRaises(ValueError):self.r.health(value)
    def test_managed_only_first_seed_preserves_custom_metadata_grants_and_exact_file_bytes(self):
        value=self.config();self.seed_fresh(value);ctx=self.r.context(value);directory=ctx.workspace/'GlobalConfiguration/.dbeaver';permissions=directory/'data-sources-permissions.json'
        permissions.chmod(0o600);permissions.write_text(json.dumps({'custom':['custom-user']}));custom=directory/'data-sources.json';self.r.create(custom,{'connections':{'custom':{'application':'owned'}}},uid=8978);custom_before=custom.read_bytes()
        document={'folders':{},'connections':{'managed':{'configuration':{'auth-properties':{'userPassword':'synthetic-password'}}}}};self.r.create(ctx.managed,document,mode=0o400);raw=ctx.managed.read_bytes()
        value.update(managed_connections={'managed':{'owner':{'source':'synthetic-owned'}}},managed_sha256=hashlib.sha256(raw).hexdigest(),cloudbeaver_image='dbeaver/cloudbeaver@sha256:'+'b'*64)
        with patch.object(self.r,'docker',return_value=''):
            self.assertEqual(self.r.managed(value),{'managed_connections':'verified','private_native_file':True})
        target=directory/'data-sources-homelab-administrators.json';self.assertEqual(target.read_bytes(),raw);self.assertEqual(custom.read_bytes(),custom_before);self.assertEqual(json.loads(permissions.read_text()),{'custom':['custom-user'],'managed':['user']})
        before={str(path.relative_to(self.root)):hashlib.sha256(path.read_bytes()).hexdigest()for path in self.root.rglob('*')if path.is_file()}
        with patch.object(self.r,'docker',side_effect=AssertionError('No writer on repeat')):self.r.managed(value,seed=False)
        after={str(path.relative_to(self.root)):hashlib.sha256(path.read_bytes()).hexdigest()for path in self.root.rglob('*')if path.is_file()};self.assertEqual(before,after)
    def test_fresh_managed_collision_or_hold_never_overwrites(self):
        value=self.config();self.seed_fresh(value);ctx=self.r.context(value);directory=ctx.workspace/'GlobalConfiguration/.dbeaver';permissions=directory/'data-sources-permissions.json'
        document={'folders':{},'connections':{'managed':{}}};self.r.create(ctx.managed,document,mode=0o400);raw=ctx.managed.read_bytes();value.update(managed_connections={'managed':{'owner':{}}},managed_sha256=hashlib.sha256(raw).hexdigest())
        self.r.create(ctx.custody/'MANAGED-CONNECTIONS-HOLD.json',{'retained':'hold'});before=permissions.read_bytes()
        with patch.object(self.r,'docker',side_effect=AssertionError('No writer under hold')),self.assertRaises(ValueError):self.r.managed(value)
        self.assertEqual(permissions.read_bytes(),before)
        (ctx.custody/'MANAGED-CONNECTIONS-HOLD.json').unlink()
        permissions.chmod(0o600);permissions.write_text(json.dumps({'managed':['foreign-user']}));before=permissions.read_bytes()
        with patch.object(self.r,'docker',side_effect=AssertionError('No writer under collision')),self.assertRaises(ValueError):self.r.managed(value)
        self.assertEqual(permissions.read_bytes(),before)
    def test_fixed_custody_and_shared_workspace_leaves_are_not_renamed(self):
        import ast
        source=ast.parse((D/'cloudbeaver-runtime.py').read_text())
        constants={node.value for node in ast.walk(source)if isinstance(node,ast.Constant)and isinstance(node.value,str)}
        self.assertTrue({'MANAGED-CONNECTIONS-HOLD.json','workspace.json','managed-connections.json','pgadmin-retirement.json','data-sources-homelab-administrators.json','data-sources-permissions.json','permissions.homelab-managed.pending'}<=constants)
    def test_retained_root_and_fresh_child_preserve_each_others_direct_leaves(self):
        retained=self.legacy();self.r.workspace(self.owner,retained);receipt=self.r.CUSTODY/'workspace.json';original=receipt.read_bytes()
        fresh=self.config();self.r.workspace(self.owner,fresh);child=Path(fresh['custody_directory'])/'workspace.json';child_original=child.read_bytes()
        self.r.workspace(self.owner,retained);self.assertEqual(receipt.read_bytes(),original);self.assertEqual(child.read_bytes(),child_original)

if __name__=='__main__':unittest.main()
