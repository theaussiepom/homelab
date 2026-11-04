"""Real Ansible include/variable scopes; native modules and targets never run."""
import base64
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from test_component_caller_paths import CallerCase
import component_ansible
from private_io import encoded, read_json, write_new

F=Path(__file__).resolve().parents[3]
ANSIBLE=F/'proxmox/applications/ansible'


def tasks(blocks):
    from ansible.playbook.block import Block
    for block in blocks:
        for task in block.block:
            if isinstance(task,Block):yield from tasks([task])
            else:yield task


class NativeAccountScopeTests(CallerCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        temporary=tempfile.TemporaryDirectory(prefix='native-account-scope-')
        cls.addClassCleanup(temporary.cleanup)
        boundary=patch.dict(os.environ,{'ANSIBLE_LOCAL_TEMP':str(Path(temporary.name).resolve()),
            'ANSIBLE_CONFIG':str(ANSIBLE/'ansible.cfg')})
        boundary.start();cls.addClassCleanup(boundary.stop)

    def setUp(self):
        super().setUp()
        for target in ('subprocess.Popen','socket.create_connection','socket.socket.connect',
                       'ansible.executor.task_executor.TaskExecutor.run'):
            boundary=patch(target,side_effect=AssertionError('No native/action/connection execution'))
            boundary.start();self.addCleanup(boundary.stop)

    def scopes(self,extra):
        # Match Ansible's own trusted playbook/include loading, without running
        # a task, strategy, native action plugin, inventory probe or connection.
        from ansible.plugins.loader import init_plugin_loader
        from ansible.parsing.dataloader import DataLoader
        from ansible.inventory.manager import InventoryManager
        from ansible.vars.manager import VariableManager
        from ansible.playbook import Playbook
        from ansible.utils.collection_loader import AnsibleCollectionConfig
        if AnsibleCollectionConfig.collection_finder is None:init_plugin_loader()
        loader=DataLoader();inventory=InventoryManager(loader=loader,sources=['fixture,'])
        inventory.add_group('application');inventory.add_host('fixture',group='application')
        manager=VariableManager(loader=loader,inventory=inventory);manager._extra_vars=copy.deepcopy(extra)
        play=Playbook.load(str(ANSIBLE/'component-preparation.yml'),variable_manager=manager,loader=loader).get_plays()[0]
        return loader,inventory,manager,play

    def included(self,scope,include,filename):
        from ansible.playbook.block import Block
        loader,inventory,manager,play=scope
        return Block.load(loader.load_from_file(str(ANSIBLE/'tasks'/filename),trusted_as_template=True),
            play=play,task_include=include,variable_manager=manager,loader=loader)

    def template(self,scope,task,*,native=None,facts=None,record=None,identity=None):
        from ansible.template import Templar
        loader,inventory,manager,play=scope
        values=manager.get_vars(play=play,host=inventory.get_host('fixture'),task=task)
        # The loop executor supplies this item after VariableManager.get_vars.
        if native is not None:values['component_native_app']=copy.deepcopy(native)
        values['ansible_facts']=copy.deepcopy(facts or {'getent_passwd':{},'getent_group':{}})
        values['database_package_account_file']={'stat':copy.deepcopy(record or {'exists':False})}
        if identity is not None:
            values['database_package_identity']=identity
            values['database_package_saved_identity']={'content':base64.b64encode(encoded(identity)).decode()}
        return Templar(loader=loader,variables=values)

    def evaluate(self,templar,expression):
        from ansible.template import trust_as_template
        return templar.evaluate_expression(trust_as_template(expression))

    def assertions(self,templar,task):
        return [self.evaluate(templar,expr)for expr in task.args['that']]

    def native_leaf(self,scope,*,after=False,mode='fixed'):
        all_tasks=list(tasks(scope[3].tasks))
        if after:
            include=next(t for t in all_tasks if t.name=='Check package-owned native identities')
            return self.included(scope,include,'database-package-account.yml')
        include=next(t for t in all_tasks if t.name=='Prepare declared native account identities')
        wrapper=self.included(scope,include,'component-native-account.yml')
        name='Prepare fixed native account identity'if mode=='fixed'else'Check package native account identity'
        include=next(t for t in tasks([wrapper])if t.name==name)
        return self.included(scope,include,'database-account.yml'if mode=='fixed'else'database-package-account.yml')

    def extra(self,adapter,identity):
        cfg,app=self.case(adapter)
        cfg['app'].update(packages=['synthetic-pinned-package=1'],required_paths=[{'path':'/srv/example','type':'directory'}])
        write_new(self.directory/'component-native.json',encoded({'selected':{'identity':identity,'services':[adapter]}}))
        return cfg,component_ansible.variables(cfg,'preparation')

    def test_fixed_postgresql_and_influx_scopes_retain_every_numeric_guard(self):
        for adapter,user in [('postgresql','postgres'),('influxdb','influxdb')]:
            with self.subTest(adapter=adapter):
                identity={'uid':1701,'gid':1702,'user':user,'group':user,'home':'/var/lib/'+user}
                cfg,extra=self.extra(adapter,identity)
                self.assertNotIn('app',extra)
                scope=self.scopes(extra);native=extra['component_native_applications'][0]
                leaf=self.native_leaf(scope);guard=next(t for t in tasks([leaf])if t.name=='Refuse numeric identity changes or collisions')
                templar=self.template(scope,guard,native=native)
                self.assertEqual(self.evaluate(templar,'app'),native)
                self.assertEqual(self.assertions(templar,guard),[True]*7)
                passwd=['x','1701','1702','','/var/lib/'+user,'/usr/sbin/nologin']
                group=['x','1702','']
                facts={'getent_passwd':{user:passwd},'getent_group':{user:group}}
                self.assertEqual(self.assertions(self.template(scope,guard,native=native,facts=facts),guard),[True]*7)
                for label,change in [
                    ('uid_nonpositive',lambda n,f:n['database'].update(uid=0)),
                    ('gid_nonpositive',lambda n,f:n['database'].update(gid=0)),
                    ('old_user_uid',lambda n,f:f['getent_passwd'][user].__setitem__(1,'1703')),
                    ('old_user_gid',lambda n,f:f['getent_passwd'][user].__setitem__(2,'1703')),
                    ('old_group_gid',lambda n,f:f['getent_group'][user].__setitem__(1,'1703')),
                    ('foreign_uid',lambda n,f:f['getent_passwd'].update(peer=['x','1701','1900','','/nonexistent','/usr/sbin/nologin'])),
                    ('foreign_gid',lambda n,f:f['getent_group'].update(peer=['x','1702','']))]:
                    with self.subTest(adapter=adapter,guard=label):
                        bad_native,bad_facts=copy.deepcopy(native),copy.deepcopy(facts);change(bad_native,bad_facts)
                        self.assertIn(False,self.assertions(self.template(scope,guard,native=bad_native,facts=bad_facts),guard))
                # Faithful old extra-vars shadow reproduces the defect despite
                # the exact same real nested include and fixed guard.
                old=copy.deepcopy(extra);old['app']=old.pop('component_preparation_app')
                old_scope=self.scopes(old);old_leaf=self.native_leaf(old_scope)
                old_guard=next(t for t in tasks([old_leaf])if t.name==guard.name)
                old_template=self.template(old_scope,old_guard,native=native)
                self.assertEqual(self.evaluate(old_template,'app')['kind'],'component')
                from ansible.errors import AnsibleUndefinedVariable
                with self.assertRaises(AnsibleUndefinedVariable):self.assertions(old_template,old_guard)

    def test_mariadb_package_pre_and_post_includes_keep_record_and_collision_guards(self):
        native_identity={'account_mode':'package','user':'mysql','group':'mysql','home':'/var/lib/mysql'}
        cfg,extra=self.extra('mariadb',native_identity);scope=self.scopes(extra)
        native=extra['component_native_applications'][0]
        facts={'getent_passwd':{'mysql':['x','1711','1712','','/var/lib/mysql','/usr/sbin/nologin']},
               'getent_group':{'mysql':['x','1712','']}}
        identity={'account_mode':'package','kind':'mariadb','user':'mysql','group':'mysql','uid':1711,'gid':1712}
        for after in (False,True):
            with self.subTest(after_packages=after):
                leaf=self.native_leaf(scope,after=after,mode='package');rows={t.name:t for t in tasks([leaf])}
                contract=rows['Require the current MariaDB package-account contract']
                templar=self.template(scope,contract,native=native,facts=facts,identity=identity)
                self.assertEqual(self.evaluate(templar,'app'),native)
                self.assertEqual(self.assertions(templar,contract),[True]*9)
                self.assertEqual(self.evaluate(templar,'database_account_after_packages'),after)
                unrecorded=rows['Refuse adopting an unrecorded existing account before package installation']
                self.assertEqual(self.assertions(self.template(scope,unrecorded,native=native),unrecorded),[True,True])
                self.assertEqual(self.assertions(templar,unrecorded),[False,False])
                self.assertEqual(all(self.evaluate(templar,expr)for expr in unrecorded.when),not after)
                guard=rows['Verify the actual package-created account without changing it']
                self.assertEqual(self.assertions(templar,guard),[True]*7)
                generated=templar.template(rows['Keep the actual package-selected numeric identity'].args['database_package_identity'])
                self.assertEqual(generated,identity)
                record_copy=rows['Record the new package-created identity once']
                self.assertIs(record_copy.args['force'],False)
                self.assertEqual(all(self.evaluate(templar,expr)for expr in record_copy.when),after)
                for missing in ('getent_passwd','getent_group'):
                    absent=copy.deepcopy(facts);absent[missing].pop('mysql')
                    with self.subTest(after_packages=after,missing=missing):
                        missing_scope=self.template(scope,guard,native=native,facts=absent)
                        self.assertFalse(all(self.evaluate(missing_scope,expr)for expr in guard.args['that']))
                for label,change in [('uid',lambda f:f['getent_passwd']['mysql'].__setitem__(1,'0')),
                    ('gid',lambda f:f['getent_group']['mysql'].__setitem__(1,'0')),
                    ('primary_gid',lambda f:f['getent_passwd']['mysql'].__setitem__(2,'1999')),
                    ('foreign_uid',lambda f:f['getent_passwd'].update(peer=['x','1711','1800','','/nonexistent','/usr/sbin/nologin'])),
                    ('foreign_gid',lambda f:f['getent_group'].update(peer=['x','1712','']))]:
                    with self.subTest(after_packages=after,guard=label):
                        bad=copy.deepcopy(facts);change(bad)
                        self.assertIn(False,self.assertions(self.template(scope,guard,native=native,facts=bad),guard))
                record_guard=rows['Require a regular root-only identity record']
                record={'exists':True,'isreg':True,'islnk':False,'uid':0,'mode':'0600'}
                self.assertEqual(self.assertions(self.template(scope,record_guard,native=native,record=record),record_guard),[True]*4)
                for field,value in [('isreg',False),('islnk',True),('uid',999),('mode','0644')]:
                    bad=dict(record,**{field:value})
                    with self.subTest(after_packages=after,record=field):
                        self.assertIn(False,self.assertions(self.template(scope,record_guard,native=native,record=bad),record_guard))
                drift=rows['Refuse package-account drift rather than repairing it']
                self.assertEqual(self.assertions(templar,drift),[True])
                retained=self.template(scope,drift,native=native,facts=facts,record=record,identity=identity)
                self.assertTrue(all(self.evaluate(retained,expr)for expr in drift.when))
                self.assertFalse(all(self.evaluate(retained,expr)for expr in unrecorded.when))
                self.assertFalse(all(self.evaluate(retained,expr)for expr in record_copy.when))
                wrong=self.template(scope,drift,native=native,facts=facts,identity=identity)
                wrong.available_variables['database_package_saved_identity']={'content':base64.b64encode(encoded(dict(identity,uid=1777))).decode()}
                self.assertEqual(self.assertions(wrong,drift),[False])
                for field,value in [('kind','postgresql'),('new_target',True),('capture',True)]:
                    bad=copy.deepcopy(native);bad[field]=value
                    with self.subTest(after_packages=after,contract=field):
                        self.assertIn(False,self.assertions(self.template(scope,contract,native=bad),contract))
                for field,value in [('account_mode','fixed'),('user','other'),('group','other'),('uid',1711),('gid',1712),('capture',True)]:
                    bad=copy.deepcopy(native);bad['database'][field]=value
                    with self.subTest(after_packages=after,database=field):
                        self.assertIn(False,self.assertions(self.template(scope,contract,native=bad),contract))

    def test_common_package_and_docker_scope_preserves_guest_prep_without_native_leak(self):
        cfg,extra=self.extra('postgresql',{'uid':1701,'gid':1702,'user':'postgres','group':'postgres','home':'/var/lib/postgresql'})
        extra['preparation_capabilities']=['linux','docker'];scope=self.scopes(extra)
        rows={t.name:t for t in tasks(scope[3].tasks)}
        for name in ('Reconcile the approved exact packages','Enable Docker'):
            with self.subTest(task=name):
                templar=self.template(scope,rows[name],native=extra['component_native_applications'][0])
                self.assertEqual(self.evaluate(templar,'app'),extra['component_preparation_app'])
                self.assertEqual(self.evaluate(templar,'app.packages'),['synthetic-pinned-package=1'])
                self.assertFalse(self.evaluate(templar,'app.database is defined'))
        cfg,app=self.case('unbound');cfg['app']['packages']=['synthetic-docker-package=1']
        empty=component_ansible.variables(cfg,'preparation');self.assertNotIn('app',empty)
        self.assertEqual(empty['component_native_applications'],[])
        scope=self.scopes(empty);task=next(t for t in tasks(scope[3].tasks)if t.name=='Reconcile the approved exact packages')
        self.assertEqual(self.evaluate(self.template(scope,task),'app.packages'),['synthetic-docker-package=1'])

    def test_run_phase_writes_real_explicit_prep_extra_vars_and_keeps_app_phase_transport(self):
        cfg,app=self.case('unbound');payload=self.selected_payload()
        operation=self.root/'operation';operation.mkdir(mode=0o700);work=self.root/'work';work.mkdir(mode=0o700)
        seen=[]
        def command(argv,environment,log):
            value=read_json(Path(argv[argv.index('--extra-vars')+1][1:]),private=True)
            phase=log.parent.name;seen.append(phase)
            if phase=='preparation':
                self.assertNotIn('app',value);self.assertEqual(value['component_preparation_app']['kind'],'component')
                self.assertEqual(value['component_preparation_app']['render_dir'],str(log.parent/'rendered'))
            else:
                self.assertIn('app',value);self.assertNotIn('component_preparation_app',value)
                self.assertEqual(value['app']['kind'],'unbound')
                self.assertEqual(value['app']['render_dir'],str(log.parent/'rendered'))
            self.assertFalse(any(key.startswith('HOMELAB_APP_SECRET_')for key in environment))
            write_new(log,b'fixture : ok=1 changed=0 failed=0\n')
        with patch.dict(os.environ,{'HOMELAB_APP_SECRET_SYNTHETIC':'not-forwarded'},clear=True), \
             patch.object(component_ansible.component_inputs,'binding',return_value={'static':'same'}), \
             patch.object(component_ansible.proxmox_guest,'dhcp_admission'), \
             patch.object(component_ansible.proxmox_guest,'guest_trust'), \
             patch.object(component_ansible,'quiet',side_effect=command):
            for phase,selected in [('preparation',None),('selected',payload)]:
                self.assertEqual(component_ansible.run_phase(cfg,self.root/'site',work,operation,{'static':'same'},phase,payload=selected),{'status':'passed','changed':False})
        self.assertEqual(seen,['preparation','selected'])


if __name__=='__main__':unittest.main()
