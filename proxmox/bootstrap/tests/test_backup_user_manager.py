"""Root bootstrap installs inherited restrictions before a standard persistent manager starts."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import yaml
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]


class ManagerBootstrapTests(unittest.TestCase):
    """Evaluate actual task conditions and ordering with the pinned Ansible templater."""
    @classmethod
    def setUpClass(cls):
        """Keep Ansible controller temporary files inside an owned fixture."""
        temporary=tempfile.TemporaryDirectory(prefix='backup-manager-contract-')
        cls.addClassCleanup(temporary.cleanup)
        boundary=patch.dict(os.environ,{'ANSIBLE_LOCAL_TEMP':str(Path(temporary.name).resolve())})
        boundary.start();cls.addClassCleanup(boundary.stop)

    def setUp(self):
        self.rows=yaml.safe_load((ROOT/'ansible/user-manager.yml').read_text())
        self.tasks={row['name']:row for row in self.rows}
        self.safe={'active':True,'policy_present':True,'policy_matches':True,'kernel_hardened':True,
                   'configured_hardened':True,'reload_needed':False}

    def assertions(self,name,values):
        from ansible.template import Templar,trust_as_template
        expressions=self.tasks[name]['ansible.builtin.assert']['that']
        return all(Templar(variables=values).evaluate_expression(trust_as_template(expr)) for expr in expressions)

    def test_active_unhardened_foreign_or_changed_manager_refuses_before_mutation(self):
        name='Preserve an existing unsafe or foreign manager without restarting it'
        def accepts(value):return self.assertions(name,{'backup_manager_before':{'stdout':json.dumps(value)}})
        self.assertTrue(accepts(self.safe))
        self.assertTrue(accepts({**self.safe,'active':False,'policy_present':False,'policy_matches':False,
                                 'kernel_hardened':False,'configured_hardened':False}))
        for key in ('policy_matches','kernel_hardened','configured_hardened','reload_needed'):
            self.assertFalse(accepts({**self.safe,key:not self.safe[key]}),key)
        self.assertFalse(accepts({**self.safe,'active':False,'policy_matches':False}))
        names=[row['name'] for row in self.rows]
        assertion=names.index(name)
        policy=names.index('Install inherited privilege restrictions before starting the manager')
        reload=names.index('Load the root-owned policy before enabling persistence')
        linger=names.index('Keep the manager available without an interactive login')
        start=names.index('Start the qualified manager without restarting existing services')
        self.assertLess(assertion,policy);self.assertLess(policy,reload);self.assertLess(reload,linger);self.assertLess(linger,start)
        self.assertLess(reload,names.index('Install the standard user-session bus package'))
        self.assertEqual(self.tasks[names[start]]['ansible.builtin.systemd_service']['state'],'started')
        self.assertNotIn('restarted',repr(self.rows))

    def test_policy_and_existing_persistence_owner_are_exact(self):
        policy=self.tasks['Install inherited privilege restrictions before starting the manager']['ansible.builtin.copy']
        sys.path.insert(0,str(ROOT.parent/'applications'))
        import backup_user
        self.assertEqual(policy['content'].encode(),backup_user.POLICY)
        self.assertEqual((policy['owner'],policy['group'],policy['mode'],policy['force'],policy['follow']),('root','root','0644',False,False))
        good={'exists':True,'isreg':True,'islnk':False,'uid':0,'nlink':1,'mode':'0644','size':0}
        name='Refuse foreign account persistence metadata'
        self.assertTrue(self.assertions(name,{'backup_linger':{'stat':good}}))
        self.assertTrue(self.assertions(name,{'backup_linger':{'stat':{'exists':False}}}))
        for key,value in [('isreg',False),('islnk',True),('uid',1000),('nlink',2),('mode','0666'),('size',1)]:
            self.assertFalse(self.assertions(name,{'backup_linger':{'stat':{**good,key:value}}}),key)
        for uid,owner in [(0,'homelab-runner'),(1000,'root')]:
            self.assertFalse(self.assertions('Refuse a privileged or mismatched deployment account',
                {'backup_manager_uid':uid,'runner_owner':owner}))

    def test_fresh_and_existing_bootstrap_share_only_manager_prerequisites(self):
        fresh=yaml.safe_load((ROOT/'ansible/install-runner.yml').read_text())[0]['tasks']
        existing=yaml.safe_load((ROOT/'ansible/backup-user-manager.yml').read_text())[0]
        self.assertEqual(existing['tasks'],[{'name':'Prepare only the persistent account manager','ansible.builtin.import_tasks':'user-manager.yml'}])
        imports=[r for r in fresh if r.get('ansible.builtin.import_tasks')=='user-manager.yml']
        self.assertEqual(len(imports),1)
        registration=next(i for i,row in enumerate(fresh) if row.get('ansible.builtin.import_tasks')=='runner-common.yml')
        self.assertLess(fresh.index(imports[0]),registration)
        runner=(ROOT/'ansible/runner.service.j2').read_text()
        self.assertIn('NoNewPrivileges=true\nPrivateTmp=true\n',runner)
        self.assertNotIn('sudo',repr(self.rows))
        self.assertNotIn('backup-activation',repr(self.rows))
