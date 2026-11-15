"""Owned all-guest read scope: exact conversion, custody, no credential changes."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import bootstrap_cd as cd
import provider_access as discovery
from test_provider_access import ProviderAPI, SECRET
from test_bootstrap_cd import config


def legacy_fixture(api, root, nas, base):
    """Synthetic original owner plus six historical finite extensions."""
    old = copy.deepcopy(base)
    old['service_discovery'] = {'vmid':12012,'address':'198.19.125.43','guests':[12002,12011,12012]}
    first = discovery.owner(old)
    token_id, token, role = discovery.identity(old)
    api.roles = [{'roleid':role,'privs':'Sys.Audit,VM.Audit','special':0}]
    api.tokens = [{'tokenid':token_id,'privsep':1,'expire':0,'comment':discovery.allowance(old)['comment']}]
    api.rules.insert(0, discovery.allowance(old))
    for folder in (root/'service-discovery',nas/'service-discovery'):
        folder.mkdir(mode=0o700)
        discovery.save_new(folder/'owner.json',first)
        discovery.save_new(folder/'token.json',{'schema':discovery.SCHEMA,'identity':token,'token':token+'='+SECRET})
        discovery.save_new(folder/'READY.json',{'schema':discovery.SCHEMA,'status':'ready'})
        (folder/'scope-extensions').mkdir(mode=0o700)
    previous=first
    for index,vmid in enumerate(range(12013,12019),1):
        following=copy.deepcopy(previous);following['configuration']['guests'].append(vmid)
        receipt={'schema':discovery.EXTENSION_SCHEMA,'previous_owner_sha256':discovery.owner_sha256(previous),'owner':following}
        for folder in (root/'service-discovery',nas/'service-discovery'):
            discovery.save_new(folder/'scope-extensions'/f'{index:04}.json',receipt)
        previous=following
    old['service_discovery']=previous['configuration']
    api.acls=[{'path':path,'roleid':role,'propagate':propagate,'ugid':token,'type':'token'}
              for path,role,propagate in discovery.acl_rows(old)]
    return previous


class OwnedScopeTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root,self.nas=Path(tmp.name)/'state',Path(tmp.name)/'nas'
        self.root.mkdir(mode=0o700);self.nas.mkdir(mode=0o700)
        self.api=ProviderAPI();base=config();base['endpoint']='https://198.19.125.11:8006/'
        base['service_discovery']={'vmid':12012,'address':'198.19.125.43','scope':'all-guests'}
        self.previous=legacy_fixture(self.api,self.root,self.nas,base)
        self.value={'schema':'homelab-owned-discovery-v1',**{key:copy.deepcopy(base[key])
            for key in ('endpoint','node','backup_source','service_discovery')}}
        self.api.writes.clear()

    def run_scope(self):
        mount={'filesystems':[{'target':str(self.nas),'source':self.value['backup_source'],'fstype':'nfs4'}]}
        with patch.object(cd.subprocess,'check_output',return_value=json.dumps(mount).encode()), \
                patch.object(cd,'run',side_effect=AssertionError('Full host CD unreachable')):
            return cd.run_owned_discovery(self.value,self.api,self.root,self.nas)

    def originals(self):
        return {str(p.relative_to(self.root)):p.read_bytes() for p in (self.root/'service-discovery').rglob('*') if p.is_file()}

    def assert_originals(self,original):
        for name,raw in original.items():
            self.assertEqual((self.root/name).read_bytes(),raw)
            self.assertEqual((self.nas/name).read_bytes(),raw)

    def manual_conversion(self):
        cfg=cd.owned_scope_configuration(self.value)
        self.api.acls=[{'path':path,'roleid':role,'propagate':propagate,
            'ugid':discovery.identity(cfg)[1],'type':'token'} for path,role,propagate in discovery.acl_rows(cfg)]

    def test_exact_conversion_preserves_six_extension_chain_and_repeat_has_no_writes(self):
        originals=self.originals();roles,tokens,rules=copy.deepcopy((self.api.roles,self.api.tokens,self.api.rules))
        result=self.run_scope()
        self.assertEqual((result['new_acl_rows'],result['removed_acl_rows']),(1,9))
        self.assertFalse(result['created']);self.assertFalse(result['firewall_rule_created'])
        self.assertEqual(len(self.api.writes),10)
        self.assertEqual(self.api.writes[0],('/access/acl','PUT',{'path':'/vms','roles':'HomelabTraefikRead12012',
            'tokens':'root@pam!homelab-traefik-12012','propagate':1}))
        self.assertTrue(all(v['delete']==1 and v['path'].startswith('/vms/') for _,_,v in self.api.writes[1:]))
        self.assertEqual((self.api.roles,self.api.tokens,self.api.rules),(roles,tokens,rules))
        self.assert_originals(originals)
        policy=json.loads(discovery.read_private(self.root/'service-discovery/read-scope.json'))
        self.assertEqual(policy['previous_owner_sha256'],discovery.owner_sha256(self.previous))
        self.assertEqual(policy['owner']['schema'],discovery.OWNER_SCHEMA)
        attempt,=self.root.glob('discovery-cd-*')
        for name in ('plan.json','result.json'):
            self.assertEqual(discovery.read_private(attempt/name),discovery.read_private(self.nas/attempt.name/name))
        writes=copy.deepcopy(self.api.writes)
        self.assertTrue(self.run_scope()['already_owned']);self.assertEqual(self.api.writes,writes)
        self.assertFalse((self.root/'CONFIGURING').exists());self.assertFalse((self.root/'BOOTSTRAP-CD-HOLD.json').exists())
        self.assertNotIn(SECRET,json.dumps(result))

    def test_completed_manual_conversion_adopts_only_verified_read_scope_without_api_writes(self):
        originals=self.originals();self.manual_conversion()
        result=self.run_scope()
        self.assertEqual((result['new_acl_rows'],result['removed_acl_rows']),(0,0))
        self.assertEqual(self.api.writes,[]);self.assert_originals(originals)
        self.assertTrue(self.run_scope()['already_owned']);self.assertEqual(self.api.writes,[])

    def test_actual_json_writer_preserves_failure_hold_and_never_replays(self):
        self.api.fail_provider_acl=True
        with self.assertRaisesRegex(ValueError,'ACL failure'):self.run_scope()
        attempt,=self.root.glob('discovery-cd-*')
        failure=json.loads(discovery.read_private(attempt/'failure.json'))
        self.assertEqual(failure,{'status':'held','error_type':'ProviderAccessError','automatic_retry':False})
        self.assertEqual(discovery.read_private(attempt/'failure.json'),discovery.read_private(self.nas/attempt.name/'failure.json'))
        self.assertEqual(discovery.read_private(self.root/'CONFIGURING'),discovery.read_private(self.root/'BOOTSTRAP-CD-HOLD.json'))
        writes=copy.deepcopy(self.api.writes)
        with self.assertRaisesRegex(ValueError,'hold'):self.run_scope()
        self.assertEqual(self.api.writes,writes)

    def test_partial_or_foreign_native_scope_is_never_adopted(self):
        for path,priv in (('/vms/12019','HomelabTraefikRead12012'),('/','HomelabTraefikRead12012'),('/vms','Administrator')):
            row={'path':path,'roleid':priv,'propagate':0,'ugid':'root@pam!homelab-traefik-12012','type':'token'}
            self.api.acls.append(row)
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'scope differs'):self.run_scope()
            self.api.acls.remove(row);self.assertEqual(self.api.writes,[])
        self.manual_conversion();self.api.extra_permission=True
        with self.assertRaisesRegex(ValueError,'effective permissions'):self.run_scope()
        self.assertEqual(self.api.writes,[])

    def test_receipt_write_failure_preserves_actual_conversion_and_hold(self):
        save=discovery.save_new
        def fail(path,value):
            if path==self.nas/'service-discovery/read-scope.json':raise OSError('Synthetic NAS receipt failure')
            return save(path,value)
        with patch.object(discovery,'save_new',side_effect=fail),self.assertRaisesRegex(OSError,'NAS receipt'):self.run_scope()
        self.assertTrue((self.root/'BOOTSTRAP-CD-HOLD.json').exists())
        writes=copy.deepcopy(self.api.writes)
        with self.assertRaisesRegex(ValueError,'hold'):self.run_scope()
        self.assertEqual(self.api.writes,writes)

    def test_missing_or_altered_historical_custody_is_not_fabricated(self):
        receipt=self.nas/'service-discovery/scope-extensions/0006.json';raw=receipt.read_bytes()
        receipt.write_text('{}')
        with self.assertRaises(ValueError):self.run_scope()
        receipt.write_bytes(raw)
        receipt.unlink()
        with self.assertRaises(ValueError):self.run_scope()
        self.assertEqual(self.api.writes,[])

    def test_read_scope_missing_or_different_mirror_refuses(self):
        self.run_scope();self.api.writes.clear()
        p=self.nas/'service-discovery/read-scope.json';raw=p.read_bytes();p.write_text('{}')
        with self.assertRaises(ValueError):self.run_scope()
        p.write_bytes(raw);p.unlink()
        with self.assertRaisesRegex(ValueError,'NAS custody'):self.run_scope()
        self.assertEqual(self.api.writes,[])

    def test_existing_disjoint_source_rule_keeps_position_and_bytes(self):
        self.api.rules.insert(0,{'type':'in','action':'ACCEPT','enable':1,'source':'198.19.126.0/24'})
        before=copy.deepcopy(self.api.rules);self.run_scope();self.assertEqual(self.api.rules,before)

    def test_earlier_overlapping_unknown_or_compound_rule_refuses_without_writes(self):
        for source in ('198.19.125.43','0.0.0.0/0','!198.19.126.0/24','198.19.126.0/24,198.19.127.0/24','+alias',None,'invalid','2001:db8::/32'):
            row={'type':'in','action':'ACCEPT','source':source,'enable':1};self.api.rules.insert(0,row)
            with self.subTest(source=source),self.assertRaises(ValueError):self.run_scope()
            self.assertEqual(self.api.writes,[]);self.api.rules.pop(0)
        for row in (None,{'type':'group','action':'ACCEPT','source':'198.19.126.0/24'},{'type':'in','action':[],'source':'198.19.126.0/24'}):
            self.assertFalse(discovery.preceding_rules_irrelevant([row],'198.19.125.43'))
        self.assertTrue(discovery.preceding_rules_irrelevant([{'type':'in','action':'DROP','source':'198.19.125.42/32'}],'198.19.125.43'))

    def test_never_mints_unowned_identity(self):
        import shutil
        for folder in (self.root/'service-discovery',self.nas/'service-discovery'):shutil.rmtree(folder)
        self.api.roles.clear();self.api.tokens.clear();self.api.acls.clear();self.api.rules=self.api.rules[1:]
        with self.assertRaisesRegex(ValueError,'existing owned'):self.run_scope()
        self.assertEqual(self.api.writes,[])

    def test_closed_input_retires_permission_inventory_and_pinned_owner(self):
        changes=[('',{}),('schema','foreign'),('endpoint','http://198.18.0.1:8006/'),('endpoint','https://198.18.0.1:bad/'),
            ('endpoint','https://198.18.0.1:8006/?'),('node',[]),('backup_source','bad\nsource'),
            ('application_vmids',[12012]),('added_guests',[]),('service_discovery_extension',{'owner_sha256':'0'*64,'guests':[12019]}),
            ('service_discovery',[]),('service_discovery',{'vmid':True,'address':'198.19.125.43','scope':'all-guests'})]
        for key,value in changes:
            data=copy.deepcopy(self.value)
            if key:data[key]=value
            else:data['unrelated_host_plan']=value
            with self.subTest(key=key),self.assertRaises(ValueError):cd.owned_scope_configuration(data)

    def test_cli_uses_only_owned_entrypoint(self):
        path=self.root/'input.json';path.write_text(json.dumps(self.value))
        with patch.object(sys,'argv',['bootstrap_cd','--config',str(path),'--owned-discovery']), \
             patch.dict(cd.os.environ,{'PROXMOX_BOOTSTRAP_TOKEN':'synthetic'}),patch.object(cd,'API') as api, \
             patch.object(cd,'run_owned_discovery',return_value={'status':'ready'}) as owned, \
             patch.object(cd,'run',side_effect=AssertionError('full host')),contextlib.redirect_stdout(io.StringIO()) as output:cd.main()
        owned.assert_called_once_with(self.value,api.return_value)
        self.assertEqual(json.loads(output.getvalue()),{'status':'ready'})


if __name__=='__main__':unittest.main()
