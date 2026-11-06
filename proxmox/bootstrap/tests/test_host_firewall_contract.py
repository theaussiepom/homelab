"""Closed host policy, native preservation and saved-plan refusal controls."""
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_firewall as h


def config():
    return {'schema':'homelab-host-firewall-v1','endpoint':'https://pve.example.invalid:8006/',
            'node':'pve','host_address':'198.18.25.10','allowances':[
                {'source':'198.18.25.11/32','port':8006,'comment':'Existing API'},
                {'source':'192.0.2.0/24','port':22,'comment':'Management SSH'}],
            'cluster':dict(deepcopy(h.DEFAULTS),enabled=True)}


def before(c=None):
    c = config() if c is None else c
    return {'rules':h.rules(c)[:-1], 'cluster':deepcopy(h.DEFAULTS)}


def plan(c=None, b=None):
    c=config() if c is None else c
    b=before(c) if b is None else b
    attrs={'id':'rule-1','node_name':c['node'],'vm_id':None,'container_id':None,'rule':b['rules']}
    oldcluster=dict(b['cluster'],id='cluster-firewall')
    oldcluster['log_ratelimit']=[oldcluster['log_ratelimit']]
    newcluster=dict(deepcopy(c['cluster']),id='cluster-firewall')
    newcluster['log_ratelimit']=[newcluster['log_ratelimit']]
    return {'resource_changes':[
        {'address':h.HOST,'mode':'managed','provider_name':'registry.opentofu.org/bpg/proxmox',
         'change':{'actions':['update'],'before':deepcopy(attrs),'after':dict(attrs,rule=h.rules(c)),
                   'after_unknown':{},'after_sensitive':{'rule':[{},{}]}}},
        {'address':h.CLUSTER,'mode':'managed','provider_name':'registry.opentofu.org/bpg/proxmox',
         'change':{'actions':['update'],'before':oldcluster,'after':newcluster,
                   'after_unknown':{},'after_sensitive':{'log_ratelimit':[{}]}}}],
        'configuration':{'root_module':{'resources':[{'address':h.HOST},{'address':h.CLUSTER}]}}}


def native(rows):
    result=[]
    for row in rows:
        v={k:v for k,v in row.items() if k not in ('enabled','security_group') and v!=''}
        v.update(enable=int(row['enabled']),ipversion=4,digest='synthetic')
        result.append(v)
    return result


class SourceControls(unittest.TestCase):
    def refused(self,c):
        with self.assertRaisesRegex(ValueError,h.ERROR):h.validate(c)

    def test_closed_success_preserves_lowered_fields_order_and_inputs(self):
        c=config();old=deepcopy(c)
        self.assertIs(h.validate(c),c)
        rows=h.rules(c)
        self.assertEqual(c,old)
        self.assertEqual([r['dport'] for r in rows],['8006','22'])
        self.assertEqual([r['source'] for r in rows],['198.18.25.11/32','192.0.2.0/24'])
        self.assertTrue(all(set(r)==h.RULE_FIELDS and r['dest']=='198.18.25.10/32' for r in rows))
        self.assertEqual(h.native_rules(native(rows)),rows)

    def test_root_and_row_and_cluster_closed_shapes(self):
        for key in config():
            c=config();del c[key]
            with self.subTest(missing=key):self.refused(c)
        for path in [(),('allowances',0),('cluster',),('cluster','log_ratelimit')]:
            for kind in ['unknown','missing']:
                c=config();node=c
                for key in path:node=node[key]
                if kind=='unknown':node['unknown']='private-sentinel'
                else:del node[next(iter(node))]
                with self.subTest(path=path,kind=kind):self.refused(c)
        for value in (None,[],True,'x'):
            with self.subTest(root=type(value).__name__):self.refused(value)

    def test_endpoint_node_host_and_source_refusals(self):
        mutations={'schema':['other',None], 'endpoint':[None,'http://pve.invalid:8006/','https://pve.invalid/',
            'https://user:password@pve.invalid:8006/','https://pve.invalid:8006/path',
            'https://pve.invalid:8006/?x=1','https://pve.invalid:8006/#x','https://pve.invalid:bad/','https://@pve.invalid:8006/','https://:@pve.invalid:8006/',
            'https://pve.invalid:8006/?','https://pve.invalid:8006/#',
            'https://pve.invalid :8006/'], 'node':[None,'','pve/name','a'*64],
            'host_address':[None,'::1','0.0.0.0','127.0.0.1','169.254.1.1','224.0.0.1','240.0.0.1','198.18.25.10/32']}
        for key,values in mutations.items():
            for value in values:
                c=config();c[key]=value
                with self.subTest(field=key,value_type=type(value).__name__):self.refused(c)
        for value in [None,'::/64','0.0.0.0/0','192.0.2.1/24','192.0.2.0/024','127.0.0.1/32','224.0.0.0/24','host.invalid']:
            c=config();c['allowances'][1]['source']=value
            with self.subTest(source_type=type(value).__name__):self.refused(c)

    def test_allowance_type_size_duplicates_and_controls(self):
        for value in (None,{},[],[config()['allowances'][0]]*33):
            c=config();c['allowances']=value
            with self.subTest(rows_type=type(value).__name__):self.refused(c)
        for key,values in [('port',[False,None,0,-1,65536,22.5,'22']),
                           ('comment',[None,'',' leading','line\nchange','x'*201,'\x7f','é'])]:
            for value in values:
                c=config();c['allowances'][1][key]=value
                with self.subTest(field=key,value_type=type(value).__name__):self.refused(c)
        for row in [deepcopy(config()['allowances'][0]),dict(config()['allowances'][1],comment='Existing API')]:
            c=config();c['allowances'].append(row);self.refused(c)

    def test_cluster_values_require_explicit_correct_types_and_bounds(self):
        for key in ('enabled','ebtables'):
            for value in (None,1,'false'):
                c=config();c['cluster'][key]=value
                with self.subTest(key=key,value=value):self.refused(c)
        for key in ('input_policy','output_policy','forward_policy'):
            c=config();c['cluster'][key]='unknown';self.refused(c)
        for key,values in [('enabled',[None,0]),('rate',[None,'0/second','1/sec','1/second,burst=3']),
                           ('burst',[False,0,2147483648,'5'])]:
            for value in values:
                c=config();c['cluster']['log_ratelimit'][key]=value
                with self.subTest(log=key,value=value):self.refused(c)

    def test_existing_reader_yaml_tags_duplicates_and_source_ambiguity(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'firewall.yaml'
            for text in ['schema: a\nschema: b\n','schema: &x a\ncopy: *x\n','value: !!str 3\n']:
                p.write_text(text)
                with self.assertRaises(ValueError):h.authored_config.read(p)
            p.write_text('schema: x\n');p.with_suffix('.json').write_text('{}')
            with self.assertRaises(ValueError):h.authored_config.read(p)

    def test_omitted_defaults_and_explicit_false_remain_distinct(self):
        omitted=h.native_cluster({'enable':0})
        explicit=h.native_cluster({'enable':0,'ebtables':0})
        self.assertEqual(omitted,h.DEFAULTS)
        self.assertIs(explicit['ebtables'],False)
        self.assertNotEqual(explicit, omitted)
        for raw in ['burst=5,enable=1,rate=1/second','enable=1,rate=1/second,burst=5']:
            self.assertEqual(h.native_cluster({'log_ratelimit':raw})['log_ratelimit'],h.DEFAULTS['log_ratelimit'])
        self.assertEqual(h.cluster_values({'ebtables':None,'log_ratelimit':[]}),h.DEFAULTS)
        self.assertFalse(h.cluster_values({'ebtables':False})['ebtables'])
        self.assertEqual(h.cluster_values({'log_ratelimit':[h.DEFAULTS['log_ratelimit']]}),h.DEFAULTS)

    def test_native_shapes_unknown_options_fields_and_wrong_types_refuse(self):
        for obj in [None,{'unknown':1},{'ebtables':2},{'enable':'0'},
                    {'log_ratelimit':[]},{'log_ratelimit':'enable=1,rate=1/second'},
                    {'log_ratelimit':'enable=1,rate=1/second,enable=0'},
                    {'log_ratelimit':'enable=2,rate=1/second,burst=5'},
                    {'log_ratelimit':'enable=1,rate=bad,burst=5'}]:
            with self.subTest(kind=type(obj).__name__):
                with self.assertRaises(ValueError):h.native_cluster(obj)
        for obj in [None,{'unknown':1},{'log_ratelimit':[{},{}]}]:
            with self.assertRaises(ValueError):h.cluster_values(obj)
        rows=native(h.rules(config()))
        for field,value in [('pos',1),('enable',2),('enable','1'),('ipversion',6),('unknown','x'),('comment',None)]:
            bad=deepcopy(rows);bad[0][field]=value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):h.native_rules(bad)
        with self.assertRaises(ValueError):h.native_rules(None)


class PlanControls(unittest.TestCase):
    def test_one_ssh_append_repeat_and_explicit_disable_keep_other_behavior(self):
        c=config();b=before()
        self.assertTrue(h.check_plan(plan(c,b),c,b))
        for enabled in (True,False):
            c=config();c['cluster']['enabled']=enabled
            b={'rules':h.rules(c),'cluster':dict(deepcopy(h.DEFAULTS),enabled=True)}
            p=plan(c,b)
            p['resource_changes'][0]['change']['actions']=['no-op']
            self.assertTrue(h.check_plan(p,c,b))
        p=plan();p['resource_changes'][1]['change']['before']={'id':'cluster-firewall','enabled':False,
            'ebtables':None,'input_policy':None,'output_policy':None,'forward_policy':None,'log_ratelimit':[]}
        self.assertTrue(h.check_plan(p,config(),before()))
        for field in ('iface','log','macro','sport','security_group','pos'):
            p=plan();p['resource_changes'][0]['change']['after']['rule'][-1][field]=None
            self.assertTrue(h.check_plan(p,config(),before()))

    def test_later_declared_changes_use_same_normal_capability(self):
        for mode in ('port', 'another', 'replace', 'ebtables', 'remove'):
            c=config();b=before()
            if mode=='port':c['allowances'][-1]['port']=443
            elif mode=='another':c['allowances'].append({'source':'203.0.113.0/24','port':22,'comment':'Another'})
            elif mode=='replace':c['allowances'][0]['comment']='Reviewed new purpose'
            elif mode=='ebtables':c['cluster']['ebtables']=False
            else:c['allowances']=c['allowances'][:1]
            with self.subTest(mode=mode):self.assertTrue(h.check_plan(plan(c,b),c,b))

    def test_missing_resources_configuration_and_actions_are_not_destroy_waivers(self):
        for path in ('resource_changes','configuration'):
            p=plan();del p[path]
            with self.assertRaises(ValueError):h.check_plan(p,config(),before())
        for action in (['create'],['delete'],['delete','create'],['read']):
            p=plan();p['resource_changes'][0]['change']['actions']=action
            with self.subTest(action=action):
                with self.assertRaises(ValueError):h.check_plan(p,config(),before())
        for mode in ('extra','drift','unknown','sensitive','import','mode','provider','errored'):
            p=plan()
            if mode=='extra':p['resource_changes'].append(deepcopy(p['resource_changes'][0]))
            elif mode=='drift':p['resource_drift']=[{'address':h.HOST}]
            elif mode in ('unknown','sensitive'):p['resource_changes'][0]['change']['after_'+mode]={'rule':[{'source':True}]}
            elif mode=='import':p['resource_changes'][0]['change']['importing']={'id':'node/pve'}
            elif mode=='errored':p['errored']=True
            else:p['resource_changes'][0]['provider_name' if mode=='provider' else mode]='wrong'
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):h.check_plan(p,config(),before())

    def test_host_target_rule_and_cluster_tampering_refuses(self):
        for field,value in [('node_name','other'),('vm_id',200),('container_id',200),('id','other')]:
            p=plan();p['resource_changes'][0]['change']['after'][field]=value
            with self.subTest(target=field):
                with self.assertRaises(ValueError):h.check_plan(p,config(),before())
        for field,value in [('source','0.0.0.0/0'),('dport','8006'),('enabled',False),('pos',5),('iface','net0')]:
            p=plan();p['resource_changes'][0]['change']['after']['rule'][-1][field]=value
            with self.subTest(rule=field):
                with self.assertRaises(ValueError):h.check_plan(p,config(),before())
        p=plan();p['resource_changes'][1]['change']['after']['ebtables']=False
        with self.assertRaises(ValueError):h.check_plan(p,config(),before())
        with self.assertRaises(ValueError):h.plan_rules(None)
        with self.assertRaises(ValueError):h.plan_rules([{}])
        self.assertFalse(h.no_true(None));self.assertTrue(h.no_true(False))


class CLIControls(unittest.TestCase):
    def test_source_check_and_runtime_dispatch_are_closed_and_sanitized(self):
        for args in [['--check'],['--work','/some/work'],[],['--check','--work','/some/work']]:
            with self.subTest(args=args), patch.object(h.sys,'argv',['host_firewall','--config','firewall.yaml',*args]), \
                 patch.object(h.authored_config,'read',return_value=config()), \
                 patch('host_firewall_run.run',return_value={'status':'passed'}) as run, \
                 patch('sys.stdout',new_callable=io.StringIO) as out, patch('sys.stderr',new_callable=io.StringIO) as err:
                code=h.main()
                self.assertEqual(code,0 if len(args) in (1,2) else 1)
                self.assertEqual(run.call_count,1 if args[:1]==['--work'] else 0)
                self.assertNotIn('password',out.getvalue()+err.getvalue())
        with patch.object(h.sys,'argv',['host_firewall','--config','firewall.yaml','--check']), \
             patch.object(h.authored_config,'read',side_effect=ValueError('private-sentinel')),patch('sys.stderr',new_callable=io.StringIO) as err:
            self.assertEqual(h.main(),1)
            self.assertNotIn('private-sentinel',err.getvalue())

    def test_actual_main_entrypoint_checks_the_public_yaml_without_target_access(self):
        import runpy
        path=Path(h.__file__).parent/'host-firewall.example.yaml'
        with patch.object(sys,'argv',['host_firewall','--config',str(path),'--check']), \
             patch('sys.stdout',new_callable=io.StringIO) as out:
            with self.assertRaises(SystemExit) as done:runpy.run_path(h.__file__,run_name='__main__')
            self.assertEqual(done.exception.code,0)
            self.assertEqual(json.loads(out.getvalue()),{'status':'valid'})
