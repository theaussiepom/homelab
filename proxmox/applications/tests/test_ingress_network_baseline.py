"""Accepted DNS custody plus additive ingress Influx; entirely synthetic/local."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import database_network_apply as apply_network
import database_network_maintenance as m
import ingress_network_baseline as baseline
import ingress_acme as acme
import test_database_network_maintenance as fixtures
from test_database_network_server import contract

OP = dict(phase='additive',client_vmids=[212],legacy_server_address=None)


def state(values,serial):
    rows=[]
    for address,value in values.items():
        module,kind,name=address.rsplit('.',2)
        rows.append({'module':module,'mode':'managed','type':kind,'name':name,
                     'instances':[{'attributes':value}]})
    return m.encoded({'lineage':'original-ingress-lineage','serial':serial,'resources':rows})


class BaselineTests(unittest.TestCase):
    def put(self,path,value):
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        m.write_new(path,value if isinstance(value,bytes) else m.encoded(value))
        return path

    def setUp(self):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.work=self.state/'212';self.work.mkdir(mode=0o700)
        self.nas=self.root/'nas/212';self.nas.mkdir(parents=True,mode=0o700)
        self.cfg=fixtures.cfg();self.cfg['guest'].update(vmid=212,hostname='proxy')
        self.cfg['guest']['rules'].pop(1)
        self.cfg['guest']['interfaces'].append(dict(bridge='vmbr1',vlan=40,mac='02:88:40:00:02:12',
            ipv4='10.88.40.33/24',ipv6='manual'))
        self.cfg['app'].update(kind='ingress',vmid=212,hostname='proxy',address='10.88.25.23')
        self.cfg['paths']=dict(state_root=str(self.state),ca_file=str(self.root/'ca'),api_token=str(self.root/'token'),
            backup_directory=str(self.root/'nas'),backup_mount=str(self.root/'nas'),backup_source='synthetic-nas:/fixture',
            private_key='/private/synthetic-key',known_hosts='/private/synthetic-known-hosts')
        self.site=self.put(self.root/'site.json',self.cfg)
        self.put(self.root/'ca',b'synthetic CA');self.put(self.root/'token',b'SYNTHETIC_PRIVATE_NEVER_LOG')
        self.source=self.root/'source';self.put(self.source/'tofu/main.tf',b'# original unchanged source\n')
        self.put(self.source/'tofu/.terraform.lock.hcl',b'# original lock\n')
        self.labels={'managed-by':'original-source'}
        self.variables={k:copy.deepcopy(self.cfg[k]) for k in ('site','guest','ssh_public_keys')}
        self.variables['guest']['routing_labels']=self.labels
        self.put(self.work/'tofu/site.auto.tfvars.json',self.variables)
        self.put(self.work/'guest.tfplan',b'original saved plan');self.put(self.work/'guest.tfplan.json',{'original':True})
        self.put(self.work/'ssh-trust.json',{'original':'trust'})
        self.input_hashes={str(self.root/'ca'):m.digest(b'synthetic CA')}
        self.receipt=dict(vmid=212,site_sha256=m.digest(self.site.read_bytes()),source_sha256='a'*64,
            input_hashes=self.input_hashes,plan_sha256=m.digest(b'original saved plan'),
            plan_json_sha256=m.digest(m.encoded({'original':True})))
        for name in ('plan.json','applied.json','started.json'):self.put(self.work/name,self.receipt)
        self.put(self.work/'rollout-complete.json',{'status':'passed','vmid':212,'plan_sha256':self.receipt['plan_sha256']})
        foundation={'status':'passed','binding':{'guest':'ingress','vmid':212},'plan_sha256':self.receipt['plan_sha256']}
        self.put(self.work/'foundation-complete.json',foundation)
        before={m.CONTAINER:fixtures.raw_container(self.cfg['guest']),
                m.OPTIONS:dict(container_id=212,node_name='pve-test',enabled=True,input_policy='DROP',output_policy='DROP'),
                m.RULES:fixtures.raw_rules(self.cfg['guest'])}
        self.accepted=copy.deepcopy(self.cfg['guest'])
        self.accepted['rules']+=acme.guest_rules(['1.1.1.1:53','1.0.0.1:53'])
        after=copy.deepcopy(before);after[m.RULES]=fixtures.raw_rules(self.accepted)
        self.before_state,self.after_state=state(before,1),state(after,2)
        self.put(self.work/'terraform.tfstate',self.after_state)
        self.selected=dict(schema='homelab-ingress-acme-update-v1',revision='c'*40,vmid=212,
            plan_sha256=self.receipt['plan_sha256'],before=['198.18.40.2:53'],after=['1.1.1.1:53','1.0.0.1:53'],
            runtime_sha256='d'*64,compose_sha256='e'*64,state_sha256=m.digest(self.before_state),
            foundation_complete_sha256=m.digest(m.encoded(foundation)),image='traefik@sha256:'+'f'*64)
        self.operation=self.work/('acme-resolvers-'+m.digest(m.encoded(self.selected['after']))[:16])
        complete={'packet':self.selected,'state_sha256':m.digest(self.after_state)}
        self.put(self.operation/'claim.json',self.selected);self.put(self.operation/'complete.json',complete)
        self.put(self.nas/(self.operation.name+'-claim.json'),self.selected)
        self.put(self.nas/(self.operation.name+'-complete.json'),complete)
        rows=[{'address':address,'change':{'actions':['no-op'] if before[address]==after[address] else ['update'],
            'before':before[address],'after':after[address],'after_unknown':{}}} for address in m.RESOURCES]
        self.put(self.operation/'attempt/dns.tfplan',b'accepted DNS plan')
        self.put(self.operation/'attempt/dns.tfplan.json',{'resource_changes':rows})
        self.put(self.operation/'attempt/reviewed-plan.json',{'plan_sha256':m.digest(b'accepted DNS plan'),
                                                          'scope':'DNS egress additions only'})
        variables=copy.deepcopy(self.variables);variables['guest']['rules']=self.accepted['rules']
        self.put(self.operation/'attempt/tofu/site.auto.tfvars.json',variables)
        self.manifest=dict(schema=baseline.SCHEMA,vmid=212,operation=self.operation.name,
            files={name:m.digest((self.operation/name).read_bytes()) for name in baseline.FILES})
        for key,label,raw in [('state_before','before-acme-resolver-update',self.before_state),
                              ('state_after','after-acme-firewall-update',self.after_state)]:
            name='123-'+label+'.tfstate';self.put(self.nas/name,raw)
            receipt={'file':name,'sha256':m.digest(raw)};self.put((self.nas/name).with_suffix('.json'),receipt)
            self.manifest[key]={'file':name,'sha256':m.digest(raw),'receipt_sha256':m.digest(m.encoded(receipt))}
        self.manifest_path=self.put(self.work/'ingress-acme-network-baseline.json',self.manifest)
        self.reference={'path':str(self.manifest_path),'sha256':m.digest(self.manifest_path.read_bytes())}
        self.catalogue=contract();self.catalogue['networks']['influxdb']['clients'].append(
            dict(vmid=212,hostname='proxy',address='10.88.33.33',mac='02:88:00:d4:21:01'))
        self.catalogue_path=self.put(self.root/'catalogue.json',self.catalogue)
        self.evidence=self.work/'database-network-plan-ingress'
        self.deployment=types.SimpleNamespace(SOURCE=self.source,validate=Mock(),source_hash=Mock(return_value='a'*64),
            input_hashes=Mock(return_value=self.input_hashes),discovery=types.SimpleNamespace(labels=Mock(return_value=self.labels)),
            execute=Mock(),backup=Mock(),application_address=Mock(return_value='10.88.25.23'),
            guest_identity=types.SimpleNamespace(pin=Mock()),api_get=Mock(),write=Mock(),quiet=Mock())
        for obj,key,value in [(m,'STATE',self.state),(m,'BOOTSTRAP_HOLD',self.root/'CONFIGURING'),
            (baseline,'nas_root',lambda cfg:self.nas),(apply_network,'nas_root',lambda cfg:self.nas)]:
            p=patch.object(obj,key,value);p.start();self.addCleanup(p.stop)
        self.originals={p:p.read_bytes() for p in self.work.rglob('*') if p.is_file()}

    def resave_manifest(self):
        self.manifest_path.write_bytes(m.encoded(self.manifest));self.reference['sha256']=m.digest(self.manifest_path.read_bytes())

    def plan_value(self,positions=False):
        original=self.accepted;candidate=copy.deepcopy(original)
        candidate['interfaces'].append(dict(bridge='vmbr33',vlan=None,mac='02:88:00:d4:21:01',ipv4='10.88.33.33/24',ipv6='manual'))
        candidate['rules'].append(dict(direction='out',proto='tcp',port='8086',source='10.88.33.33/32',
            destination='10.88.33.26/32',comment='influxdb approved client proxy'))
        before={m.CONTAINER:fixtures.raw_container(original),m.OPTIONS:dict(container_id=212,node_name='pve-test',
            enabled=True,input_policy='DROP',output_policy='DROP'),m.RULES:fixtures.raw_rules(original)}
        after={m.CONTAINER:fixtures.raw_container(candidate),m.OPTIONS:copy.deepcopy(before[m.OPTIONS]),m.RULES:fixtures.raw_rules(candidate)}
        if positions:
            for values in (before,after):
                for i,row in enumerate(values[m.RULES]['rule']):row['pos']=i
        return {'resource_changes':[{'address':address,'mode':'managed','change':{'actions':
            ['no-op'] if before[address]==after[address] else ['update'],'before':before[address],
            'after':after[address],'after_unknown':{},'replace_paths':[]}} for address in m.RESOURCES]},candidate

    def check(self,value):
        return m.check_plan(value,self.cfg,self.catalogue,'influxdb',**OP,ingress_acme_baseline=self.reference)

    def test_exact_baseline_keeps_original_nics_and_four_dns_rules_then_adds_one_sql_rule(self):
        result=baseline.load(self.cfg,self.work,self.reference,current=True)
        self.assertEqual(result['guest'],self.accepted)
        for positions in (False,True):
            value,candidate=self.plan_value(positions)
            self.assertEqual(self.check(value)['candidate_guest'],candidate)
            self.assertEqual(candidate['interfaces'][:3],self.cfg['guest']['interfaces'])
            self.assertEqual(candidate['rules'][:-1],self.accepted['rules'])
        for path,raw in self.originals.items():self.assertEqual(path.read_bytes(),raw)
        self.deployment.execute.assert_not_called()

    def test_without_explicit_baseline_the_old_missing_sql_template_guard_stays(self):
        value,_=self.plan_value()
        with self.assertRaises(ValueError):m.check_plan(value,self.cfg,self.catalogue,'influxdb',**OP)

    def test_changed_custody_state_original_rule_or_confirmation_refuses(self):
        paths=[self.operation/'claim.json',self.nas/(self.operation.name+'-complete.json'),
               self.nas/self.manifest['state_before']['file'],self.operation/'attempt/dns.tfplan',
               self.operation/'attempt/tofu/site.auto.tfvars.json',self.work/'terraform.tfstate']
        for path in paths:
            raw=path.read_bytes();path.write_bytes(raw+b' ')
            with self.subTest(path=path.name),self.assertRaises(ValueError):baseline.load(self.cfg,self.work,self.reference,current=True)
            path.write_bytes(raw)
        self.put(self.operation/'confirmation-claim.json',{'incomplete':True})
        with self.assertRaises(ValueError):baseline.load(self.cfg,self.work,self.reference)

    def test_arbitrary_extra_baseline_rule_is_refused_even_with_rebound_file_hash(self):
        path=self.operation/'attempt/tofu/site.auto.tfvars.json';value=json.loads(path.read_bytes())
        value['guest']['rules'].append(dict(direction='out',proto='tcp',port='22',destination='0.0.0.0/0'))
        path.write_bytes(m.encoded(value));self.manifest['files']['attempt/tofu/site.auto.tfvars.json']=m.digest(path.read_bytes())
        self.resave_manifest()
        with self.assertRaises(ValueError):baseline.load(self.cfg,self.work,self.reference)

    def test_new_rule_cannot_inherit_interface_macro_sport_or_other_authority(self):
        for field,bad in [('iface','eth1'),('sport','22'),('macro','SSH'),('enabled',False),('log','info'),('unknown','anything')]:
            value,_=self.plan_value();rule=value['resource_changes'][2]['change']['before']['rule'][1]
            rule[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):self.check(value)
        value,_=self.plan_value();value['resource_changes'][2]['change']['after']['rule'][-1]['dest']='0.0.0.0/0'
        with self.assertRaises(ValueError):self.check(value)

    def test_other_guests_engines_phases_and_members_cannot_select_this_baseline(self):
        for engine,phase,members in [('mariadb','additive',[212]),('influxdb','cutover',[212]),('influxdb','additive',[200,212])]:
            with self.subTest(engine=engine,phase=phase,members=members),self.assertRaises(ValueError):
                baseline.scope(self.cfg,engine,phase,members,None)
        cfg=copy.deepcopy(self.cfg);cfg['guest']['vmid']=211
        with self.assertRaises(ValueError):baseline.scope(cfg,'influxdb','additive',[212],None)

    def fake_tofu(self,command,environment,log,output=None):
        if 'plan' in command:m.write_new(self.evidence/'guest.tfplan',b'additive network saved plan')
        if output:m.write_new(output,m.encoded(self.plan_value()[0]))

    def prepare(self):
        with patch.object(m,'tofu',side_effect=self.fake_tofu):
            return m.plan(self.deployment,self.site,self.catalogue_path,self.evidence,'influxdb',**OP,
                          ingress_acme_baseline=self.reference)

    def test_readonly_plan_and_apply_admission_use_same_baseline_and_original_custody(self):
        result=self.prepare();self.assertEqual(result['status'],'review_required')
        variables=json.loads((self.evidence/'tofu/site.auto.tfvars.json').read_bytes())
        self.assertEqual(variables['guest']['rules'],self.plan_value()[1]['rules'])
        selected=dict(schema=apply_network.SCHEMA,vmid=212,request_sha256=m.digest((self.evidence/'request.json').read_bytes()),
            review_packet_sha256=m.digest((self.evidence/'review-packet.json').read_bytes()),
            apply_helper_sha256=m.digest(Path(apply_network.__file__).read_bytes()),allow_guest_restart=True)
        path=self.put(self.root/'apply.json',selected)
        c=apply_network.load(self.deployment,self.site,self.catalogue_path,self.evidence,path,m.digest(path.read_bytes()))
        apply_network.admission(self.deployment,c)
        self.assertEqual(c['ingress_acme']['guest'],self.accepted)
        for path,raw in self.originals.items():self.assertEqual(path.read_bytes(),raw)
        self.deployment.execute.assert_not_called()

    def test_runtime_successor_uses_only_existing_guest_verification_and_no_old_acme_plan(self):
        directory=self.work/'verify-test';directory.mkdir(mode=0o700)
        context={'cfg':self.cfg,'ingress_acme':baseline.load(self.cfg,self.work,self.reference)}
        baseline.verify_runtime(self.deployment,context,directory)
        argv=self.deployment.quiet.call_args.args[0]
        self.assertEqual(argv[0],'ansible-playbook');self.assertTrue(argv[-2]=='--extra-vars')
        variables=json.loads((directory/'ingress-variables.json').read_bytes())
        self.assertTrue(variables['acme_verify_only']);self.assertEqual(variables['acme_settings'],self.selected)
        self.deployment.execute.assert_not_called()

    def test_completed_confirmation_binds_original_failed_evidence_and_both_nas_records(self):
        for name in acme.FAILURE_FILES:
            if not (self.operation/name).exists():self.put(self.operation/name,b'synthetic retained failure')
        confirmation=dict(schema='homelab-ingress-acme-confirmation-v1',revision='b'*40,vmid=212,
            plan_sha256=self.selected['plan_sha256'],update=self.selected,state_sha256=m.digest(self.after_state),
            runtime_sha256='1'*64,guest_hold_sha256='2'*64,
            failure_hashes={name:m.digest((self.operation/name).read_bytes()) for name in acme.FAILURE_FILES})
        for name in baseline.CONFIRMATION:
            self.put(self.operation/name,confirmation);self.put(self.nas/(self.operation.name+'-'+name),confirmation)
            self.manifest['files'][name]=m.digest(m.encoded(confirmation))
        self.resave_manifest()
        self.assertEqual(baseline.load(self.cfg,self.work,self.reference)['guest'],self.accepted)
        path=self.operation/'attempt/ansible.log';path.write_bytes(b'changed failed evidence')
        with self.assertRaises(ValueError):baseline.load(self.cfg,self.work,self.reference)

    def test_apply_and_later_verify_preserve_dns_baseline_without_old_acme_plan(self):
        self.prepare()
        selected=dict(schema=apply_network.SCHEMA,vmid=212,request_sha256=m.digest((self.evidence/'request.json').read_bytes()),
            review_packet_sha256=m.digest((self.evidence/'review-packet.json').read_bytes()),
            apply_helper_sha256=m.digest(Path(apply_network.__file__).read_bytes()),allow_guest_restart=True)
        packet_path=self.put(self.root/'apply.json',selected)
        args=(self.deployment,self.site,self.catalogue_path,self.evidence,packet_path,m.digest(packet_path.read_bytes()))
        calls=[]
        def native(command,environment,log,output=None):
            calls.append(command)
            value,candidate=self.plan_value()
            if 'apply' in command:
                values={row['address']:row['change']['after'] for row in value['resource_changes']}
                (self.work/'terraform.tfstate').write_bytes(state(values,3))
            if 'plan' in command:
                path=Path(next(part.split('=',1)[1] for part in command if part.startswith('-out=')))
                m.write_new(path,b'synthetic fresh no-op plan')
            if output:
                if command[-1] != str(self.evidence/'guest.tfplan'):
                    for row in value['resource_changes']:
                        row['change']['before']=copy.deepcopy(row['change']['after']);row['change']['actions']=['no-op']
                m.write_new(output,m.encoded(value))
        with patch.object(m,'tofu',side_effect=native),patch.object(acme,'run',side_effect=AssertionError('Old ACME path forbidden')):
            first=apply_network.apply(*args)
            self.assertEqual(first['state_serial'],3)
            calls.clear();self.deployment.quiet.reset_mock()
            second=apply_network.verify(*args)
        self.assertEqual(second['status'],'network_overlay_verified')
        self.assertFalse(any('apply' in command for command in calls))
        self.deployment.quiet.assert_called_once()
        attempt=self.work/('database-network-apply-'+selected['review_packet_sha256'])
        self.assertEqual((attempt/'ingress-acme-baseline.json').read_bytes(),self.manifest_path.read_bytes())
        self.assertEqual((self.nas/attempt.name/'ingress-acme-baseline.json').read_bytes(),self.manifest_path.read_bytes())
        for path,raw in self.originals.items():
            if path.name != 'terraform.tfstate':self.assertEqual(path.read_bytes(),raw)
        self.assertFalse((self.work/'HOLD.json').exists())
        self.deployment.execute.assert_not_called()


class MountTests(unittest.TestCase):
    def test_autofs_and_one_active_matching_nfs_are_accepted_without_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            mount=Path(temp);nas=mount/'backup/212';nas.mkdir(parents=True,mode=0o700)
            cfg={'guest':{'vmid':212},'paths':{'backup_mount':str(mount),
                'backup_directory':str(mount/'backup'),'backup_source':'synthetic-nas:/approved'}}
            for value,accepted in [('autofs systemd-1\nnfs4 synthetic-nas:/approved\n',True),
                                   ('autofs systemd-1\nnfs4 other-nas:/different\n',False),
                                   ('nfs4 synthetic-nas:/approved\nnfs synthetic-nas:/approved\n',False),
                                   ('autofs systemd-1\n',False)]:
                with self.subTest(value=value),patch.object(baseline.os.path,'ismount',return_value=True),\
                        patch.object(baseline.subprocess,'check_output',return_value=value):
                    if accepted:self.assertEqual(baseline.nas_root(cfg),nas)
                    else:
                        with self.assertRaises(ValueError):baseline.nas_root(cfg)


if __name__=='__main__':unittest.main()
