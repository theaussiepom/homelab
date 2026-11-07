"""Structural compiler dispatch integrations, not bind/lower/render or E2E.

Each row runs Resolver.validate and a selected real mini-validator. Unrelated
validators are conforming stubs; source loading and global references are not
claimed by this matrix. Public synthetic records only.
"""
from contextlib import ExitStack
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'proxmox/applications'))
import component_plan
import component_types as types
import component_monitoring
import component_backup
import component_secrets
import component_foundations
import component_properties
from component_errors import ComponentError
import test_component_small_types as small


LIBRARY=('guest_templates','app_profiles','software','runtime_profiles','health_profiles','monitoring_profiles','backup_profiles')
SITE=('contexts','networks','guests','apps','storage','secret_sources','devices')
ROOTS=((types,'template'),(types,'profile'),(types,'software'),(types,'runtime'),(types,'health'),
       (component_monitoring,'profile'),(component_backup,'profile'),(types,'context'),(types,'network'),(types,'guest'),
       (types,'app'),(types,'network_policy'),(component_secrets,'source'),(types,'device'))
CHILDREN=('resource','startup','security','interface','volume','root_path','storage_layout',
          'policy_binding','timezone','role','storage_role','allocation')


def resolver():
    value=component_plan.Resolver.__new__(component_plan.Resolver)
    value.library={key:{} for key in LIBRARY};value.site={key:{} for key in SITE};value.policy={'network':{}}
    return value


def template():
    return {'resources':{'cpu_cores':1,'memory_mib':1024,'root_gib':4,'os_reserve_mib':256},
        'startup':{'started':True,'start_on_boot':True,'boot_order':20},
        'security':{'unprivileged':True,'protection':True,'nesting':False,'keyctl':False}}


def profile():
    return {'adapter':'unbound','display_name':'Synthetic recursive resolver',
        'interfaces':{'service':{'required':True,'accepts':['guest-interface']}},
        'listeners':{'dns':{'service':'unbound','namespace':'app-network','interface':'service',
            'bind':'interface','protocol':'udp','port':53}},
        'endpoints':{'dns':{'listener':'dns','protocol':'udp','via':'service'}}}


def app():
    return {'profile':'recursive','guest':'worker','lifecycle':'fresh','interfaces':{'service':{'interface':'control'}}}


def case(collection,name,value,target,*,child=None):
    return {'collection':collection,'name':name,'value':value,'target':target,'child':child}


class CompilerValidationDispatchTests(unittest.TestCase):
    def test_backup_profile_dispatch_preserves_typed_source_errors_without_executing_a_client(self):
        value = {'type': 'pbs-client', 'software': ['pbs-client'],
                 'configuration': {'ssh': {'path': '/etc/ssh', 'kind': 'directory'}}}
        spec = case('backup_profiles', 'pbs', value, ('component_backup', 'profile'))
        self.matrix(spec, [
            ('empty-software', lambda x: x.update(software=[])),
            ('wrong-client', lambda x: x.update(type='shell')),
            ('whole-root', lambda x: x['configuration']['ssh'].update(path='/')),
            ('unknown-key', lambda x: x.update(command='PRIVATE_SENTINEL'))])

    def dispatch(self,spec,value):
        r=resolver();collection,name=spec['collection'],spec['name']
        if collection in LIBRARY:r.library[collection][name]=value
        elif collection=='network_policy':r.policy['network'][name]=value
        else:r.site[collection][name]=value
        if collection=='devices':
            r.site['contexts']['primary']=small.context()
        if collection=='storage':r.site['contexts']['primary']=small.context()
        selected=spec['target'];child=spec.get('child');spies={}
        with ExitStack() as contexts:
            for module,field in ROOTS:
                real=getattr(module,field)
                key=(module.__name__,field)
                spy=Mock(wraps=real) if key==selected else Mock(return_value=None)
                spies[key]=contexts.enter_context(patch.object(module,field,spy))
            for field in CHILDREN:
                real=getattr(types,field);key=(types.__name__,field)
                spy=Mock(wraps=real) if key==child else Mock(return_value=None)
                spies[key]=contexts.enter_context(patch.object(types,field,spy))
            contexts.enter_context(patch.object(types,'adapter',return_value={'services':('unbound',),'native':()}))
            contexts.enter_context(patch.object(component_secrets,'requirements',return_value=None))
            contexts.enter_context(patch.object(component_monitoring,'reference',return_value=None))
            contexts.enter_context(patch.object(component_foundations,'validate',return_value=None))
            contexts.enter_context(patch.object(component_properties,'validate',return_value=None))
            try:r.validate()
            finally:
                if selected is not None:self.assertEqual(spies[selected].call_count,1)
                if child is not None:self.assertEqual(spies[child].call_count,1)
        return r

    def matrix(self,spec,variants,*,path=None):
        original=copy.deepcopy(spec['value']);self.dispatch(spec,copy.deepcopy(original))
        expected=path or ((('policies','network',spec['name']) if spec['collection']=='network_policy'
                          else (spec['collection'],spec['name'])))
        for label,mutate in variants:
            value=copy.deepcopy(original);replacement=mutate(value)
            if replacement is not None:value=replacement
            with self.subTest(component=spec['collection'],case=label),self.assertRaises(ComponentError) as caught:
                self.dispatch(spec,value)
            self.assertEqual(caught.exception.path[:len(expected)],expected)
            self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))
        self.assertEqual(spec['value'],original)

    def test_context_real_validator_dispatch_and_structural_reference_paths(self):
        spec=case('contexts','primary',small.context(),(types.__name__,'context'))
        self.matrix(spec,[('missing',lambda v:v.pop('node') and None),
            ('unknown',lambda v:v.update(raw='PRIVATE_SENTINEL')),('type',lambda v:v.update(protected_guests='PRIVATE_SENTINEL')),
            ('bounds',lambda v:v.update(protected_guests=[0])),
            ('endpoint-shape',lambda v:v.update(api_endpoint={'external':'bad!PRIVATE_SENTINEL'})),
            ('credential-reference',lambda v:v['credentials'].update(api_token='../PRIVATE_SENTINEL'))])

    def test_network_real_validator_dispatch_cidr_vlan_gateway_and_refusals(self):
        value={'context':'primary','cidr':'198.18.25.0/24','bridge':'example0','vlan':None,'gateway':'198.18.25.1'}
        self.matrix(case('networks','management',value,(types.__name__,'network')),[
            ('missing',lambda v:v.pop('bridge') and None),('unknown',lambda v:v.update(raw='PRIVATE_SENTINEL')),
            ('type',lambda v:v.update(cidr=[])),('vlan-bound',lambda v:v.update(vlan=4095)),
            ('noncanonical-network',lambda v:v.update(cidr='198.18.25.8/24')),
            ('gateway-ownership',lambda v:v.update(gateway='198.18.26.1'))])

    def test_guest_real_validator_dispatch_keeps_identity_control_and_safe_source_paths(self):
        self.matrix(case('guests','worker',small.guest(),(types.__name__,'guest')),[
            ('missing',lambda v:v.pop('template') and None),('unknown',lambda v:v.update(raw='PRIVATE_SENTINEL')),
            ('identity-type',lambda v:v['identity'].update(vmid=True)),('identity-bounds',lambda v:v['identity'].update(vmid=0)),
            ('control-reference',lambda v:v.update(control_interface='missing')),
            ('template-reference-syntax',lambda v:v.update(template='../PRIVATE_SENTINEL'))])

    def test_nic_validator_is_reached_through_real_guest_then_compiler_checked_path(self):
        spec=case('guests','worker',small.guest(),(types.__name__,'guest'),child=(types.__name__,'interface'))
        self.matrix(spec,[('missing',lambda v:v['interfaces']['control'].pop('mac') and None),
            ('unknown',lambda v:v['interfaces']['control'].update(raw='PRIVATE_SENTINEL')),
            ('type',lambda v:v['interfaces']['control'].update(address=[])),
            ('slot-bounds',lambda v:v['interfaces']['control'].update(slot=32)),
            ('network-reference',lambda v:v['interfaces']['control'].update(network='bad!PRIVATE_SENTINEL'))],
            path=('guests','worker','interfaces','control'))

    def test_template_real_validator_dispatch_defines_only_selected_component_references(self):
        value=template();value.update(software=['linux'],runtime=['native'])
        self.matrix(case('guest_templates','base',value,(types.__name__,'template')),[
            ('missing',lambda v:v.pop('startup') and None),('unknown',lambda v:v.update(raw='PRIVATE_SENTINEL')),
            ('software-type',lambda v:v.update(software={})),('runtime-reference',lambda v:v.update(runtime=['bad!PRIVATE_SENTINEL'])),
            ('duplicate-reference',lambda v:v.update(software=['linux','linux']))])

    def test_resource_validator_compiler_dispatch_through_template_preserves_numeric_floor(self):
        spec=case('guest_templates','base',template(),(types.__name__,'template'),child=(types.__name__,'resource'))
        self.matrix(spec,[('missing',lambda v:v['resources'].pop('memory_mib') and None),
            ('unknown',lambda v:v['resources'].update(raw='PRIVATE_SENTINEL')),
            ('type',lambda v:v['resources'].update(memory_mib=True)),('bounds',lambda v:v['resources'].update(memory_mib=255))])

    def test_startup_validator_compiler_dispatch_keeps_boolean_and_order_bounds(self):
        spec=case('guest_templates','base',template(),(types.__name__,'template'),child=(types.__name__,'startup'))
        self.matrix(spec,[('missing',lambda v:v['startup'].pop('started') and None),
            ('unknown',lambda v:v['startup'].update(raw='PRIVATE_SENTINEL')),
            ('type',lambda v:v['startup'].update(started=1)),('bounds',lambda v:v['startup'].update(boot_order=-1))])

    def test_security_validator_compiler_dispatch_does_not_coerce_or_broaden_policy(self):
        spec=case('guest_templates','base',template(),(types.__name__,'template'),child=(types.__name__,'security'))
        self.matrix(spec,[('missing',lambda v:v['security'].pop('protection') and None),
            ('unknown',lambda v:v['security'].update(raw='PRIVATE_SENTINEL')),
            ('type',lambda v:v['security'].update(nesting=1)),('privilege-floor',lambda v:v['security'].update(unprivileged=False))])

    def test_software_validator_dispatch_enforces_packages_images_and_repository_references(self):
        value={'packages':['example=1.0'],'images':{'worker':'declared_image'},
            'repositories':[{'name':'vendor','source':'deb https://vendor.example.invalid stable main','key_asset':'vendor_key'}]}
        self.matrix(case('software','linux',value,(types.__name__,'software')),[
            ('unknown',lambda v:v.update(raw='PRIVATE_SENTINEL')),('type',lambda v:v.update(packages={})),
            ('unpinned-package',lambda v:v.update(packages=['example'])),
            ('image-reference',lambda v:v.update(images={'worker':'bad!PRIVATE_SENTINEL'})),
            ('key-reference',lambda v:v['repositories'][0].update(key_asset='../PRIVATE_SENTINEL'))])

    def test_runtime_validator_dispatch_preserves_finite_native_container_and_privilege_bounds(self):
        value={'native':{'memory_mib':256},'requirements':{'nesting':True},'containers':{
            'worker':{'memory_mib':128,'cpu_limit':1,'pids_limit':64,'cap_drop':['ALL']}}}
        self.matrix(case('runtime_profiles','bounded',value,(types.__name__,'runtime')),[
            ('unknown',lambda v:v.update(raw='PRIVATE_SENTINEL')),('type',lambda v:v.update(native=[])),
            ('native-memory-bound',lambda v:v['native'].update(memory_mib=0)),
            ('container-cpu-bound',lambda v:v['containers']['worker'].update(cpu_limit=257)),
            ('capability-refusal',lambda v:v['containers']['worker'].update(cap_add=['SYS_ADMIN'])),
            ('package-reference',lambda v:v.update(packages=['bad!PRIVATE_SENTINEL']))])

    def test_health_validator_dispatch_requires_declared_readiness_not_arbitrary_argv(self):
        value={'type':'adapter','check':'readiness','source_interface':'management'}
        self.matrix(case('health_profiles','ready',value,(types.__name__,'health')),[
            ('missing',lambda v:v.pop('check') and None),('unknown',lambda v:v.update(argv=['PRIVATE_SENTINEL'])),
            ('type',lambda v:v.update(check=[])),('unsupported-check',lambda v:v.update(check='command')),
            ('source-reference',lambda v:v.update(source_interface='bad!PRIVATE_SENTINEL'))])

    def test_monitoring_profile_validator_dispatch_requires_explicit_finite_workloads(self):
        value={'type':'zabbix-agent','profiles':['linux']}
        self.matrix(case('monitoring_profiles','linux',value,(component_monitoring.__name__,'profile')),[
            ('missing',lambda v:v.pop('profiles') and None),('unknown',lambda v:v.update(raw='PRIVATE_SENTINEL')),
            ('type',lambda v:v.update(profiles={})),('empty',lambda v:v.update(profiles=[])),
            ('unsupported-workload',lambda v:v.update(profiles=['shell']))])

    def test_secret_source_validator_dispatch_is_metadata_only_and_rejects_value_bags(self):
        value={'type':'environment','name':'DECLARED_INPUT','workflow_secret':'EXISTING_ALIAS'}
        self.matrix(case('secret_sources','declared',value,(component_secrets.__name__,'source')),[
            ('missing',lambda v:v.pop('name') and None),('unknown',lambda v:v.update(password='PRIVATE_SENTINEL')),
            ('type',lambda v:v.update(name=[])),('name-bound',lambda v:v.update(name='A'*129)),
            ('alias-reference',lambda v:v.update(workflow_secret='bad!PRIVATE_SENTINEL'))])
        for record in ({'type':'file','path':'/selected/never-opened-input'},
                       {'type':'generated','credential_id':'declared-account'}):
            self.dispatch(case('secret_sources','declared',record,(component_secrets.__name__,'source')),record)

    def test_device_validator_and_compiler_context_capability_reference_checks_are_real(self):
        value={'type':'serial','context':'primary','path':'/dev/serial/by-id/usb-synthetic','capability':'coordinator'}
        self.matrix(case('devices','coordinator',value,(types.__name__,'device')),[
            ('missing',lambda v:v.pop('path') and None),('unknown',lambda v:v.update(raw='PRIVATE_SENTINEL')),
            ('type',lambda v:v.update(path=[])),('unsupported-type',lambda v:v.update(type='usb')),
            ('fixed-path',lambda v:v.update(path='/dev/ttyUSB0')),('context-reference',lambda v:v.update(context='missing')),
            ('capability-reference',lambda v:v.update(capability='missing'))])

    def test_policy_validator_dispatch_preserves_null_ports_and_bounded_named_references(self):
        value={'rules':[{'direction':'out','proto':'tcp','comment':'explicit source policy','port':None,
                        'destination':{'endpoint':'database'}}]}
        self.matrix(case('network_policy','access',value,(types.__name__,'network_policy')),[
            ('unknown',lambda v:v.update(raw='PRIVATE_SENTINEL')),('type',lambda v:v.update(rules={})),
            ('bound',lambda v:v.update(rules=[{}]*4097)),('direction',lambda v:v['rules'][0].update(direction='both')),
            ('port-reference',lambda v:v['rules'][0].update(port={'endpoint':'bad!PRIVATE_SENTINEL'})),
            ('address-reference',lambda v:v['rules'][0].update(destination={'host':'PRIVATE_SENTINEL'}))])

    def test_pool_storage_inline_compiler_validation_has_exact_named_subject_path(self):
        value={'context':'primary','pool':'local-lvm'}
        self.matrix(case('storage','selected',value,None),[
            ('missing',lambda v:v.pop('pool') and None),('unknown',lambda v:v.update(owner='PRIVATE_SENTINEL')),
            ('type',lambda v:v.update(pool=[])),('empty',lambda v:v.update(pool='')),
            ('context-reference',lambda v:v.update(context='missing'))])

    def test_volume_validator_dispatch_through_guest_has_nested_slot_path_bounds_and_no_owner(self):
        value=small.guest();value['volumes']={'data':{'storage':'selected','slot':0,'path':'/srv/data','size_gib':4}}
        spec=case('guests','worker',value,(types.__name__,'guest'),child=(types.__name__,'volume'))
        self.matrix(spec,[('missing',lambda v:v['volumes']['data'].pop('size_gib') and None),
            ('unknown',lambda v:v['volumes']['data'].update(owner='PRIVATE_SENTINEL')),
            ('type',lambda v:v['volumes']['data'].update(slot=True)),('bounds',lambda v:v['volumes']['data'].update(size_gib=0)),
            ('storage-reference',lambda v:v['volumes']['data'].update(storage='bad!PRIVATE_SENTINEL')),
            ('control-path',lambda v:v['volumes']['data'].update(path='/etc/ssh'))],path=('guests','worker','volumes','data'))

    def test_root_storage_validator_dispatch_through_guest_refuses_control_and_nonliteral_paths(self):
        value=small.guest();value['root_paths']={'data':{'path':'/srv/root-owned'}}
        spec=case('guests','worker',value,(types.__name__,'guest'),child=(types.__name__,'root_path'))
        self.matrix(spec,[('missing',lambda v:v['root_paths']['data'].pop('path') and None),
            ('unknown',lambda v:v['root_paths']['data'].update(owner='PRIVATE_SENTINEL')),
            ('type',lambda v:v['root_paths']['data'].update(path=[])),
            ('control-path',lambda v:v['root_paths']['data'].update(path='/var/lib/homelab')),
            ('nonliteral-path',lambda v:v['root_paths']['data'].update(path='/srv/${PRIVATE_SENTINEL}'))],
            path=('guests','worker','root_paths','data'))

    def test_app_validator_dispatch_preserves_closed_named_bindings_without_resolving_them(self):
        value=app();value['resources']={'containers':{'unbound':{'memory_mib':128}}}
        self.matrix(case('apps','recursive',value,(types.__name__,'app')),[
            ('missing',lambda v:v.pop('profile') and None),('unknown',lambda v:v.update(environment={'RAW':'PRIVATE_SENTINEL'})),
            ('type',lambda v:v.update(properties=[])),('lifecycle',lambda v:v.update(lifecycle='adopt')),
            ('display-bound',lambda v:v.update(display_name='PRIVATE_SENTINEL'*274)),
            ('profile-reference-syntax',lambda v:v.update(profile='bad!PRIVATE_SENTINEL')),
            ('secret-reference-syntax',lambda v:v.update(secrets={'probe':'bad!PRIVATE_SENTINEL'}))])

    def test_profile_validator_dispatch_has_real_listener_bounds_and_local_endpoint_references(self):
        self.matrix(case('app_profiles','recursive',profile(),(types.__name__,'profile')),[
            ('missing',lambda v:v.pop('display_name') and None),('unknown',lambda v:v.update(raw='PRIVATE_SENTINEL')),
            ('type',lambda v:v['interfaces']['service'].update(required=1)),
            ('port-bound',lambda v:v['listeners']['dns'].update(port=65536)),
            ('listener-reference',lambda v:v['endpoints']['dns'].update(listener='missing')),
            ('physical-reference',lambda v:v['listeners']['dns'].update(interface='missing'))])

    def test_profile_storage_role_validator_is_reached_from_actual_compiler_and_profile(self):
        value=profile();value['storage']={'data':{'target':'/config','read_only':False,'required':True,'kind':'directory',
            'initialize':{'type':'directory','uid':1000,'gid':1000,'mode':'0700'}}}
        spec=case('app_profiles','recursive',value,(types.__name__,'profile'),child=(types.__name__,'storage_role'))
        self.matrix(spec,[('missing',lambda v:v['storage']['data'].pop('kind') and None),
            ('unknown',lambda v:v['storage']['data'].update(chown='PRIVATE_SENTINEL')),
            ('type',lambda v:v['storage']['data'].update(required=1)),
            ('uid-bound',lambda v:v['storage']['data']['initialize'].update(uid=65536)),
            ('mode-floor',lambda v:v['storage']['data']['initialize'].update(mode='0777'))],
            path=('app_profiles','recursive','storage','data'))

    def test_storage_layout_validator_dispatch_through_guest_refuses_slot_and_path_overlap(self):
        value=small.guest();value['volumes']={
            'first':{'storage':'selected','slot':0,'path':'/srv/first','size_gib':4},
            'second':{'storage':'selected','slot':1,'path':'/srv/second','size_gib':4}}
        value['root_paths']={'root':{'path':'/srv/root-owned'}}
        spec=case('guests','worker',value,(types.__name__,'guest'),child=(types.__name__,'storage_layout'))
        self.matrix(spec,[('duplicate-slot',lambda v:v['volumes']['second'].update(slot=0)),
            ('same-path',lambda v:v['volumes']['second'].update(path='/srv/first')),
            ('nested-path',lambda v:v['volumes']['second'].update(path='/srv/first/child')),
            ('rootfs-shadow',lambda v:v['root_paths']['root'].update(path='/srv/first/child'))])

    def test_app_allocation_validator_dispatch_has_actual_nested_service_path_and_budget_types(self):
        value=app();value['resources']={'containers':{'unbound':{'memory_mib':128,'cpu_limit':0.5,'pids_limit':64}}}
        spec=case('apps','recursive',value,(types.__name__,'app'),child=(types.__name__,'allocation'))
        self.matrix(spec,[('empty',lambda v:v['resources']['containers'].update(unbound={})),
            ('unknown',lambda v:v['resources']['containers']['unbound'].update(raw='PRIVATE_SENTINEL')),
            ('type',lambda v:v['resources']['containers']['unbound'].update(cpu_limit=True)),
            ('memory-bound',lambda v:v['resources']['containers']['unbound'].update(memory_mib=0)),
            ('cpu-bound',lambda v:v['resources']['containers']['unbound'].update(cpu_limit=257))],
            path=('apps','recursive','resources','containers','unbound'))

    def test_app_role_validator_dispatch_rejects_unknown_scope_or_symbolic_role_shape(self):
        spec=case('apps','recursive',app(),(types.__name__,'app'),child=(types.__name__,'role'))
        self.matrix(spec,[('empty',lambda v:v['interfaces'].update(service={})),
            ('unknown',lambda v:v['interfaces']['service'].update(source='PRIVATE_SENTINEL')),
            ('type',lambda v:v['interfaces'].update(service=[])),
            ('reference-syntax',lambda v:v['interfaces']['service'].update(interface='bad!PRIVATE_SENTINEL')),
            ('unsupported-scope',lambda v:v['interfaces'].update(service={'scope':'host'}))])

    def test_policy_binding_validator_dispatch_through_guest_preserves_typed_fragment_refs(self):
        value=small.guest();value['network_policy']=[{'policy':'common',
            'interfaces':{'local':'control','remote':{'app':'database','interface':'service'}},
            'networks':{'lan':'management'},'endpoints':{'db':{'app':'database','endpoint':'sql'}}}]
        spec=case('guests','worker',value,(types.__name__,'guest'),child=(types.__name__,'policy_binding'))
        self.matrix(spec,[('missing',lambda v:v['network_policy'][0].pop('policy') and None),
            ('unknown',lambda v:v['network_policy'][0].update(rule='PRIVATE_SENTINEL')),
            ('type',lambda v:v['network_policy'][0].update(interfaces=[])),
            ('fragment-reference',lambda v:v['network_policy'][0].update(policy='bad!PRIVATE_SENTINEL')),
            ('endpoint-reference',lambda v:v['network_policy'][0]['endpoints'].update(db={'external':'bad!PRIVATE_SENTINEL'}))])



if __name__=='__main__':unittest.main()
