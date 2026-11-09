"""Current app caller units: real owned files/proofs, inert component executors."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

F=Path(os.environ.get('HOMELAB_FRAMEWORK',Path(__file__).resolve().parents[3])).resolve()
sys.path[:0]=[str(F/'blueprints'),str(F/'proxmox/applications'),str(F/'proxmox/applications/tests')]
import application_contract as contract
import component_ansible as ansible
import component_continuity as continuity
import component_inputs as inputs
import component_payload as payloads
import component_prepare as prepare
import component_private_material as material
import managed_credentials
from private_io import encoded, read_json, sha, write_bytes, write_new
import test_component_app_hooks as hook_fixtures
import test_component_foundation_files as foundation_fixtures
import test_component_private_inputs as private_fixtures
import test_component_proxy_files as proxy_fixtures


class CallerCase(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.serial=0

    def case(self,adapter,extra=None,*,lifecycle='fresh'):
        self.serial+=1;root=self.root/str(self.serial);root.mkdir(mode=0o700)
        directory=root/'inputs';directory.mkdir(mode=0o700)
        state=root/'state';state.mkdir(mode=0o700)
        roles=contract.ADAPTERS[adapter]['services']
        names={role:'owned-'+role.replace('_','-') for role in roles}
        app={'id':'selected','adapter':adapter,'lifecycle':lifecycle,
             'identity':{'phase':'selected','runtime_id':'selected','services':names,
                         'runtime_directory':'/opt/homelab-app/runtime/selected'},
             'settings':{},'storage_paths':{},'software_selection':{'images':{}},'input_sources':{}}
        if roles:app.update(project_name='owned-project',project_file='compose-owned.yml')
        if extra:
            for key,value in extra.items():
                if key=='identity':app[key].update(copy.deepcopy(value))
                else:app[key]=copy.deepcopy(value)
        app['id']='selected'
        if roles:
            app.setdefault('project_file','compose-owned.yml');app.setdefault('project_name','owned-project')
        app['runtime_files']={'app':app['id'],'guest':'fixture',
            'directory':app['identity']['runtime_directory'],
            'files':sorted(contract.runtime_files(app)),'directory_mounts':[]}
        phase={'id':app['id'],'adapter':adapter,'lifecycle':app['lifecycle'],'runtime_id':'selected'}
        if roles:phase.update(project=app['project_name'],compose_file=app['project_file'],
                              services=contract.ordered_services(app))
        cfg={'schema':'homelab-component-guest-v1','site':{'node':'fixture-node',
              'api_endpoint':'https://198.18.25.10:8006/'},
             'guest':{'vmid':610,'hostname':'fixture','interfaces':[
                 {'ipv4':'198.18.20.10/24','mac':'02:00:00:20:00:10'},{'ipv4':'manual'}]},
             'paths':{'state_root':str(state),'ca_file':str(root/'context.pem'),
                      'known_hosts':str(root/'known_hosts'),'private_key':str(root/'key')},
             'app':{'hostname':'fixture','address':'198.18.20.10','service_health_checks':{
                 'selected':[{'name':'selected readiness','argv':['true'],'expect':''}]},
                 },
             'deployment':{'contract':3,'capabilities':['linux','docker'] if roles else ['linux'],
                 'input_directory':str(directory),'runtime_file':str(directory/'component-runtime.json'),
                 'input_identity':'a'*64,'protected_guests':[9900],
                 'phases':['preparation','selected'],'applications':{'selected':phase},
                 'payload_phases':{'selected':app['id']}}}
        write_new(root/'context.pem',b'public synthetic trust\n')
        self.cfg,self.app,self.directory,self.attempt=cfg,app,directory,SimpleNamespace(receipt=root/'absent-receipt')
        self.save()
        return cfg,app

    def save(self):
        runtime=self.directory/'component-runtime.json'
        write_bytes(runtime,encoded({'applications':{self.app['id']:self.app}}))
        if 'project_file' in self.app:
            services=contract.ordered_services(self.app)
            write_bytes(self.directory/'component-projects.json',encoded({self.app['project_name']:{
                'file':self.app['project_file'],'applications':{self.app['id']:services}}}))
            write_bytes(self.directory/self.app['project_file'],encoded({'services':{s:{} for s in services}}))

    def selected_payload(self,extra=None,*,app=None,name='selected'):
        parent=inputs.app_directory(self.cfg,create=True)
        selected=self.app if app is None else app
        values={'application.json':encoded(selected),'runtime-files.json':encoded([]),
                continuity.FILE:encoded(continuity.document(selected,{}))}
        values.update(extra or {})
        return payloads.prepare(parent,self.cfg['deployment']['input_identity'],name,values)

    def rows(self):
        return [{'path':name,'content':b'owned component output','uid':0,'gid':0,'mode':'0400'}
                for name in sorted(contract.runtime_files(self.app))]


class AnsibleCallerTests(CallerCase):
    def test_native_influx_ansible_refuses_a_missing_database_role(self):
        """The Ansible caller propagates the native frontend's clear refusal."""
        from test_separate_web_listeners import influx
        selected = influx()
        selected['role_addresses'].pop('service')
        selected['software_selection']['images'] = {}
        cfg, _ = self.case('influxdb', selected)
        write_new(self.directory/'component-native.json', encoded({'selected':{
            'identity':{'user':'influxdb'}, 'services':['influxdb']}}))
        payload = self.selected_payload()
        with self.assertRaisesRegex(ValueError, 'Resolve the native database service role'):
            ansible.variables(cfg, 'selected', payload=payload)

    def test_selected_native_influx_phase_derives_only_its_owned_web_units(self):
        """Exercise optional frontend derivation through the real Ansible caller."""
        import component_native
        from test_separate_web_listeners import influx
        for split in (False, True):
            selected=influx()
            selected['software_selection']['images']={}
            if not split:selected['role_addresses'].pop('web')
            cfg,app=self.case('influxdb',selected)
            write_new(self.directory/'component-native.json',encoded({'selected':{
                'identity':{'user':'influxdb'},'services':['influxdb']}}))
            payload=self.selected_payload()
            values=ansible.variables(cfg,'selected',payload=payload)
            self.assertEqual(values['component_native_frontend'],component_native.web_frontend(app))
            self.assertEqual(values['component_native_frontend']['enabled'],split)
            self.assertNotIn('component_compose_file',values)

    def test_native_preparation_and_selected_administrator_metadata_have_no_compose_dependency(self):
        for selected_admin in (False,True):
            with self.subTest(administrator=selected_admin):
                cfg,app=self.case('postgresql')
                identity={'uid':70,'gid':1000,'user':'postgres','group':'postgres','home':'/var/lib/postgresql',
                    'version_command':['/usr/lib/postgresql/16/bin/postgres','--version'],
                    'version_pattern':'16.13','config_files':[]}
                if selected_admin:
                    app['database_administrators']={'admin':{'username':'fixture_admin','credential_id':'fixture-admin',
                        'credential_file':str(self.directory/'applications/selected/managed-fixture-admin.json'),
                        'access':'server-administration','transport':'tls','owner':{'engine':'postgresql','node':'fixture-node'}}}
                    self.save()
                write_new(self.directory/'component-native.json',encoded({'selected':{
                    'identity':identity,'services':['postgresql']}}))
                staged=ansible.variables(cfg,'preparation')
                self.assertEqual(staged['component_native_applications'],[{'kind':'postgresql','database':identity}])
                self.assertEqual(staged['network_ready_interfaces'],['eth0'])
                payload=self.selected_payload();values=ansible.variables(cfg,'selected',payload=payload)
                self.assertEqual(values['app']['database'],identity)
                self.assertEqual(values['component_native_services'],['postgresql'])
                self.assertEqual('database_administrators' in values['app'],selected_admin)
                self.assertNotIn('component_preflight',values);self.assertNotIn('component_compose_file',values)
                with self.assertRaisesRegex(ValueError,'cannot consume'):ansible.variables(cfg,'preparation',payload=payload)

    def test_database_agent_reads_only_its_selected_payload_and_refuses_peer_password(self):
        import monitoring_agent
        for workload,adapter,port in [('postgresql','postgresql',5432),('mysql','mariadb',3306)]:
            with self.subTest(workload=workload):
                cfg,app=self.case(adapter)
                parent=inputs.app_directory(cfg,create=True);agent=parent/'agent'
                monitor={'hostname':'fixture-node-610','psk_identity':'fixture-node-610',
                    'server_active':'198.18.25.36:10051','profiles':['linux',workload],
                    'server_vmid':816,'server_hostname':'observer','credential_file':str(agent/'monitoring-agent.json'),
                    'database_password_file':str(agent/'monitoring-database-password'),
                    'database_uri':'tcp://198.18.20.10:'+str(port)}
                cfg['app']['monitoring']=monitor;cfg['deployment']['phases'].append('zabbix-agent')
                cfg['deployment']['payload_phases']['zabbix-agent']='agent'
                proof=payloads.prepare(parent,'a'*64,'agent',{'application.json':encoded({
                    'schema':'homelab-component-agent-input-v1','monitoring':monitor}),
                    'monitoring-agent.json':encoded({'psk':'a'*64}),'monitoring-database-password':b'b'*64})
                values=ansible.variables(cfg,'zabbix-agent',payload=proof)
                self.assertFalse(values['app']['start_services'])
                self.assertEqual(values['zabbix_agent']['workloads'],{workload:{'uri':monitor['database_uri'],
                    'password_file':str(agent/'monitoring-database-password')}})
                self.assertIn('Password='+'b'*64,values['monitoring_agent_configuration'])
                with patch.object(monitoring_agent,'validate',return_value=dict(monitor,
                        database_password_file=str(parent/'peer/monitoring-database-password'))), \
                     patch.object(monitoring_agent,'configuration') as configure,self.assertRaisesRegex(ValueError,'another phase'):
                    ansible.variables(cfg,'zabbix-agent',payload=proof)
                configure.assert_not_called()

    def test_selected_app_hook_and_private_overlay_do_not_use_peer_service_or_payload(self):
        cfg,app=self.case('pihole',{'settings':{'dns_records':{}}})
        marker={'helpers':[{'source':'dns_records.py','destination':'/opt/homelab-app/dns_records.py','mode':'0700'}],
                'pihole_records':{'reconcile_argv':['selected-only']}}
        payload=self.selected_payload({'environment.yml':b'{"services":{"owned-pihole":{"environment":{"OWNED":"literal"}}}}'})
        with patch.object(ansible.component_app_hooks,'descriptors',return_value=copy.deepcopy(marker)) as hooks:
            values=ansible.variables(cfg,'selected',payload=payload)
        hooks.assert_called_once_with(app,compose_file='/opt/homelab-app/'+app['project_file'])
        self.assertEqual(values['component_helpers'],marker['helpers'])
        self.assertEqual(values['pihole_records'],marker['pihole_records'])
        self.assertEqual(values['component_environment_source'],str(payload.directory/'environment.yml'))
        self.assertEqual(values['component_environment_file'],'/opt/homelab-app/component-selected-environment.yml')
        foreign=copy.deepcopy(app);foreign['settings']['dns_records']={'peer.example.invalid':'198.18.20.99'}
        peer=self.selected_payload(app=foreign,name='peer')
        with patch.object(ansible.component_app_hooks,'descriptors') as hook,self.assertRaisesRegex(ValueError,'selected app payload'):
            ansible.variables(cfg,'selected',payload=peer)
        hook.assert_not_called()
        other=self.root/'foreign-inputs';other.mkdir(mode=0o700)
        drift=payloads.prepare(other,'a'*64,'selected',{'application.json':encoded(foreign),
            'runtime-files.json':encoded([]),continuity.FILE:encoded(continuity.document(foreign,{}))})
        with self.assertRaisesRegex(ValueError,'exact selected runtime'):
            ansible.variables(cfg,'selected',payload=drift)

    def test_pega_key_and_vault_environment_are_phase_owned_and_parser_failure_stops_variables(self):
        cfg,app=self.case('pegaprox');payload=self.selected_payload({'pegaprox-db-key':b'opaque-synthetic-key'})
        result=ansible.variables(cfg,'selected',payload=payload)
        self.assertEqual(result['app']['pegaprox'],{'key_source':str(payload.directory/'pegaprox-db-key'),
            'key_runtime_path':app['identity']['runtime_directory']+'/pegaprox-db-key'})
        vault,raw,environment=private_fixtures.vault()
        cfg,app=self.case('bitwarden',vault,lifecycle='retained')
        app['software_selection']['images']['bitwarden']={'image':'vendor/vault:latest'};self.save()
        proof=self.selected_payload({'bitwarden-environment.json':raw})
        with patch.object(ansible.bitwarden_runtime,'environment_bytes',return_value=environment) as parser:
            values=ansible.variables(cfg,'selected',payload=proof)
        parser.assert_called_once_with(raw,app['settings']['runtime'],app['settings']['settings'])
        self.assertEqual(values['component_bitwarden']['environment'],environment)
        self.assertEqual(values['component_bitwarden']['image'],'vendor/vault:latest')
        with patch.object(ansible.bitwarden_runtime,'environment_bytes',side_effect=ValueError('owned parser refused')), \
             self.assertRaisesRegex(ValueError,'owned parser refused'):
            ansible.variables(cfg,'selected',payload=proof)

    def test_discovery_preflight_precedes_trust_and_selected_execution_and_filters_scalar_slots(self):
        cfg,app=self.case('traefik');payload=self.selected_payload({'provider-record.json':b'owned provider record'})
        work=self.root/'work';work.mkdir(mode=0o700);operation=self.root/'operation';operation.mkdir(mode=0o700)
        events=[];expected={'source':'bound'}
        def execute(argv,environment,log):
            events.append('execute')
            self.assertFalse(any(k.startswith('HOMELAB_APP_SECRET_') for k in environment))
            self.assertEqual(environment['UNRELATED_SETTING'],'preserved')
            self.assertIn('StrictHostKeyChecking=yes',environment['ANSIBLE_SSH_ARGS'])
            self.assertEqual(argv[argv.index('--private-key')+1],cfg['paths']['private_key'])
            self.assertEqual(Path(argv[-3]).name,'component-reconcile.yml')
            write_new(log,b'fixture : ok=1 changed=2 failed=0\n')
        with patch.object(ansible.component_inputs,'binding',return_value=expected), \
             patch.object(ansible.component_discovery,'verify',side_effect=lambda *a:events.append('discovery')) as discovery, \
             patch.object(ansible.proxmox_guest,'dhcp_admission',side_effect=lambda *a:events.append('dhcp')), \
             patch.object(ansible.proxmox_guest,'guest_trust',side_effect=lambda *a:events.append('trust')), \
             patch.object(ansible,'quiet',side_effect=execute),patch.dict(os.environ,{
                 'HOMELAB_APP_SECRET_NODE_RED_API_TOKEN':'never native','UNRELATED_SETTING':'preserved'}):
            self.assertEqual(ansible.run_phase(cfg,self.directory/'site.json',work,operation,expected,
                'selected',payload=payload),{'status':'passed','changed':True})
        self.assertEqual(events,['discovery','dhcp','trust','execute'])
        discovery.assert_called_once_with(cfg,app,b'owned provider record')
        for failure in ('binding','discovery'):
            with self.subTest(failure=failure),patch.object(ansible.component_inputs,'binding',return_value={}
                    if failure=='binding' else expected),patch.object(ansible.component_discovery,'verify',
                    side_effect=ValueError('selected discovery refused')), \
                 patch.object(ansible.proxmox_guest,'dhcp_admission') as dhcp, \
                 patch.object(ansible,'quiet') as native,self.assertRaises(ValueError):
                ansible.run_phase(cfg,self.directory/'site.json',work,operation,expected,'selected',payload=payload)
            dhcp.assert_not_called();native.assert_not_called()


class PreparationCallerTests(CallerCase):
    def test_pihole_and_zigbee_sidecars_are_fixed_owned_leaves_inside_real_payloads(self):
        for adapter,leaf in [('pihole','dns-records.json'),('zigbee2mqtt','zigbee-settings.json')]:
            with self.subTest(adapter=adapter):
                extra={'settings':{'dns_records':{}}} if adapter=='pihole' else {}
                cfg,app=self.case(adapter,extra,lifecycle='retained')
                app['sidecar_files']=copy.deepcopy(contract.SIDECAR_FILES[adapter]);self.save()
                hook={'zigbee_state':{'settings_file':{'content':'{"synthetic":"settings"}\n'}}}
                dns={'schema':'homelab-component-dns-records-v2','records':{},'previous':{}}
                with patch.object(prepare.component_app_hooks,'descriptors',return_value=hook) as builder, \
                     patch.object(prepare,'dns_document',return_value=dns) as dns_builder:
                    proof=prepare.prepare(cfg,'selected',{},attempt=self.attempt)
                if adapter=='pihole':dns_builder.assert_called_once_with(cfg,app,self.attempt)
                else:dns_builder.assert_not_called()
                self.assertEqual(read_json(proof.directory/'runtime-files.json',private=True),[
                    {'source':leaf,**contract.SIDECAR_FILES[adapter][leaf]}])
                self.assertEqual(read_json(proof.directory/continuity.FILE,private=True)['roles'],{})
                if adapter=='zigbee2mqtt':builder.assert_called_once_with(app,compose_file='/opt/homelab-app/'+app['project_file'])
                else:builder.assert_not_called()
                for bad_app,bad_name,bad_raw,bad_payload in [
                    (dict(app,sidecar_files={}),leaf,b'owned',{}),(app,'peer.json',b'owned',{}),
                    (app,leaf,'not-bytes',{}),(app,leaf,b'owned',{leaf:b'prior'})]:
                    with self.subTest(refusal=bad_name),self.assertRaises(ValueError):
                        prepare.sidecar(bad_app,bad_name,bad_raw,bad_payload)

    def test_optional_node_without_material_has_no_late_overlay_and_foreign_slot_refuses_before_builders(self):
        cfg,app=self.case('node_red')
        with patch.object(prepare.component_private_inputs,'bind') as builder:
            proof=prepare.prepare(cfg,'selected',{},attempt=self.attempt)
        self.assertFalse((proof.directory/'environment.yml').exists());builder.assert_not_called()
        self.assertEqual(read_json(proof.directory/continuity.FILE,private=True),continuity.document(app,{}))
        cfg,app=self.case('node_red')
        with patch.object(prepare.component_private_inputs,'bind') as builder, \
             patch.object(prepare.component_monitoring_inputs,'prepare') as monitor,self.assertRaisesRegex(ValueError,'selected scalar'):
            prepare.prepare(cfg,'selected',{'HOMELAB_APP_SECRET_AUTHENTIK_SECRET_KEY':'foreign'},attempt=self.attempt)
        builder.assert_not_called();monitor.assert_not_called()
        self.assertFalse((self.directory/'applications/selected').exists())
        with self.assertRaises(TypeError):prepare.prepare(cfg,'selected',{})

    def test_mqtt_file_builder_without_environment_preserves_selected_role_proof_and_attempt(self):
        cfg,app=self.case('mqtt',lifecycle='retained')
        source=self.root/'mqtt-probe.json';raw=encoded({'username':'synthetic_probe','password':'synthetic-value'})
        write_new(source,raw);app['input_sources']={'probe':{'type':'file','path':str(source),'source_id':'broker-probe'}};self.save()
        with patch.object(prepare.component_continuity,'verify') as verifier:
            proof=prepare.prepare(cfg,'selected',{},attempt=self.attempt)
        expected=continuity.document(app,material.project(app,{'probe':raw}))
        verifier.assert_called_once_with(self.attempt,app,expected)
        self.assertEqual(read_json(proof.directory/continuity.FILE,private=True),expected)
        self.assertFalse((proof.directory/'environment.yml').exists())
        self.assertEqual({row['source'] for row in read_json(proof.directory/'runtime-files.json',private=True)}, {'mqtt-probe.json'})
        cfg,app=self.case('mqtt',lifecycle='retained');app['input_sources']={'probe':{'type':'file','path':str(source)}};self.save()
        with patch.object(prepare.component_continuity,'verify',side_effect=ValueError('prior material differs')), \
             patch.object(prepare.component_private_inputs,'bind') as builder, \
             patch.object(prepare.component_monitoring_inputs,'prepare') as monitor,self.assertRaisesRegex(ValueError,'prior material'):
            prepare.prepare(cfg,'selected',{},attempt=self.attempt)
        builder.assert_not_called();monitor.assert_not_called();self.assertFalse((self.directory/'applications/selected').exists())

    def test_traefik_publishes_only_selected_record_and_explicit_public_trust_without_discovery_calls(self):
        original,values,ca,cas,route_plan=foundation_fixtures.ingress()
        cfg,app=self.case('traefik',original,lifecycle='retained')
        source=self.root/'provider.json';write_new(source,values['proxmox_token'])
        route_ca=self.root/'route-ca.pem';write_new(route_ca,ca)
        app['input_sources']['proxmox_token']['path']=str(source)
        app['settings']['route_ca_files']['verified']['source']=str(route_ca);app['route_plan']=route_plan;self.save()
        slot=prepare.component_input_secrets.slots('traefik',app['input_sources'])['cloudflare_dns_token']
        with patch.object(prepare.component_continuity,'verify') as verifier, \
             patch.object(prepare.component_foundation_files,'files',return_value=self.rows()) as builder, \
             patch.object(ansible.component_discovery,'verify') as discovery:
            proof=prepare.prepare(cfg,'selected',{slot:values['cloudflare_dns_token'].decode()},attempt=self.attempt)
        discovery.assert_not_called()
        expected=continuity.document(app,material.project(app,values))
        verifier.assert_called_once_with(self.attempt,app,expected)
        self.assertEqual(read_json(proof.directory/continuity.FILE,private=True),expected)
        self.assertEqual((proof.directory/'provider-record.json').read_bytes(),values['proxmox_token'])
        builder.assert_called_once_with(app,secrets=values,public_ca=b'public synthetic trust\n',
            route_cas={'verified':ca},route_plan=route_plan)
        self.assertNotIn('proxmox-token',{row['source'] for row in read_json(proof.directory/'runtime-files.json',private=True)})

    def test_administrator_record_location_owner_and_duplicate_inputs_refuse_before_payload_publication(self):
        cfg,app=self.case('postgresql')
        owner={'node':'fixture-node','engine':'postgresql','database_vmid':610,'source_vmid':612,
               'server_address':'198.18.20.10','source_address':'198.18.20.12','username':'fixture_admin',
               'purpose':'database-administration'}
        name='fixture-admin';leaf=managed_credentials.input_name(name)
        app['database_administrators']={'admin':{'credential_id':name,'owner':owner,
            'credential_file':str(self.directory/'applications/selected'/leaf)}};self.save()
        proof=prepare.prepare(cfg,'selected',{},attempt=self.attempt)
        record=read_json(proof.directory/leaf,private=True)
        self.assertEqual(record['owner'],owner)
        store=Path(cfg['paths']['state_root'])/'managed-credentials'/('fixture-admin.json')
        before=(store.stat().st_ino,store.read_bytes())
        prepare.prepare(cfg,'selected',{},attempt=self.attempt)
        self.assertEqual(before,(store.stat().st_ino,store.read_bytes()))
        for kind in ('location','duplicate','owner'):
            with self.subTest(kind=kind):
                cfg,app=self.case('postgresql');row={'credential_id':name,'owner':owner,
                    'credential_file':str(self.directory/'applications/selected'/leaf)}
                app['database_administrators']={'admin':copy.deepcopy(row)}
                if kind=='location':app['database_administrators']['admin']['credential_file']=str(self.directory/'applications/peer'/leaf)
                if kind=='duplicate':app['database_administrators']['second']=copy.deepcopy(row)
                if kind=='owner':
                    managed_credentials.credential(cfg['paths']['state_root'],name,dict(owner,username='different_admin'))
                self.save()
                with self.assertRaises(ValueError):prepare.prepare(cfg,'selected',{},attempt=self.attempt)
                self.assertFalse((self.directory/'applications/selected').exists())

    def test_explorer_owned_account_creation_is_canonical_and_duplicate_credential_refuses(self):
        original,_=proxy_fixtures.explorer();cfg,app=self.case('mqtt_explorer',original)
        first={};record=prepare.account_records(cfg,app,first)
        self.assertEqual(set(record),{'fixture-gui'});self.assertEqual(set(first),{'managed-fixture-gui.json'})
        store=Path(cfg['paths']['state_root'])/'managed-credentials/fixture-gui.json'
        before=(store.stat().st_ino,store.read_bytes())
        self.assertEqual(prepare.account_records(cfg,app,{}),record)
        self.assertEqual(before,(store.stat().st_ino,store.read_bytes()))
        cloud=proxy_fixtures.cloud();proxy_fixtures.managed(cloud)
        row=next(iter(cloud['settings']['managed_connections'].values()))
        # The same credential selected twice is not two independent inputs.
        cloud['settings']['managed_connections']={'first':row,'second':copy.deepcopy(row)}
        managed_credentials.credential(cfg['paths']['state_root'],row['credential_id'],row['owner'])
        with self.assertRaisesRegex(ValueError,'one canonical'):prepare.account_records(cfg,cloud,{})


class StaticSourceBindingTests(CallerCase):
    def test_selected_route_trust_and_discovery_sources_bind_without_any_private_app_reads(self):
        cfg,app=self.case('traefik',{'settings':{'provider':{},'route_ca_files':{}}})
        ca=self.root/'route.pem';scope=self.root/'scope.json'
        write_new(ca,b'synthetic route trust');write_new(scope,b'{"synthetic":"public identity proof"}')
        app['settings']['route_ca_files']={'owned':{'source':str(ca),'filename':'route-owned.pem'}}
        app['settings']['provider']['discovery']={'local_directory':str(self.root/'discovery'),
            'mirror_directory':str(self.root/'mirror/discovery'),'owner_sha256':'b'*64,'guests':[610,611]};self.save()
        static={str(self.directory/'component-runtime.json'):sha(self.directory/'component-runtime.json')}
        with patch.object(inputs,'inspect',side_effect=lambda *args:static.copy()), \
             patch.object(inputs.discovery_scope,'scope_source_files',return_value=[str(scope)]) as discovery, \
             patch('deployment_inputs.source_hash',return_value='d'*64), \
             patch.object(prepare.component_input_secrets,'selected',side_effect=AssertionError('No static app secret read')), \
             patch.object(managed_credentials,'credential',side_effect=AssertionError('No static credential read')):
            site=self.directory/'site.json';write_new(site,encoded(cfg))
            bound=inputs.binding(cfg,site)
            discovery.assert_called_once_with(app['settings']['provider']['discovery'],[9900])
            self.assertEqual(bound['input_hashes'][str(ca)],sha(ca));self.assertEqual(bound['input_hashes'][str(scope)],sha(scope))
            write_bytes(ca,b'changed public route trust')
            with patch.object(ansible.proxmox_guest,'dhcp_admission') as native, \
                 patch.object(ansible.proxmox_guest,'guest_trust') as trust, \
                 self.assertRaisesRegex(ValueError,'changed before Ansible'):
                ansible.run_phase(cfg,site,self.root,self.root,bound,'selected')
            native.assert_not_called();trust.assert_not_called()
            app['settings']['provider'].pop('discovery');self.save();discovery.reset_mock()
            self.assertNotIn(str(scope),inputs.binding(cfg,site)['input_hashes']);discovery.assert_not_called()


if __name__=='__main__':unittest.main()
