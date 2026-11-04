"""Three owned app units; common helpers mocked, exact baseline once per app."""
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
F=Path(Path(__file__).resolve().parents[3]).resolve()
sys.path[:0]=[str(F/'proxmox/applications'),str(F/'blueprints')]


import bitwarden
import pegaprox
import foundation
import component_runtime as core
BASELINE=json.loads((HERE/'edge-compose-baseline.json').read_text())


def listener(service,port,address=None):
    row={'service':service,'port':port,'protocol':'tcp','namespace':'app-network',
         'interface':'private','bind':'wildcard','actual_bind':'0.0.0.0'}
    if address:row.update(publication_address=address,publish={'port':port,'scope':'guest-interface','interface':'web'})
    return row


def descriptor(adapter):
    expected=BASELINE[adapter]; service=expected['services'][adapter]
    app={'id':'app-a','adapter':adapter,'lifecycle':'retained','project_name':expected['name'],
         'identity':{'services':{adapter:adapter},'networks':{} if adapter=='traefik' else {'default':'default'}},
         'containers':{adapter:{'memory_mib':int(service['mem_limit'][:-1]),'cpu_limit':service['cpus'],'pids_limit':service['pids_limit']}},
         'software_selection':{'images':{adapter:{'image':service['image']}}},'role_addresses':{},'settings':{},'properties':{},'storage_paths':{}}
    if adapter=='bitwarden':
        app['software_selection']['images']['bitwarden']={'image':'ghcr.io/bitwarden/lite:latest'}
        app['settings']={'settings':{'schema':'homelab-bitwarden-runtime-v1',
            'image_id':service['image'],'bind_address':'198.18.30.35',
            'database_server':'198.18.32.35','database_provider':'mysql','database_name':'vault',
            'data_uid':1000,'data_gid':1000},'runtime':{'environment_sha256':'a'*64}}
        app['storage_paths']={name:{'source':'/srv/homelab/data/bitwarden/'+name,'target':target,'kind':'directory','read_only':False} for name,target in [('data','/etc/bitwarden'),('logs','/var/log/bitwarden')]}
        app['listeners']={'web':listener('bitwarden',8080,'198.18.30.35')}
    elif adapter=='pegaprox':
        app['identity']['runtime_directory']='/opt/homelab-app/runtime'
        app['secret_bindings']={'database_key':{'type':'file','path':'/run/synthetic/key'}}
        app['settings']={'trusted_proxy':'198.18.25.33/32'};app['role_addresses']={'web':'198.18.25.34'}
        app['storage_paths']={name:{'source':'/srv/homelab/data/pegaprox/'+name,'target':'/app/'+name,'kind':'directory','read_only':False} for name in ('config','logs')}
        app['containers']['pegaprox'].update(read_only=True,cap_drop=['ALL'],no_new_privileges=True,tmpfs=['/tmp:rw,nosuid,nodev,size=64m'])
        app['listeners']={'web':listener('pegaprox',5000,'198.18.25.34')}
    else:
        app['identity']['runtime_directory']='/opt/homelab-app/runtime'
        app['secret_bindings']={'cloudflare_dns_token':{'type':'file','path':'/run/synthetic/dns'},'proxmox_token':{'type':'file','path':'/run/synthetic/provider'}}
        app['settings']={'provider':{'url':'https://198.18.25.10:8006'},'acme':{'propagation_timeout_seconds':2100},
                        'route_ca_files':{'proxmox':{'source':'/run/synthetic/ca.pem','filename':'route-proxmox.pem'}}}
        app['storage_paths']={'certs':{'source':'/srv/homelab/data/traefik/certs','target':'/var/traefik/certs','kind':'directory','read_only':False}}
        app['listeners']={str(port):dict(listener('traefik',port),namespace='host',interface='frontend',bind='interface',actual_bind='198.18.40.33') for port in (80,443)}
    return app


def guest(adapter):return {'timezone':'Australia/Brisbane','memory_mib':2048,'os_reserve_mib':512 if adapter=='pegaprox' else 256}


def units(app):
    stack=ExitStack()
    stack.enter_context(mock.patch.object(bitwarden,'validate_settings'))
    stack.enter_context(mock.patch.object(core,'_service',side_effect=lambda a,n,g:{'image':a['software_selection']['images'][n]['image'],'environment':{'TZ':g['timezone']},'volumes':[]}))
    stack.enter_context(mock.patch.object(core,'_ports',side_effect=lambda a,n:[r['publication_address']+':'+str(r['publish']['port'])+':'+str(r['port'])+'/tcp' for r in a['listeners'].values() if r['service']==n and 'publish'in r]))
    stack.enter_context(mock.patch.object(core,'_mounts',return_value=[]))
    stack.enter_context(mock.patch.object(core,'_runtime_mount',side_effect=lambda a,n,t:{'type':'bind','source':a['identity']['runtime_directory']+'/'+n,'target':t,'read_only':True,'bind':{'create_host_path':False}}))
    return stack


class BitwardenTests(unittest.TestCase):
    def test_preview_has_no_invented_timezone_user_or_process_and_uses_observed_image(self):
        app=descriptor('bitwarden')
        with units(app):result=core._bitwarden(app,guest('bitwarden'))['bitwarden']
        self.assertEqual(result['environment'],{})
        self.assertEqual(result['image'],app['settings']['settings']['image_id'])
        self.assertNotIn('user',result);self.assertNotIn('command',result)
        self.assertEqual(result['healthcheck'],BASELINE['bitwarden']['services']['bitwarden']['healthcheck'])
        self.assertEqual(result['volumes'],BASELINE['bitwarden']['services']['bitwarden']['volumes'])

    def test_only_internal_prepared_environment_is_consumed_and_compose_dollars_are_literal(self):
        app=descriptor('bitwarden');app['private_environment']={'BW_DB_PASSWORD':'synthetic-$value','TZ':'Etc/UTC','PUID':'1000'}
        with units(app),mock.patch('builtins.open',side_effect=AssertionError('No private input read')):
            result=core._bitwarden(app,guest('bitwarden'))['bitwarden']
        self.assertEqual(result['environment'],{'BW_DB_PASSWORD':'synthetic-$$value','TZ':'Etc/UTC','PUID':'1000'})
        self.assertNotIn('user',result)
        app['private_environment'].pop('TZ')
        with units(app):self.assertNotIn('TZ',core._bitwarden(app,guest('bitwarden'))['bitwarden']['environment'])

    def test_image_selection_and_state_process_environment_fail_closed(self):
        changes=[lambda a:a.update(lifecycle='fresh'),lambda a:a['settings']['settings'].update(image_id='latest'),
            lambda a:a['software_selection']['images']['bitwarden'].update(image='example/foreign@sha256:'+'a'*64),
            lambda a:a['containers']['bitwarden'].update(user='1000'),lambda a:a['storage_paths'].pop('logs'),
            lambda a:a['storage_paths']['data'].update(read_only=True),lambda a:a.update(private_environment={}),
            lambda a:a.update(private_environment={'BAD':True}),lambda a:a.update(private_environment={'BAD':'line\nbreak'}),
            lambda a:a['listeners']['web'].update(port=80),lambda a:a.update(listeners={})]
        for change in changes:
            app=descriptor('bitwarden');change(app)
            with self.subTest(change=change),units(app),self.assertRaises(ValueError):core._bitwarden(app,guest('bitwarden'))

    def test_immutable_official_and_retained_archive_selections_are_not_rewritten(self):
        for selected in ({'image':'ghcr.io/bitwarden/lite@sha256:'+'b'*64},
                         {'image':'sha256:'+'0'*64,'archive':'/run/synthetic/lite.tar','archive_sha256':'c'*64}):
            app=descriptor('bitwarden');app['software_selection']['images']['bitwarden']=selected
            with units(app):result=core._bitwarden(app,guest('bitwarden'))['bitwarden']
            self.assertEqual(result['image'],selected['image'])


class PegaProxTests(unittest.TestCase):
    def test_rootfs_data_key_mount_and_hardening_preserve_protocol(self):
        app=descriptor('pegaprox');app['identity']['runtime_directory']='/opt/homelab-app/runtime/proxy-a'
        with units(app):result=core._pegaprox(app,guest('pegaprox'))['pegaprox']
        self.assertEqual(result['platform'],'linux/amd64');self.assertTrue(result['read_only'])
        self.assertEqual(result['cap_drop'],['ALL']);self.assertEqual(result['security_opt'],['no-new-privileges:true'])
        self.assertEqual(result['tmpfs'],['/tmp:rw,nosuid,nodev,size=64m'])
        self.assertEqual(result['volumes'][-1]['source'],'/opt/homelab-app/runtime/proxy-a/pegaprox-db-key')
        self.assertTrue(result['volumes'][-1]['read_only'])
        self.assertEqual(result['environment'],BASELINE['pegaprox']['services']['pegaprox']['environment'])
        self.assertNotIn('user',result)

    def test_resource_reserve_floor_and_source_process_capability_boundaries(self):
        for change in [lambda a:a['secret_bindings'].clear(),lambda a:a['containers']['pegaprox'].update(memory_mib=768),
            lambda a:a['containers']['pegaprox'].update(cpu_limit=3),lambda a:a['containers']['pegaprox'].update(pids_limit=513),
            lambda a:a['containers']['pegaprox'].update(read_only=False),lambda a:a['containers']['pegaprox'].update(user='root'),
            lambda a:a['storage_paths'].pop('config'),lambda a:a['storage_paths']['logs'].update(read_only=True),
            lambda a:a['software_selection']['images']['pegaprox'].update(image='example/foreign@sha256:'+'a'*64),
            lambda a:a['settings'].update(trusted_proxy='198.18.25.0/24'),lambda a:a['settings'].update(trusted_proxy='198.18.25.34/32'),
            lambda a:a['settings'].update(trusted_proxy='192.0.2.1/32'),lambda a:a['listeners']['web'].update(port=443)]:
            app=descriptor('pegaprox');change(app)
            with self.subTest(change=change),units(app),self.assertRaises(ValueError):core._pegaprox(app,guest('pegaprox'))
        for changed in [dict(guest('pegaprox'),os_reserve_mib=256),dict(guest('pegaprox'),memory_mib=1792)]:
            with self.subTest(guest=changed),units(descriptor('pegaprox')),self.assertRaises(ValueError):core._pegaprox(descriptor('pegaprox'),changed)


class TraefikTests(unittest.TestCase):
    def test_selected_provider_acme_routes_and_certificate_store_mounts_are_exact(self):
        app=descriptor('traefik');app['identity']['runtime_directory']='/opt/homelab-app/runtime/ingress-a'
        with units(app):result=core._traefik(app,guest('traefik'))['traefik']
        self.assertEqual(result['network_mode'],'host')
        self.assertEqual(result['command'],['--configFile=/etc/traefik/traefik.yml'])
        self.assertEqual(result['environment']['CLOUDFLARE_PROPAGATION_TIMEOUT'],'2100')
        self.assertEqual(result['environment']['CF_DNS_API_TOKEN_FILE'],'/run/secrets/cloudflare-dns-token')
        self.assertEqual(result['environment']['SSL_CERT_FILE'],'/etc/ssl/certs/homelab-pve.pem')
        self.assertEqual(result['volumes'][-1]['source'],'/opt/homelab-app/runtime/ingress-a/route-proxmox.pem')
        self.assertTrue(all(row.get('read_only') for row in result['volumes'] if row['target']!='/var/traefik/certs'))
        self.assertNotIn('ports',result);self.assertNotIn('user',result)
        self.assertNotIn('/var/run/docker.sock',[row['target'] for row in result['volumes']])

    def test_omitted_timeout_does_not_inject_one_and_no_unselected_route_ca_is_bound(self):
        app=descriptor('traefik');app['settings']['acme']={};app['settings']['route_ca_files']={}
        with units(app):result=core._traefik(app,guest('traefik'))['traefik']
        self.assertNotIn('CLOUDFLARE_PROPAGATION_TIMEOUT',result['environment'])
        self.assertFalse(any('/route-' in row['target'] for row in result['volumes']))

    def test_source_capability_secret_namespace_filename_and_timeout_drift_refuse(self):
        changes=[lambda a:a['settings'].pop('provider'),lambda a:a['secret_bindings'].pop('cloudflare_dns_token'),
            lambda a:a['containers']['traefik'].update(user='root'),lambda a:a['storage_paths']['certs'].update(read_only=True),
            lambda a:a['settings']['acme'].update(propagation_timeout_seconds=2101),
            lambda a:a['settings']['acme'].update(propagation_timeout_seconds=True),
            lambda a:a['settings']['route_ca_files']['proxmox'].update(filename='../ca.pem'),
            lambda a:a['settings']['route_ca_files'].update({'../../foreign':{'source':'/run/synthetic/ca.pem','filename':'route-../../foreign.pem'}}),
            lambda a:a['listeners']['80'].update(port=8080)]
        for change in changes:
            app=descriptor('traefik');change(app)
            with self.subTest(change=change),units(app),self.assertRaises(ValueError):core._traefik(app,guest('traefik'))


class BaselineIntegrationTests(unittest.TestCase):
    def test_each_real_handler_and_common_helpers_match_complete_preserved_service(self):
        for adapter,expected in BASELINE.items():
            app=descriptor(adapter);cfg={'schema':'homelab-component-runtime-v1','guest':guest(adapter),'applications':{'a':app}}
            with self.subTest(adapter=adapter):self.assertEqual(next(iter(core.compositions(cfg).values())),expected)

    def test_relabel_and_declared_data_rebinding_change_only_owned_sources(self):
        for adapter in BASELINE:
            app=descriptor(adapter);before=core.HANDLERS[adapter](app,guest(adapter))
            original=copy.deepcopy(app)
            for row in app['storage_paths'].values():row['source']=row['source'].replace('/srv/homelab/data/','/srv/example/alternate/')
            if 'runtime_directory'in app['identity']:app['identity']['runtime_directory']='/opt/homelab-app/runtime/alternate'
            after=core.HANDLERS[adapter](app,guest(adapter))
            changed={key:copy.deepcopy(value) for key,value in after.items()}
            for value in changed.values():
                for mount in value['volumes']:
                    mount['source']=mount['source'].replace('/srv/example/alternate/','/srv/homelab/data/').replace('/opt/homelab-app/runtime/alternate/','/opt/homelab-app/runtime/')
            self.assertEqual(changed,before)
            self.assertNotEqual(app['storage_paths'],original['storage_paths'])


if __name__=='__main__':unittest.main()
