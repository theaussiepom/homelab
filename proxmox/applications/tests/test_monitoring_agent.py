"""Native agent settings are closed, active-only and tied to each guest."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_agent as agent


def cfg(kind='dns', docker=False):
    selected = {'hostname':'fixture-208','psk_identity':'fixture-208',
                'server_active':'198.18.25.36:10051','server_vmid':216,
                'credential_file':'/private/inputs/monitoring-agent.json'}
    c = {'app':{'kind':kind,'monitoring':selected},
         'guest':{'vmid':208,'hostname':kind,'interfaces':[{'ipv4':'198.18.31.23/24'}, {'ipv4':'manual'}, {'ipv4':'dhcp'}]},
         'site':{'node':'fixture','api_endpoint':'https://198.18.25.10:8006/'},
         'paths':{'ca_file':'/private/ca.pem'},
         'deployment':{'contract':2,'capabilities':['linux']+(['docker'] if docker else [])}}
    selected['profiles'] = agent.profiles(c)
    if kind in {'postgresql','mariadb'}:
        selected.update(database_uri='tcp://127.0.0.1:'+('5432' if kind=='postgresql' else '3306'),
                        database_password_file='/private/inputs/monitoring-database-password')
    if kind=='postgresql':selected['storage_password_file']='/private/inputs/monitoring-storage-password'
    if kind=='monitoring':
        selected['server_vmid']=208
        selected.update(server_file='/private/inputs/monitoring-server.json',postgresql_address='198.18.31.23',
                        influxdb_address='198.18.33.26',proxmox={'hostname':'fixture','endpoint':c['site']['api_endpoint'],'ca_file':c['paths']['ca_file']},
                        members=[{'guest':'monitoring','vmid':208,'guest_hostname':'zabbix','hostname':'fixture-208',
                                  'psk_identity':'fixture-208','profiles':['linux','docker']},
                                 {'guest':'influxdb','vmid':204,'guest_hostname':'influxdb','hostname':'fixture-204',
                                  'psk_identity':'fixture-204','profiles':['linux','docker','influxdb'],'url':'http://198.18.33.26:8086'}])
    return c


class AgentTests(unittest.TestCase):
    def test_active_linux_docker_and_owning_database_sessions(self):
        for kind,docker in [('dns',False),('automation',True),('postgresql',False),('mariadb',False),('monitoring',True)]:
            with self.subTest(kind=kind):
                c=cfg(kind,docker);text=agent.configuration(c, 'a'*64)
                self.assertIn('ServerActive=198.18.25.36:10051',text)
                self.assertIn('TLSConnect=psk',text)
                self.assertNotIn('\nServer=',text)
                self.assertNotIn('UnsafeUserParameters',text)
                self.assertEqual('Plugins.Docker.Endpoint=' in text,docker)
                self.assertEqual('User=zbx_monitor' in text,kind in {'postgresql','mariadb'})
                self.assertEqual('Plugins.PostgreSQL.System.Path=' in text,kind=='postgresql')
        own=cfg('mariadb');own['app']['monitoring']['database_uri']='tcp://198.18.31.23:3306'
        self.assertIn('Uri=tcp://198.18.31.23:3306',agent.configuration(own,'b'*64))

    def test_bad_identity_endpoint_paths_profiles_and_database_destinations_refuse(self):
        for field,value in [('extra',True),('hostname','foreign'),('psk_identity','foreign'),('profiles',['linux','docker']),
                            ('server_active','8.8.8.8:10051'),('server_active','10.0.0.1:10050'),
                            ('server_vmid',True),('server_vmid',99),('credential_file','relative'),('credential_file','/private/../escape')]:
            c=cfg();c['app']['monitoring'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):agent.configuration(c)
        for uri in ['tcp://10.99.0.3:5432','tcp://127.0.0.1:3306','http://127.0.0.1:5432',
                    'tcp://user:secret@127.0.0.1:5432','tcp://127.0.0.1:5432/path','tcp://127.0.0.1:5432?q=1',
                    'tcp://127.0.0.1:5432#fragment']:
            c=cfg('postgresql');c['app']['monitoring']['database_uri']=uri
            with self.subTest(uri=uri),self.assertRaises(ValueError):agent.configuration(c,'a'*64)
        for password in [None,'', 'x'*64,'a'*63]:
            with self.subTest(password_type=type(password).__name__),self.assertRaises(ValueError):agent.configuration(cfg('postgresql'),password)

    def test_server_inventory_rejects_foreign_extra_or_ambiguous_members(self):
        good=cfg('monitoring',True)
        self.assertEqual(agent.validate(good),good['app']['monitoring'])
        inactive=copy.deepcopy(good);inactive['app']['monitoring']['members']=[]
        self.assertEqual(agent.validate(inactive)['members'],[])
        mutations=[lambda x:x.update(members={}), lambda x:x['members'].append(copy.deepcopy(x['members'][0])),
                   lambda x:x['members'][0].update(extra='foreign'), lambda x:x['members'][0].update(profiles=['docker']),
                   lambda x:x['members'][0].update(profiles=['linux','unknown']),lambda x:x['members'][0].update(profiles=['linux','linux']),
                   lambda x:x['members'][0].update(vmid=True),lambda x:x['members'][0].update(hostname='foreign'),
                   lambda x:x['members'][0].update(guest_hostname='not a hostname'),lambda x:x['members'][1].update(url='http://foreign/'),
                   lambda x:x.update(server_vmid=999),lambda x:x['proxmox'].update(endpoint='https://foreign/'),
                   lambda x:x.update(postgresql_address='8.8.8.8')]
        for mutate in mutations:
            c=copy.deepcopy(good);mutate(c['app']['monitoring'])
            with self.subTest(case=mutations.index(mutate)),self.assertRaises(ValueError):agent.validate(c)
