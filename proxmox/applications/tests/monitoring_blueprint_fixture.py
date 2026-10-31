"""Test the production API configurator against disposable local Zabbix data.

Only loopback ports are published. No host Docker socket, production endpoint,
credential or data directory enters a container. Cleanup selects this UUID's
project only and retains its synthetic failure evidence.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring
import monitoring_configure
import monitoring_agent
import monitoring_templates


def main(output):
    name = 'zabbix-blueprint-fixture-' + uuid.uuid4().hex[:10]
    root = output.resolve() / name
    root.mkdir(parents=True, mode=0o700)
    password = secrets.token_hex(32)
    key = secrets.token_hex(32)
    document = {'services': {
        'postgres': {'image': monitoring.VERSIONS['fixture_postgresql'], 'platform': 'linux/amd64',
                     'environment': {'POSTGRES_PASSWORD': password, 'POSTGRES_DB': 'zabbix'},
                     'healthcheck': {'test': ['CMD', 'pg_isready', '-U', 'postgres'],
                                     'interval': '2s', 'timeout': '2s', 'retries': 60}},
        'zabbix_server': {'image': monitoring.VERSIONS['zabbix_server'], 'platform': 'linux/amd64',
                         'environment': {'DB_SERVER_HOST': 'postgres', 'POSTGRES_USER': 'postgres',
                                         'POSTGRES_PASSWORD': password, 'POSTGRES_DB': 'zabbix'},
                         'depends_on': {'postgres': {'condition': 'service_healthy'}}},
        'zabbix_web': {'image': monitoring.VERSIONS['zabbix_web'], 'platform': 'linux/amd64',
                      'environment': {'DB_SERVER_HOST': 'postgres', 'POSTGRES_USER': 'postgres',
                                      'POSTGRES_PASSWORD': password, 'POSTGRES_DB': 'zabbix',
                                      'ZBX_SERVER_HOST': 'zabbix_server'},
                      'ports': ['127.0.0.1::8080'],
                      'depends_on': ['zabbix_server']},
        'docker_mock': {'image': 'homelab-app-test', 'platform': 'linux/amd64', 'pull_policy': 'never',
                        'entrypoint': ['python3','-c','import sys,threading;sys.path.insert(0,"/tests");import docker_api_mock;s=docker_api_mock.start();threading.Event().wait()'],
                        'volumes': [str(Path(__file__).resolve().parent)+':/tests:ro','mock:/mock-docker']}},
        'volumes': {'mock':{}}}
    path = root/'compose.json';path.write_text(json.dumps(document));path.chmod(0o600)
    command = ['docker', 'compose', '-p', name, '-f', str(path)]
    try:
        subprocess.run(command + ['up', '-d'], check=True, timeout=600)
        ports = subprocess.check_output(command + ['port', 'zabbix_web', '8080'], text=True).strip()
        assert ports.startswith('127.0.0.1:')
        api = monitoring_configure.API(int(ports.rsplit(':',1)[1]))
        deadline = time.monotonic() + 240
        while True:
            try:
                version = api('apiinfo.version', {})
                break
            except Exception:
                if time.monotonic() >= deadline:raise RuntimeError('Local fixture API startup timeout') from None
                time.sleep(2)
        assert version == monitoring.VERSIONS['version']
        value = {'owner': {'node': 'fixture', 'vmid': 216, 'hostname': 'zabbix'},
                 'admin_password': 'Zbx!7' + secrets.token_hex(32),
                 'templates': [monitoring_templates.prepared(n) for n in monitoring.VERSIONS['templates']],
                 'members': [{'hostname': 'fixture-208', 'psk_identity': 'fixture-208',
                              'psk': key, 'profiles': ['linux', 'docker']},
                             {'hostname': 'fixture-postgresql', 'psk_identity': 'fixture-postgresql',
                              'psk': secrets.token_hex(32), 'profiles': ['linux', 'postgresql']},
                             {'hostname': 'fixture-mysql', 'psk_identity': 'fixture-mysql',
                              'psk': secrets.token_hex(32), 'profiles': ['linux', 'mysql']},
                             {'hostname': 'fixture-influxdb', 'psk_identity': 'fixture-influxdb',
                              'psk': secrets.token_hex(32), 'profiles': ['linux', 'influxdb'],
                              'url': 'http://198.18.33.26:8086'}],
                 'proxmox': {'hostname': 'fixture-pve', 'endpoint': 'https://198.18.25.10:8006/',
                             'token_id': 'fixture@pve!monitoring', 'token_secret': 'synthetic-token'}}
        first = monitoring_configure.configure(api, value, root/'owner.json')
        second = monitoring_configure.configure(api, value, root/'owner.json')
        api.token = api('user.login', {'username': 'Admin', 'password': value['admin_password']})
        hosts = api('host.get', {'output': ['hostid','host','tls_accept','description'],
                                 'selectParentTemplates': ['host']})
        selected = {h['host']: h for h in hosts if h['host'].startswith('fixture-')}
        assert set(selected) == {m['hostname'] for m in value['members']} | {'fixture-pve'}
        for member in value['members']:
            row = selected[member['hostname']]
            assert row['tls_accept'] == '2'
            assert {t['host'] for t in row['parentTemplates']} == {
                monitoring_configure.PROFILE_TEMPLATES[p] for p in member['profiles']}
        http = api('item.get', {'hostids': [selected['fixture-pve']['hostid']],
                               'filter': {'type':19}, 'output':['verify_peer','verify_host']})
        assert http and all(r['verify_peer']=='1' and r['verify_host']=='1' for r in http)
        # Exercise production active/Docker configuration against the actual
        # pinned Agent2. The Docker socket belongs only to a synthetic API.
        server_id=subprocess.check_output(command+['ps','-q','zabbix_server'],text=True).strip()
        server_network=json.loads(subprocess.check_output(['docker','inspect',server_id],text=True))[0]['NetworkSettings']['Networks']
        server_address=server_network[name+'_default']['IPAddress']
        agent_value={'site':{'node':'fixture'},'guest':{'vmid':208,'interfaces':[]},
                     'deployment':{'capabilities':['linux','docker']},
                     'app':{'kind':'automation','monitoring':{'hostname':'fixture-208','psk_identity':'fixture-208',
                         'server_active':server_address+':10051','server_vmid':216,'profiles':['linux','docker'],
                         'credential_file':'/fixture/agent.json'}}}
        configuration=monitoring_agent.configuration(agent_value).replace('LogType=system','LogType=console').replace('/run/zabbix/agent.sock','/tmp/agent.sock').replace('unix:///var/run/docker.sock','unix:///mock-docker/docker.sock')
        conf=root/'agent.conf';conf.write_text(configuration);conf.chmod(0o644)
        psk=root/'agent.psk';psk.write_text(key+'\n');psk.chmod(0o644)
        document['services']['agent']={'image':monitoring.VERSIONS['fixture_agent'],'platform':'linux/amd64',
             'entrypoint':['/usr/sbin/zabbix_agent2','-f','-c','/etc/zabbix/zabbix_agent2.conf'],
             'volumes':[str(conf)+':/etc/zabbix/zabbix_agent2.conf:ro',str(psk)+':/etc/zabbix/agent.psk:ro','mock:/mock-docker:ro']}
        path.write_text(json.dumps(document))
        hostid=selected['fixture-208']['hostid']
        for item_key in ('system.uptime','docker.info'):
            item=api('item.get',{'hostids':[hostid],'filter':{'key_':item_key},'output':['itemid','type']})[0]
            assert item['type']=='7'
            api('item.update',{'itemid':item['itemid'],'delay':'1s'})
        subprocess.run(command+['up','-d','agent'],check=True,timeout=120)
        deadline=time.monotonic()+180
        keys=['system.uptime','docker.containers.running']
        while True:
            samples=api('item.get',{'hostids':[hostid],'filter':{'key_':keys},'output':['key_','lastclock','lastvalue','state']})
            if len(samples)==2 and all(int(row['lastclock'])>0 and row['state']=='0' and float(row['lastvalue'])>0 for row in samples):break
            if time.monotonic()>=deadline:raise RuntimeError('Fresh PSK Linux/Docker metrics did not arrive')
            time.sleep(2)
        result = {'fixture':name, 'zabbix_version':version, 'first_install':first['first_install'],
                  'second_install_preserved':not second['first_install'], 'managed_hosts':len(selected),
                  'all_selected_templates_linked':True, 'agent_PSK_only':True,
                  'proxmox_full_TLS_items':True, 'fresh_active_Linux_and_Docker_metrics':True,
                  'limits':'Real API/linkage, repeatability and Agent2 PSK Linux/Docker synthetic data. No production/native guest acceptance.'}
        (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result))
    except Exception:
        if 'api' in locals():
            (root/'api-error-metadata.json').write_text(json.dumps(api.last_error))
        raise
    finally:
        log = subprocess.run(command + ['logs','--no-color'], capture_output=True, text=True)
        (root/'services.log').write_text(log.stdout + log.stderr)
        subprocess.run(command + ['down','--volumes','--remove-orphans'], check=True, timeout=60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    main(parser.parse_args().output)
