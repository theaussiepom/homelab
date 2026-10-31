"""Pinned Agent2 plugins and source SQL against disposable native-DB namespaces.

Synthetic credentials only; no host Docker socket or production target enters a
container. This verifies SQL/plugin behavior, not a production systemd rollout.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import monitoring
import monitoring_agent

MARIA='mariadb:12.3.3@sha256:71541e69e0a1fbec2fa57d6b3b30d751c7847ca77ce66f5af4ffff48060c37c8'


def client(kind):
    assert Path('/.dockerenv').is_file() and os.geteuid()==0
    root=Path('/fixture')
    for name,pin in [('agent',monitoring_agent.AGENT_PACKAGE),('postgresql',monitoring_agent.POSTGRESQL_PACKAGE)]:
        if name=='postgresql' and kind!='postgresql':continue
        path=Path('/'+name+'.deb')
        assert hashlib.sha256(path.read_bytes()).hexdigest()==pin['sha256']
        subprocess.run(['dpkg-deb','-x',str(path),'/'],check=True,stdout=subprocess.DEVNULL)
    cfg=json.loads((root/(kind+'-config.json')).read_text())
    password=(root/'password').read_text()
    configuration=monitoring_agent.configuration(cfg,password).replace('LogType=system','LogType=console').encode()
    def invoke(arguments):
        # The short-lived plugin test needs no persisted database credential.
        # Pass the complete configuration through an inherited anonymous pipe.
        reader,writer=os.pipe()
        try:
            assert len(configuration)<4096
            os.write(writer,configuration);os.close(writer);writer=None
            return subprocess.run(['/usr/sbin/zabbix_agent2','-c','/proc/self/fd/'+str(reader),*arguments],
                                  pass_fds=(reader,),capture_output=True,text=True,check=True)
        finally:
            os.close(reader)
            if writer is not None:os.close(writer)
    Path('/etc/zabbix').mkdir(exist_ok=True);Path('/etc/zabbix/agent.psk').write_text('a'*64+'\n')
    invoke(['-T'])
    prefix='pgsql' if kind=='postgresql' else 'mysql'
    result={}
    for key in [prefix+'.ping[homelab]',prefix+('.dbstat.sum[homelab]' if kind=='postgresql' else '.get_status_variables[homelab]')]:
        run=invoke(['-t',key])
        assert 'ZBX_NOTSUPPORTED' not in run.stdout and '"error"' not in run.stdout
        if '.ping[' in key:assert float(run.stdout.rsplit('|',1)[1].strip().rstrip(']'))==1
        result[key]=True
    print(json.dumps(result))


def main(args):
    import yaml
    from ansible.plugins.loader import init_plugin_loader
    init_plugin_loader()
    from ansible.template import Templar,trust_as_template
    from ansible.parsing.dataloader import DataLoader
    prefix='zabbix-workload-fixture-'+uuid.uuid4().hex[:10]
    root=args.output.resolve()/prefix;root.mkdir(mode=0o700,parents=True)
    password=secrets.token_hex(32);(root/'password').write_text(password);(root/'password').chmod(0o600)
    tasks=yaml.safe_load((Path(__file__).resolve().parents[1]/'ansible/tasks/monitoring-database-account.yml').read_text())
    def docker(*cmd,check=True,**kw):
        try:return subprocess.run(['docker',*map(str,cmd)],timeout=180,check=check,**kw)
        except subprocess.CalledProcessError as error:
            (root/'failed-command.log').write_text(str(error.stdout or '')+'\n'+str(error.stderr or ''))
            raise
    def wait(function):
        deadline=time.monotonic()+150
        while not function():
            if time.monotonic()>=deadline:raise RuntimeError('Synthetic database readiness timed out')
            time.sleep(1)
    results={}
    try:
        docker('network','create','--internal','--subnet','198.18.157.0/24',prefix,stdout=subprocess.DEVNULL)
        for kind,image,address,env in [('postgresql',monitoring.VERSIONS['fixture_postgresql'],'198.18.157.2','POSTGRES_PASSWORD=synthetic-admin'),('mysql',MARIA,'198.18.157.3','MARIADB_ROOT_PASSWORD=synthetic-admin')]:
            container=prefix+'-'+kind
            docker('run','-d','--platform','linux/amd64','--network',prefix,'--ip',address,'--name',container,'-e',env,image,stdout=subprocess.DEVNULL)
            command=['psql','-U','postgres','-v','ON_ERROR_STOP=1'] if kind=='postgresql' else ['mariadb','-uroot','-psynthetic-admin']
            wait(lambda:docker('exec',container,*( ['pg_isready','-h','127.0.0.1','-U','postgres'] if kind=='postgresql' else [*command,'--protocol=TCP','-h','127.0.0.1','-e','SELECT 1']),capture_output=True,check=False).returncode==0)
            uri='tcp://127.0.0.1:5432' if kind=='postgresql' else 'tcp://'+address+':3306'
            task=next(t for t in tasks if t['name'].startswith('Create the dedicated PostgreSQL' if kind=='postgresql' else 'Create the MySQL statistics'))
            variables={'monitoring_db_config':{'uri':uri,'password_file':str(root/'password')}}
            sql=Templar(loader=DataLoader(),variables=variables).template(trust_as_template(task['ansible.builtin.command']['stdin']))
            docker('exec','-i',container,*command,input=sql,text=True,capture_output=True)
            if kind=='postgresql':
                task=next(t for t in tasks if t['name'].startswith('Set the new PostgreSQL'))
                argv=list(task['ansible.builtin.command']['argv']);position=argv.index('psql')+1;argv[position:position]=['-U','postgres']
                docker('exec','-i',container,*argv,input=password+'\n'+password+'\n',text=True,capture_output=True)
                task=next(t for t in tasks if t['name'].startswith('Verify the statistics role'))
                sql=task['ansible.builtin.command']['argv'][-1]
                assert docker('exec',container,*command,'-At','-c',sql,capture_output=True,text=True).stdout.strip()=='1'
                docker('exec',container,*command,'-c','CREATE TABLE private_application(secret text);',capture_output=True)
                for sql in ['CREATE DATABASE forbidden','CREATE ROLE forbidden','SELECT * FROM private_application']:
                    denied=docker('exec','-e','PGPASSWORD='+password,container,'psql','-h','127.0.0.1','-U','zbx_monitor','-d','postgres','-v','ON_ERROR_STOP=1','-c',sql,check=False,capture_output=True)
                    assert denied.returncode and b'permission denied' in denied.stderr
            else:
                grants=docker('exec',container,*command,'--batch','--skip-column-names','-e',"SELECT PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(CHAR(39),'zbx_monitor',CHAR(39),'@',CHAR(39),'198.18.157.3',CHAR(39));",capture_output=True,text=True).stdout.splitlines()
                assert set(grants)=={'PROCESS','BINLOG MONITOR','SHOW DATABASES','SHOW VIEW'}
            cfg={'site':{'node':'fixture'},'guest':{'vmid':208,'interfaces':[{'ipv4':address+'/24'}]},'deployment':{'capabilities':['linux']},'app':{'kind':'postgresql' if kind=='postgresql' else 'mariadb','monitoring':{'hostname':'fixture-208','psk_identity':'fixture-208','profiles':['linux','postgresql' if kind=='postgresql' else 'mysql'],'server_active':'198.18.157.9:10051','server_vmid':216,'credential_file':'/fixture/agent.json','database_uri':uri,'database_password_file':'/fixture/password'}}}
            if kind=='postgresql':cfg['app']['monitoring']['storage_password_file']='/fixture/storage'
            (root/(kind+'-config.json')).write_text(json.dumps(cfg))
            run=docker('run','--rm','--platform','linux/amd64','--network','container:'+container,
                       '-v',str(Path(__file__).resolve().parents[3])+':/src:ro','-v',str(root)+':/fixture:ro',
                       '-v',str(args.agent.resolve())+':/agent.deb:ro','-v',str(args.postgresql.resolve())+':/postgresql.deb:ro',
                       'homelab-app-test','python3','/src/proxmox/applications/tests/monitoring_workload_fixture.py','--client',kind,capture_output=True,text=True)
            (root/(kind+'-client.log')).write_text(run.stdout+run.stderr)
            results[kind]=json.loads(run.stdout.splitlines()[-1])
        (root/'result.json').write_text(json.dumps({'metrics':results,'postgresql_no_admin_or_application_rows':True,'mariadb_finite_statistics_grants':True,'scope':'Disposable owning-network namespaces and pinned Agent2 plugins; no native rollout.'},indent=2)+'\n')
        print((root/'result.json').read_text())
    finally:
        for kind in ('postgresql','mysql'):
            logs=docker('logs',prefix+'-'+kind,check=False,capture_output=True,text=True)
            (root/(kind+'-server.log')).write_text(logs.stdout+logs.stderr)
            docker('rm','-fv',prefix+'-'+kind,check=False,capture_output=True)
        docker('network','rm',prefix,check=False,capture_output=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--client',choices=['postgresql','mysql'])
    p.add_argument('--agent',type=Path);p.add_argument('--postgresql',type=Path);p.add_argument('--output',type=Path)
    args=p.parse_args()
    client(args.client) if args.client else main(args)
