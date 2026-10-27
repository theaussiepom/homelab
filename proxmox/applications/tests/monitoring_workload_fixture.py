"""Real Agent2 PostgreSQL/MySQL sessions against isolated synthetic databases.

Renders the CREATE statements from the shared native account tasks. This checks
SQL and exact plugin binaries, not native systemd or the Ansible target lifecycle.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring
import monitoring_profiles
from foundation_cd import write_new

MARIA = 'mariadb:12.3.3@sha256:71541e69e0a1fbec2fa57d6b3b30d751c7847ca77ce66f5af4ffff48060c37c8'


def client():
    import yaml
    from ansible.plugins.loader import init_plugin_loader
    init_plugin_loader()
    from ansible.template import Templar
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import trust_as_template
    root = Path('/fixture')
    for archive, expected in [(Path('/agent.deb'), 'd846b7f6b2eae0d5457decf6f0814df8169361d3335aa900d93e0eb838ab36e7'),
                              (Path('/postgresql.deb'), monitoring_profiles.POSTGRESQL_PLUGIN['sha256'])]:
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected
        subprocess.run(['dpkg-deb', '-x', archive, '/'], check=True)
    # Linux bind mounts retain the runner's UID (usually 1001), whereas this
    # disposable extraction client is root. Copy into its private tmpfs instead
    # of changing host file ownership or weakening the production owner guard.
    secret_root = Path('/run/secrets'); secret_root.mkdir(mode=0o700, exist_ok=True)
    password = secret_root / 'monitor-password'
    write_new(password, (root / 'monitor-password').read_bytes())
    config = {'postgresql': {'uri':'tcp://198.18.157.2:5432', 'password_file':str(password)},
              'mysql': {'uri':'tcp://198.18.157.3:3306', 'password_file':str(password)}}
    tasks = yaml.safe_load(Path('/src/proxmox/common/ansible/zabbix-database-account.yml').read_text())
    for kind, title in [('postgresql', 'Create the dedicated PostgreSQL'), ('mysql', 'Create the MySQL statistics')]:
        task = next(t for t in tasks if t['name'].startswith(title))
        # Source address for this disposable network; native role requires a
        # guest-local session before reaching these same CREATE statements.
        variables = {'monitoring_db_config':config[kind]}
        if kind == 'mysql': variables['monitoring_db_config'] = dict(config[kind], uri='tcp://198.18.157.4:3306')
        sql = Templar(loader=DataLoader(), variables=variables).template(trust_as_template(task['ansible.builtin.command']['stdin']))
        (root / (kind + '.sql')).write_text(sql)
    Path('/etc/zabbix').mkdir(exist_ok=True)
    Path('/run/zabbix').mkdir(exist_ok=True)
    Path('/etc/zabbix/agent.psk').write_text('a' * 64 + '\n')
    Path('/etc/zabbix/homelab-monitoring.conf').write_text(monitoring_profiles.plugin_config(config))
    conf = root / 'agent.conf'
    conf.write_text(monitoring.agent_config({'hostname':'fixture-db', 'server_active':'198.18.157.9:10051',
        'psk_identity':'fixture-db', 'psk_path':'/etc/zabbix/agent.psk', 'plugins':True}).replace('LogType=system','LogType=console'))
    subprocess.run(['/usr/sbin/zabbix_agent2','-T','-c',conf],check=True)
    # Parent creates accounts after the real source SQL is rendered.
    (root / 'ready').touch()
    until = time.monotonic() + 120
    while not (root / 'accounts-created').exists():
        if time.monotonic() > until: raise RuntimeError('Account setup did not complete')
        time.sleep(1)
    results = {}
    for key in ['pgsql.ping[homelab]', 'pgsql.dbstat.sum[homelab]', 'mysql.ping[homelab]', 'mysql.get_status_variables[homelab]']:
        result = subprocess.run(['/usr/sbin/zabbix_agent2','-c',conf,'-t',key],capture_output=True,text=True,check=True)
        assert 'ZBX_NOTSUPPORTED' not in result.stdout and '"error"' not in result.stdout, result.stdout
        if '.ping[' in key: assert float(result.stdout.rsplit('|', 1)[1].rstrip().rstrip(']')) == 1, result.stdout
        results[key] = True
    (root / 'result.json').write_text(json.dumps(results))


def main(args):
    prefix = 'homelab-monitor-plugins-' + uuid.uuid4().hex[:10]
    def docker(*cmd, **kw):
        return subprocess.run(['docker',*map(str,cmd)],timeout=180,check=kw.pop('check',True),**kw)
    with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
        root = Path(tmp); root.chmod(0o755)
        password = 'synthetic-database-monitor-password-1234'
        write_new(root / 'monitor-password', password.encode())
        def wait(condition):
            until = time.monotonic()+150
            while not condition():
                if time.monotonic()>until: raise RuntimeError('Workload fixture timed out')
                time.sleep(1)
        try:
            docker('network','create','--internal','--subnet','198.18.157.0/24',prefix,stdout=subprocess.DEVNULL)
            for kind, image, address, env in [('pg',monitoring.VERSIONS['fixture_postgresql'],'198.18.157.2','POSTGRES_PASSWORD=synthetic-admin'),
                                             ('mysql',MARIA,'198.18.157.3','MARIADB_ROOT_PASSWORD=synthetic-admin')]:
                docker('run','-d','--platform','linux/amd64','--network',prefix,'--ip',address,'--name',prefix+'-'+kind,
                    '-e',env,'-v',str(root)+':/fixture',image,stdout=subprocess.DEVNULL)
            wait(lambda: docker('exec',prefix+'-pg','pg_isready','-U','postgres',capture_output=True,check=False).returncode==0)
            wait(lambda: docker('exec',prefix+'-mysql','mariadb','-uroot','-psynthetic-admin','-e','SELECT 1',capture_output=True,check=False).returncode==0)
            docker('run','-d','--platform','linux/amd64','--network',prefix,'--ip','198.18.157.4','--name',prefix+'-client',
                '--tmpfs','/run/secrets:rw,nosuid,nodev,size=1m,mode=0700',
                '-v',str(Path(__file__).resolve().parents[3])+':/src:ro','-v',str(root)+':/fixture',
                '-v',str(args.agent.resolve())+':/agent.deb:ro','-v',str(args.postgresql.resolve())+':/postgresql.deb:ro',
                args.tools_image,'python3','/src/proxmox/applications/tests/monitoring_workload_fixture.py','--client',stdout=subprocess.DEVNULL)
            wait(lambda: (root/'ready').exists() or docker('inspect','-f','{{.State.Running}}',prefix+'-client',capture_output=True,text=True).stdout.strip()=='false')
            if not (root/'ready').exists(): raise RuntimeError('Plugin fixture client failed before SQL generation')
            for kind, cmd in [('postgresql',['psql','-U','postgres','-v','ON_ERROR_STOP=1']),('mysql',['mariadb','-uroot','-psynthetic-admin'])]:
                container=prefix+('-pg' if kind=='postgresql' else '-mysql')
                docker('exec','-i',container,*cmd,input=(root/(kind+'.sql')).read_text(),capture_output=True,text=True)
            # Prove the monitor cannot create a role/database or read application rows.
            docker('exec',prefix+'-pg','psql','-U','postgres','-c','CREATE TABLE private_application(secret text);',capture_output=True)
            for statement in ['CREATE DATABASE forbidden','CREATE ROLE forbidden','SELECT * FROM private_application']:
                result=docker('exec','-e','PGPASSWORD='+password,prefix+'-pg','psql','-h','127.0.0.1','-U','zbx_monitor','-d','postgres','-v','ON_ERROR_STOP=1','-c',statement,check=False,capture_output=True)
                assert result.returncode!=0 and b'permission denied' in result.stderr, result.stderr
            grants = docker('exec',prefix+'-mysql','mariadb','-uroot','-psynthetic-admin','--batch','--skip-column-names','-e',
                "SELECT PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(CHAR(39),'zbx_monitor',CHAR(39),'@',CHAR(39),'198.18.157.4',CHAR(39));",
                capture_output=True,text=True).stdout.splitlines()
            assert set(grants) == {'PROCESS','BINLOG MONITOR','SHOW DATABASES','SHOW VIEW'}, grants
            account = docker('exec',prefix+'-mysql','mariadb','-uroot','-psynthetic-admin','--batch','--skip-column-names','-e',
                "SELECT Host,max_user_connections FROM mysql.user WHERE User='zbx_monitor'; SELECT count(*) FROM mysql.db WHERE User='zbx_monitor'; SELECT count(*) FROM mysql.tables_priv WHERE User='zbx_monitor';",
                capture_output=True,text=True).stdout.splitlines()
            assert account == ['198.18.157.4\t3','0','0'], account
            (root/'accounts-created').touch()
            wait(lambda: docker('inspect','-f','{{.State.Running}}',prefix+'-client',capture_output=True,text=True).stdout.strip()=='false')
            assert (root/'result.json').exists(), 'Plugin metric collection failed'
            print((root/'result.json').read_text())
        except Exception:
            logs=docker('logs',prefix+'-client',capture_output=True,text=True,check=False)
            print((logs.stdout+logs.stderr)[-6000:])
            raise
        finally:
            for name in ['client','pg','mysql']: docker('rm','-fv',prefix+'-'+name,check=False,capture_output=True)
            docker('network','rm',prefix,check=False,capture_output=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--client',action='store_true'); p.add_argument('--agent',type=Path)
    p.add_argument('--postgresql',type=Path);p.add_argument('--tools-image',default='homelab-app-test')
    a=p.parse_args()
    client() if a.client else main(a)
