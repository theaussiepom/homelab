"""Prove manual unless-stopped clients survive a disposable Docker daemon cycle.

The privileged daemon is a resource-bounded, network-isolated test container.
No host Docker socket, deployment credentials, actual Authentik data or Proxmox
service is mounted. Only its own UUID-named volume/container are removed.
Docker26.1.4 is a synthetic policy fixture, not Debian26.1.5/LXC acceptance.
Preload the two immutable image references before running this script.
"""
import json
from pathlib import Path
import subprocess
import time
import uuid

DAEMON = 'docker@sha256:dd43b430341a40d88f4f30edb03865daa9d6fa39c9b1da70f27e2a89cec3eae1'
ALPINE = 'alpine@sha256:b95359c2505145f16c6aa384f9cc74eeff78eb36d308ca4fd902eeeb0a0b161b'


def docker(*args, data=None, timeout=90):
    return subprocess.check_output(['docker',*args],input=data,stderr=subprocess.STDOUT,timeout=timeout)


def main():
    name = 'homelab-identity-cycle-' + uuid.uuid4().hex[:12]
    volume = name + '-data'
    docker('image','inspect',DAEMON)
    image = docker('image','inspect','--format','{{.Id}}',ALPINE).decode().strip()
    archive = docker('image','save',image)
    inner = lambda *args, **kw: docker('exec','-i',name,'docker',*args,**kw)
    def ready():
        deadline = time.monotonic()+60
        while True:
            try:
                inner('info',timeout=5);return
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired):
                if time.monotonic()>deadline:raise RuntimeError('Disposable Docker daemon did not become ready') from None
                time.sleep(1)
    def inspect(service):
        ident = inner('compose','-f','/tmp/identity-compose.json','ps','--all','--quiet',service).decode().strip()
        return json.loads(inner('inspect','--format','{{json .}}',ident))
    try:
        docker('volume','create',volume)
        docker('run','--detach','--name',name,'--privileged','--network','none','--cpus','1',
               '--memory','768m','--pids-limit','256','--mount','type=volume,source='+volume+',target=/var/lib/docker',
               '--entrypoint','dockerd','-e','DOCKER_TLS_CERTDIR=',DAEMON,'--host=unix:///var/run/docker.sock',
               '--storage-driver=vfs','--iptables=false','--bridge=none','--ip-forward=false',
               '--ip-masq=false','--userland-proxy=false')
        ready();inner('image','load',data=archive)
        document = {'name':'homelab-identity','services':{service:{'image':image,
            'command':['sleep','3600'],'restart':'unless-stopped','network_mode':'none',
            'volumes':['state:/state']} for service in ('server','worker','redis')},'volumes':{'state':{}}}
        document['services']['redis']['healthcheck']={'test':['CMD','true'],'interval':'1s','timeout':'1s','retries':5}
        for service in ('server','worker'):
            document['services'][service]['depends_on']={'redis':{'condition':'service_healthy'}}
        docker('exec','-i',name,'sh','-c','cat > /tmp/identity-compose.json',data=json.dumps(document).encode())
        inner('compose','-f','/tmp/identity-compose.json','up','-d','--pull','never')
        inner('exec',inspect('redis')['Id'],'sh','-c','printf synthetic-state > /state/marker')
        before = {n:inspect(n) for n in ('server','worker','redis')}
        for n in ('server','worker'):
            assert before[n]['Config']['Labels']['com.docker.compose.depends_on']=='redis:service_healthy:false'
        inner('compose','-f','/tmp/identity-compose.json','stop','--timeout','10','server','worker')
        for n in ('server','worker'):
            row=inspect(n);assert not row['State']['Running'] and row['State']['Status']=='exited'
            assert row['HostConfig']['RestartPolicy']['Name']=='unless-stopped'
        docker('stop','--time','30',name);docker('start',name);ready()
        after = {n:inspect(n) for n in ('server','worker','redis')}
        for n in ('server','worker'):
            assert after[n]['Id']==before[n]['Id'] and after[n]['State']['StartedAt']==before[n]['State']['StartedAt']
            assert not after[n]['State']['Running'] and after[n]['State']['Status']=='exited'
        assert after['redis']['Id']==before['redis']['Id'] and after['redis']['State']['Running']
        assert after['redis']['State']['StartedAt']!=before['redis']['State']['StartedAt']
        assert inner('exec',after['redis']['Id'],'cat','/state/marker')==b'synthetic-state'
        inner('compose','-f','/tmp/identity-compose.json','up','-d','--no-deps','--no-build',
              '--force-recreate','--pull','never','--wait','--wait-timeout','30','server','worker')
        for n in ('server','worker'):
            row=inspect(n);assert row['Id']!=before[n]['Id'] and row['State']['Running']
            assert row['Config']['Labels']['com.docker.compose.replace']==before[n]['Id']
            assert row['Config']['Labels']['com.docker.compose.depends_on']==''
        assert inspect('redis')['Id']==after['redis']['Id']
        assert inspect('redis')['State']['StartedAt']==after['redis']['State']['StartedAt']
        print(json.dumps({'status':'passed','daemon':'26.1.4','manually_stopped_clients_survived_daemon_cycle':True,
            'redis_restarted_with_same_container_and_synthetic_state':True,
            'only_two_clients_recreated_after_cycle':True,'replacement_history_names_original_clients':True,'native_lxc_verified':False},indent=2))
    except Exception:
        print(docker('logs','--tail','50',name).decode(errors='replace'))
        raise
    finally:
        subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=40)
        subprocess.run(['docker','volume','rm',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=40)


if __name__ == '__main__':main()
