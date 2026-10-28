"""Actual Docker restart policy across a disposable daemon/container cycle.

The nested daemon has no external network, published port, host socket, private
input or bind mount. Its one dedicated volume persists only synthetic Docker
state. Privilege is confined to this test daemon; never restart the host daemon.
This proves Docker26.1.4 policy behavior, not native Proxmox lifecycle effects or
the separately pinned Debian26.1.5 package's complete target qualification.
"""
import json
import subprocess
import time
import uuid

DIND = 'docker:26.1.4-dind@sha256:dd43b430341a40d88f4f30edb03865daa9d6fa39c9b1da70f27e2a89cec3eae1'


def docker(*args, **kwargs):
    return subprocess.run(['docker',*args],check=True,timeout=180,**kwargs)


def run():
    name='homelab-pgadmin-cycle-'+uuid.uuid4().hex[:12]
    volume=name+'-data'
    def inner(*args, **kwargs): return docker('exec',name,'docker',*args,**kwargs)
    def ready():
        for attempt in range(60):
            result=subprocess.run(['docker','exec',name,'docker','info'],capture_output=True,timeout=10)
            if result.returncode==0: return
            time.sleep(0.5)
        raise RuntimeError('Isolated Docker fixture did not become ready')
    def inspect(container):
        return json.loads(inner('inspect',container,capture_output=True,text=True).stdout)[0]
    try:
        architecture=docker('info','--format','{{.Architecture}}',capture_output=True,text=True).stdout.strip()
        # A nested runtime must run natively: emulated x86 runc cannot qualify
        # daemon restart behavior on an ARM workstation. CI uses native x86.
        platform={'aarch64':'linux/arm64','arm64':'linux/arm64','x86_64':'linux/amd64','amd64':'linux/amd64'}[architecture]
        docker('pull','--platform',platform,DIND,stdout=subprocess.DEVNULL)
        image_id=docker('image','inspect',DIND,'--format','{{.Id}}',capture_output=True,text=True).stdout.strip()
        docker('volume','create',volume,stdout=subprocess.DEVNULL)
        docker('run','-d','--name',name,'--platform',platform,'--privileged',
               '--network','none','--cpus','2','--memory','1g','--stop-timeout','30',
               '-v',volume+':/var/lib/docker','--entrypoint','dockerd',DIND,
               '--host=unix:///var/run/docker.sock','--bridge=none','--iptables=false',
               '--ip6tables=false','--ip-forward=false','--storage-driver=vfs',stdout=subprocess.DEVNULL)
        ready()
        # Supply an already digest-verified image over stdin; the inner daemon
        # has no network and cannot pull anything. The workload is a shell loop.
        archive=subprocess.Popen(['docker','image','save',image_id],stdout=subprocess.PIPE)
        try:
            loaded=subprocess.run(['docker','exec','-i',name,'docker','load'],stdin=archive.stdout,
                                  capture_output=True,timeout=180)
            archive.stdout.close()
            assert loaded.returncode==0 and archive.wait(timeout=30)==0
        finally:
            if archive.poll() is None: archive.kill();archive.wait()
        workload="trap 'exit 0' TERM; while :; do sleep 1; done"
        for container,policy in (('selected-pgadmin','unless-stopped'),('cycle-control','always')):
            inner('run','-d','--network','none','--name',container,'--restart',policy,
                  '--entrypoint','/bin/sh',image_id,'-c',workload,stdout=subprocess.DEVNULL)
        inner('stop','--time','10','selected-pgadmin',stdout=subprocess.DEVNULL)
        stopped=inspect('selected-pgadmin');control=inspect('cycle-control')
        assert stopped['State']['Running'] is False
        docker('restart','--time','30',name,stdout=subprocess.DEVNULL)
        ready()
        after=inspect('selected-pgadmin')
        assert after['Id']==stopped['Id'] and after['Image']==stopped['Image']
        assert after['HostConfig']['RestartPolicy']['Name']=='unless-stopped'
        assert after['State']['Running'] is False and after['RestartCount']==stopped['RestartCount']
        assert after['State']['StartedAt']==stopped['State']['StartedAt']
        assert after['State']['FinishedAt']==stopped['State']['FinishedAt']
        for attempt in range(30):
            restarted=inspect('cycle-control')
            if restarted['State']['Running'] and restarted['State']['StartedAt']!=control['State']['StartedAt']: break
            time.sleep(0.5)
        else: raise AssertionError('Control workload did not actually restart across the daemon cycle')
        print('Isolated Docker26.1.4 cycle passed: manually quiesced unless-stopped container retained '
              'ID/image/stopped timestamps/restart count, while the control restarted. '
              'Native provider lifecycle remains unqualified.')
    except Exception:
        subprocess.run(['docker','logs','--tail','40',name],check=False,timeout=20)
        raise
    finally:
        subprocess.run(['docker','rm','-f',name],check=False,timeout=30,stdout=subprocess.DEVNULL)
        subprocess.run(['docker','volume','rm',volume],check=False,timeout=30,stdout=subprocess.DEVNULL)


if __name__=='__main__': run()
