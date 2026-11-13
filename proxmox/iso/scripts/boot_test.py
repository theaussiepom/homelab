#!/usr/bin/env python3
"""One bounded local VM boot; only new sparse virtual disks, no host devices."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import tempfile
import time


def image_sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024**2),b''):digest.update(block)
    return digest.hexdigest()


def command(qmp, name, arguments=None):
    request={'execute':name}
    if arguments is not None:request['arguments']=arguments
    qmp.sendall((json.dumps(request)+'\n').encode())
    stream=qmp.makefile('rb')
    while True:
        row=json.loads(stream.readline())
        if 'return' in row:return row['return']
        if 'error' in row:raise RuntimeError(row['error'])


def menu_key(qmp_path, key):
    """Inject one bounded emulated menu key, avoiding serial escape-sequence loss."""
    if key not in {'down', 'ret'}:
        raise ValueError('Unsupported synthetic menu key')
    with socket.socket(socket.AF_UNIX) as qmp:
        qmp.settimeout(10)
        qmp.connect(qmp_path)
        greeting=json.loads(qmp.makefile('rb').readline(8193))
        if not isinstance(greeting, dict) or 'QMP' not in greeting:
            raise ValueError('Expected the local synthetic VM QMP greeting')
        command(qmp, 'qmp_capabilities')
        command(qmp, 'input-send-event', {'events': [
            {'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': key}}}
            for down in (True, False)
        ]})


class MenuSelection:
    """Send one arrow per observed GRUB highlight, then enter the exact serial item."""
    entries = (b'CHECK ONLY - no installation', b'INSTALL - two NEW SSDs; confirmation required',
               b'CHECK ONLY - serial console', b'INSTALL - serial console; confirmation required')

    def __init__(self, cancel):
        self.target = 3 if cancel else 2
        self.waiting = None
        self.done = False

    def choose(self, send, plain):
        if self.done:
            return True
        if not all(entry in plain for entry in self.entries[2:]) or b'The highlighted entry will be executed automatically' not in plain:
            return False
        highlighted = re.findall(rb'\*Proxmox: (' + b'|'.join(re.escape(entry) for entry in self.entries) + rb')', plain)
        if not highlighted:
            return False
        index = self.entries.index(highlighted[-1])
        if index > self.target or (self.waiting is not None and index != self.waiting):
            return False
        send('ret' if index == self.target else 'down')
        if index == self.target:
            self.done = True
        else:
            self.waiting = index + 1
        return self.done


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('case',choices=['matching-check','wrong-machine','missing-member','ambiguous-member','cancel-install','profile-wrong-machine'])
    parser.add_argument('--seconds',type=int,default=240)
    args=parser.parse_args()
    root=Path('/work')
    case=root/'build/vm-tests'/(args.case+'-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    case.mkdir(parents=True,mode=0o700)
    production=args.case=='profile-wrong-machine'
    source='production' if production else 'fixture'
    iso=root/'build'/('single-usb-'+source)/('Proxmox-9.2-1-'+source+'.iso')
    assert iso.is_file(), 'built image missing'
    serials=['LAB-NEW-A','LAB-NEW-B','LAB-OLD']
    if args.case=='missing-member':serials[1]='NOT-THE-NEW-B'
    if args.case=='ambiguous-member':serials.append('LAB-NEW-A')
    disks=[]
    for i,serial in enumerate(serials):
        disk=case/('disk'+str(i)+'.raw')
        with disk.open('xb') as stream:
            stream.write(('PRESERVE-VM-DISK-'+str(i)+'\n').encode());stream.truncate((24 if i==2 else 16)*1024**3)
        disks.append((disk,serial))
    firmware=case/'OVMF_VARS.fd';shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd',firmware)
    with tempfile.TemporaryDirectory(prefix='homelab-vm-') as temp:
        qmp_path=str(Path(temp)/'qmp.sock')
        uuid='33333333-3333-4333-8333-333333333333' if args.case=='wrong-machine' else '11111111-1111-4111-8111-111111111111'
        if production:
            target_uuid=json.loads((root/'build/single-usb-production/readback/homelab/config.json').read_text())['machine_uuid']
            if uuid==target_uuid:uuid='33333333-3333-4333-8333-333333333333'
        argv=['qemu-system-x86_64','-machine','q35,accel=tcg','-cpu','max','-smp','2','-m','3072','-uuid',uuid,'-display','none','-serial','stdio','-monitor','none','-no-reboot','-qmp','unix:'+qmp_path+',server=on,wait=off',
          '-drive','if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd','-drive','if=pflash,format=raw,file='+str(firmware),
          '-device','qemu-xhci,id=xhci','-drive','if=none,id=usbmedia,format=raw,readonly=on,file='+str(iso),'-device','usb-storage,bus=xhci.0,drive=usbmedia,removable=on,bootindex=1']
        for i,(disk,serial) in enumerate(disks):
            # Distinct subsystem NQNs ensure Linux exposes both physical test
            # disks even when their serials deliberately collide. Without this,
            # Linux rejects a duplicate controller before the guard can see it.
            argv+=['-drive',f'if=none,id=disk{i},format=raw,file={disk}',
                   '-device',f'nvme-subsys,id=subsys{i},nqn=nqn.2026-10.org.homelab.fixture:{i}',
                   '-device',f'nvme,id=nvme{i},subsys=subsys{i},serial={serial}',
                   '-device',f'nvme-ns,bus=nvme{i},drive=disk{i},nsid=1']
        for i,mac in enumerate(['02:00:00:00:10:01','02:00:00:00:10:02']):
            argv+=['-netdev',f'user,id=net{i},net=10.0.{i+2}.0/24,restrict=on','-device',f'e1000e,netdev=net{i},mac={mac}']
        (case/'argv.json').write_text(json.dumps(argv,indent=2)+'\n')
        started=time.monotonic();proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,bufsize=0)
        data=b'';menu=False;cancelled=False;matched=False;stop=None
        selector=MenuSelection(args.case=='cancel-install')
        print('Boot test started:',args.case,flush=True)
        try:
            with (case/'console.log').open('wb') as log:
                while time.monotonic()-started<args.seconds and proc.poll() is None:
                    if not select.select([proc.stdout],[],[],1)[0]:continue
                    chunk=os.read(proc.stdout.fileno(),65536)
                    if not chunk:break
                    log.write(chunk);log.flush();data+=chunk
                    plain=re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]',b'',data)
                    if not menu and selector.choose(lambda key: menu_key(qmp_path, key), plain):
                        menu=True
                        print('Confirmed guarded serial entry:',args.case,flush=True)
                    if b'HOMELAB_CHECK_PASS:' in plain and not matched:
                        matched=True;print('Reached successful live guard:',args.case,flush=True)
                    if args.case=='cancel-install' and b'Type exactly:' in plain and not cancelled:
                        proc.stdin.write(b'CANCEL\n');proc.stdin.flush();cancelled=True
                    if re.search(rb'HOMELAB_REFUSED:[^\n]*\n',plain):
                        stop='refused';break
                    if args.case=='matching-check' and b'CHECK ONLY selected; installation cannot continue' in plain:
                        stop='checked-and-stopped';break
            stats=[]
            if proc.poll() is None and Path(qmp_path).exists():
                with socket.socket(socket.AF_UNIX) as qmp:
                    qmp.settimeout(10);qmp.connect(qmp_path);qmp.recv(8192)
                    command(qmp,'qmp_capabilities');stats=command(qmp,'query-blockstats');command(qmp,'quit')
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10)
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
        plain=re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]',b'',data)
        writes={row['device']:row['stats']['wr_bytes'] for row in stats if row.get('device','').startswith('disk')}
        no_writes=len(writes)==len(disks) and all(v==0 for v in writes.values())
        expected='checked-and-stopped' if args.case=='matching-check' else 'refused'
        reasons={'wrong-machine':'wrong machine UUID','profile-wrong-machine':'wrong machine UUID','missing-member':'missing, ambiguous or conflicting disk identity: LAB-NEW-B','ambiguous-member':'missing, ambiguous or conflicting disk identity: LAB-NEW-A','cancel-install':'installation was not explicitly confirmed'}
        refusal=re.search(rb'HOMELAB_REFUSED:([^\r\n]*)',plain)
        reason=refusal.group(1).decode().strip() if refusal else None
        expected_reason=reasons.get(args.case)
        reason_matches=expected_reason is None or (reason is not None and expected_reason in reason)
        receipt={'case':args.case,'seconds':round(time.monotonic()-started,2),'result':stop,'expected':expected,'refusal_reason':reason,'expected_refusal_reason':expected_reason,'reason_matches':reason_matches,'guard_success_seen':matched,'disk_write_bytes':writes,'no_target_disk_writes':no_writes,'local_vm_exit':proc.returncode,'production_host_accessed':False,'console_log':str(case/'console.log'),'image_sha256':image_sha(iso)}
        (case/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        print(json.dumps(receipt),flush=True)
        if stop!=expected or not no_writes or not reason_matches:
            print(plain[-3500:].decode(errors='replace'),flush=True)
            raise SystemExit(1)


if __name__=='__main__':main()
