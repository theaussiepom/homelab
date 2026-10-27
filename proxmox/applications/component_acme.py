"""Change only Traefik's declared ACME resolvers inside its existing guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

import component_image as shared
from ingress_acme import candidate, require

CONFIG = Path('/opt/homelab-app/runtime/traefik.yml')
STATE = Path('/var/lib/homelab-acme-updates')
# The commissioned ingress profile uses this same bounded readiness check.
HEALTH = ['curl','--retry','30','--retry-delay','2','--retry-all-errors',
          '--retry-max-time','180','--fail','--silent','--show-error',
          '--max-time','10','http://127.0.0.1:8082/ping']


def ready(image):
    """Allow normal startup before asserting the final running image."""
    require(shared.command(HEALTH, timeout=200).strip() == b'OK', 'Ingress health check did not pass')
    shared.runtime(image)


def read_config():
    """Read only the existing private, root-owned regular runtime file."""
    with os.fdopen(os.open(CONFIG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) in (0o400,0o600) and info.st_size <= 1024*1024,
                'Expected the private installed Traefik configuration')
        return stream.read(1024*1024+1)


def run(settings, verify_only=False, confirmation=None):
    """Preserve certificate state, image and Compose; hold any failed change."""
    require(os.geteuid() == 0, 'Run only through the guest maintenance playbook')
    shared.image(settings['image'])
    identity = json.loads(shared.read(shared.IDENTITY))
    require(identity.get('vmid') == settings['vmid'] and identity.get('kind') == 'ingress',
            'Wrong installed ingress guest')
    require(hashlib.sha256(shared.read(shared.COMPOSE)).hexdigest() == settings['compose_sha256'],
            'Installed Compose changed')
    compose = json.loads(shared.read(shared.COMPOSE))
    require(compose.get('name') == 'homelab-ingress' and set(compose.get('services',{})) == {'traefik'}
            and compose['services']['traefik']['image'] == settings['image']
            and any(isinstance(m,dict) and m.get('source') == str(CONFIG)
                    and m.get('target') == '/etc/traefik/traefik.yml' and m.get('read_only') is True
                    for m in compose['services']['traefik'].get('volumes',[])),
            'Expected the unchanged image and mounted runtime configuration')
    STATE.mkdir(mode=0o700,exist_ok=True)
    info = STATE.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            'Expected the private ACME evidence directory')
    encoded = (json.dumps(settings,sort_keys=True,indent=2)+'\n').encode()
    # Code-only revisions cannot create a fresh retry identity on this guest.
    operation = STATE / hashlib.sha256(json.dumps(settings['after']).encode()).hexdigest()
    if confirmation is not None:
        require(not verify_only and confirmation['update'] == settings,
                'Confirmation must preserve the original resolver packet')
        info = operation.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'Expected the original private resolver operation')
        original = shared.read(operation/'traefik-before.json')
        require(shared.read(operation/'settings.json') == encoded
                and hashlib.sha256(original).hexdigest() == settings['runtime_sha256']
                and read_config() == candidate(original,settings['before'],settings['after'])
                and hashlib.sha256(read_config()).hexdigest() == confirmation['runtime_sha256'],
                'Applied resolver configuration or original evidence differs')
        claim = (json.dumps(confirmation,sort_keys=True,indent=2)+'\n').encode()
        # One confirmation identity, even if a later source revision changes.
        shared.save(operation/'confirmation-claim.json',claim)
        try:
            require(hashlib.sha256(shared.read(operation/'HOLD.json')).hexdigest() == confirmation['guest_hold_sha256']
                    and not (operation/'complete.json').exists() and not (operation/'complete.json').is_symlink(),
                    'Expected the exact failed guest check')
            ready(settings['image'])
            require(read_config() == candidate(original,settings['before'],settings['after'])
                    and hashlib.sha256(shared.read(shared.COMPOSE)).hexdigest() == settings['compose_sha256']
                    and hashlib.sha256(shared.read(operation/'HOLD.json')).hexdigest() == confirmation['guest_hold_sha256'],
                    'Guest configuration or hold changed during confirmation')
            require(not (operation/'failed-HOLD.json').exists() and not (operation/'failed-HOLD.json').is_symlink(),
                    'Preserve existing archived failure evidence')
            (operation/'HOLD.json').rename(operation/'failed-HOLD.json');shared.sync(operation)
            shared.save(operation/'complete.json',b'{"status":"passed"}\n')
            return {'status':'passed','changed':False}
        except Exception as error:
            shared.save(operation/'confirmation-failure.json',(json.dumps({
                'error':type(error).__name__,'reason':str(error) if type(error) is ValueError else None})+'\n').encode())
            raise
    if verify_only:
        original = shared.read(operation/'traefik-before.json')
        require(shared.read(operation/'complete.json') == b'{"status":"passed"}\n'
                and not (operation/'HOLD.json').exists() and not (operation/'HOLD.json').is_symlink()
                and hashlib.sha256(original).hexdigest() == settings['runtime_sha256']
                and read_config() == candidate(original,settings['before'],settings['after']),
                'Completed resolver update differs')
        shared.runtime(settings['image'])
        return {'status':'passed','changed':False}
    require(not any(not (p/'complete.json').is_file() for p in STATE.iterdir()),
            'An earlier guest resolver update is still held')
    operation.mkdir(mode=0o700)  # An interrupted or failed operation cannot replay.
    original = read_config()
    require(hashlib.sha256(original).hexdigest() == settings['runtime_sha256'], 'Runtime configuration drifted')
    updated = candidate(original,settings['before'],settings['after'])
    shared.runtime(settings['image'])
    shared.save(operation/'settings.json',encoded)
    shared.save(operation/'traefik-before.json',original)
    shared.save(operation/'HOLD.json',b'{"automatic_retry":false}\n')
    shared.command(['docker','compose','-f',str(shared.COMPOSE),'config','--quiet'])
    with os.fdopen(os.open(CONFIG,os.O_RDONLY|os.O_NOFOLLOW),'rb') as anchor:
        info=os.fstat(anchor.fileno());mode=stat.S_IMODE(info.st_mode)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
                and mode in (0o400,0o600) and anchor.read()==original,
                'Runtime configuration changed before update')
        # The owner can update its0400 file without relying on DAC override.
        # Restore the exact original mode even if opening/writing fails.
        os.fchmod(anchor.fileno(),0o600)
        try:
            with os.fdopen(os.open(CONFIG,os.O_RDWR|os.O_NOFOLLOW),'r+b') as stream:
                current=os.fstat(stream.fileno())
                require((current.st_dev,current.st_ino)==(info.st_dev,info.st_ino)
                        and stream.read()==original,'Runtime file changed during admission')
                stream.seek(0);stream.write(updated);stream.truncate();stream.flush();os.fsync(stream.fileno())
        finally:
            os.fchmod(anchor.fileno(),mode);os.fsync(anchor.fileno())
    shared.command(['docker','compose','-f',str(shared.COMPOSE),'up','-d','--no-deps','--force-recreate','--pull','never','traefik'])
    require(read_config()==updated and hashlib.sha256(shared.read(shared.COMPOSE)).hexdigest()==settings['compose_sha256'],
            'Resolver or Compose readback differs')
    ready(settings['image'])
    shared.save(operation/'complete.json',b'{"status":"passed"}\n')
    (operation/'HOLD.json').unlink();shared.sync(operation)
    return {'status':'passed','changed':True}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings',type=Path,required=True)
    parser.add_argument('--verify-only',action='store_true')
    parser.add_argument('--confirmation',type=Path)
    args=parser.parse_args()
    try:
        print(json.dumps(run(json.loads(shared.read(args.settings)),args.verify_only,
            json.loads(shared.read(args.confirmation)) if args.confirmation else None)))
    except Exception:
        raise SystemExit('ACME resolver update held; preserve private evidence. No automatic retry.') from None
