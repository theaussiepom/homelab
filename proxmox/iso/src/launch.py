#!/usr/bin/python3
"""Attended, same-boot pre-write gate for the custom installer media.

No test switch, alternative target, network fetch or failure fallback exists here.
Only a successful explicit install-mode check and confirmation reaches execv.
"""
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from homelab_installer import core
from homelab_installer.observe import observe

SLOTS = ['/dev/HOMELAB_TARGET_A', '/dev/HOMELAB_TARGET_B']
RUNTIME = '/usr/bin/proxmox-auto-installer'


def validate_config(cfg):
    fields = {'schema', 'environment', 'machine_uuid', 'disk_members', 'protected_disks', 'interface_names', 'runtime_sha256'}
    if 'thunderbolt_devices' in cfg:
        fields.add('thunderbolt_devices')
    core.exact(cfg, fields, 'static launch configuration')
    core.require(cfg['schema'] == 'homelab-static-launch-v1', 'unsupported static launch contract')
    core.require(cfg['environment'] in ('production', 'synthetic'), 'unknown media environment')
    cfg['machine_uuid'] = core.identifier(cfg['machine_uuid'], 'machine UUID')
    core.digest(cfg['runtime_sha256'], 'runtime SHA256')
    core.require(len(cfg['disk_members']) == 2 and len(cfg['protected_disks']) == 1, 'two new disks and one protected original required')
    declared = cfg['disk_members'] + cfg['protected_disks']
    for identity in declared:
        core.exact(identity, {'disk_serial', 'disk_by_id', 'disk_size_bytes'}, 'disk identity')
        core.literal(identity['disk_serial'], 'disk serial', r'[A-Za-z0-9_.:-]{1,128}')
        core.literal(identity['disk_by_id'], 'disk by-id', r'/dev/disk/by-id/[A-Za-z0-9_.:+-]{1,200}')
        core.integer(identity['disk_size_bytes'], 1024**3, 64 * 1024**4, 'disk capacity')
    core.require(len({d['disk_serial'] for d in declared}) == 3 and len({d['disk_by_id'] for d in declared}) == 3, 'overlapping mirror/protected identities')
    core.require(type(cfg['interface_names']) is dict and set(cfg['interface_names'].values()) == {'mgmt0', 'fast0'} and len(cfg['interface_names']) == 2, 'two pinned NIC roles required')
    for mac in cfg['interface_names']:
        core.require(core.MAC.fullmatch(mac), 'invalid literal MAC')
    from thunderbolt import validate_devices
    devices = cfg.get('thunderbolt_devices', [])
    validate_devices(devices)
    core.require(all(d['mac'] in cfg['interface_names'] for d in devices), 'Thunderbolt MAC must be a pinned physical NIC')


def check_hardware(cfg, observation, native):
    validate_config(cfg)
    core.require(observation['context'] == 'installer-live', 'actual installer environment required')
    core.require(observation['machine_uuid'] == cfg['machine_uuid'], 'wrong machine UUID')
    core.require(observation['uefi'] is True and native.get('boot_type') == 'efi', 'UEFI installer boot required')
    core.identifier(observation['boot_id'], 'installer boot ID')
    core.require(observation['runtime_binary_path'] == RUNTIME and observation['runtime_binary_sha256'] == cfg['runtime_sha256'], 'wrong native installer runtime')
    disks = observation['disks']
    names, aliases = set(), set()
    for disk in disks:
        core.require(core.DEV.fullmatch(disk['devname']) and disk['devname'] == disk['udev'].get('DEVNAME') and disk['devname'] not in names, 'invalid or duplicate observed disk path')
        names.add(disk['devname'])
        for alias in disk['by_ids']:
            core.require(alias not in aliases, 'duplicate observed disk alias')
            aliases.add(alias)
    rows = native.get('disks')
    core.require(type(rows) is list and all(type(r) is list and len(r) == 6 for r in rows), 'unsupported native writer disk inventory')
    native_names = [r[1] for r in rows]
    core.require(len(set(native_names)) == len(rows) and len({r[0] for r in rows}) == len(rows), 'ambiguous native writer disk inventory')
    core.require(set(native_names) == names, 'native writer and live disk inventories differ')
    for row in rows:
        observed = next(d for d in disks if d['devname'] == row[1])
        core.require(row[2] * 512 == observed['size_bytes'], 'native writer/live capacity disagreement')
    selected = []
    protected = []
    for index, identity in enumerate(cfg['disk_members'] + cfg['protected_disks']):
        serial = [d for d in disks if d['udev'].get('ID_SERIAL_SHORT') == identity['disk_serial']]
        by_id = [d for d in disks if identity['disk_by_id'] in d['by_ids']]
        core.require(len(serial) == len(by_id) == 1 and serial == by_id, 'missing, ambiguous or conflicting disk identity: ' + identity['disk_serial'])
        disk = serial[0]
        core.require(disk['size_bytes'] == identity['disk_size_bytes'], 'wrong disk capacity: ' + identity['disk_serial'])
        if index < 2:
            core.require(disk['read_only'] is False and disk['removable'] is False, 'mirror target is read-only or removable')
            selected.append(disk['devname'])
        else:
            protected.append(disk['devname'])
    core.require(len(set(selected)) == 2 and not set(selected) & set(protected), 'protected disk selected')
    # Native disk-list performs path-suffix matching. Full paths must resolve uniquely.
    for path in selected:
        core.require([p for p in native_names if p.endswith(path)] == [path], 'native disk-list would select another disk')
    nics = observation['nics']
    for mac in cfg['interface_names']:
        hits = [n for n in nics if n['mac'] == mac]
        prop = 'enx' + mac.replace(':', '')
        core.require(len(hits) == 1 and hits[0]['udev'].get('ID_NET_NAME_MAC') == prop, 'missing or ambiguous pinned NIC')
        core.require(sum(n['udev'].get('ID_NET_NAME_MAC') == prop for n in nics) == 1, 'ambiguous native NIC property')
    return {'targets': selected, 'protected': protected, 'boot_id': observation['boot_id']}


def render_answer(template, targets):
    parsed = tomllib.loads(template.decode())
    disk = parsed['disk-setup']
    core.require(disk['filesystem'] == 'zfs' and disk['zfs']['raid'] == 'raid1' and disk['disk-list'] == SLOTS and 'filter' not in disk, 'unsafe static answer template')
    rows = template.decode().splitlines()
    matches = [i for i, line in enumerate(rows) if line.startswith('disk-list = ')]
    core.require(len(matches) == 1, 'ambiguous answer disk-list')
    rows[matches[0]] = 'disk-list = ' + json.dumps(targets)
    rendered = ('\n'.join(rows) + '\n').encode()
    core.require(tomllib.loads(rendered.decode())['disk-setup']['disk-list'] == targets, 'native answer serialization failed')
    return rendered


def fetched_template(fetched, embedded):
    # The pinned vendor fetcher uses println!("{answer}"): exactly one LF is
    # appended to the embedded file. Validate that transport framing explicitly.
    core.require(fetched == embedded + b'\n', 'fetched answer differs from embedded template plus vendor newline')
    return embedded


def verify_media(root, expected_manifest):
    body = core.read_file(root / 'homelab/manifest.json')
    core.require(core.sha(body) == expected_manifest, 'media manifest hash mismatch')
    manifest = core.decode_json(body)
    core.exact(manifest, {'schema', 'build_approval', 'files'}, 'media manifest')
    core.require(manifest['schema'] == 'homelab-static-media-build-v1', 'unknown media build contract')
    expected = {'answer.toml', 'auto-installer-mode.toml', 'proxmox-first-boot', 'homelab/config.json', 'homelab/launch.py', 'homelab/thunderbolt.py', 'homelab/src/homelab_installer/core.py', 'homelab/src/homelab_installer/observe.py', 'homelab/src/homelab_installer/__init__.py'}
    core.require(set(manifest['files']) == expected, 'unexpected or missing media members')
    for path, digest in manifest['files'].items():
        core.require(core.sha(core.read_file(root / path, limit=4*1024**2)) == digest, 'media member changed: ' + path)
    return core.decode_json(core.read_file(root / 'homelab/config.json'))


def boot_media_disk():
    mounted = subprocess.run(['findmnt','--json','--mountpoint','/cdrom','--output','SOURCE,FSTYPE,OPTIONS'],check=True,capture_output=True,text=True,timeout=15)
    rows = json.loads(mounted.stdout)['filesystems']
    core.require(len(rows)==1 and rows[0]['fstype']=='iso9660' and 'ro' in rows[0]['options'].split(','), 'actual read-only ISO9660 boot mount required')
    source = os.path.realpath(rows[0]['source'])
    core.require(source.startswith('/dev/') and stat.S_ISBLK(os.stat(source).st_mode), 'installer mount is not block media')
    info = subprocess.run(['lsblk','--json','--nodeps','--paths','--output','PATH,TYPE,PKNAME',source],check=True,capture_output=True,text=True,timeout=15)
    devices = json.loads(info.stdout)['blockdevices']
    core.require(len(devices)==1, 'ambiguous installer mount device')
    disk=devices[0]
    if disk['type']=='rom':
        return None
    whole = disk['pkname'] if disk['type']=='part' else disk['path']
    core.require(type(whole) is str and core.DEV.fullmatch(whole), 'unsupported boot media whole-device path')
    return whole


def live(cfg):
    media = boot_media_disk()
    observation = observe(media_disk=media)
    age = (datetime.now(timezone.utc) - core.timestamp(observation['captured_at'])).total_seconds()
    core.require(0 <= age <= 10, 'observation expired')
    native_bytes = core.read_file(Path('/run/proxmox-installer/run-env-info.json'))
    native = core.decode_json(native_bytes)
    result = check_hardware(cfg, observation, native)
    core.require(media not in result['targets'] + result['protected'], 'installer boot medium overlaps a declared SSD')
    result['boot_media_disk'] = media
    result['native_sha256'] = core.sha(native_bytes)
    result['observation'] = {k:v for k,v in observation.items() if k != 'captured_at'}
    return result


def hold(message):
    print(message, flush=True)
    print('STOPPED. No installation was launched. Power off or reboot manually when ready.', flush=True)
    while True:
        time.sleep(3600)


def read_confirmation(fd, phrase, timeout=300):
    deadline=time.monotonic()+timeout
    pending=bytearray()
    while b'\n' not in pending:
        remaining=deadline-time.monotonic()
        core.require(remaining>0 and select.select([fd],[],[],remaining)[0], 'attended confirmation timed out')
        chunk=os.read(fd,512-len(pending))
        core.require(chunk, 'confirmation input closed')
        pending.extend(chunk)
        core.require(len(pending)<512, 'confirmation input too long')
    core.require(pending.decode().strip()==phrase, 'installation was not explicitly confirmed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args()
    root = Path('/cdrom')
    cfg = verify_media(root, args.manifest_sha256)
    template = fetched_template(sys.stdin.buffer.read(1024**2), core.read_file(root / 'answer.toml'))
    first = live(cfg)
    modes = [p.split('=',1)[1] for p in Path('/proc/cmdline').read_text().split() if p.startswith('homelab.mode=')]
    core.require(len(modes) == 1 and modes[0] in ('check', 'install'), 'explicit guarded boot mode required')
    print('HOMELAB_CHECK_PASS: machine, UEFI, exact disks, protected original, NICs, runtime and media verified.', flush=True)
    for identity, path in zip(cfg['disk_members'], first['targets']):
        print('NEW MIRROR TARGET:', identity['disk_serial'], path, identity['disk_size_bytes'], 'bytes', flush=True)
    print('PROTECTED UBUNTU:', cfg['protected_disks'][0]['disk_serial'], first['protected'][0], flush=True)
    if modes[0] == 'check':
        hold('CHECK ONLY selected; installation cannot continue from this boot.')
    phrase = 'INSTALL ' + ' '.join(i['disk_serial'] for i in cfg['disk_members'])
    fd = os.open('/dev/console', os.O_RDWR | os.O_NOCTTY)
    with os.fdopen(os.dup(fd), 'rb') as console_in, os.fdopen(fd, 'w', buffering=1) as console_out:
        console_out.write('This erases ONLY the two NEW mirror targets above.\nType exactly: ' + phrase + '\n> ')
        read_confirmation(console_in.fileno(),phrase)
    verify_media(root, args.manifest_sha256)
    second = live(cfg)
    core.require(first == second, 'hardware, boot or native inventory changed during confirmation')
    answer = render_answer(template, second['targets'])
    path = Path('/run/automatic-installer-answers')
    tmp = path.with_name('homelab-answers.ready')
    core.new_file(tmp, answer)
    os.replace(tmp, path)
    core.new_file(Path('/run/homelab-install-admission.json'), core.canonical({'schema':'homelab-attended-admission-v1','boot_id':second['boot_id'],'targets':second['targets'],'protected':second['protected'],'manifest_sha256':args.manifest_sha256,'answer_sha256':core.sha(answer)}))
    # Hash the actual native executable once more at the last boundary.
    core.require(core.sha(core.read_file(Path(RUNTIME), limit=32*1024**2)) == cfg['runtime_sha256'], 'runtime changed before launch')
    print('HOMELAB_ADMITTED: explicit confirmation and same-boot recheck passed; starting native installer.', flush=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    os.dup2(fd, 0)
    os.close(fd)
    os.execv(RUNTIME, [RUNTIME])


def guarded_main():
    try:
        main()
    except Exception as error:
        # Inventory commands and malformed runtime data must also stay stopped.
        hold('HOMELAB_REFUSED: ' + (str(error) if isinstance(error, core.Refusal) else type(error).__name__))


if __name__ == '__main__':
    guarded_main()
