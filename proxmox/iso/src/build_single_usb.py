#!/usr/bin/env python3
"""Approved static-media contract for the attended two-disk installer.

Run offline in the isolated Linux builder. Never opens a physical device.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path('/work')
sys.path.insert(0, str(ROOT / 'src'))
from homelab_installer import core
from launch import SLOTS, validate_config

ISO = ROOT / 'build/vendor/proxmox-ve_9.2-1.iso'
HELPER = ROOT / 'build/assistant-root/usr/bin/proxmox-auto-install-assistant'
STARTUP_SHA = '7a5be4ff18f286b9216811a6216e3ddd098d49206d4c900192c75b3c89b74d7c'


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(8*1024**2), b''): digest.update(block)
    return digest.hexdigest()


def run(args, **kwargs):
    result = subprocess.run([str(x) for x in args], capture_output=True, **kwargs)
    if result.returncode:
        (ROOT/'evidence/latest-build-command-failure.json').write_text(json.dumps({'argv':[str(x) for x in args],'exit':result.returncode,'stdout':result.stdout.decode(errors='replace'),'stderr':result.stderr.decode(errors='replace')},indent=2)+'\n')
        raise RuntimeError(result.stderr.decode(errors='replace')[-2000:])
    return result


def template(config, password, public, site=None):
    core.require(re.fullmatch(r'\$6\$(?:rounds=[0-9]+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}', password), 'valid password hash required')
    public = core.ssh_key(public)
    from site_profile import validate_site
    site = validate_site(site)
    fqdn, mailto = site['fqdn'], site['mailto']
    mac = next(mac for mac, name in config['interface_names'].items() if name == 'mgmt0')
    q = json.dumps
    lines = ['[global]', 'keyboard = ' + q(site['keyboard']), 'country = ' + q(site['country']), 'timezone = ' + q(site['timezone']),
             'fqdn = ' + q(fqdn), 'mailto = ' + q(mailto),
             'root-password-hashed = ' + q(password), 'root-ssh-keys = ' + q([public]),
             'reboot-mode = "power-off"', '', '[first-boot]', 'source = "from-iso"', 'ordering = "before-network"',
             '', '[network]', 'source = "from-answer"',
             'cidr = ' + q(site['management']['address']),
             'gateway = ' + q(site['management']['gateway']),
             'dns = ' + q(site['management']['dns']),
             'filter.ID_NET_NAME_MAC = ' + q('enx' + mac.replace(':','')),
             '', '[network.interface-name-pinning]', 'enabled = true', '[network.interface-name-pinning.mapping]']
    lines += [q(mac) + ' = ' + q(name) for mac, name in sorted(config['interface_names'].items())]
    lines += ['', '[disk-setup]', 'filesystem = "zfs"', 'zfs.raid = "raid1"', 'zfs.ashift = 12',
              'zfs.checksum = "on"', 'zfs.compress = "lz4"', 'zfs.copies = 1', 'zfs.arc-max = 2048',
              'disk-list = ' + q(SLOTS), '']
    return '\n'.join(lines).encode()


def grub(vendor):
    marker = 'if [ -f auto-installer-mode.toml ]; then\n'
    core.require(vendor.count(marker) == 1, 'unsupported vendor GRUB layout')
    prefix = vendor.split(marker,1)[0]
    core.require('menuentry' not in prefix, 'unexpected earlier boot entry')
    result = prefix + '\nset default="homelab-check"\nset timeout_style=menu\nset timeout=30\n'
    for serial, mode, title in [(False,'check','CHECK ONLY - no installation'),(False,'install','INSTALL - two NEW SSDs; confirmation required'),(True,'check','CHECK ONLY - serial console'),(True,'install','INSTALL - serial console; confirmation required')]:
        name = 'homelab-' + mode + ('-serial' if serial else '')
        console = 'console=ttyS0,115200n8' if serial else 'console=tty0'
        result += f"\nmenuentry 'Proxmox: {title}' --id '{name}' {{\n"
        result += f'    linux /boot/linux26 ro ramdisk_size=16777216 rw splash=verbose proxmox-start-auto-installer homelab.mode={mode} {console}\n'
        result += '    initrd /boot/initrd.img\n}\n'
    return result.encode()


def patched_startup(original, manifest_sha, code_pins):
    core.require(core.sha(original) == STARTUP_SHA, 'vendor startup differs from inspected pin')
    inventory = b'/usr/bin/proxmox-low-level-installer dump-env\n'
    core.require(original.count(inventory) == 1, 'native inventory boundary changed')
    expected = {'homelab/thunderbolt.py', 'homelab/launch.py', 'homelab/src/homelab_installer/core.py', 'homelab/src/homelab_installer/observe.py', 'homelab/src/homelab_installer/__init__.py'}
    core.require(set(code_pins) == expected, 'missing pre-inventory code pins')
    for digest in code_pins.values():
        core.digest(digest, 'pre-inventory code SHA256')
    lines = ' '.join("'" + code_pins[path] + '  /cdrom/' + path + "'" for path in sorted(expected))
    preparation = ("if ! printf '%s\\n' " + lines + " | sha256sum --check --status; then\n"
                   "    echo 'HOMELAB_REFUSED: media code changed before Thunderbolt preparation'\n"
                   "    echo 'STOPPED. No installation was launched.'\n"
                   "    while true; do sleep 3600; done\n"
                   "fi\n"
                   '/usr/bin/python3 /cdrom/homelab/thunderbolt.py --manifest-sha256 ' + manifest_sha + '\n').encode()
    changed = original.replace(inventory, preparation + inventory)
    needle = b'if /usr/bin/proxmox-auto-installer </run/automatic-installer-answers; then'
    core.require(changed.count(needle) == 1, 'native launch boundary changed')
    changed = changed.replace(needle, ('if /usr/bin/python3 /cdrom/homelab/launch.py --manifest-sha256 ' + manifest_sha + ' </run/automatic-installer-answers; then').encode())
    core.require(changed.count(b'\ndhclient -v\n') == 1, 'vendor DHCP boundary changed')
    changed = changed.replace(b'\ndhclient -v\n', b'\ntimeout 15 dhclient -1 -v || true\n')
    core.require(b'if /usr/bin/proxmox-auto-installer ' not in changed, 'unguarded native automatic launch remains')
    return changed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture', action='store_true', help='Separate synthetic-only ISO, never a runtime override')
    parser.add_argument('--resume-packaging', action='store_true', help='Resume only a failed image-packaging stage after validation')
    args = parser.parse_args()
    name = 'fixture' if args.fixture else 'production'
    outdir = ROOT / 'build' / ('single-usb-' + name)
    if args.resume_packaging:
        finish(outdir)
        return
    outdir.mkdir(mode=0o700)
    if args.fixture:
        config = core.decode_json(core.read_file(ROOT / 'config/fixture-hardware.json'))
        core.require(config['environment'] == 'synthetic', 'fixture must be synthetic')
        site = core.decode_json(core.read_file(ROOT / 'config/fixture-site.json'))
        public = (ROOT / 'config/fixture-ssh.pub').read_text().strip()
        password = '$6$synthetic$' + 'A'*86
        payload = b'#!/bin/sh\nset -eu\nexit 0\n'
        approval = {'approved_by':'synthetic fixture only','scope':'local-synthetic-media-tests-only','production_boot_or_erase_authorized':False}
    else:
        approval = core.decode_json(core.read_file(ROOT / '.local/media-approval.json', protected=True))
        core.require(set(approval)=={'approved_by','scope','production_boot_or_erase_authorized'}, 'unexpected approval fields')
        core.require(type(approval['approved_by']) is str and approval['approved_by'].strip() and 'REPLACE' not in approval['approved_by'] and approval['scope']=='build-and-prepare-removable-media-only' and approval['production_boot_or_erase_authorized'] is False, 'explicit local operator media preparation approval required')
        known = core.decode_json(core.read_file(ROOT / '.local/hardware.json', protected=True))
        fields = {'machine_uuid','disk_members','protected_disks','interface_names'}
        if 'thunderbolt_devices' in known:
            fields.add('thunderbolt_devices')
        core.exact(known, fields, 'local hardware profile')
        config = dict(known, schema='homelab-static-launch-v1', environment='production', runtime_sha256=core.RUNTIME_SHA256)
        site = core.decode_json(core.read_file(ROOT / '.local/site.json', protected=True))
        public = core.read_file(ROOT / '.local/root-ssh.pub', protected=True).decode().strip()
        password = core.read_file(ROOT / '.local/root-recovery-password.hash', protected=True).decode().strip()
        from site_profile import first_boot_payload, validate_production
        validate_production(config,site)
        payload = first_boot_payload(config,site)
    approval_path = outdir/'media-approval.json'
    core.new_file(approval_path,core.canonical(approval))
    core.require(sha(ISO) == core.ISO_SHA256 and sha(HELPER) == core.ASSISTANT_SHA256, 'vendor source or helper hash mismatch')
    validate_config(config)
    answer = template(config, password, public, site)
    stage = outdir / 'stage'
    (stage / 'homelab/src/homelab_installer').mkdir(mode=0o700, parents=True)
    core.new_file(stage / 'answer.toml', answer)
    core.new_file(stage / 'proxmox-first-boot', payload)
    core.new_file(stage / 'homelab/config.json', core.canonical(config))
    shutil.copyfile(ROOT / 'src/launch.py', stage / 'homelab/launch.py')
    shutil.copyfile(ROOT / 'src/thunderbolt.py', stage / 'homelab/thunderbolt.py')
    for filename in ('core.py','observe.py','__init__.py'):
        shutil.copyfile(ROOT / 'src/homelab_installer' / filename, stage / 'homelab/src/homelab_installer' / filename)
    validation = run([HELPER, 'validate-answer', stage / 'answer.toml'])
    (outdir / 'native-validation.txt').write_bytes(validation.stdout + validation.stderr)
    helper_base = outdir / 'native-prepared.iso'
    run([HELPER, 'prepare-iso', ISO, '--fetch-from','iso','--answer-file',stage/'answer.toml','--on-first-boot',stage/'proxmox-first-boot','--tmp',outdir,'--output',helper_base])
    run(['xorriso','-osirrox','on','-indev',helper_base,'-extract','/auto-installer-mode.toml',stage/'auto-installer-mode.toml'])
    members = {str(p.relative_to(stage)):sha(p) for p in stage.rglob('*') if p.is_file()}
    manifest = {'schema':'homelab-static-media-build-v1','build_approval':sha(approval_path),'files':members}
    core.new_file(stage / 'homelab/manifest.json', core.canonical(manifest))
    manifest_sha = sha(stage / 'homelab/manifest.json')
    original = (ROOT / 'build/unconfigured.sh').read_bytes()
    code_pins = {path: digest for path, digest in members.items() if path.endswith('.py')}
    changed = patched_startup(original, manifest_sha, code_pins)
    with tempfile.TemporaryDirectory(prefix='homelab-iso-', dir='/tmp') as temp:
        # Pseudo export preserves vendor xattrs as metadata, without trying to
        # apply trusted.overlay attributes to the unprivileged build container.
        exported = ROOT/'build/vendor-files.pseudo'
        core.require(exported.is_file(), 'vendor metadata/data export required')
        startup = outdir/'unconfigured-patched.sh'
        startup.write_bytes(changed)
        run(['bash','-n',startup])
        pseudo = Path(temp)/'edited.pseudo'
        count = 0
        with exported.open('rb') as source, pseudo.open('wb') as target:
            while True:
                line=source.readline()
                core.require(line, 'missing pseudo data marker')
                if line.startswith(b'usr/sbin/unconfigured.sh R '):
                    parts=line.decode().split()
                    line=(' '.join(parts[:1]+['F']+parts[2:6])+ ' cat '+str(startup)+'\n').encode()
                    count+=1
                target.write(line)
                if line == b'# START OF DATA - DO NOT MODIFY\n':
                    shutil.copyfileobj(source,target,8*1024**2)
                    break
        core.require(count==1, 'ambiguous startup pseudo entry')
        empty=Path(temp)/'empty';empty.mkdir()
        modified = outdir/'pve-installer.squashfs'
        with exported.open('rb') as records:
            root_record=records.readline().decode().split()
        core.require(root_record[:2]==['/','D'], 'missing vendor root metadata')
        run(['mksquashfs',empty,modified,'-pf',pseudo,'-noappend','-root-time',root_record[2],'-root-mode',root_record[3],'-root-uid',root_record[4],'-root-gid',root_record[5],'-comp','zstd','-Xcompression-level','3','-processors','2','-no-progress'])
        read_startup=run(['unsquashfs','-cat',modified,'usr/sbin/unconfigured.sh']).stdout
        core.require(read_startup==changed, 'modified startup readback differs')
        native=run(['unsquashfs','-cat',modified,'usr/bin/proxmox-auto-installer']).stdout
        core.require(core.sha(native)==core.RUNTIME_SHA256, 'native runtime changed during filesystem rebuild')
    menu = grub((ROOT/'build/vendor-grub.cfg').read_text())
    core.new_file(outdir/'grub.cfg',menu)
    finish(outdir)


def finish(outdir):
    stage=outdir/'stage'
    helper_base=outdir/'native-prepared.iso'
    modified=outdir/'pve-installer.squashfs'
    config=core.decode_json(core.read_file(stage/'homelab/config.json'))
    validate_config(config)
    name='fixture' if config['environment']=='synthetic' else 'production'
    manifest=core.decode_json(core.read_file(stage/'homelab/manifest.json'))
    members=manifest['files']
    for path,expected in members.items():
        core.require(sha(stage/path)==expected,'staged media member changed')
    manifest_sha=sha(stage/'homelab/manifest.json')
    changed=(outdir/'unconfigured-patched.sh').read_bytes()
    core.require(manifest_sha.encode() in changed, 'startup does not bind current manifest')
    core.require(run(['unsquashfs','-cat',modified,'usr/sbin/unconfigured.sh']).stdout==changed,'modified filesystem/startup mismatch')
    core.require(core.sha(run(['unsquashfs','-cat',modified,'usr/bin/proxmox-auto-installer']).stdout)==core.RUNTIME_SHA256,'native runtime mismatch')
    menu=(outdir/'grub.cfg').read_bytes()
    final=outdir/('Proxmox-9.2-1-'+name+'.iso')
    core.require(not final.exists(),'refuse final ISO overwrite')
    report=run(['xorriso','-dev',helper_base,'-report_system_area','cmd']).stdout.decode()
    uuid=next(line.split()[-1].strip("'") for line in report.splitlines() if line.startswith('-volume_date uuid'))
    core.require(re.fullmatch('[0-9]{16}',uuid),'unexpected source ISO volume UUID')
    shutil.copyfile(helper_base,final)
    # Use the vendor assistant's in-place keep/UUID-preservation method. Replaying
    # all hybrid partition commands into a new image overlaps its HFS/GPT ranges.
    run(['xorriso','-boot_image','any','keep','-volume_date','uuid',uuid,'-dev',final,'-map',modified,'/pve-installer.squashfs','-map',outdir/'grub.cfg','/boot/grub/grub.cfg','-map',stage/'homelab','/homelab'])
    readback = outdir/'readback'
    readback.mkdir(mode=0o700)
    for path in ['/homelab','/answer.toml','/auto-installer-mode.toml','/proxmox-first-boot','/boot/grub/grub.cfg']:
        run(['xorriso','-osirrox','on','-indev',final,'-extract',path,readback/Path(path).name])
    for path, expected in members.items():
        actual = readback/path if path.startswith('homelab/') else readback/Path(path).name
        core.require(sha(actual)==expected, 'final media member readback mismatch: '+path)
    core.require(sha(readback/'homelab/manifest.json')==manifest_sha and (readback/'grub.cfg').read_bytes()==menu, 'manifest or menu readback mismatch')
    result = run(['xorriso','-indev',final,'-report_el_torito','plain','-report_system_area','plain'])
    (outdir/'boot-record.txt').write_bytes(result.stdout+result.stderr)
    core.require(b'UEFI' in result.stdout and b'BIOS' in result.stdout, 'boot entries missing')
    receipt = {'schema':'homelab-single-usb-build-v1','environment':config['environment'],'iso':str(final),'sha256':sha(final),'bytes':final.stat().st_size,'source_iso_sha256':core.ISO_SHA256,'modified_startup_sha256':core.sha(changed),'modified_squashfs_sha256':sha(modified),'manifest_sha256':manifest_sha,'native_answer_validation':'passed static nonresolving placeholders','embedded_payload_readback':'passed','boot_structure':'BIOS and UEFI','default_entry':'check only','production_boot_or_erase_authorized':False,'native_boot_tests':'pending'}
    (outdir/'build-receipt.json').write_bytes(core.canonical(receipt))
    print(json.dumps(receipt), flush=True)


if __name__=='__main__': main()
