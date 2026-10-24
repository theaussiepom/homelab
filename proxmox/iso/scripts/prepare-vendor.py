#!/usr/bin/env python3
"""Verify cached vendor files; extract only build inputs, never a disk device."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

ROOT=Path('/work');sys.path.insert(0,str(ROOT/'src'))
from homelab_installer import core


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024**2),b''):h.update(block)
    return h.hexdigest()


DERIVED=('vendor.squashfs','vendor-grub.cfg','unconfigured.sh','vendor-files.pseudo')


def verify_derived(build):
    receipt=build/'vendor-inputs.json'
    if not receipt.exists():
        core.require(not any((build/name).exists() for name in DERIVED),'incomplete vendor preparation exists; preserve and review those derived files before retrying')
        return False
    record=core.decode_json(core.read_file(receipt))
    core.require(set(record)=={'source_iso_sha256','files'} and record['source_iso_sha256']==core.ISO_SHA256 and set(record['files'])==set(DERIVED),'unsupported derived-vendor receipt')
    for name,expected in record['files'].items():
        path=build/name
        core.require(path.is_file() and not path.is_symlink() and digest(path)==expected,'derived vendor input changed: '+name)
    return True


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--fetch',action='store_true');args=parser.parse_args()
    build=ROOT/'build';vendor=build/'vendor';vendor.mkdir(parents=True,exist_ok=True)
    iso=vendor/'proxmox-ve_9.2-1.iso'
    if args.fetch:
        if not iso.exists():
            partial=iso.with_suffix('.iso.download')
            core.require(not partial.exists(),'partial download exists; inspect it before retrying')
            print('Downloading the pinned vendor ISO (about 1.7 GB)...',flush=True)
            with urllib.request.urlopen('https://enterprise.proxmox.com/iso/proxmox-ve_9.2-1.iso',timeout=60) as response,partial.open('xb') as target:
                while True:
                    block=response.read(8*1024**2)
                    if not block:break
                    target.write(block)
                    core.require(target.tell()<=2*1024**3,'unexpected oversized ISO')
            core.require(digest(partial)==core.ISO_SHA256,'downloaded ISO hash mismatch');partial.rename(iso)
        subprocess.run([sys.executable,str(ROOT/'scripts/fetch-assistant.py')],check=True)
    core.require(iso.is_file() and digest(iso)==core.ISO_SHA256,'place the pinned vendor ISO in build/vendor/ or run make fetch')
    helper=build/'assistant-root/usr/bin/proxmox-auto-install-assistant'
    core.require(helper.is_file() and digest(helper)==core.ASSISTANT_SHA256,'verified native assistant missing; run make fetch')
    cached=verify_derived(build)
    for src,name in [('/pve-installer.squashfs','vendor.squashfs'),('/boot/grub/grub.cfg','vendor-grub.cfg')]:
        dest=build/name
        if not dest.exists():subprocess.run(['xorriso','-osirrox','on','-indev',str(iso),'-extract',src,str(dest)],check=True,capture_output=True)
    squash=build/'vendor.squashfs'
    runtime=subprocess.run(['unsquashfs','-cat',str(squash),'usr/bin/proxmox-auto-installer'],check=True,capture_output=True).stdout
    core.require(core.sha(runtime)==core.RUNTIME_SHA256,'native runtime differs from supported release')
    startup=subprocess.run(['unsquashfs','-cat',str(squash),'usr/sbin/unconfigured.sh'],check=True,capture_output=True).stdout
    from build_single_usb import STARTUP_SHA
    core.require(core.sha(startup)==STARTUP_SHA,'vendor startup differs from supported release')
    (build/'unconfigured.sh').write_bytes(startup)
    pseudo=build/'vendor-files.pseudo'
    if not pseudo.exists():subprocess.run(['unsquashfs','-processors','1','-pf',str(pseudo),str(squash)],check=True,capture_output=True)
    if not cached:
        record={'source_iso_sha256':core.ISO_SHA256,'files':{name:digest(build/name) for name in DERIVED}}
        core.new_file(build/'vendor-inputs.json',core.canonical(record))
    print('Vendor ISO, helper and native runtime verified; build inputs ready.',flush=True)


if __name__=='__main__':main()
