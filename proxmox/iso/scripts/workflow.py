#!/usr/bin/env python3
"""Small command dispatcher. Heavy VM cases run one at a time."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path('/work')


def run(*args):subprocess.run([sys.executable,*map(str,args)],check=True)


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024**2),b''):h.update(block)
    return h.hexdigest()


def source_digest():
    digest=hashlib.sha256()
    files=[p for folder in ('src','scripts','tests','config','docker') for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    files += [ROOT/'Makefile',ROOT/'.dockerignore']
    for path in sorted(files):
        if path.is_file():digest.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes()+b'\0')
    return digest.hexdigest()


def unit():
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    receipt={'passed':result.wasSuccessful(),'tests_run':result.testsRun,'source_sha256':source_digest(),'recorded_at':datetime.now(timezone.utc).isoformat()}
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    for name in ('source-tests-'+stamp+'.json','source-tests.json'):
        (ROOT/'evidence'/name).write_text(json.dumps(receipt,indent=2)+'\n')
    if not result.wasSuccessful():raise SystemExit(1)


def qualify():
    unit_path=ROOT/'evidence/source-tests.json'
    if not unit_path.is_file():raise ValueError('Run make unit first; current source test evidence is missing')
    units=json.loads(unit_path.read_text())
    if units.get('passed') is not True or units.get('source_sha256')!=source_digest():raise ValueError('Run make unit again; source tests failed or no longer match the source')
    cases=['matching-check','wrong-machine','missing-member','ambiguous-member','cancel-install','profile-wrong-machine']
    images={name:json.loads((ROOT/f'build/single-usb-{name}/build-receipt.json').read_text()) for name in ('fixture','production')}
    for env,record in images.items():
        image=ROOT/f'build/single-usb-{env}/Proxmox-9.2-1-{env}.iso'
        if sha(image)!=record['sha256']:raise ValueError('Image changed since its build')
    accepted=[]
    for case in cases:
        receipts=sorted((ROOT/'build/vm-tests').glob(case+'-*/receipt.json'))
        if not receipts:raise ValueError('Missing boot test: '+case)
        path=receipts[-1];record=json.loads(path.read_text());env='production' if case=='profile-wrong-machine' else 'fixture'
        if record.get('result')!=record['expected'] or not record.get('no_target_disk_writes') or not record.get('reason_matches') or record.get('local_vm_exit')!=0 or record.get('image_sha256')!=images[env]['sha256']:
            raise ValueError('Boot test did not pass for the current image: '+case)
        accepted.append({'case':case,'receipt':str(path.relative_to(ROOT)),'receipt_sha256':sha(path)})
    meta=json.loads((ROOT/'evidence/final-metadata-verification.json').read_text())
    if meta.get('all_other_vendor_metadata_preserved') is not True or meta.get('modified_squashfs_sha256')!=images['production']['modified_squashfs_sha256']:
        raise ValueError('Metadata verification missing, failed or stale for the current image')
    record={'schema':'homelab-packaged-media-acceptance-v1','production_iso_sha256':images['production']['sha256'],'usb_write_admitted':True,'source_sha256':units['source_sha256'],'unit_test_count':units['tests_run'],'cases':accepted,'scope':'Local media preparation only; physical installation and first boot remain unverified.'}
    (ROOT/'evidence/media-acceptance.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Current images passed the required local checks. USB preparation can proceed; physical installation is a separate step.')


def main():
    action=sys.argv[1]
    if action in ('fixture','build-production'):
        run(ROOT/'scripts/prepare-vendor.py')
        run(ROOT/'src/build_single_usb.py',*(['--fixture'] if action=='fixture' else []))
        if action=='build-production':run(ROOT/'scripts/verify_metadata.py')
    elif action=='test-boot':
        for case in ['matching-check','wrong-machine','missing-member','ambiguous-member','cancel-install']:run(ROOT/'scripts/boot_test.py',case)
    elif action=='test-profile':run(ROOT/'scripts/boot_test.py','profile-wrong-machine')
    elif action=='qualify':qualify()
    elif action=='unit':unit()
    else:raise ValueError('Unsupported workflow action')


if __name__=='__main__':main()
