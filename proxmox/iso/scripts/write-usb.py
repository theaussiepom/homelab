#!/usr/bin/env python3
"""macOS USB helper. Inspection is read-only; --write is always explicit."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
IDENTITY_KEYS=('DeviceIdentifier','WholeDisk','Internal','BusProtocol','IORegistryEntryName','TotalSize','WritableMedia','SystemImage','DeviceTreePath')


def checked(args):return subprocess.run(args,check=True,capture_output=True).stdout


def device_name(value):
    if not re.fullmatch(r'/dev/disk[0-9]+',value or ''):raise ValueError('Choose an explicit whole disk, for example /dev/disk4; partitions and other paths are refused')
    return value


def safe_identity(info):
    if info.get('WholeDisk') is not True or info.get('Internal') is not False or info.get('BusProtocol')!='USB' or info.get('WritableMedia') is not True or info.get('SystemImage') is not False:
        raise ValueError('Target must be a writable, external, physical USB whole disk')
    if not isinstance(info.get('TotalSize'),int) or not info.get('DeviceTreePath') or not info.get('IORegistryEntryName'):
        raise ValueError('USB physical identity is incomplete')
    return {key:info[key] for key in IDENTITY_KEYS}


def snapshot(device):
    device_name(device)
    info=safe_identity(plistlib.loads(checked(['diskutil','info','-plist',device])))
    external=plistlib.loads(checked(['diskutil','list','-plist','external','physical']))
    if external['WholeDisks']!=[device.removeprefix('/dev/')]:raise ValueError('Disconnect other external physical disks before preparing this USB')
    listing=plistlib.loads(checked(['diskutil','list','-plist',device]))
    disks=listing['AllDisksAndPartitions']
    if len(disks)!=1 or disks[0]['DeviceIdentifier']!=info['DeviceIdentifier']:raise ValueError('Unexpected partition listing')
    partitions=[]
    for part in disks[0].get('Partitions',[]):
        detail=plistlib.loads(checked(['diskutil','info','-plist','/dev/'+part['DeviceIdentifier']]))
        partitions.append({'device':part['DeviceIdentifier'],'bytes':part['Size'],'content':part.get('Content'),'uuid':detail.get('DiskUUID',detail.get('PartitionUUID'))})
    return {'identity':info,'partitions':partitions}


def sha(path):
    result=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024**2),b''):result.update(block)
    return result.hexdigest()


def write_all(fd,data):
    view=memoryview(data)
    while view:
        written=os.write(fd,view)
        if written<=0:raise OSError('Short USB write')
        view=view[written:]


def save_receipt(path,record):
    record['recorded_at']=datetime.now(timezone.utc).isoformat()
    temp=path.with_suffix('.pending')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'w') as stream:json.dump(record,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    os.replace(temp,path)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inspect');parser.add_argument('--save',type=Path)
    parser.add_argument('--device');parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    if sys.platform!='darwin':raise ValueError('This automatic USB writer supports macOS only; see README for other systems')
    if args.inspect:
        if args.write or args.device:raise ValueError('Inspect and write modes cannot be combined')
        record=snapshot(args.inspect);print(json.dumps(record,indent=2))
        if args.save:
            fd=os.open(args.save,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
            with os.fdopen(fd,'w') as stream:json.dump(record,stream,indent=2);stream.write('\n')
            print('Saved the USB identity. No device bytes were changed. Check the model and size before continuing.')
        return
    device=device_name(args.device)
    expected=json.loads((ROOT/'.local/usb.json').read_text())
    safe_identity(expected['identity'])
    if snapshot(device)!=expected:raise ValueError('USB identity or partition layout changed since inspection; stop and investigate')
    build=json.loads((ROOT/'build/single-usb-production/build-receipt.json').read_text())
    image=ROOT/'build/single-usb-production/Proxmox-9.2-1-production.iso'
    if build['environment']!='production' or image.is_symlink() or not image.is_file():raise ValueError('Expected a regular production image; practice images are refused')
    size=image.stat().st_size
    if size!=build['bytes'] or sha(image)!=build['sha256']:raise ValueError('Image changed since its build')
    acceptance=json.loads((ROOT/'evidence/media-acceptance.json').read_text())
    if acceptance.get('usb_write_admitted') is not True or acceptance.get('production_iso_sha256')!=build['sha256']:raise ValueError('Run make test-profile qualify for this exact image first')
    record={'device':device,'image_sha256':build['sha256'],'image_bytes':size,'identity':expected['identity'],'write_started':False,'image_bytes_written':0,'written':False,'readback_verified':False,'ejected':False}
    if not args.write:
        print('READ-ONLY CHECK PASSED. Nothing was written. Use make usb-write with the same USB argument to write it.')
        print(json.dumps(record,indent=2));return
    if os.geteuid()!=0:raise PermissionError('Run the explicit usb-write command; macOS administrator authentication is required')
    receipt=ROOT/'evidence/usb-write-receipt.json'
    if receipt.exists():raise ValueError('A USB operation receipt already exists. Do not replay the operation; review that receipt first')
    if size+65536>=expected['identity']['TotalSize']:raise ValueError('The image does not fit on this USB')
    save_receipt(receipt,record)
    fd=None
    try:
        print('WRITE MODE: unmounting only the inspected USB...',flush=True)
        checked(['diskutil','unmountDisk',device])
        if snapshot(device)!=expected:raise ValueError('USB identity changed immediately before writing')
        raw='/dev/r'+device.removeprefix('/dev/')
        fd=os.open(raw,os.O_RDWR|os.O_EXCL)
        if not stat.S_ISCHR(os.fstat(fd).st_mode):raise ValueError('Expected the raw USB device')
        record['write_started']=True;save_receipt(receipt,record)
        os.lseek(fd,expected['identity']['TotalSize']-65536,os.SEEK_SET);write_all(fd,b'\0'*65536)
        record['old_backup_partition_table_cleared']=True
        os.lseek(fd,0,os.SEEK_SET);mark=25
        with image.open('rb') as source:
            for block in iter(lambda:source.read(1024**2),b''):
                write_all(fd,block);record['image_bytes_written']+=len(block)
                if record['image_bytes_written']*100//size>=mark:
                    save_receipt(receipt,record);print('USB write '+str(mark)+'%',flush=True);mark+=25
        checked(['/bin/sync']);record['written']=True;save_receipt(receipt,record)
        print('Write finished. Reading the entire image back...',flush=True)
        os.lseek(fd,0,os.SEEK_SET);digest=hashlib.sha256();remaining=size
        while remaining:
            block=os.read(fd,min(1024**2,remaining))
            if not block:raise OSError('Short USB readback')
            digest.update(block);remaining-=len(block)
        record['readback_sha256']=digest.hexdigest()
        if record['readback_sha256']!=build['sha256']:raise ValueError('USB readback differs; stop and do not retry')
        record['readback_verified']=True
        os.close(fd);fd=None
        if safe_identity(plistlib.loads(checked(['diskutil','info','-plist',device])))!=expected['identity']:raise ValueError('USB physical identity changed after writing')
        checked(['diskutil','eject',device]);record['ejected']=True
    except Exception as error:
        record['error']=str(error);raise
    finally:
        if fd is not None:os.close(fd)
        save_receipt(receipt,record)
    print(json.dumps({'usb_ready':True,'readback_verified':True,'ejected':True}),flush=True)


if __name__=='__main__':main()
