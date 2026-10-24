import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from homelab_installer import core
from homelab_installer.observe import checked_inventory
import launch


def facts():
    cfg=json.loads((ROOT/'config/fixture-hardware.json').read_text())
    obs={'context':'installer-live','machine_uuid':cfg['machine_uuid'],'uefi':True,'boot_id':'22222222-2222-4222-8222-222222222222','runtime_binary_path':launch.RUNTIME,'runtime_binary_sha256':cfg['runtime_sha256'],'disks':[],'nics':[]}
    native={'boot_type':'efi','disks':[]}
    for index,identity in enumerate(cfg['disk_members']+cfg['protected_disks']):
        path='/dev/vd'+chr(ord('a')+index)
        obs['disks'].append({'devname':path,'by_ids':[identity['disk_by_id']],'size_bytes':identity['disk_size_bytes'],'read_only':False,'removable':False,'udev':{'DEVNAME':path,'ID_SERIAL_SHORT':identity['disk_serial']}})
        native['disks'].append([index,path,identity['disk_size_bytes']//512,'fixture',512,'/sys/fixture'])
    for index,mac in enumerate(cfg['interface_names']):
        obs['nics'].append({'name':'ens'+str(index+3),'mac':mac,'udev':{'ID_NET_NAME_MAC':'enx'+mac.replace(':','')}})
    return cfg,obs,native


class LaunchTests(unittest.TestCase):
    def test_confirmation_requires_exact_line_and_bounds_partial_input(self):
        for message,expected in [(b'INSTALL A B\n',True),(b'CANCEL\n',False),(b'INSTALL A',False)]:
            read,write=os.pipe()
            try:
                os.write(write,message)
                if expected:launch.read_confirmation(read,'INSTALL A B',timeout=0.01)
                else:
                    with self.assertRaises(core.Refusal):launch.read_confirmation(read,'INSTALL A B',timeout=0.01)
            finally:os.close(read);os.close(write)

    def test_only_actual_boot_media_can_be_excluded_from_native_inventory(self):
        checked_inventory({'/dev/sda','/dev/vda','/dev/vdb'}, {'/dev/vda','/dev/vdb'}, '/dev/sda')
        checked_inventory({'/dev/vda','/dev/vdb'}, {'/dev/vda','/dev/vdb'})
        checked_inventory({'/dev/sda','/dev/vda'}, {'/dev/sda','/dev/vda'}, '/dev/sda')
        with self.assertRaises(core.Refusal):checked_inventory({'/dev/sda','/dev/vda','/dev/vdb'}, {'/dev/vda'}, '/dev/sda')
        with self.assertRaises(core.Refusal):checked_inventory({'/dev/vda','/dev/vdb'}, {'/dev/vda','/dev/vdb'}, '/dev/sda')
        with self.assertRaises(core.Refusal):checked_inventory({'/dev/sda','/dev/vda'}, {'/dev/vda'})

    def test_vendor_transport_adds_exactly_one_newline(self):
        original=b'[global]\nfqdn = "pve.example.invalid"\n'
        self.assertEqual(launch.fetched_template(original+b'\n',original),original)
        for changed in [original,original+b'\n\n',original+b'\n[extra]\n',original.replace(b'pve.',b'other.')+b'\n']:
            with self.assertRaises(core.Refusal):launch.fetched_template(changed,original)

    def test_resolves_identity_not_prior_disk_order(self):
        cfg,obs,native=facts()
        for disk,row,new in zip(obs['disks'],native['disks'],['/dev/nvme2n1','/dev/nvme0n1','/dev/nvme1n1']):
            disk['devname']=disk['udev']['DEVNAME']=row[1]=new
        result=launch.check_hardware(cfg,obs,native)
        self.assertEqual(result['targets'],['/dev/nvme2n1','/dev/nvme0n1'])
        self.assertEqual(result['protected'],['/dev/nvme1n1'])

    def test_rejects_mismatches_before_render_or_writer(self):
        changes=[
          ('obs',['machine_uuid'],'33333333-3333-4333-8333-333333333333'),
          ('obs',['uefi'],False),('native',['boot_type'],'bios'),
          ('obs',['context'],'installed-host'),('obs',['runtime_binary_sha256'],'aa'*32),
          ('obs',['disks',1,'read_only'],True),('obs',['disks',1,'removable'],True),
          ('obs',['disks',0,'udev','ID_SERIAL_SHORT'],'WRONG'),
          ('obs',['disks',1,'by_ids'],[]),('obs',['disks',2,'by_ids'],[]),
          ('obs',['disks',2,'size_bytes'],1),('native',['disks',1,2],1),
          ('native',['disks',1,1],'/dev/vdz'),('native',['disks',1,0],0),
          ('obs',['nics',1,'mac'],'02:00:00:00:10:03'),
          ('obs',['nics',0,'udev','ID_NET_NAME_MAC'],'enxBAD'),
          ('cfg',['disk_members',1,'disk_serial'],'LAB-OLD'),
          ('cfg',['disk_members',1,'disk_by_id'],'/dev/disk/by-id/virtio-LAB-OLD'),
          ('cfg',['disk_members',0,'disk_serial'],'LAB-*'),
        ]
        for area,path,value in changes:
            with self.subTest(area=area,path=path):
                cfg,obs,native=facts(); obj={'cfg':cfg,'obs':obs,'native':native}[area]
                for key in path[:-1]:obj=obj[key]
                obj[path[-1]]=value
                with self.assertRaises(core.Refusal):launch.check_hardware(cfg,obs,native)

    def test_duplicate_serial_and_alias_each_refuse(self):
        for duplicate in ['serial','alias','nic']:
            cfg,obs,native=facts()
            if duplicate=='nic':obs['nics'].append(copy.deepcopy(obs['nics'][0]))
            else:
                new=copy.deepcopy(obs['disks'][0]);new['devname']=new['udev']['DEVNAME']='/dev/vdd'
                if duplicate=='serial':new['by_ids']=[]
                else:new['udev']['ID_SERIAL_SHORT']='OTHER'
                obs['disks'].append(new);native['disks'].append([3,'/dev/vdd',new['size_bytes']//512,'fixture',512,'/sys/fixture'])
            with self.subTest(duplicate=duplicate),self.assertRaises(core.Refusal):launch.check_hardware(cfg,obs,native)

    def test_only_placeholder_disk_list_is_replaced(self):
        cfg,obs,native=facts()
        # Load the build module without relying on its Linux-only absolute input directory.
        import build_single_usb as build
        public=(ROOT/'config/fixture-ssh.pub').read_text().strip()
        template=build.template(cfg,'$6$synthetic$'+'A'*86,public,json.loads((ROOT/'config/fixture-site.json').read_text()))
        result=launch.render_answer(template,launch.check_hardware(cfg,obs,native)['targets'])
        parsed=tomllib.loads(result.decode()); old=tomllib.loads(template.decode())
        self.assertEqual(parsed['disk-setup']['disk-list'],['/dev/vda','/dev/vdb'])
        self.assertEqual(parsed['global'],old['global'])
        self.assertEqual(parsed['network'],old['network'])
        self.assertEqual(parsed['first-boot'],old['first-boot'])
        with self.assertRaises(core.Refusal):launch.render_answer(result,['/dev/vdc','/dev/vdd'])

    def test_media_file_change_and_missing_members_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'homelab').mkdir()
            body=core.canonical({'schema':'homelab-static-media-build-v1','build_approval':'ab'*32,'files':{}})
            (root/'homelab/manifest.json').write_bytes(body)
            with self.assertRaisesRegex(core.Refusal,'hash mismatch'):launch.verify_media(root,'00'*32)
            with self.assertRaisesRegex(core.Refusal,'missing media members'):launch.verify_media(root,core.sha(body))


if __name__=='__main__': unittest.main()
