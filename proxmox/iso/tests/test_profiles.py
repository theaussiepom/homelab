import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from homelab_installer import core
from site_profile import first_boot_payload,validate_site,validate_production

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('usb_writer',ROOT/'scripts/write-usb.py')
usb=importlib.util.module_from_spec(spec);spec.loader.exec_module(usb)
workflow_spec=importlib.util.spec_from_file_location('workflow',ROOT/'scripts/workflow.py')
workflow=importlib.util.module_from_spec(workflow_spec);workflow_spec.loader.exec_module(workflow)
vendor_spec=importlib.util.spec_from_file_location('vendor_prepare',ROOT/'scripts/prepare-vendor.py')
vendor=importlib.util.module_from_spec(vendor_spec);vendor_spec.loader.exec_module(vendor)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.site=json.loads((ROOT/'config/fixture-site.json').read_text())
        self.hw=json.loads((ROOT/'config/fixture-hardware.json').read_text())

    def test_fixture_renders_the_selected_network_and_preserves_credential_boundary(self):
        payload=first_boot_payload(self.hw,self.site).decode()
        compile(payload,'first-boot','exec')
        self.assertIn('198.18.25.2/24',payload)
        self.assertNotIn('root-password',payload)
        self.assertNotIn('PRIVATE KEY',payload)
        namespace={'__name__':'fixture_import'};exec(payload,namespace)
        nics={name:mac for mac,name in self.hw['interface_names'].items()}
        rendered=namespace['configuration'](nics)
        self.assertEqual(rendered.count('gateway '),1)
        self.assertIn('bridge-ports mgmt0',rendered)
        self.assertIn('bridge-ports fast0',rendered)
        self.assertNotIn('vmbr0.15',rendered)

    def test_bad_or_ambiguous_network_settings_refuse(self):
        for field,value in [('admin_vlans',[25,25]),('fast_vlans',[20,25]),('timezone','NOT_A_TIMEZONE'),('fqdn','bad\nname.example.invalid')]:
            site=copy.deepcopy(self.site);site[field]=value
            with self.subTest(field=field),self.assertRaises((ValueError,KeyError)):validate_site(site)
        for field,value in [('gateway','198.18.99.1'),('address','198.18.25.0/24'),('vlan',True)]:
            site=copy.deepcopy(self.site);site['management'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):validate_site(site)

    def test_production_rejects_example_values_and_requires_exact_real_inputs(self):
        self.hw['environment']='production'
        with self.assertRaises(core.Refusal):validate_production(self.hw,self.site)
        self.site['fqdn']='pve.unit.example.org';self.site['mailto']='operator@unit.example.org'
        self.hw['machine_uuid']='33333333-3333-4333-8333-333333333333'
        for i,disk in enumerate(self.hw['disk_members']+self.hw['protected_disks']):
            disk['disk_serial']='UNIT-'+str(i);disk['disk_by_id']='/dev/disk/by-id/UNIT-'+str(i)
        validate_production(self.hw,self.site)
        self.hw['disk_members'][0]['disk_serial']='REPLACE_DISK'
        with self.assertRaises(core.Refusal):validate_production(self.hw,self.site)


class UsbTests(unittest.TestCase):
    def test_only_explicit_whole_disk_names_are_allowed(self):
        self.assertEqual(usb.device_name('/dev/disk4'),'/dev/disk4')
        for value in [None,'/dev/disk4s1','/dev/rdisk4','/dev/nvme0n1','disk4','/dev/disk4;echo unsafe']:
            with self.subTest(value=value),self.assertRaises(ValueError):usb.device_name(value)

    def test_internal_readonly_virtual_or_incomplete_media_refuse(self):
        good={'DeviceIdentifier':'disk4','WholeDisk':True,'Internal':False,'BusProtocol':'USB','IORegistryEntryName':'Fixture USB','TotalSize':32*1024**3,'WritableMedia':True,'SystemImage':False,'DeviceTreePath':'fixture-port'}
        self.assertEqual(usb.safe_identity(good),good)
        for key,value in [('Internal',True),('WholeDisk',False),('WritableMedia',False),('SystemImage',True),('BusProtocol','PCI'),('DeviceTreePath',None)]:
            bad=dict(good);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):usb.safe_identity(bad)

    def test_failed_write_evidence_retains_progress_and_prevents_silent_loss(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'receipt.json';record={'write_started':True,'image_bytes_written':1024,'written':False,'readback_verified':False,'error':'fixture short write'}
            usb.save_receipt(path,record)
            actual=json.loads(path.read_text())
            self.assertEqual(actual['image_bytes_written'],1024)
            self.assertFalse(actual['readback_verified'])
            self.assertIn('recorded_at',actual)


class AcceptanceTests(unittest.TestCase):
    def test_missing_source_test_evidence_blocks_acceptance(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(workflow,'ROOT',Path(folder)):
            with self.assertRaisesRegex(ValueError,'make unit first'):workflow.qualify()

    def test_stale_or_failed_source_evidence_blocks_acceptance(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(workflow,'ROOT',Path(folder)):
            evidence=Path(folder)/'evidence';evidence.mkdir()
            for passed,digest in [(True,'stale'),(False,workflow.source_digest())]:
                (evidence/'source-tests.json').write_text(json.dumps({'passed':passed,'source_sha256':digest}))
                with self.subTest(passed=passed),self.assertRaisesRegex(ValueError,'make unit again'):workflow.qualify()


class VendorCacheTests(unittest.TestCase):
    def test_partial_vendor_preparation_is_not_silently_reused(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            self.assertFalse(vendor.verify_derived(root))
            (root/'vendor.squashfs').write_bytes(b'incomplete fixture')
            with self.assertRaisesRegex(core.Refusal,'incomplete vendor preparation'):vendor.verify_derived(root)

    def test_changed_derived_cache_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in vendor.DERIVED:(root/name).write_bytes(name.encode())
            record={'source_iso_sha256':core.ISO_SHA256,'files':{name:vendor.digest(root/name) for name in vendor.DERIVED}}
            (root/'vendor-inputs.json').write_text(json.dumps(record))
            self.assertTrue(vendor.verify_derived(root))
            (root/'vendor.squashfs').write_bytes(b'changed fixture')
            with self.assertRaisesRegex(core.Refusal,'derived vendor input changed'):vendor.verify_derived(root)


if __name__=='__main__':unittest.main()
