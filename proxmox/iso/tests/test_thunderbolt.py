import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import thunderbolt as tb
from homelab_installer import core
import launch
import build_single_usb as build
from site_profile import first_boot_payload

ROOT = Path(__file__).resolve().parents[1]
MACHINE = '11111111-1111-4111-8111-111111111111'
DEVICE = '22222222-2222-4222-8222-222222222222'
OTHER = '33333333-3333-4333-8333-333333333333'
MAC = '02:00:00:00:10:02'


def profile():
    return {'machine_uuid': MACHINE, 'devices': [{'unique_id': DEVICE, 'mac': MAC}]}


def machine(root, device=DEVICE, state='0', security='user', mac=MAC):
    path = root / 'sys/class/dmi/id/product_uuid'
    path.parent.mkdir(parents=True); path.write_text(MACHINE + '\n')
    (root / 'sys/firmware/efi').mkdir(parents=True)
    bus = root / 'sys/bus/thunderbolt/devices'
    (bus / 'domain0').mkdir(parents=True)
    (bus / 'domain0/security').write_text(security + '\n')
    adapter = bus / '0-1'; adapter.mkdir()
    (adapter / 'unique_id').write_text(device + '\n')
    (adapter / 'authorized').write_text(state + '\n')
    net = root / 'sys/class/net/fast0'; net.mkdir(parents=True)
    (net / 'address').write_text(mac + '\n')
    return adapter


class ThunderboltTests(unittest.TestCase):
    def test_usb_authorisation_precedes_both_native_inventory_snapshots(self):
        vendor = (b'#!/bin/bash\ndhclient -v\n'
                  b'/usr/bin/proxmox-low-level-installer dump-env\n'
                  b'/usr/bin/proxmox-low-level-installer dump-udev\n'
                  b'if /usr/bin/proxmox-auto-installer </run/automatic-installer-answers; then\nfi\n')
        with patch.object(build, 'STARTUP_SHA', core.sha(vendor)):
            paths = ['homelab/thunderbolt.py', 'homelab/launch.py', 'homelab/src/homelab_installer/core.py', 'homelab/src/homelab_installer/observe.py', 'homelab/src/homelab_installer/__init__.py']
            script = build.patched_startup(vendor, 'ab' * 32, {p: 'cd' * 32 for p in paths})
            invocation = b'/usr/bin/python3 /cdrom/homelab/thunderbolt.py'
            self.assertLess(script.index(b'sha256sum --check --status'), script.index(invocation))
            self.assertLess(script.index(invocation), script.index(b' dump-env'))
            self.assertLess(script.index(b' dump-env'), script.index(b' dump-udev'))
            self.assertLess(script.index(b' dump-udev'), script.index(b'if /usr/bin/python3 /cdrom/homelab/launch.py'))

    def test_changed_media_cannot_reach_device_authorisation(self):
        with patch('sys.argv', ['thunderbolt.py', '--manifest-sha256', '00' * 32]), \
             patch.object(launch, 'verify_media', side_effect=core.Refusal('media changed')), \
             patch.object(launch, 'hold', side_effect=RuntimeError('stopped')), \
             patch.object(tb, 'authorize') as authorize:
            with self.assertRaisesRegex(RuntimeError, 'stopped'): tb.main()
            authorize.assert_not_called()

    def test_only_selected_device_is_authorised_and_other_devices_stay_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); selected = machine(root)
            other = selected.with_name('0-2'); other.mkdir()
            (other / 'unique_id').write_text(OTHER + '\n')
            (other / 'authorized').write_text('0\n')
            tb.authorize(profile(), root=root, timeout=0)
            self.assertEqual((selected / 'authorized').read_text().strip(), '1')
            self.assertEqual((other / 'authorized').read_text().strip(), '0')

    def test_wrong_machine_and_legacy_boot_refuse_before_authorisation(self):
        for change in ('machine', 'uefi'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); adapter = machine(root)
                if change == 'machine':
                    (root / 'sys/class/dmi/id/product_uuid').write_text(OTHER)
                else:
                    (root / 'sys/firmware/efi').rmdir()
                with self.assertRaises(ValueError): tb.authorize(profile(), root=root, timeout=0)
                self.assertEqual((adapter / 'authorized').read_text().strip(), '0')

    def test_missing_or_duplicate_identity_refuses_without_authorising_any_device(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); adapter = machine(root, device=DEVICE if duplicate else OTHER)
                if duplicate:
                    other = adapter.with_name('0-2'); other.mkdir()
                    (other / 'unique_id').write_text(DEVICE)
                    (other / 'authorized').write_text('0')
                with self.assertRaises(ValueError): tb.authorize(profile(), root=root, timeout=0)
                self.assertEqual((adapter / 'authorized').read_text().strip(), '0')

    def test_secure_mode_requires_its_existing_trust_and_is_not_downgraded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); adapter = machine(root, security='secure')
            with self.assertRaises(ValueError): tb.authorize(profile(), root=root, timeout=0)
            self.assertEqual((adapter / 'authorized').read_text().strip(), '0')
            (adapter / 'authorized').write_text('1')
            tb.authorize(profile(), root=root, timeout=0)

    def test_mac_mismatch_and_duplicate_mac_refuse_after_enumeration(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); machine(root, mac=MAC if duplicate else '02:00:00:00:99:99')
                if duplicate:
                    other = root / 'sys/class/net/other'; other.mkdir()
                    (other / 'address').write_text(MAC)
                with self.assertRaises(ValueError): tb.authorize(profile(), root=root, timeout=0)

    def test_each_boot_can_authorise_again_and_already_authorised_is_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); adapter = machine(root)
            tb.authorize(profile(), root=root, timeout=0)
            tb.authorize(profile(), root=root, timeout=0)
            (adapter / 'authorized').write_text('0')
            tb.authorize(profile(), root=root, timeout=0)
            self.assertEqual((adapter / 'authorized').read_text().strip(), '1')

    def test_failed_mac_validation_revokes_only_a_new_authorisation(self):
        for initial in ('0', '1'):
            with self.subTest(initial=initial), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); adapter = machine(root, state=initial, mac='02:00:00:00:99:99')
                with self.assertRaisesRegex(ValueError, 'MAC did not appear'):
                    tb.authorize(profile(), root=root, timeout=0)
                self.assertEqual((adapter / 'authorized').read_text().strip(), initial)

    def test_failed_validation_does_not_revoke_a_replacement_device(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); adapter = machine(root)
            def replaced(*args):
                (adapter / 'unique_id').write_text(OTHER)
                raise ValueError('MAC did not appear')
            with patch.object(tb, 'wait_for_mac', side_effect=replaced):
                with self.assertRaisesRegex(RuntimeError, 'could not be revoked'):
                    tb.authorize(profile(), root=root, timeout=0)
            self.assertEqual((adapter / 'authorized').read_text().strip(), '1')

    def test_failed_revocation_reports_that_access_may_remain(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); adapter = machine(root, mac='02:00:00:00:99:99')
            original = Path.write_text
            def write(path, value, *args, **kwargs):
                if path == adapter / 'authorized' and value == '0\n':
                    raise PermissionError('revocation denied')
                return original(path, value, *args, **kwargs)
            with patch.object(Path, 'write_text', write):
                with self.assertRaisesRegex(RuntimeError, 'could not be revoked'):
                    tb.authorize(profile(), root=root, timeout=0)
            self.assertEqual((adapter / 'authorized').read_text().strip(), '1')

    def test_uppercase_machine_uuid_can_reach_adapter_authorisation(self):
        cfg = json.loads((ROOT / 'config/fixture-hardware.json').read_text())
        cfg['machine_uuid'] = 'AABBCCDD-1111-4111-8111-111111111111'
        cfg['thunderbolt_devices'] = profile()['devices']
        launch.validate_config(cfg)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); adapter = machine(root)
            (root / 'sys/class/dmi/id/product_uuid').write_text(cfg['machine_uuid'].lower())
            tb.authorize({'machine_uuid': cfg['machine_uuid'], 'devices': cfg['thunderbolt_devices']}, root=root, timeout=0)
            self.assertEqual((adapter / 'authorized').read_text().strip(), '1')

    def test_hardware_profile_rejects_wildcards_and_unpinned_mac(self):
        cfg = json.loads((ROOT / 'config/fixture-hardware.json').read_text())
        cfg['thunderbolt_devices'] = profile()['devices']
        launch.validate_config(cfg)
        for key, value in [('unique_id', '*'), ('mac', '02:00:00:00:99:99')]:
            bad = copy.deepcopy(cfg); bad['thunderbolt_devices'][0][key] = value
            with self.assertRaises((ValueError, core.Refusal)): launch.validate_config(bad)

    def test_generated_first_boot_installs_a_self_contained_required_every_boot_service(self):
        cfg = json.loads((ROOT / 'config/fixture-hardware.json').read_text())
        cfg['thunderbolt_devices'] = profile()['devices']
        site = json.loads((ROOT / 'config/fixture-site.json').read_text())
        payload = first_boot_payload(cfg, site)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); adapter = machine(root)
            mgmt = root / 'sys/class/net/mgmt0'; mgmt.mkdir()
            (mgmt / 'address').write_text('02:00:00:00:10:01')
            interfaces = root / 'etc/network/interfaces'; interfaces.parent.mkdir(parents=True)
            interfaces.write_text('vendor network\n')
            source = root / 'hook.py'; source.write_bytes(payload)
            spec = importlib.util.spec_from_file_location('generated_hook', source)
            hook = importlib.util.module_from_spec(spec); spec.loader.exec_module(hook)
            hook.install(root)
            self.assertEqual((adapter / 'authorized').read_text().strip(), '1')
            self.assertEqual(interfaces.with_name('interfaces.before-homelab').read_text(), 'vendor network\n')
            service = root / 'etc/systemd/system/homelab-thunderbolt.service'
            self.assertIn('Before=network-pre.target networking.service', service.read_text())
            required = root / 'etc/systemd/system/networking.service.requires/homelab-thunderbolt.service'
            self.assertTrue(required.is_symlink())
            helper = root / 'usr/local/libexec/homelab-thunderbolt.py'
            helper_spec = importlib.util.spec_from_file_location('installed_tb', helper)
            installed = importlib.util.module_from_spec(helper_spec); helper_spec.loader.exec_module(installed)
            (adapter / 'authorized').write_text('0')
            installed.authorize(installed.THUNDERBOLT_PROFILE, root=root, timeout=0)
            self.assertEqual((adapter / 'authorized').read_text().strip(), '1')

    def test_existing_startup_file_refuses_before_authorisation_or_network_change(self):
        cfg = json.loads((ROOT / 'config/fixture-hardware.json').read_text())
        cfg['thunderbolt_devices'] = profile()['devices']
        site = json.loads((ROOT / 'config/fixture-site.json').read_text())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); adapter = machine(root)
            interfaces = root / 'etc/network/interfaces'; interfaces.parent.mkdir(parents=True)
            interfaces.write_text('preserve network\n')
            unit = root / 'etc/systemd/system/homelab-thunderbolt.service'
            unit.parent.mkdir(parents=True); unit.write_text('preserve service\n')
            source = root / 'hook.py'; source.write_bytes(first_boot_payload(cfg, site))
            spec = importlib.util.spec_from_file_location('conflicting_hook', source)
            hook = importlib.util.module_from_spec(spec); spec.loader.exec_module(hook)
            with self.assertRaisesRegex(ValueError, 'Existing Thunderbolt'): hook.install(root)
            self.assertEqual((adapter / 'authorized').read_text().strip(), '0')
            self.assertEqual(interfaces.read_text(), 'preserve network\n')
            self.assertEqual(unit.read_text(), 'preserve service\n')


if __name__ == '__main__': unittest.main()
