import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('first_boot', Path(__file__).resolve().parents[1]/'src/first_boot.py')
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
import json
r=Path(__file__).resolve().parents[1]
site=json.loads((r/'config/fixture-site.json').read_text())
hw=json.loads((r/'config/fixture-hardware.json').read_text())
boot.PROFILE={'expected':{name:mac for mac,name in hw['interface_names'].items()},'management':site['management'],'storage':site['storage'],'admin_vlans':site['admin_vlans'],'fast_vlans':site['fast_vlans']}
boot.EXPECTED=boot.PROFILE['expected']


class NetworkHookTests(unittest.TestCase):
    def test_selected_network_has_one_gateway_and_no_host_address_in_admin_vlan(self):
        config = boot.configuration(boot.EXPECTED)
        self.assertEqual(config.count('gateway '), 1)
        self.assertIn('bridge-ports mgmt0', config)
        self.assertIn('bridge-vids 15 25', config)
        self.assertIn('bridge-ports fast0', config)
        self.assertIn('bridge-vids 20 30 40 100 107', config)
        self.assertNotIn('vmbr0.15', config)
        self.assertNotIn('vmbr1.25', config)

    def test_wrong_missing_duplicate_and_unpinned_nics_refuse(self):
        cases = [{}, {'mgmt0': boot.EXPECTED['fast0'], 'fast0': boot.EXPECTED['mgmt0']},
                 dict(boot.EXPECTED, other=boot.EXPECTED['mgmt0']),
                 {'enp47s0': boot.EXPECTED['mgmt0'], 'ens1': boot.EXPECTED['fast0']}]
        for nics in cases:
            with self.subTest(nics=nics), self.assertRaises(ValueError):
                boot.configuration(nics)

    def test_fresh_install_preserves_vendor_file_and_repeated_hook_refuses(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, mac in boot.EXPECTED.items():
                n = root / 'sys/class/net' / name
                n.mkdir(parents=True)
                (n/'address').write_text(mac+'\n')
            interfaces = root / 'etc/network/interfaces'
            interfaces.parent.mkdir(parents=True)
            interfaces.write_text('vendor configuration\n')
            boot.install(root)
            self.assertEqual(interfaces.with_name('interfaces.before-homelab').read_text(), 'vendor configuration\n')
            self.assertIn('198.18.25.2/24', interfaces.read_text())
            with self.assertRaises(ValueError): boot.install(root)

    def test_wrong_hardware_does_not_change_network_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'sys/class/net').mkdir(parents=True)
            interfaces=root/'etc/network/interfaces'
            interfaces.parent.mkdir(parents=True)
            interfaces.write_text('preserve\n')
            with self.assertRaises(ValueError): boot.install(root)
            self.assertEqual(interfaces.read_text(),'preserve\n')
            self.assertFalse(interfaces.with_name('interfaces.before-homelab').exists())


if __name__ == '__main__': unittest.main()
