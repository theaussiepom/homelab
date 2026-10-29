"""Trusted PVE reads hold changed leases before guest SSH, with no native contact."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ansible_guest
import deployment_inputs
import deploy
import guest_identity
import private_io
import proxmox_guest as pve
from fixtures import guest
import test_guest_identity as identity_cases
from test_plan import fixture as plan_fixture
import test_deployment as deployment_cases

REAL_RUN_PHASE = ansible_guest.run_phase


def dynamic_case(root):
    case = identity_cases.IdentityTests()
    cfg = case.setup_fixture(root)
    cfg['app']['address'] = '198.18.100.42'
    cfg['guest']['interfaces'][0].update(ipv4='dhcp', ipv4_endpoint='198.18.100.42/27', gateway=None)
    case.config['net0'] += ',ip=dhcp'
    case.interfaces[0]['inet'] = '198.18.100.42/27'
    return case, cfg


class DhcpAdmissionTests(unittest.TestCase):
    def test_new_guest_keeps_creation_proof_and_existing_guest_never_repins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case, cfg = dynamic_case(root)
            with patch.object(guest_identity.subprocess, 'run', side_effect=case.command):
                result = guest_identity.pin(cfg, root, cfg['app']['address'], case.fetch, case.persist)
            self.assertEqual(result['source'], 'synthetic-creation')
            before = (root / 'hosts').read_bytes()
            case.calls.clear()
            with patch.object(pve, 'api_get', side_effect=lambda c, p: case.fetch(p)), patch.object(guest_identity.subprocess, 'run') as command:
                pve.dhcp_admission(cfg)
            command.assert_not_called()
            self.assertEqual((root / 'hosts').read_bytes(), before)
            self.assertEqual(len(case.calls), 2)
            self.assertFalse(any('/tasks?' in p for p in case.calls))

    def test_changed_ambiguous_or_unqualified_network_holds_without_ssh_or_trust_changes(self):
        for scenario in ['mode', 'gateway', 'bridge', 'vlan', 'mac', 'address', 'prefix', 'observed-missing', 'observed-malformed', 'observed-v6', 'observed-type', 'active-duplicate', 'configured-duplicate', 'field-duplicate', 'field-malformed', 'selected-duplicate', 'selected-address', 'selected-manual']:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                case, cfg = dynamic_case(root)
                if scenario == 'mode': case.config['net0'] = case.config['net0'].replace('ip=dhcp', 'ip=198.18.100.42/27')
                if scenario == 'gateway': case.config['net0'] += ',gw=198.18.100.1'
                if scenario == 'bridge': case.config['net0'] = case.config['net0'].replace('vmbr0', 'vmbr1')
                if scenario == 'vlan': case.config['net0'] = case.config['net0'].replace('tag=40', 'tag=41')
                if scenario == 'mac': case.config['net0'] = case.config['net0'].replace('61:01', '61:02')
                if scenario == 'address': case.interfaces[0]['inet'] = '198.18.100.43/27'
                if scenario == 'prefix': case.interfaces[0]['inet'] = '198.18.100.42/24'
                if scenario == 'observed-missing': case.interfaces[0].pop('inet')
                if scenario == 'observed-malformed': case.interfaces[0]['inet'] = '198.18.100.42'
                if scenario == 'observed-v6': case.interfaces[0]['inet'] = '2001:db8::42/64'
                if scenario == 'observed-type': case.interfaces[0]['inet'] = None
                if scenario == 'active-duplicate': case.interfaces += copy.deepcopy(case.interfaces)
                if scenario == 'configured-duplicate': case.config['net1'] = case.config['net0']
                if scenario == 'field-duplicate': case.config['net0'] += ',ip=dhcp'
                if scenario == 'field-malformed': case.config['net0'] += ',bare-flag'
                if scenario == 'selected-duplicate': cfg['guest']['interfaces'] += copy.deepcopy(cfg['guest']['interfaces'])
                if scenario == 'selected-address': cfg['app']['address'] = '198.18.100.43'
                if scenario == 'selected-manual':
                    dynamic = dict(cfg['guest']['interfaces'][0], mac='02:00:00:00:61:02', ipv4_endpoint='198.18.100.43/27')
                    cfg['guest']['interfaces'][0] = dict(cfg['guest']['interfaces'][0], ipv4='manual')
                    cfg['guest']['interfaces'][0].pop('ipv4_endpoint')
                    cfg['guest']['interfaces'].append(dynamic)
                before = (root / 'hosts').read_bytes()
                with patch.object(pve, 'api_get', side_effect=lambda c, p: case.fetch(p)), patch.object(guest_identity.subprocess, 'run') as command, self.assertRaises(ValueError):
                    pve.dhcp_admission(cfg)
                command.assert_not_called()
                self.assertEqual((root / 'hosts').read_bytes(), before)
                self.assertFalse((root / 'host-key-evidence.json').exists())

    def test_a_dhcp_interface_is_verified_even_when_ssh_uses_another_static_interface(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case, cfg = dynamic_case(root)
            static = {'ipv4': '198.18.25.8/24', 'mac': '02:00:00:00:25:08', 'bridge': 'vmbr0', 'vlan': 25}
            cfg['guest']['interfaces'] += [static, dict(static, ipv4='198.18.25.9/24', mac='02:00:00:00:25:09')]
            cfg['app'].update(address='198.18.25.8', mac=static['mac'])
            case.config['net1'] = 'name=eth1,bridge=vmbr0,hwaddr=' + static['mac'] + ',tag=25,ip=198.18.25.8/24'
            case.interfaces.append({'hwaddr': static['mac'], 'inet': '198.18.25.8/24'})
            with patch.object(pve, 'api_get', side_effect=lambda c, p: case.fetch(p)):
                pve.dhcp_admission(cfg)
                case.interfaces[0]['inet'] = '198.18.100.42/24'
                with self.assertRaises(ValueError):
                    pve.dhcp_admission(cfg)

    def test_provider_projection_preserves_dhcp_and_excludes_endpoint_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = guest(root)
            cfg['guest']['vmid'] = cfg['app']['vmid'] = 6100
            cfg['site']['node'] = 'pve-lab'
            nic = cfg['guest']['interfaces'][0]
            nic.update(ipv4='dhcp', ipv4_endpoint='198.18.25.8/27', gateway=None)
            before = copy.deepcopy(cfg)
            work, operation = root / 'work', root / 'attempt'
            work.mkdir(); operation.mkdir()
            (work / 'terraform.tfstate').write_bytes(b'existing authoritative backend')
            private_io.write_new(root / 'api', b'fixture@pve!deploy=synthetic')
            plan = plan_fixture()
            for row in plan['resource_changes']:
                row['change'].update(actions=['no-op'], before=copy.deepcopy(row['change']['after']))
            def quiet(args, environment, log):
                if 'plan' in args: (operation / 'guest.tfplan').write_bytes(b'saved no-op plan')
            config = {'hostname': cfg['guest']['hostname'], 'protection': 1, 'unprivileged': 1, 'net0': 'bridge=vmbr0,hwaddr='+nic['mac']+',tag=25,ip=dhcp'}
            def fetch(c, path):
                return config if path.endswith('/config') else [{'hwaddr':nic['mac'], 'inet':nic['ipv4_endpoint']}]
            with patch.object(deployment_inputs, 'binding', return_value={}), patch.object(pve, 'backup'), patch.object(pve, 'quiet', side_effect=quiet), patch.object(pve.subprocess, 'check_output', return_value=json.dumps(plan).encode()), patch.object(pve, 'api_get', side_effect=fetch), patch.object(pve.guest_identity, 'pin') as pin:
                result = pve.infrastructure(cfg, root/'site', work, operation, {})
            self.assertFalse(result['changed'])
            pin.assert_not_called()
            projected = json.loads((operation / 'tofu/site.auto.tfvars.json').read_text())['guest']['interfaces'][0]
            self.assertEqual(projected, {k:v for k,v in nic.items() if k != 'ipv4_endpoint'})
            self.assertEqual(projected['ipv4'], 'dhcp')
            self.assertIsNone(projected['gateway'])
            self.assertEqual(cfg, before)

    def test_valid_dhcp_preparation_and_app_verify_before_using_pinned_ssh(self):
        for phase in ("preparation", "mariadb"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cfg = guest(root)
                nic = cfg["guest"]["interfaces"][0]
                nic.update(ipv4="dhcp", ipv4_endpoint="198.18.25.8/27", gateway=None)
                config = {"hostname": cfg["guest"]["hostname"], "protection": 1, "unprivileged": 1,
                          "net0": "bridge=vmbr0,hwaddr=" + nic["mac"] + ",tag=25,ip=dhcp"}
                events = []
                def fetch(c, path):
                    events.append("config" if path.endswith("/config") else "interfaces")
                    return config if path.endswith("/config") else [{"hwaddr": nic["mac"], "inet": nic["ipv4_endpoint"]}]
                def quiet(command, environment, log):
                    events.append("ssh")
                    log.write_text("changed=0\n")
                with patch.object(deployment_inputs, "binding", return_value={}), patch.object(pve, "api_get", side_effect=fetch), patch.object(pve, "guest_trust", side_effect=lambda *_: events.append("trust")), patch.object(ansible_guest, "quiet", side_effect=quiet):
                    self.assertFalse(REAL_RUN_PHASE(cfg, root / "site", root, root, {}, phase)["changed"])
                self.assertEqual(events, ["config", "interfaces", "trust", "ssh"])
                inventory = json.loads((root / phase / "inventory.json").read_text())
                self.assertEqual(inventory["application"]["hosts"][cfg["app"]["hostname"]]["ansible_host"], "198.18.25.8")
                variables = json.loads((root / phase / "variables.json").read_text())
                self.assertEqual(variables["network_ready_interfaces"], ["eth0"])

    def test_lease_change_during_preparation_creates_a_durable_hold_before_ssh(self):
        case = deployment_cases.LifecycleTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        cfg = case.cfg
        cfg['guest']['interfaces'][0].update(ipv4='dhcp', ipv4_endpoint='198.18.25.8/27', gateway=None)
        hosts = Path(cfg['paths']['known_hosts'])
        hosts.write_text('retained synthetic trust\n'); hosts.chmod(0o600)
        state = (case.work / 'terraform.tfstate').read_bytes()
        deploy.run('infrastructure', case.site)
        case.app.side_effect = REAL_RUN_PHASE
        config = {'hostname':cfg['guest']['hostname'], 'protection':1, 'unprivileged':1, 'net0':'bridge=vmbr0,hwaddr='+cfg['app']['mac']+',tag=25,ip=dhcp'}
        def fetch(c, path):
            return config if path.endswith('/config') else [{'hwaddr':cfg['app']['mac'], 'inet':'198.18.25.8/24'}]
        with patch.object(pve, 'api_get', side_effect=fetch) as api, patch.object(pve, 'guest_trust') as trust, patch.object(ansible_guest, 'quiet') as ssh:
            with self.assertRaisesRegex(ValueError, 'observed guest endpoint'):
                deploy.run('preparation', case.site)
            calls = api.call_count
            with self.assertRaises(ValueError):
                deploy.run('preparation', case.site)
            self.assertEqual(api.call_count, calls)
        trust.assert_not_called(); ssh.assert_not_called()
        self.assertTrue((case.work / 'ORDINARY-HOLD.json').is_file())
        self.assertEqual((case.work / 'terraform.tfstate').read_bytes(), state)
        self.assertEqual(hosts.read_text(), 'retained synthetic trust\n')
