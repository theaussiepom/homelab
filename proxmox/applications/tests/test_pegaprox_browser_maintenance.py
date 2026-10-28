"""The PegaProx route uses existing controller custody and preserves history."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import foundation_cd as fc
import ingress_browser_maintenance as maintenance
import pegaprox_browser as browser
import test_pegaprox_browser as certificates
import test_foundation_maintenance as fixtures


class MaintenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):certificates.BrowserTests.setUpClass()
    @classmethod
    def tearDownClass(cls):certificates.BrowserTests.tearDownClass()

    def setUp(self):
        fixtures.ImageMaintenanceTests.setUp(self)
        self.original=b'{"http":{"middlewares":{"security-headers":{"headers":{"contentTypeNosniff":true}}},"routers":{"influx":{"rule":"Host(`influx.example.invalid`)"}}}}\n'
        self.selected={'schema':'homelab-pegaprox-browser-update-v1','revision':'b'*40,'vmid':702,
            'plan_sha256':self.plan['plan_sha256'],'state_sha256':fc.digest((self.work/'terraform.tfstate').read_bytes()),
            'foundation_complete_sha256':fc.digest((self.work/'foundation-complete.json').read_bytes()),
            'compose_sha256':'c'*64,'runtime_sha256':'d'*64,'image':'traefik@sha256:'+'a'*64,
            'shared_before_sha256':fc.digest(self.original),'route':certificates.BrowserTests().settings(),
            'startup':{'interfaces':['eth0','eth1','eth2','eth3'],**{k+'_sha256':'e'*64 for k in ('gate','docker_dependency','routing_unit','routing_dependency')}}}
        self.selected['shared_after_sha256']=fc.digest(browser.candidate(self.original,self.selected['route']))
        evidence=self.work/'admission';evidence.mkdir(mode=0o700)
        self.policy={'schema':'homelab-pegaprox-browser-policy-evidence-v1','vmid':702,
            'route_sha256':fc.digest(fc.encoded(self.selected['route'])),'native_login_retained':True,
            'authentik_deferred':True,'network_enforcement_deferred':True}
        for name,value in [('network_evidence',{'schema':'homelab-database-network-overlay-v1','status':'network_overlay_verified','vmid':702,'state_sha256':self.selected['state_sha256']}),('policy_evidence',self.policy)]:
            p=evidence/(name+'.json');fc.write_new(p,fc.encoded(value));self.selected[name]={'path':str(p),'sha256':fc.digest(p.read_bytes())}
        p=patch.object(browser,'EVIDENCE_ROOT',self.state);p.start();self.addCleanup(p.stop)
        self.deployment.quiet.side_effect=self.ansible

    def ansible(self,argv,*args):
        self.assertTrue(argv[-3].endswith('/ansible/component-pegaprox-hostname.yml'))
        value=json.loads(Path(argv[-1][1:]).read_bytes())
        if not value['browser_verify_only']:fc.write_new(Path(value['browser_archive']),self.original)

    def run_update(self):
        return maintenance.run(self.deployment,fc,self.cfg,self.site,self.root/'helper',self.selected,self.state,profile='pegaprox')

    def test_original_installation_and_influx_custody_are_preserved(self):
        historical=self.nas/'influx-browser-complete.json';fc.write_new(historical,b'accepted-influx-history')
        original={p:p.read_bytes() for p in self.work.iterdir() if p.is_file()}
        self.assertTrue(self.run_update()['changed'])
        self.assertFalse(self.run_update()['changed'])
        self.assertEqual(historical.read_bytes(),b'accepted-influx-history')
        self.assertEqual((self.nas/'pegaprox-browser-shared-before.json').read_bytes(),self.original)
        for p,raw in original.items():self.assertEqual(p.read_bytes(),raw)
        self.deployment.execute.assert_not_called()
        self.assertFalse((self.work/'CONTINUATION-HOLD.json').exists())

    def test_policy_or_current_network_mismatch_stops_before_claim(self):
        p=Path(self.selected['policy_evidence']['path']);value={**self.policy,'native_login_retained':False}
        p.write_bytes(fc.encoded(value));self.selected['policy_evidence']['sha256']=fc.digest(p.read_bytes())
        with self.assertRaisesRegex(ValueError,'local-login'):self.run_update()
        self.assertFalse((self.work/'pegaprox-browser-route').exists())
        self.deployment.quiet.assert_not_called()
        p.write_bytes(fc.encoded(self.policy));self.selected['policy_evidence']['sha256']=fc.digest(p.read_bytes())
        self.selected['state_sha256']='0'*64
        with self.assertRaises(ValueError):self.run_update()
        self.deployment.quiet.assert_not_called()

    def test_failed_activation_holds_and_changed_revision_cannot_replay(self):
        self.deployment.quiet.side_effect=RuntimeError('synthetic target failure')
        with self.assertRaises(RuntimeError):self.run_update()
        self.assertTrue((self.work/'CONTINUATION-HOLD.json').exists())
        self.assertTrue((self.nas/'pegaprox-browser-claim.json').exists())
        self.selected['revision']='f'*40
        with self.assertRaises(ValueError):self.run_update()
        self.deployment.quiet.assert_called_once()
