"""PegaProx's native login is proxied with verified backend HTTPS."""
import copy
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pegaprox_browser as browser


class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();root=Path(cls.tmp.name)
        cfg=root/'cert.cnf';cfg.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=prox.example.invalid\n[ext]\nsubjectAltName=DNS:prox.example.invalid,IP:198.18.25.34\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        subprocess.run(['openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','2','-config',str(cfg),'-keyout',str(root/'key'),'-out',str(root/'cert')],check=True,capture_output=True)
        cls.pem=(root/'cert').read_text()
        cls.fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cls.pem)).hexdigest()
        cls.spki=browser.spki(cls.pem)

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    def settings(self):return {'source_cidrs':['198.18.100.0/24'],'schema':browser.SCHEMA,'host':'prox.example.invalid','backend':'https://198.18.25.34:5000','proxy_address':'198.18.25.33','frontend_address':'198.18.40.33','backend_certificate_pem':self.pem,'backend_certificate_sha256':self.fingerprint,'backend_spki_sha256':self.spki}

    def test_verified_https_transport_native_login_and_no_discovery(self):
        http=browser.objects(self.settings())['http']
        self.assertEqual(http['routers']['pegaprox-browser']['rule'],'Host(`prox.example.invalid`)')
        self.assertEqual(http['routers']['pegaprox-browser']['middlewares'],['pegaprox-local','security-headers'])
        self.assertEqual(http['routers']['pegaprox-browser']['tls'],{'certResolver':'letsencrypt'})
        service=http['services']['pegaprox-private']['loadBalancer']
        self.assertEqual(service['servers'],[{'url':'https://198.18.25.34:5000'}])
        self.assertEqual(service['serversTransport'],'pegaprox-verified@file')
        transport=http['serversTransports']['pegaprox-verified']
        self.assertEqual(transport['serverName'],'prox.example.invalid')
        self.assertEqual(transport['rootCAs'],[self.pem])
        self.assertNotIn('insecureSkipVerify',transport)
        self.assertEqual(http['middlewares'],{'pegaprox-local':{'ipAllowList':{'sourceRange':['198.18.100.0/24']}}})

    def test_empty_broad_or_proxy_header_based_client_policy_is_refused(self):
        for value in ([],['0.0.0.0/0'],['10.0.0.0/8'],['198.18.100.0/24']*2):
            cfg=self.settings();cfg['source_cidrs']=value
            with self.subTest(value=value),self.assertRaises(ValueError):browser.validate(cfg)
        cfg=self.settings();cfg.pop('source_cidrs')
        with self.assertRaises(ValueError):browser.validate(cfg)
        cfg=self.settings();cfg['ipStrategy']={'depth':1}
        with self.assertRaises(ValueError):browser.validate(cfg)

    def test_existing_influx_overlay_is_preserved_and_input_is_not_mutated(self):
        from ingress_browser import objects
        from test_ingress_browser import settings
        original=objects(settings());original['http']['middlewares']['security-headers']={'headers':{'contentTypeNosniff':True}}
        before=copy.deepcopy(original);updated=browser.merge(original,self.settings())
        self.assertEqual(original,before)
        for kind,values in before['http'].items():
            for name,value in values.items():self.assertEqual(updated['http'][kind][name],value)
        with self.assertRaises(ValueError):browser.merge(updated,self.settings())

    def test_collision_unknown_router_and_untrusted_certificate_are_holds(self):
        for existing in ({'routers':{'x':{'rule':'Host(`prox.example.invalid`)'}}},{'routers':{'x':{'rule':'HostRegexp(`.*`)'}}},{'services':{'pegaprox-private':{}}},{'serversTransports':{'pegaprox-verified':{}}}):
            original={'http':dict(existing,middlewares={'security-headers':{}})}
            with self.assertRaises(ValueError):browser.merge(original,self.settings())
        for key,value in [('host','other.example.invalid'),('backend','https://198.18.25.35:5000'),('backend','http://198.18.25.34:5000'),('backend','https://198.18.25.34:8006'),('backend','https://user:secret@198.18.25.34:5000'),('backend_certificate_sha256','0'*64),('backend_spki_sha256','0'*64),('insecureSkipVerify',True),('authentik',True)]:
            cfg=self.settings();cfg[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):browser.validate(cfg)
