"""Direct pure foundation/security contracts; no fixed guest bundle or secret I/O."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import foundation


def selected():
    return {'bind_address':'198.18.40.33','proxmox_url':'https://198.18.25.10:8006/',
        'proxmox_token_id':'fixture@pve!discovery','acme_email':'operator@example.invalid',
        'acme_dns_resolvers':['198.18.40.2:53','198.18.100.4:53']}


class PureFoundationTests(unittest.TestCase):
    def test_text_preserves_literal_values_and_rejects_empty_or_control_characters(self):
        self.assertEqual(foundation.text('literal-$value','input'),'literal-$value')
        for value in (None,False,0,[],{},'', 'two\nlines','carriage\rreturn','nul\0byte'):
            with self.subTest(kind=type(value).__name__),self.assertRaises(ValueError)as error:
                foundation.text(value,'input')
            self.assertEqual(str(error.exception),'Invalid foundation input')

    def test_selected_ipv4_address_and_unsafe_bind_refusals(self):
        self.assertEqual(foundation.address('198.18.40.33'),'198.18.40.33')
        for value in (None,[],{},'invalid','256.1.1.1','0.0.0.0','127.0.0.1','224.0.0.1','169.254.1.2'):
            with self.subTest(value=value),self.assertRaises(ValueError):foundation.address(value)

    def test_origin_preserves_verified_https_port_and_rejects_transport_bypasses(self):
        self.assertEqual(foundation.origin('https://pve.example.invalid:8006/','api'),'https://pve.example.invalid:8006')
        for value in (None,'http://pve.example.invalid','https://user@pve.example.invalid',
                'https://user:password@pve.example.invalid','https://pve.example.invalid/a',
                'https://pve.example.invalid/?query','https://pve.example.invalid/#fragment',
                'https://pve.example.invalid:bad','https://pve.example.invalid:0','https://pve.example.invalid:65536',
                'https://pve.example.invalid/\\path','https://pve.example.invalid /'):
            with self.subTest(value=value),self.assertRaises(ValueError):foundation.origin(value,'api')

    def test_dns_resolver_explicit_unique_ipv4_port_and_count_bounds(self):
        expected=['198.18.40.2:53','198.18.100.4:53']
        self.assertEqual(foundation.dns_resolvers(expected),expected)
        for value in (None,[], '198.18.40.2:53',[None],['dns.example.invalid:53'],['127.0.0.1:53'],
                ['0.0.0.0:53'],['198.18.40.2:853'],['198.18.40.2'],['198.18.40.2:53','198.18.40.2:53'],
                [f'198.18.40.{i}:53'for i in range(2,6)]):
            with self.subTest(value=value),self.assertRaises(ValueError):foundation.dns_resolvers(value)

    def test_static_document_pins_provider_tls_hash_and_acme_dns_policy(self):
        value=selected();document=foundation.ingress_static(value,'synthetic-token')
        provider=document['providers']['plugin'][foundation.PLUGIN]
        self.assertEqual(provider['apiToken'],'synthetic-token')
        self.assertEqual(provider['apiTokenId'],value['proxmox_token_id'])
        self.assertEqual(provider['apiEndpoint'],value['proxmox_url'].rstrip('/'))
        self.assertEqual(provider['apiValidateSSL'],'true')
        self.assertNotIn('docker',document['providers'])
        self.assertEqual(document['experimental']['plugins'][foundation.PLUGIN],{
            'moduleName':'github.com/NX211/traefik-proxmox-provider','version':'v0.7.0',
            'hash':'9e3b91e0ba79fc27dd2587e8b92db725a424a9c21cb17cfcf07b1ef6e354efd7'})
        self.assertTrue(document['experimental']['abortOnPluginFailure'])
        challenge=document['certificatesResolvers']['letsencrypt']['acme']['dnsChallenge']
        self.assertEqual(challenge['resolvers'],value['acme_dns_resolvers'])
        self.assertEqual(challenge['propagation'],{'disableANSChecks':True,'requireAllRNS':True})
        self.assertNotIn('disableChecks',challenge['propagation'])
        self.assertEqual(document['entryPoints']['websecure']['address'],'198.18.40.33:443')
        self.assertEqual(document['entryPoints']['health']['address'],'127.0.0.1:8082')
        self.assertEqual(document['ping'],{'entryPoint':'health'})
        self.assertFalse(document['api']['dashboard'])

    def test_dashboard_is_explicit_and_static_inputs_are_not_mutated_or_opened(self):
        value=selected();value['dashboard']=True;before=copy.deepcopy(value)
        with patch('builtins.open',side_effect=AssertionError('Pure helper never opens sources')):
            document=foundation.ingress_static(value,'synthetic-token')
        self.assertTrue(document['api']['dashboard']);self.assertEqual(value,before)

    def test_ingress_service_uses_fixed_private_file_ca_and_certificate_mounts(self):
        service={'environment':{'TZ':'Etc/UTC'},'volumes':[]}
        mount=Mock(side_effect=lambda name,target:{'leaf':name,'target':target})
        result=foundation.ingress_service(service,mount=mount,certs_source='/srv/example/certs')
        self.assertIs(result,service)
        self.assertEqual(service['environment'],{'TZ':'Etc/UTC','CF_DNS_API_TOKEN_FILE':'/run/secrets/cloudflare-dns-token',
            'SSL_CERT_FILE':'/etc/ssl/certs/homelab-pve.pem'})
        self.assertEqual([call.args for call in mount.call_args_list],[
            ('traefik.yml','/etc/traefik/traefik.yml'),('shared.yml','/etc/traefik/shared.yml'),
            ('pve-ca.pem','/etc/ssl/certs/homelab-pve.pem'),('cloudflare-dns-token','/run/secrets/cloudflare-dns-token')])
        self.assertEqual(service['volumes'][-1],{'type':'bind','source':'/srv/example/certs','target':'/var/traefik/certs',
            'bind':{'create_host_path':False}})
        self.assertNotIn('docker.sock',json.dumps(service))

    def test_selected_timeout_changes_only_canonical_environment_and_route_cas_are_preserved(self):
        def build(timeout=None):
            service={'environment':{'TZ':'Etc/UTC'},'volumes':[]}
            foundation.ingress_service(service,mount=lambda name,target:{'leaf':name,'target':target},
                certs_source='/srv/example/certs',propagation_timeout_seconds=timeout,
                route_ca_mounts=({'type':'bind','source':'selected-public-ca','target':'/etc/route.pem'},))
            return service
        baseline=build()
        for seconds in (120,2100):
            actual=build(seconds)
            self.assertEqual(actual['environment'].pop('CLOUDFLARE_PROPAGATION_TIMEOUT'),str(seconds))
            self.assertEqual(actual,baseline)


if __name__=='__main__':unittest.main()
