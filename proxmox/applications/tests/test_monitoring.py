"""Pure monitoring template, active-agent and SAML protocol contracts."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import monitoring
import component_proxy_files


def mount(source,target):
    return {'type':'bind','source':'/opt/homelab-app/runtime/'+source,'target':target,'read_only':True,
            'bind':{'create_host_path':False}}


def service_configuration(saml=None):
    settings={'postgresql_host':'198.18.31.23','postgresql_database':'zabbix','postgresql_user':'zabbix'}
    if saml is not None:settings['saml']=saml
    return monitoring.service_configuration(settings,{'zabbix_server':{},'zabbix_web':{}},mount=mount,
        server_ports=['198.18.30.50:10051:10051'],web_ports=['198.18.30.50:8080:8080','127.0.0.1:8081:8080'])


class MonitoringPureTests(unittest.TestCase):
    def test_agent_is_active_only_and_rejects_injection(self):
        value={'hostname':'practice-pve','server_active':'198.18.30.50:10051',
               'psk_identity':'practice-pve-unique','psk_path':'/etc/zabbix/agent.psk'}
        text=monitoring.agent_config(value)
        self.assertNotIn('\nServer=',text);self.assertNotIn('Include=',text)
        self.assertIn('TLSConnect=psk\n',text);self.assertIn('DenyKey=system.run[*]',text)
        for key in value:
            bad=dict(value);bad[key]+='\nServer=0.0.0.0/0'
            with self.subTest(key=key),self.assertRaises(ValueError):monitoring.agent_config(bad)

    def test_template_hashes_are_pinned(self):
        monitoring.check_templates()

    def test_single_text_values_refuse_nontext_empty_and_controls(self):
        self.assertEqual(monitoring.text('synthetic-$value'),'synthetic-$value')
        for value in (None,False,1,[],{},'','two\nlines','nul\0value','carriage\rreturn'):
            with self.subTest(kind=type(value).__name__),self.assertRaises(ValueError):monitoring.text(value)


class SamlFrontendTests(unittest.TestCase):
    certificate=Path(__file__).with_name('monitoring-synthetic-saml-certificate.pem').read_text()

    def selected(self):
        return {'public_url':'https://zabbix.example.invalid','idp_signing_certificate':self.certificate}

    def test_strict_certificate_trust_changes_only_frontend_sso_environment(self):
        original=service_configuration();self.assertNotIn('ZBX_SSO_SETTINGS',original['zabbix_web']['environment'])
        actual=service_configuration(self.selected())
        settings=json.loads(actual['zabbix_web']['environment'].pop('ZBX_SSO_SETTINGS'))
        self.assertIs(settings['strict'],True);self.assertIs(settings['use_proxy_headers'],False)
        self.assertEqual(settings['baseurl'],'https://zabbix.example.invalid/')
        self.assertEqual(settings['idp']['x509certMulti']['signing'],[self.certificate])
        self.assertEqual(actual,original)
        value=self.selected();value['public_url']+='/'
        self.assertEqual(monitoring.saml_settings(value),settings)

    def test_unknown_saml_knobs_and_untrusted_public_origins_refuse(self):
        for bad in (None,False,[],{},dict(self.selected(),strict=False),dict(self.selected(),private_key='unapproved')):
            with self.subTest(kind=type(bad).__name__),self.assertRaises(ValueError):monitoring.saml_settings(bad)
        for url in (None,'','http://zabbix.example.invalid','https://','https://user:password@zabbix.example.invalid',
                'https://zabbix.example.invalid:443','https://bad_host.example.invalid','https://zabbix.example.invalid/subpath',
                'https://zabbix.example.invalid/?x=1','https://zabbix.example.invalid/#fragment','https://zabbix.example.invalid\n'):
            value=self.selected();value['public_url']=url
            with self.subTest(url=url),self.assertRaises(ValueError):monitoring.saml_settings(value)

    def test_saml_default_login_changes_only_one_owned_view_and_rejects_unknown_defaults(self):
        original=service_configuration(self.selected())
        self.assertEqual(service_configuration(dict(self.selected(),default_login='zabbix')),original)
        selected=dict(self.selected(),default_login='saml')
        current=service_configuration(selected)
        local=current['zabbix_web']['volumes'].pop()
        self.assertEqual(local,mount('saml-login.php','/usr/share/zabbix/local/app/views/general.login.php'))
        self.assertEqual(current,original)
        app={'id':'monitor','adapter':'zabbix','identity':{'services':{'zabbix_server':'zabbix_server','zabbix_web':'zabbix_web'},
            'runtime_directory':'/opt/homelab-app/runtime'},'project_name':'homelab-monitoring',
            'settings':{'database':{'name':'zabbix','user':'zabbix','host':'198.18.31.23'}},'authentication_resolved':selected}
        rows=component_proxy_files.files(app,secrets={'database_password':b'synthetic-password'},records={},
            public_ca=b'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n')
        self.assertEqual(rows[-1],{'path':'saml-login.php','uid':1997,'gid':1995,'mode':'0400',
            'content':(monitoring.ROOT/'saml-login.php').read_text()})
        for default in (None,False,True,1,[],{},'','http','SAML'):
            with self.subTest(default=default),self.assertRaises(ValueError):monitoring.saml_settings(dict(self.selected(),default_login=default))

    def test_malformed_multiple_or_private_certificates_refuse(self):
        for certificate in (None,'x'*65537,self.certificate*2,self.certificate.replace('-----END CERTIFICATE-----',''),
                'annotation\n'+self.certificate,self.certificate+'annotation',
                self.certificate.replace('-----END CERTIFICATE-----','PRIVATE KEY\n-----END CERTIFICATE-----'),
                self.certificate.replace('-----END CERTIFICATE-----','\x00-----END CERTIFICATE-----'),
                '-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\n'):
            with self.subTest(kind=type(certificate).__name__),self.assertRaises(ValueError):
                monitoring.saml_settings(dict(self.selected(),idp_signing_certificate=certificate))


if __name__=='__main__':unittest.main()
