"""Readiness has one fixed verified peer/source and rejects unbound packets."""
import json
from pathlib import Path
import ssl
import sys
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import component_pegaprox_browser as component
import test_pegaprox_browser as fixtures


class ComponentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixtures.BrowserTests.setUpClass()
    @classmethod
    def tearDownClass(cls):fixtures.BrowserTests.tearDownClass()

    def test_readiness_uses_exact_source_and_verified_sni_without_credentials(self):
        route=fixtures.BrowserTests().settings()
        context=Mock()
        reply=Mock(status=200);reply.read.return_value=b'{"status":"ok"}'
        conn=Mock();conn.getresponse.return_value=reply
        with patch.object(component.ssl,'SSLContext',return_value=context) as factory,patch.object(component.socket,'create_connection') as connect,patch.object(component.http.client,'HTTPSConnection',return_value=conn):
            self.assertEqual(component.request(route,route['host'],'/api/health'),(200,{'status':'ok'}))
            connect.assert_called_once_with(('198.18.25.34',5000),timeout=4,source_address=('198.18.25.33',0))
            context.wrap_socket.assert_called_once_with(connect.return_value,server_hostname=route['host'])
            factory.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations.assert_called_once_with(cadata=route['backend_certificate_pem'])
            self.assertEqual(context.minimum_version,ssl.TLSVersion.TLSv1_2)
            conn.request.assert_called_once_with('GET','/api/health')

    def test_native_authentication_readiness_rejects_oidc_and_uninitialized_state(self):
        route=fixtures.BrowserTests().settings()
        health=(200,{'status':'ok','version':'1.4.1'})
        for state in ({'initialized':False},{'initialized':True,'authenticated':False,'oidc_enabled':True,'ldap_enabled':False},{'initialized':True,'authenticated':False,'oidc_enabled':False,'ldap_enabled':True}):
            with patch.object(component,'request',side_effect=[health,(401,state)]),self.assertRaises(ValueError):component.readiness(route)

    def test_unbound_packet_stops_before_guest_or_backend_access(self):
        with patch.object(component.base,'guard',side_effect=AssertionError('No native read')):
            with self.assertRaisesRegex(ValueError,'closed'):component.run({})

    def test_unadmitted_frontend_probe_requires_denial_not_an_acl_exception(self):
        route=fixtures.BrowserTests().settings()
        with patch.object(component,'request',return_value=(403,b'Forbidden')) as request:
            component.readiness(route,frontend=True)
        request.assert_called_once_with(route,route['host'],'/api/health',True)
        with patch.object(component,'request',return_value=(200,{})),self.assertRaises(ValueError):component.readiness(route,frontend=True)
