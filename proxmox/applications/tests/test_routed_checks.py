"""Real request policy with DNS/TLS/socket collaborators; no target traffic."""
import copy
import http.client
import io
import json
from pathlib import Path
import runpy
import ssl
import struct
import sys
import unittest
from unittest.mock import MagicMock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import routed_checks as m


def row():
    return {'exposure':'web','host':'web.example.invalid','port':443,'path':'/',
        'source_address':'198.18.20.10','resolver_address':'198.18.20.53','resolver_source':'198.18.20.10',
        'ingress_address':'198.18.20.80','mode':'page','contains':'Expected service',
        'route_origins':['https://web.example.invalid'],'auth_origins':[]}


class RoutedRuntimeTests(unittest.TestCase):
    def assert_page_response(self, payload, contains, cause=None, status=200):
        value=row();value['contains']=contains
        stream=io.BytesIO(payload)
        response=MagicMock(status=status);response.read.side_effect=stream.read
        response.getheader.return_value=None
        context=MagicMock(check_hostname=True,verify_mode=ssl.CERT_REQUIRED)
        with patch.object(m.dns_records,'probe'),patch.object(m.socket,'create_connection')as connect,\
             patch.object(m.ssl,'create_default_context',return_value=context),\
             patch.object(m.http.client,'HTTPSConnection')as client,patch.object(m.time,'monotonic',return_value=1):
            client.return_value.getresponse.return_value=response
            if cause is None:
                m.check(value,100)
            else:
                with self.assertRaises(m.RouteFailure)as caught:m.check(value,100)
                self.assertEqual(caught.exception.details,{'stage':'expectation','cause':cause,'http_status':status})
        response.read.assert_called_once_with(m.BODY_INSPECTION_LIMIT+1)
        self.assertEqual(stream.tell(),min(len(payload),m.BODY_INSPECTION_LIMIT+1))
        client.return_value.close.assert_called_once();connect.return_value.close.assert_called_once()

    def test_marker_must_exist_within_bounded_prefix_even_for_large_200_responses(self):
        marker=b'Expected service';budget=m.BODY_INSPECTION_LIMIT
        cases=[(marker,None),
               (b'x'*(budget-len(marker))+marker,None),
               (marker+b'x'*(budget*2),None),
               (b'x'*(budget*2),'marker_missing'),
               (b'x'*budget+marker,'marker_missing'),
               (b'x'*(budget-4)+marker,'marker_missing')]
        for payload,cause in cases:
            with self.subTest(length=len(payload),cause=cause):
                self.assert_page_response(payload,'EXPECTED SERVICE',cause)
        self.assert_page_response(marker+b'x'*(budget*2),'Expected service','unexpected_status',status=403)

    def test_prefix_utf8_boundary_does_not_invent_a_marker_and_keeps_casefold_and_malformed_bytes(self):
        with patch.object(m,'BODY_INSPECTION_LIMIT',8):
            cases=[('Straße trailing'.encode(),'STRASSE',None),
                   (b'x'*6+'é'.encode(),'é',None),
                   (b'x'*7+'é tail'.encode(),'é','marker_missing'),
                   (b'x'*7+'é tail'.encode(),'\ufffd','marker_missing'),
                   (b'a\xffb tail','a\ufffdb',None),
                   (b'a\xffb tail','ab','marker_missing'),
                   (b'end\xc3','end\ufffd',None),
                   (b'x'*7+b'\xc3','\ufffd',None)]
            for payload,contains,cause in cases:
                with self.subTest(payload=payload,contains=contains):
                    self.assert_page_response(payload,contains,cause)

    def test_command_input_cap_stays_one_mib_independently_of_body_inspection_budget(self):
        self.assertEqual(m.INPUT_LIMIT,1024*1024)
        selected=json.dumps([row()]);selected+=' '*(m.INPUT_LIMIT-len(selected))
        with patch.object(m,'BODY_INSPECTION_LIMIT',8),patch.object(sys,'argv',['route',selected]),\
             patch.object(m,'verify',return_value={'status':'passed'})as verify,\
             patch('sys.stdout',new_callable=io.StringIO):m.main()
        verify.assert_called_once_with([row()])
        with patch.object(sys,'argv',['route',selected+' ']),patch.object(m.json,'loads')as parse,\
             patch.object(m,'verify')as verify,self.assertRaises(SystemExit):m.main()
        parse.assert_not_called();verify.assert_not_called()

    def test_terminal_diagnostic_keeps_last_stage_and_attempt_without_sensitive_text(self):
        secret = 'PRIVATE-body-cookie-header-url?state=credential'
        first, second = row(), row()
        second.update(host='alias.example.invalid', route_origins=['https://alias.example.invalid'])
        with patch.object(m, 'check', side_effect=[None, m.RouteFailure('dns', 'invalid_response'),
                m.RouteFailure('connect', 'timeout')]), patch.object(m.time, 'sleep') as sleep, \
             patch.object(m.time, 'monotonic', side_effect=[0, 1, 601]), \
             self.assertRaises(m.VerificationFailure) as caught:
            m.verify([first, second])
        expected = {'status':'failed', 'endpoint':1, 'exposure':'web', 'attempts':2,
                    'stage':'connect', 'cause':'timeout'}
        self.assertEqual(caught.exception.diagnostic, expected)
        sleep.assert_called_once_with(2)
        for error in (caught.exception, m.VerificationFailure({**expected, 'http_status':403})):
            with patch.object(sys, 'argv', ['route', json.dumps([row()])]), \
                 patch.object(m, 'verify', side_effect=error), \
                 patch('sys.stderr', new_callable=io.StringIO) as out, \
                 self.assertRaises(SystemExit):
                m.main()
            diagnostic = json.loads(out.getvalue())
            self.assertEqual(diagnostic, error.diagnostic)
            self.assertLess(len(out.getvalue()), 512)
        for error, cause in ((ValueError(secret), 'invalid_response'),
                             (http.client.HTTPException(secret), 'protocol_error'),
                             (OSError(secret), 'io_error')):
            with patch.object(m, 'check', side_effect=error), \
                 patch.object(m.time, 'monotonic', side_effect=[0, 601]), \
                 self.assertRaises(m.VerificationFailure) as caught:
                m.verify([row()])
            self.assertEqual(caught.exception.diagnostic['cause'], cause)
            self.assertNotIn(secret, json.dumps(caught.exception.diagnostic))

    def test_real_request_stages_classify_collaborator_failures_and_close_sockets(self):
        secret = 'PRIVATE response body https://user:password@foreign.invalid/?state=token'
        context = MagicMock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
        cases = [('dns', ValueError(secret), 'invalid_response'), ('dns', TimeoutError(secret), 'timeout'),
                 ('connect', TimeoutError(secret), 'timeout'), ('connect', ConnectionRefusedError(secret), 'refused'),
                 ('connect', OSError(secret), 'io_error'), ('tls', ssl.SSLCertVerificationError(secret), 'certificate'),
                 ('tls', ssl.SSLError(secret), 'tls_error'), ('http', http.client.BadStatusLine(secret), 'protocol_error')]
        for stage, error, cause in cases:
            with self.subTest(stage=stage, cause=cause), patch.object(m.dns_records, 'probe') as dns, \
                 patch.object(m.socket, 'create_connection') as connect, \
                 patch.object(m.ssl, 'create_default_context', return_value=context), \
                 patch.object(m.http.client, 'HTTPSConnection') as client, \
                 patch.object(m.time, 'monotonic', return_value=1), self.assertRaises(m.RouteFailure) as caught:
                context.wrap_socket.side_effect = None
                selected = {'dns':dns, 'connect':connect, 'tls':context.wrap_socket,
                            'http':client.return_value.request}[stage]
                selected.side_effect = error
                m.fetch(row(), 'https://web.example.invalid', 100)
            self.assertEqual(caught.exception.details, {'stage':stage, 'cause':cause})
            self.assertNotIn(secret, str(caught.exception))
            if stage in ('tls', 'http'):
                client.return_value.close.assert_called_once()
                connect.return_value.close.assert_called_once()
        for status, body, expected in [(403, '', 'unexpected_status'), (200, secret, 'marker_missing')]:
            with patch.object(m, 'fetch', return_value=(status, None, body)), self.assertRaises(m.RouteFailure) as caught:
                m.check(row(), 100)
            self.assertEqual(caught.exception.details, {'stage':'expectation', 'cause':expected, 'http_status':status})
        for target in ('https://bad:port/', 'https://[bad/', 'https://foreign.invalid/?state='+secret):
            with patch.object(m, 'fetch', return_value=(302, target, secret)), self.assertRaises(m.RouteFailure) as caught:
                m.check(row(), 100)
            self.assertEqual(caught.exception.details['stage'], 'redirect')
            self.assertNotIn(secret, str(caught.exception))

    def test_tls_uses_real_resolver_answer_exact_bound_source_and_fqdn_sni(self):
        value=row();response=MagicMock();response.status=200;response.read.return_value=b'Expected service'
        response.getheader.return_value=None
        context=MagicMock(check_hostname=True,verify_mode=ssl.CERT_REQUIRED)
        with patch.object(m.dns_records,'probe')as dns,patch.object(m.socket,'create_connection')as connect,\
             patch.object(m.ssl,'create_default_context',return_value=context),\
             patch.object(m.http.client,'HTTPSConnection')as client,patch.object(m.time,'monotonic',return_value=1):
            client.return_value.getresponse.return_value=response
            self.assertEqual(m.fetch(value,'https://web.example.invalid/info?q=one',100),(200,None,'Expected service'))
        dns.assert_called_once_with('web.example.invalid','198.18.20.80',server='198.18.20.53',source='198.18.20.10')
        connect.assert_called_once_with(('198.18.20.80',443),timeout=10,source_address=('198.18.20.10',0))
        context.wrap_socket.assert_called_once_with(connect.return_value,server_hostname='web.example.invalid')
        self.assertEqual(context.minimum_version,ssl.TLSVersion.TLSv1_2)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
        self.assertEqual(client.call_args.args,('web.example.invalid',443))
        self.assertEqual(client.return_value.request.call_args.args,('GET','/info?q=one'))
        client.return_value.close.assert_called_once();connect.return_value.close.assert_called_once()
        with patch.object(m.dns_records,'probe',side_effect=ValueError('wrong DNS')),\
             patch.object(m.socket,'create_connection')as connect,self.assertRaises(ValueError):m.fetch(value,'https://web.example.invalid',100)
        connect.assert_not_called()

    def test_nonstandard_port_prefix_budget_deadline_and_tls_requirements(self):
        value=row();value.update(port=8443,route_origins=['https://web.example.invalid:8443'])
        context=MagicMock(check_hostname=True,verify_mode=ssl.CERT_REQUIRED)
        response=MagicMock(status=200);response.read.return_value=b'x'*(m.BODY_INSPECTION_LIMIT+1)
        response.getheader.return_value=None
        with patch.object(m.dns_records,'probe'),patch.object(m.socket,'create_connection'),\
             patch.object(m.ssl,'create_default_context',return_value=context),patch.object(m.http.client,'HTTPSConnection')as client,\
             patch.object(m.time,'monotonic',return_value=1):
            client.return_value.getresponse.return_value=response
            self.assertEqual(m.fetch(value,'https://web.example.invalid:8443',100),(200,None,'x'*m.BODY_INSPECTION_LIMIT))
        response.read.assert_called_once_with(m.BODY_INSPECTION_LIMIT+1)
        for selected,deadline in [(MagicMock(check_hostname=False),100),(MagicMock(check_hostname=True,verify_mode=ssl.CERT_NONE),100),(context,0)]:
            with patch.object(m.dns_records,'probe'),patch.object(m.ssl,'create_default_context',return_value=selected),\
                 patch.object(m.time,'monotonic',return_value=1),self.assertRaises(ValueError):m.fetch(value,'https://web.example.invalid:8443',deadline)

    def test_page_redirect_auth_redirect_and_foreign_or_looping_responses(self):
        value=row()
        with patch.object(m,'fetch',side_effect=[(302,'/info',''),(200,None,'EXPECTED SERVICE')]):m.check(value,100)
        value.update(mode='auth-redirect',contains='',auth_origins=['https://idp.example.invalid'])
        with patch.object(m,'fetch',side_effect=[(302,'/start',''),(302,'https://idp.example.invalid/login?state=generated','')]):m.check(value,100)
        for response in [(200,None,'Expected service'),(403,None,''),(302,None,''),(302,'http://web.example.invalid',''),
                         (302,'https://foreign.example.invalid',''),(302,'https://u:p@idp.example.invalid',''),(302,'/\r\nbad',''),(302,'/','')]:
            with self.subTest(response=response),patch.object(m,'fetch',return_value=response),self.assertRaises(ValueError):m.check(value,100)
        with patch.object(m,'fetch',side_effect=[(302,'/path'+str(n),'')for n in range(8)]),self.assertRaisesRegex(ValueError,'limit'):m.check(value,100)
        value=row()
        with patch.object(m,'fetch',return_value=(200,None,'different app')),self.assertRaises(ValueError):m.check(value,100)

    def test_retry_budget_summary_and_cli_safe_failure(self):
        with patch.object(m,'check',side_effect=[OSError(),None]),patch.object(m.time,'sleep')as sleep,\
             patch.object(m.time,'monotonic',return_value=10):
            self.assertEqual(m.verify([row()]),{'status':'passed','routed_endpoints':1,'credentialed_login':False})
        sleep.assert_called_once_with(2)
        for error in (ValueError(),http.client.HTTPException()):
            with patch.object(m,'check',side_effect=error),patch.object(m.time,'monotonic',side_effect=[0,601]),self.assertRaises(ValueError):m.verify([row()])
        with patch.object(sys,'argv',['route',json.dumps([row()])]),patch.object(m,'verify',return_value={'status':'passed'}),patch('sys.stdout',new_callable=io.StringIO)as out:m.main()
        self.assertIn('passed',out.getvalue())
        for args in (['route'],['route','x'*(m.INPUT_LIMIT+1)],['route','not-json']):
            with patch.object(sys,'argv',args),self.assertRaisesRegex(SystemExit,'preserve its private evidence'):m.main()
        with patch.object(sys,'argv',['route','not-json']),self.assertRaises(SystemExit):runpy.run_path(m.__file__,run_name='__main__')

    def test_closed_rows_reject_unsafe_endpoints_paths_modes_and_origins(self):
        m.validate([row()])
        invalid=[None,{},[],[None],[{}],[row(),row()]]
        changes=[('host','localhost'),('host','bad..example'),('port',True),('port',0),('path','//foreign'),('path','/a?b'),
            ('path','/a\\b'),('path','/a\n'),('mode','login'),('contains',''),('contains','x\n'),('source_address','bad'),
            ('resolver_address','::1'),('resolver_source',None),('ingress_address','010.0.0.1'),('exposure','../bad'),
            ('route_origins',[]),('route_origins',['https://other.example.invalid']),('route_origins',['http://web.example.invalid']),
            ('route_origins',['https://web.example.invalid/']),('auth_origins',['https://idp.example.invalid/login']),
            ('auth_origins',['https://user:password@idp.example.invalid']),('auth_origins',['https://idp.example.invalid?query']),
            ('auth_origins',['https://idp.example.invalid#fragment']),('auth_origins',['https://idp.example.invalid\n']),
            ('auth_origins',['https://idp.example.invalid:0']),('auth_origins',['https://idp.example.invalid','https://idp.example.invalid'])]
        for key,value in changes:
            selected=row();selected[key]=value;invalid.append([selected])
        selected=row();selected.update(mode='auth-redirect',contains='');invalid.append([selected])
        for value in invalid:
            with self.subTest(value=value),self.assertRaises(ValueError):m.validate(value)
        with self.assertRaises(ValueError):m.fetch(row(),'https://foreign.example.invalid',100)

    def test_dns_probe_keeps_legacy_default_and_supports_selected_resolver_source(self):
        import dns_records as dns
        question=b'\x03web\x07example\x07invalid\0\0\1\0\1'
        answer=struct.pack('!6H',0x4d51,0x8000,1,1,0,0)+question+b'\xc0\x0c'+struct.pack('!HHIH',1,1,1,4)+bytes([198,18,20,80])
        with patch.object(dns.socket,'socket')as client:
            client.return_value.__enter__.return_value.recv.return_value=answer
            dns.probe('web.example.invalid','198.18.20.80',server='198.18.20.53',source='198.18.20.10')
        selected=client.return_value.__enter__.return_value
        selected.bind.assert_called_once_with(('198.18.20.10',0));selected.connect.assert_called_once_with(('198.18.20.53',53))
        for value in (None,'::1','bad'):
            with self.subTest(value=value),self.assertRaises(ValueError):dns.probe('web.example.invalid','198.18.20.80',server=value)
