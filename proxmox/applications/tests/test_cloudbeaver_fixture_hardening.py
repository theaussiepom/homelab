"""The synthetic HTTP fixture has closed targets, safe headers and modern TLS."""
import ast
import json
import tempfile
from types import SimpleNamespace
from pathlib import Path
import unittest
from urllib.parse import parse_qs,urlencode,urlsplit

SOURCE=Path(__file__).with_name('cloudbeaver_gateway_fixture.py')


def helpers():
    tree=ast.parse(SOURCE.read_text())
    selected=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in {'clean_header','proxy_target','query_error_projection','combined_checks'}]
    namespace={'urlsplit':urlsplit,'urlencode':urlencode,'parse_qs':parse_qs,'json':json}
    exec(compile(ast.Module(selected,type_ignores=[]),str(SOURCE),'exec'),namespace)
    return namespace


class FixtureHardeningTests(unittest.TestCase):
    def test_headers_reject_either_line_separator_before_forwarding(self):
        clean=helpers()['clean_header']
        self.assertEqual(clean('a=b; Secure; HttpOnly'),'a=b; Secure; HttpOnly')
        for value in ('Header\rInjected','Header\nInjected',None):
            with self.assertRaises(ValueError):clean(value)

    def test_only_exact_frontdoor_and_known_callback_parameters_reach_gateway(self):
        target=helpers()['proxy_target']
        self.assertEqual(target('GET','/'),('GET','/'))
        self.assertEqual(target('POST','/api/gql'),('POST','/api/gql'))
        query={'code':'fixture_code-123','state':'nonce:https://cloud.fixture.test:123/'}
        self.assertEqual(target('GET','/oauth2/callback?'+urlencode(query)),('GET','/oauth2/callback?'+urlencode(query)))
        for method,path in [('GET','http://foreign.invalid/'),('GET','//foreign.invalid/'),('CONNECT','/'),
             ('GET','/admin'),('GET','/?extra=1'),('POST','/oauth2/callback?code=x&state=y'),
             ('GET','/oauth2/callback?code=x&state=y&extra=z'),('GET','/oauth2/callback?code=x&state=y&state=z'),
             ('GET','/oauth2/callback?code=&state=y'),('GET','/oauth2/callback?code=x&state='),
             ('GET','/oauth2/callback?code=x%0D&state=y'),('GET','/oauth2/callback?code=x&state=y%0A'),
             ('GET','/oauth2/callback?code=x&state=y#fragment'),('GET','/\\escape')]:
            with self.subTest(method=method,path=path),self.assertRaises(ValueError):target(method,path)

    def test_query_error_projection_is_bounded_and_never_echoes_untrusted_text(self):
        project=helpers()['query_error_projection']
        secret='synthetic-private-password-session-sentinel'
        errors=[{'message':'Permission denied: '+secret, 'path':['userConnections',secret,{'nested':secret}],
                 'extensions':{'errorCode':'ACCESS_DENIED','classification':'DataFetchingException','details':secret}}]
        self.assertEqual(project(errors),[{'path':['userConnections','other','other'],
            'error_code':'ACCESS_DENIED','error_kind':'DataFetchingException','message_category':'access'}])
        other=project([{'message':secret,'path':secret,'extensions':{'code':secret,'classification':secret}},
                       {'message':None,'extensions':None},secret])
        self.assertNotIn(secret,json.dumps(other))
        self.assertEqual(other[-1],{'error_kind':'invalid-error'})
        self.assertEqual(project({'errors':secret}),[{'error_kind':'invalid-envelope'}])
        self.assertEqual(len(project(errors*100)),8)
        self.assertEqual(len(project([{'path':['name']*100}])[0]['path']),8)
        for message,category in [('Session missing','session'),('Missing project','project-resource'),
                                 ('Driver missing','driver'),('SQL exception','database'),('other','unclassified')]:
            self.assertEqual(project([{'message':message}])[0]['message_category'],category)

    def test_failed_normal_user_query_keeps_refusal_and_only_records_safe_diagnostics(self):
        ns=helpers();secret='synthetic-private-password-session-sentinel'
        error={'errors':[{'message':'Permission denied '+secret,'path':['userConnections'],
                          'extensions':{'classification':'DataFetchingException'}}]}
        replies=iter([(302,{},''),(302,{},''),(200,{},json.dumps({'data':{'openSession':{'valid':True}}})),
                      (200,{},json.dumps(error))])
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);records=[];state={}
            ns.update(HEADERS=['X-User'],provider=SimpleNamespace(public_url='https://fixture.invalid'),ROOT=root,
                      get=lambda *args:next(replies),login=lambda **kwargs:('jar',200,{},[302,200]),
                      record=lambda *args,**kwargs:records.append(args),result=state,
                      write=lambda path,raw:path.write_text(raw))
            with self.assertRaisesRegex(RuntimeError,'Community query rejected declared read-only fields'):
                ns['combined_checks']({'settings':{'recovery_admin':'fixture-recovery'}})
            self.assertEqual(len(records),4)
            self.assertEqual(json.loads((root/'ce-query-errors.json').read_text()),error)
            self.assertNotIn(secret,json.dumps(state))
            self.assertEqual(state['query_error_diagnostics'][0]['path'],['userConnections'])
            self.assertEqual(state['query_error_diagnostics'][0]['message_category'],'access')

    def test_tls_server_explicitly_requires_at_least_tls12(self):
        tree=ast.parse(SOURCE.read_text())
        server=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='server')
        assignments=[node for node in ast.walk(server) if isinstance(node,ast.Assign)]
        self.assertTrue(any(any(isinstance(t,ast.Attribute) and t.attr=='minimum_version' for t in n.targets)
                            and ast.unparse(n.value)=='ssl.TLSVersion.TLSv1_2' for n in assignments))


if __name__=='__main__':unittest.main()
