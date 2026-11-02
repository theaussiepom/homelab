"""The synthetic HTTP fixture has closed targets, safe headers and modern TLS."""
import ast
from pathlib import Path
import unittest
from urllib.parse import parse_qs,urlencode,urlsplit

SOURCE=Path(__file__).with_name('cloudbeaver_gateway_fixture.py')


def helpers():
    tree=ast.parse(SOURCE.read_text())
    selected=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in {'clean_header','proxy_target'}]
    namespace={'urlsplit':urlsplit,'urlencode':urlencode,'parse_qs':parse_qs}
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

    def test_tls_server_explicitly_requires_at_least_tls12(self):
        tree=ast.parse(SOURCE.read_text())
        server=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='server')
        assignments=[node for node in ast.walk(server) if isinstance(node,ast.Assign)]
        self.assertTrue(any(any(isinstance(t,ast.Attribute) and t.attr=='minimum_version' for t in n.targets)
                            and ast.unparse(n.value)=='ssl.TLSVersion.TLSv1_2' for n in assignments))


if __name__=='__main__':unittest.main()
