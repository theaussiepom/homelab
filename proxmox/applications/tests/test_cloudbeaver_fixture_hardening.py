"""The synthetic HTTP fixture has closed targets, safe headers and modern TLS."""
import ast
import contextlib
import hashlib
import io
import json
import os
import stat
import subprocess
import tempfile
import traceback
from types import SimpleNamespace
from pathlib import Path
import unittest
from urllib.parse import parse_qs,urlencode,urlsplit

SOURCE=Path(__file__).with_name('cloudbeaver_gateway_fixture.py')


def helpers():
    tree=ast.parse(SOURCE.read_text())
    selected=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in {'clean_header','proxy_target','query_error_projection','community_exception_projection','combined_checks','record','write','execute'}]
    namespace={'urlsplit':urlsplit,'urlencode':urlencode,'parse_qs':parse_qs,'json':json,
               'os':os,'hashlib':hashlib,'traceback':traceback}
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

    def test_community_log_projection_observes_only_closed_symbols_not_messages(self):
        """Retain recognised log observations without claiming the query's cause."""
        project=helpers()['community_exception_projection'];secret='private-cookie-key-password-sentinel'
        raw=('java.lang.NullPointerException: '+secret+'\n'
             '\tat io.cloudbeaver.service.core.impl.WebServiceCore.getUserConnections(WebServiceCore.java:1)\n'
             'Caused by: java.util.ConcurrentModificationException: '+secret+'\n'
             '\tat io.cloudbeaver.model.session.WebSession.getAccessibleProjects(WebSession.java:14)\n'
             '\tat io.cloudbeaver.WebServiceUtils.getApplicableDriversIds(WebServiceUtils.java:1000000)\n')
        value=project(raw+raw)
        self.assertEqual(value,{'log_status':'symbols-observed','log_available':True,
            'log_truncated':False,'symbol_limit_reached':False,
            'observed_exception_types':['java.lang.NullPointerException','java.util.ConcurrentModificationException'],
            'observed_frames':[{'frame':'WebServiceCore.getUserConnections','line':1},
                              {'frame':'WebSession.getAccessibleProjects','line':14},
                              {'frame':'WebServiceUtils.getApplicableDriversIds','line':1000000}],
            'unknown_exception_lines':0,'unknown_frame_lines':0})
        self.assertNotIn(secret,json.dumps(value))
        self.assertNotIn('cause',value)

    def test_community_log_projection_handles_unknown_absent_and_misleading_text(self):
        """Unknown details stay counts; invalid frames and unrelated mentions stay opaque."""
        project=helpers()['community_exception_projection'];secret='private-cookie-key-password-sentinel'
        for absent in (None,False,[],{}):
            with self.subTest(absent=absent):
                self.assertEqual(project(absent)['log_status'],'unavailable')
                self.assertFalse(project(absent)['log_available'])
        for text in ('','INFO java.lang.NullPointerException: '+secret,
                     'message: Caused by: java.lang.NullPointerException: '+secret):
            with self.subTest(text=text):
                self.assertEqual(project(text)['log_status'],'no-matching-lines')
        value=project('private.'+secret+'.Exception: '+secret+'\nat private.'+secret+'.method(private.java:9)')
        self.assertEqual(value['unknown_exception_lines'],1)
        self.assertEqual(value['unknown_frame_lines'],1)
        self.assertEqual(value['observed_exception_types'],[])
        self.assertEqual(value['observed_frames'],[])
        self.assertNotIn(secret,json.dumps(value))
        for number in ('0','-1','1000001','00000001','1.0','１','1) extra'):
            with self.subTest(number=number):
                value=project('at io.cloudbeaver.service.core.impl.WebServiceCore.getUserConnections(WebServiceCore.java:'+number+')')
                self.assertEqual(value['observed_frames'],[])
                self.assertEqual(value['unknown_frame_lines'],1)

    def test_community_log_projection_bounds_tail_symbols_and_unknown_counts(self):
        """Large logs cannot widen the output or promote a truncated partial line."""
        project=helpers()['community_exception_projection']
        value=project('java.lang.NullPointerException: old\n'+'x'*70000+'\njava.io.IOException: new')
        self.assertTrue(value['log_truncated'])
        self.assertEqual(value['observed_exception_types'],['java.io.IOException'])
        self.assertEqual(project('x'*70000)['log_status'],'no-matching-lines')
        types=['java.lang.NullPointerException','java.util.ConcurrentModificationException',
               'java.lang.IllegalStateException','java.lang.IllegalArgumentException',
               'java.util.NoSuchElementException','java.lang.ClassCastException','java.io.IOException',
               'org.jkiss.dbeaver.DBException','io.cloudbeaver.DBWebException']
        raw='\n'.join(types)+'\n'+''.join('at io.cloudbeaver.service.core.impl.WebServiceCore.getUserConnections(WebServiceCore.java:'+str(n)+')\n' for n in range(1,14))
        value=project(raw)
        self.assertEqual(value['observed_exception_types'],types[:8])
        self.assertEqual(len(value['observed_frames']),12)
        self.assertTrue(value['symbol_limit_reached'])
        value=project(('private.XException: opaque\nat private.C.m(C.java:1)\n')*1000)
        self.assertEqual((value['unknown_exception_lines'],value['unknown_frame_lines']),(999,999))
        self.assertTrue(value['symbol_limit_reached'])

    def test_community_log_projection_keeps_complete_tail_boundary_lines(self):
        """A complete first type or frame at the tail boundary must remain visible."""
        project=helpers()['community_exception_projection']
        rows=[('java.lang.NullPointerException: synthetic', ['java.lang.NullPointerException'], []),
              ('at io.cloudbeaver.service.core.impl.WebServiceCore.getUserConnections(WebServiceCore.java:14)',
               [], [{'frame':'WebServiceCore.getUserConnections','line':14}])]
        for separator in ('\n','\r','\r\n','\v','\f','\x1c','\x1d','\x1e','\x85','\u2028','\u2029'):
            for line,types,frames in rows:
                with self.subTest(separator=repr(separator),line=line):
                    tail=line+'\n'+'x'*(65536-len(line)-1)
                    self.assertEqual(len(tail),65536)
                    value=project('discarded'+separator+tail)
                    self.assertTrue(value['log_truncated'])
                    self.assertEqual(value['observed_exception_types'],types)
                    self.assertEqual(value['observed_frames'],frames)

    def test_community_log_projection_discards_mid_line_tail_symbols(self):
        """An exception-shaped suffix of a cut line is not a complete observation."""
        project=helpers()['community_exception_projection']
        for first in ('java.lang.NullPointerException: synthetic',
                      'at io.cloudbeaver.service.core.impl.WebServiceCore.getUserConnections(WebServiceCore.java:14)'):
            with self.subTest(first=first):
                rows=first+'\njava.io.IOException: complete\n'
                tail=rows+'x'*(65536-len(rows))
                value=project('not-a-line-boundary-'+tail)
                self.assertTrue(value['log_truncated'])
                self.assertEqual(value['observed_exception_types'],['java.io.IOException'])
                self.assertEqual(value['observed_frames'],[])

    def execute_case(self, community_status='owned', community_log=None, *, passed=False, query=True):
        """Run real refusal and JSON output with injected HTTP, login and Docker responses."""
        ns=helpers();secret='private-cookie-key-password-session-sentinel';calls=[]
        if community_log is None:
            community_log='java.lang.NullPointerException: '+secret+'\nat io.cloudbeaver.service.core.impl.WebServiceCore.getUserConnections(WebServiceCore.java:14)\n'
        error={'errors':[{'message':secret,'path':['userConnections'],
                         'extensions':{'classification':'DataFetchingException'}}]}
        replies=iter([(302,{},''),(302,{},''),(200,{},json.dumps({'data':{'openSession':{'valid':True}}})),
                      (200,{},json.dumps(error))])
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);state={'tests':[]}
            def docker(*args,**kwargs):
                calls.append(args);self.assertEqual(kwargs,{'check':False})
                if args[0]=='inspect':
                    self.assertIn(args[1],('gateway-id','fixture-config','community-id'))
                    if args[1]=='community-id' and community_status=='absent':
                        return subprocess.CompletedProcess(args,1,'',secret)
                    owner='foreign' if args[1]=='community-id' and community_status=='unowned' else 'this-run'
                    body=[{'Id':args[1],'Config':{'Labels':{'org.homelab.fixture.owner':owner}}}]
                    return subprocess.CompletedProcess(args,0,json.dumps(body),'')
                if args[0]=='logs':
                    text=community_log if args[1]=='community-id' else 'java.lang.IllegalStateException: '+secret
                    code=1 if args[1]=='community-id' and community_status=='logs-failed' else 0
                    return subprocess.CompletedProcess(args,code,text,'')
                self.assertEqual(args[:2],('rm','--force'))
                return subprocess.CompletedProcess(args,0,'','')
            def main():
                if passed:state.update(status='PASS');return
                if query:ns['combined_checks']({'settings':{'recovery_admin':'fixture-recovery'}})
                raise RuntimeError('Other fixture failure')
            ns.update(ROOT=root,result=state,HEADERS=['X-User'],provider=SimpleNamespace(public_url='https://fixture.invalid'),
                      get=lambda *args:next(replies),login=lambda **kwargs:('jar',200,{},[302,200]),main=main,
                      docker=docker,container_id='gateway-id',container_name='fixture',ce_id='community-id',
                      ce_name='community-name',run_id='this-run',network_id=None,servers=[])
            with contextlib.redirect_stdout(io.StringIO()) as output:
                if passed:ns['execute']()
                else:
                    with self.assertRaises(SystemExit) as stopped:ns['execute']()
                    self.assertEqual(stopped.exception.code,1)
            public=output.getvalue();summary=json.loads(public);stored=json.loads((root/'result.json').read_text())
            self.assertNotIn(secret,public);self.assertNotIn(secret,json.dumps(stored))
            files={path.name:path.read_text() for path in root.iterdir()}
            for path in root.iterdir():self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            return summary,stored,calls,files,secret

    def test_real_query_execute_summary_retains_closed_owned_community_observations(self):
        """The original failure survives JSON serialisation and existing owned cleanup."""
        summary,stored,calls,files,secret=self.execute_case()
        self.assertEqual(summary['status'],'FAIL');self.assertEqual(summary['tests'],4)
        self.assertEqual(summary['error'],'Community query rejected declared read-only fields')
        self.assertEqual(set(summary),{'status','tests','failed_tests','error_type','error','result',
                                     'query_error_diagnostics','community_exception_diagnostics'})
        observed=summary['community_exception_diagnostics']
        self.assertEqual(observed,stored['community_exception_diagnostics'])
        self.assertEqual(observed['observed_exception_types'],['java.lang.NullPointerException'])
        self.assertEqual(observed['observed_frames'],[{'frame':'WebServiceCore.getUserConnections','line':14}])
        self.assertEqual(summary['query_error_diagnostics'],stored['query_error_diagnostics'])
        self.assertIn(secret,files['ce-query-errors.json']);self.assertIn(secret,files['community.log'])
        self.assertEqual(calls,[('inspect','gateway-id'),('logs','gateway-id'),('rm','--force','gateway-id'),
            ('inspect','fixture-config'),('logs','fixture-config'),('rm','--force','fixture-config'),
            ('inspect','community-id'),('logs','community-id'),('rm','--force','community-id')])

    def test_execute_summary_distinguishes_unavailable_unowned_and_unmatched_logs(self):
        """Foreign, missing and failed logs never borrow symbols from other containers."""
        for mode,status in [('absent','unavailable'),('logs-failed','unavailable'),('unowned','unowned'),('owned','no-matching-lines')]:
            with self.subTest(mode=mode):
                summary,stored,calls,files,_=self.execute_case(mode,'' if mode=='owned' else None)
                value=summary['community_exception_diagnostics']
                self.assertEqual(value['log_status'],status)
                self.assertEqual(value['log_available'],mode=='owned')
                self.assertEqual(value['observed_exception_types'],[])
                self.assertEqual(value['observed_frames'],[])
                self.assertEqual(value,stored['community_exception_diagnostics'])
                if mode in {'absent','unowned'}:
                    self.assertNotIn(('logs','community-id'),calls)
                    self.assertNotIn(('rm','--force','community-id'),calls)
                    self.assertNotIn('community.log',files)

    def test_execute_pass_and_other_failure_do_not_add_query_diagnostics(self):
        """Diagnostics cannot change success or become a general server-log exporter."""
        for passed in (True,False):
            with self.subTest(passed=passed):
                summary,stored,_,_,_=self.execute_case(passed=passed,query=False)
                self.assertEqual(summary['status'],'PASS' if passed else 'FAIL')
                self.assertNotIn('community_exception_diagnostics',summary)
                self.assertNotIn('community_exception_diagnostics',stored)

    def test_tls_server_explicitly_requires_at_least_tls12(self):
        tree=ast.parse(SOURCE.read_text())
        server=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='server')
        assignments=[node for node in ast.walk(server) if isinstance(node,ast.Assign)]
        self.assertTrue(any(any(isinstance(t,ast.Attribute) and t.attr=='minimum_version' for t in n.targets)
                            and ast.unparse(n.value)=='ssl.TLSVersion.TLSv1_2' for n in assignments))


if __name__=='__main__':unittest.main()
