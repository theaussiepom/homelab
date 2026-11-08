"""PBS transport tests stop at a fake connected socket, never a real endpoint."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_api


class Connection:
    def __init__(self, raw=b'{"data":null}', status=200, error=None):
        self.raw, self.status, self.error = raw, status, error
        self.calls = []; self.closed = False
        self.sock = SimpleNamespace(getpeercert=lambda **kwargs: b'synthetic-peer')

    def connect(self):
        self.calls.append('connect')
        if self.error: raise self.error

    def request(self, *args, **kwargs): self.calls.append((args, kwargs))
    def getresponse(self): return self
    def read(self, size): return self.raw[:size]
    def close(self): self.closed = True


class TransportTests(unittest.TestCase):
    def setUp(self):
        sha = hashlib.sha256(b'synthetic-peer').hexdigest()
        self.destination = {'server': '192.0.2.50', 'port': 8007, 'datastore': 'recovery',
                            'fingerprint': ':'.join(sha[i:i+2] for i in range(0,64,2))}
        self.token = 'management@pbs!deployment:synthetic-secret-value'

    def api(self, connection):
        return backup_api.PBS(self.destination, self.token, connect=lambda *a, **k: connection)

    def test_pin_is_checked_before_any_authentication_header(self):
        connection = Connection(); self.destination['fingerprint'] = ':'.join(['00']*32)
        with self.assertRaisesRegex(ValueError, 'certificate identity'): self.api(connection).users()
        self.assertEqual(connection.calls, ['connect']); self.assertTrue(connection.closed)
        connection = Connection(b'{"data":[]}'); result = self.api(connection)
        result.destination['fingerprint'] = ':'.join(hashlib.sha256(b'synthetic-peer').hexdigest()[i:i+2] for i in range(0,64,2))
        self.assertEqual(result.users(), [])
        self.assertEqual(connection.calls[0], 'connect')
        args, kwargs = connection.calls[1]
        self.assertEqual(args, ('GET', '/api2/json/access/users?include_tokens=1'))
        self.assertIsNone(kwargs['body'])
        self.assertEqual(kwargs['headers']['Authorization'], 'PBSAPIToken='+self.token)
        self.assertTrue(connection.closed)

    def test_writes_are_finite_and_form_encoded(self):
        connection = Connection(); api = self.api(connection)
        api.request('POST', '/access/users', {'userid': 'hl-'+'a'*32+'@pbs', 'comment':'owned scope'})
        self.assertIn('comment=owned+scope', connection.calls[1][1]['body'])
        for method, path, fields in [('DELETE','/access/users',None), ('POST','/config/datastore/recovery',{}),
                ('GET','https://elsewhere/',None), ('GET','/config/datastore/other',None),
                ('POST','/access/users/root@pam/token/backup',{}), ('GET','/access/users',{'x':True}),
                ('GET','/access/users',[]), ('GET','/access/users',{'x':'a'*8193})]:
            before = list(connection.calls)
            with self.subTest(path=path), self.assertRaises(ValueError): api.request(method,path,fields)
            self.assertEqual(connection.calls,before)

    def test_failures_are_bounded_redacted_and_never_retried(self):
        for raw,status,error in [(b'PRIVATE_SENTINEL',403,None), (b'PRIVATE_SENTINEL',302,None),
                (b'{"data":1,"data":2}',200,None), (b'[]',200,None), (b'{}',200,None),
                (b'x'*(backup_api.LIMIT+1),200,None), (b'',200,OSError('PRIVATE_SENTINEL')),
                (b'',200,http.client.HTTPException('PRIVATE_SENTINEL'))]:
            connection=Connection(raw,status,error)
            with self.subTest(status=status,error=type(error).__name__), self.assertRaises(ValueError) as caught:
                self.api(connection).request('GET','/access/users')
            self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))
            self.assertEqual(connection.calls.count('connect'),1); self.assertTrue(connection.closed)

    def test_invalid_destination_or_token_never_constructs_transport(self):
        for field, value in [('server','https://other'),('server',None),('port',True),('port',0),
                ('port',65536),('datastore','../other'),('datastore',None),('fingerprint','bad')]:
            destination=copy.deepcopy(self.destination); destination[field]=value
            with self.subTest(field=field), self.assertRaises(ValueError): backup_api.PBS(destination,self.token)
        for token in (None,'root@pam:password',self.token+'\n','user@pbs!token:short'):
            with self.subTest(token_type=type(token).__name__), self.assertRaises(ValueError):
                backup_api.PBS(self.destination,token)

    def test_inventory_shapes_and_expected_datastore_are_checked(self):
        def api(value): return self.api(Connection(json.dumps({'data':value}).encode()))
        api({'name':'recovery','path':'/mnt/backup/recovery'}).datastore('/mnt/backup/recovery')
        for value in (None,{'name':'other','path':'/mnt/backup/recovery'}, {'name':'recovery','path':'/wrong'}):
            with self.assertRaises(ValueError): api(value).datastore('/mnt/backup/recovery')
        self.assertEqual(api([{'ns':'guests'}]).namespaces(),{'guests'})
        self.assertEqual(api([{'userid':'one@pbs'}]).users(),[{'userid':'one@pbs'}])
        self.assertEqual(api({'/':{'Sys.Audit':True}}).permission('one@pbs'),{'/':{'Sys.Audit':True}})
        for method, value in [('namespaces',{}),('namespaces',[{}]),('namespaces',[1]),
                ('users',{}),('users',[{}]),('users',[1]),('permission',[]),
                ('permission',{'/':[]}),('permission',{'/':{'Sys.Audit':1}})]:
            with self.subTest(method=method), self.assertRaises(ValueError):
                getattr(api(value),method)(*(['one@pbs'] if method=='permission' else []))


if __name__ == '__main__': unittest.main()
