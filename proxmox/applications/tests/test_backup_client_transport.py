"""Real bounded local pipes substitute for SSH; no guest or credential is contacted."""
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import backup_client_transport as subject

class ClientTransportTests(unittest.TestCase):
    cfg={'paths':{'known_hosts':'/known','private_key':'/key'},'app':{'address':'192.0.2.12'}}
    def run_peer(self,code,**options):
        processes=[];calls=[]
        def launch(argv,**kwargs):
            calls.append((argv,kwargs));peer=subprocess.Popen([sys.executable,'-c',code],**kwargs);processes.append(peer);return peer
        try:return subject.fetch(self.cfg,'a'*64,create=options.get('create',False),launch=launch),calls
        finally:
            self.assertTrue(all(p.poll() is not None for p in processes))
            self.assertTrue(all(p.stdout.closed and p.stdin.closed for p in processes))
    def test_chunked_private_output_and_fixed_command_keep_strict_trust(self):
        code="import json,sys,time;v=json.load(sys.stdin);assert v['action']=='create';sys.stdout.write('synthetic');sys.stdout.flush();time.sleep(.01);sys.stdout.write('-key')"
        raw,calls=self.run_peer(code,create=True);self.assertEqual(raw,b'synthetic-key')
        argv,kwargs=calls[0]
        self.assertEqual(argv[-1],'/usr/bin/python3 /opt/homelab-backup/backup_client_key.py')
        for option in ('StrictHostKeyChecking=yes','IdentitiesOnly=yes','BatchMode=yes'):self.assertIn(option,argv)
        self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
        self.assertEqual(set(kwargs['env']),{'PATH','HOME'})
    def test_empty_nonzero_oversized_and_silent_peer_fail_and_are_reaped(self):
        for code in ('import sys;sys.stdin.read()', 'import sys;sys.stdin.read();sys.stdout.write("key");sys.exit(1)',
                     'import sys;sys.stdin.read();sys.stdout.write("x"*16385);sys.stdout.flush()'):
            with self.subTest(code=code),self.assertRaises(ValueError):self.run_peer(code)
        with patch.object(subject.selectors.DefaultSelector,'select',return_value=[]),self.assertRaisesRegex(ValueError,'timed out'):
            self.run_peer('import sys,time;sys.stdin.read();time.sleep(10)')
    def test_elapsed_deadline_and_failed_request_write_close_peer(self):
        with patch.object(subject.time,'monotonic',side_effect=[0,100]),self.assertRaisesRegex(ValueError,'timed out'):
            self.run_peer('import sys,time;sys.stdin.read();time.sleep(10)')
        with self.assertRaises(ValueError):subject.fetch(self.cfg,'a'*64,create='yes')
        # A broken pipe cannot leave a helper running or a sensitive stdout open.
        from unittest.mock import Mock
        peer=Mock(stdin=io.BytesIO(),stdout=io.BytesIO())
        peer.stdin=Mock(closed=False);peer.stdin.write.side_effect=BrokenPipeError()
        peer.poll.return_value=0
        with self.assertRaises(BrokenPipeError):subject.fetch(self.cfg,'a'*64,create=False,launch=lambda *a,**k:peer)
        peer.stdin.close.assert_called_once();self.assertTrue(peer.stdout.closed)

if __name__=='__main__':unittest.main()
