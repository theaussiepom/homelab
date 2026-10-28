"""Synthetic first-start approval contracts; no guest, service or radio access."""
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE))
import zigbee2mqtt as radio
from test_zigbee2mqtt import fixture,state


def approval_for(cfg,capture,restore,now=None):
    now=now or datetime.now(timezone.utc)
    stamp=lambda value:value.strftime('%Y-%m-%dT%H:%M:%SZ')
    return {'schema':1,'approved':True,'capture_sha256':capture,
        'selection_sha256':radio.fingerprint(cfg),
        'restore_receipt_sha256':hashlib.sha256(restore.read_bytes()).hexdigest(),
        'exclusive_writer_window':{'id':'synthetic-window','confirmed':True,
            'not_before':stamp(now-timedelta(minutes=1)),
            'expires_at':stamp(now+timedelta(minutes=30))}}


class FirstStartApprovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.root=self.base/'data/zigbee2mqtt';self.root.mkdir(parents=True)
        files=state();self.cfg=fixture()['zigbee']
        self.cfg['state_sha256']={n:hashlib.sha256(v).hexdigest() for n,v in files.items()}
        for n,v in files.items():(self.root/n).write_bytes(v)
        self.capture='1'*64;self.receipt=self.base/'admission.json';self.restore=self.base/'restore.json'
        self.restore.write_text(json.dumps({'state':'complete','sha256':self.capture,'destination':str(self.root.parent)}))
        self.restore.chmod(0o600)

    def check(self,**kwargs):
        return radio.check_start(self.root,self.cfg,self.receipt,self.restore,self.capture,**kwargs)

    def test_start_alone_never_mints_first_start_approval(self):
        with self.assertRaises(ValueError):self.check(admit=True)
        self.assertFalse(self.receipt.exists())

    def test_approval_binds_capture_selection_restore_and_one_current_writer_window(self):
        good=approval_for(self.cfg,self.capture,self.restore)
        invalid=[None,{},False]
        for key,value in [('approved',False),('approved',1),('schema',True),
                ('capture_sha256','2'*64),('selection_sha256','2'*64),
                ('restore_receipt_sha256','2'*64),('extra',True)]:
            bad=copy.deepcopy(good);bad[key]=value;invalid.append(bad)
        for key,value in [('confirmed',False),('confirmed',1),('id',''),
                ('not_before','2099-01-01T00:00:00Z'),('expires_at','2000-01-01T00:00:00Z'),
                ('expires_at','2099-01-01T00:00:00Z'),('expires_at','2026-10-28T01:00:00'),
                ('extra',True)]:
            bad=copy.deepcopy(good);bad['exclusive_writer_window'][key]=value;invalid.append(bad)
        for bad in invalid:
            with self.subTest(approval=bad),self.assertRaises(ValueError):self.check(admit=True,approval=bad,require_admission=True)
            self.assertFalse(self.receipt.exists())
        self.assertFalse(self.check())
        with self.assertRaises(ValueError):self.check(require_admission=True)
        self.assertFalse(self.receipt.exists())
        self.assertTrue(self.check(admit=True,approval=good,require_admission=True))
        sealed=json.loads(self.receipt.read_text())
        self.assertEqual(sealed['schema'],2)
        self.assertEqual(sealed['first_start_approval_sha256'],radio.fingerprint(good))
        self.assertEqual(sealed['writer_window_id'],'synthetic-window')
        (self.root/'database.db').write_bytes(b'live database counters')
        before=self.receipt.read_bytes()
        self.assertFalse(self.check(require_admission=True))
        self.assertEqual(before,self.receipt.read_bytes())

    def test_legacy_or_changed_approval_receipt_is_held_without_replacement(self):
        self.check(admit=True,approval=approval_for(self.cfg,self.capture,self.restore),require_admission=True)
        good=json.loads(self.receipt.read_text())
        for bad in ([],None,'invalid'):
            self.receipt.write_text(json.dumps(bad));before=self.receipt.read_bytes()
            with self.subTest(receipt=bad),self.assertRaises(ValueError):self.check(require_admission=True)
            self.assertEqual(before,self.receipt.read_bytes())
        for key,value in [('schema',1),('first_start_approval_sha256','wrong'),('writer_window_id','')]:
            bad=dict(good);bad[key]=value;self.receipt.write_text(json.dumps(bad));before=self.receipt.read_bytes()
            with self.subTest(field=key),self.assertRaises(ValueError):self.check(require_admission=True)
            self.assertEqual(before,self.receipt.read_bytes())
