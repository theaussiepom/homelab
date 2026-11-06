"""Direct historical receipt and app-contract refusals over owned synthetic files."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

APP=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(APP),str(APP/'tests')]
import component_continuity as continuity
import component_generation as generation
import component_ownership as ownership
import component_payload
import dns_records
import test_component_continuity as material_cases
import test_component_receipt as receipt_cases
from private_io import encoded,read_json,write_bytes,write_new


class HistoricalComponentReadUnits(unittest.TestCase):
    def test_optional_old_prior_pointer_absence_is_read_only(self):
        case=receipt_cases.ComponentReceiptTests();case.setUp();self.addCleanup(case.doCleanups)
        value,operation=case.success()
        for path in operation.glob('*-started.json'):
            row=read_json(path,private=True);row.pop('previous_ordinary_sha256')
            write_bytes(path,encoded(row))
        before={p:(p.stat().st_ino,p.read_bytes())for p in case.root.rglob('*')if p.is_file()}
        self.assertTrue(generation.component_success(value,operation))
        self.assertEqual(before,{p:(p.stat().st_ino,p.read_bytes())for p in before})

    def test_noncomponent_contract_never_grants_owned_app_or_private_continuity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            receipt=root/'ordinary-complete.json';write_new(receipt,encoded({'operation':'/example/ordinary-1-1'}))
            attempt=SimpleNamespace(receipt=receipt)
            app=material_cases.app();app['lifecycle']='retained'
            current=material_cases.proof(app,{'api_token':b'synthetic-material'})
            before=(receipt.stat().st_ino,receipt.read_bytes())
            with patch.object(generation,'component_success',return_value=False)as validator,patch.object(component_payload.AppPayload,'load',side_effect=AssertionError('No unowned private payload read')):
                self.assertFalse(ownership.prior(attempt,app))
                with self.assertRaisesRegex(ValueError,'genuine prior component success'):
                    continuity.verify(attempt,app,current)
            self.assertEqual(validator.call_count,2)
            self.assertEqual((receipt.stat().st_ino,receipt.read_bytes()),before)


class DnsSidecarInputUnits(unittest.TestCase):
    def test_oversize_and_duplicate_json_refuse_before_native_reconcile(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary).resolve()/'records.json'
            for raw in(b' '*(1024*1024+1),b'{"schema":"homelab-component-dns-records-v2","records":{},"records":{},"previous":{}}'):
                path.write_bytes(raw);output=io.StringIO()
                with self.subTest(size=len(raw)),patch.object(sys,'argv',['dns_records.py','reconcile','--records',str(path),'--compose','/example/compose.yml']),patch.object(dns_records,'reconcile')as native,redirect_stdout(output),self.assertRaises(ValueError):
                    dns_records.main()
                native.assert_not_called();self.assertEqual(output.getvalue(),'')
                self.assertEqual(path.read_bytes(),raw)


if __name__=='__main__':unittest.main()
