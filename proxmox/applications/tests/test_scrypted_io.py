"""The review CLI must keep private references out of its output."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ScryptedReviewIOTests(unittest.TestCase):
    def test_private_references_are_not_echoed(self):
        cfg = json.loads((ROOT / 'examples/scrypted.preparation.example.json').read_text())
        cfg['inputs'] = {key: 'private-receipt-value' for key in cfg['inputs']}
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'input.json'
            source.write_text(json.dumps(cfg))
            result = subprocess.run([sys.executable, str(ROOT / 'scrypted.py'), '--config', str(source)],
                                    capture_output=True, text=True, timeout=5, check=True)
        self.assertNotIn('private-receipt-value', result.stdout + result.stderr)
        self.assertFalse(json.loads(result.stdout)['deployable'])

    def test_duplicate_keys_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'input.json'
            source.write_text('{"enabled":true,"enabled":false}')
            result = subprocess.run([sys.executable, str(ROOT / 'scrypted.py'), '--config', str(source)],
                                    capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Duplicate', result.stderr)


if __name__ == '__main__': unittest.main()
