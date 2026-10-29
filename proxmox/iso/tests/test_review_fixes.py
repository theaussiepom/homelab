"""Regressions for the installer review's failure and evidence boundaries."""
from contextlib import redirect_stdout
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from homelab_installer import core
import launch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('review_workflow', ROOT/'scripts/workflow.py')
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)


class QualificationTests(unittest.TestCase):
    def test_metadata_must_pass_for_the_current_squashfs(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(workflow, 'ROOT', Path(folder)):
            root = Path(folder)
            def put(path, value):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
            images = {}
            for env in ('fixture', 'production'):
                image = root/f'build/single-usb-{env}/Proxmox-9.2-1-{env}.iso'
                image.parent.mkdir(parents=True)
                image.write_bytes(('mock image '+env).encode())
                images[env] = workflow.sha(image)
                put(image.parent/'build-receipt.json', {'sha256': images[env], 'modified_squashfs_sha256': 'a'*64})
            put(root/'evidence/source-tests.json', {'passed': True, 'source_sha256': workflow.source_digest(), 'tests_run': 1})
            for case in ('matching-check', 'wrong-machine', 'missing-member', 'ambiguous-member', 'cancel-install', 'profile-wrong-machine'):
                env = 'production' if case == 'profile-wrong-machine' else 'fixture'
                result = 'checked-and-stopped' if case == 'matching-check' else 'refused'
                put(root/f'build/vm-tests/{case}-20261025T000000Z/receipt.json', {'result': result, 'expected': result, 'no_target_disk_writes': True, 'reason_matches': True, 'local_vm_exit': 0, 'image_sha256': images[env]})
            for metadata in ({'all_other_vendor_metadata_preserved': True},
                             {'all_other_vendor_metadata_preserved': True, 'modified_squashfs_sha256': 'b'*64},
                             {'all_other_vendor_metadata_preserved': False, 'modified_squashfs_sha256': 'a'*64}):
                put(root/'evidence/final-metadata-verification.json', metadata)
                with self.subTest(metadata=metadata), self.assertRaisesRegex(ValueError, 'Metadata'):
                    workflow.qualify()
                self.assertFalse((root/'evidence/media-acceptance.json').exists())
            put(root/'evidence/final-metadata-verification.json', {'all_other_vendor_metadata_preserved': True, 'modified_squashfs_sha256': 'a'*64})
            with redirect_stdout(io.StringIO()):
                workflow.qualify()
            self.assertTrue(json.loads((root/'evidence/media-acceptance.json').read_text())['usb_write_admitted'])


class GuardFailureTests(unittest.TestCase):
    def test_command_and_unexpected_runtime_failures_hold_without_launching(self):
        errors = (subprocess.CalledProcessError(1, ['findmnt']),
                  subprocess.TimeoutExpired(['udevadm'], 15),
                  IndexError('malformed inventory'), AttributeError('malformed inventory'),
                  core.Refusal('wrong machine UUID'))
        for error in errors:
            with self.subTest(error=type(error).__name__), patch.object(launch, 'main', side_effect=error), patch.object(launch, 'hold') as hold, patch.object(launch.os, 'execv') as execute:
                launch.guarded_main()
                reason = str(error) if isinstance(error, core.Refusal) else type(error).__name__
                hold.assert_called_once_with('HOMELAB_REFUSED: '+reason)
                execute.assert_not_called()


class FetchVerificationTests(unittest.TestCase):
    def test_optimized_python_rejects_wrong_key_and_tampered_index(self):
        source = (ROOT/'scripts/fetch-assistant.py').read_text()
        fingerprint = '24B30F06ECC1836A4E5EFECBA7BCD1420BFE778E'
        # Execute the real fetch script with optimisation. All inputs stay local,
        # and any attempted download or helper execution fails the test.
        for failure in ('key', 'index'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root/'proxmox-release-trixie.gpg').write_bytes(b'fixture key')
                package_path = 'pve-no-subscription/binary-amd64/Packages.gz'
                trusted = gzip.compress(b'Package: fixture\n')
                (root/'InRelease').write_text(f'SHA256:\n {hashlib.sha256(trusted).hexdigest()} {len(trusted)} {package_path}\n')
                (root/'Packages.gz').write_bytes(b'tampered index')
                def vendor_command(argv, **kwargs):
                    self.assertEqual(argv[0], 'gpg', 'downloaded helper must never execute')
                    if '--show-keys' in argv:
                        shown = '0'*40 if failure == 'key' else fingerprint
                        output = 'fpr:::::::::'+shown+':\n'
                    else:
                        output = '[GNUPG:] VALIDSIG '+fingerprint+' 2026-10-25\n'
                    return subprocess.CompletedProcess(argv, 0, stdout=output, stderr='')
                def local_path(value):
                    return root if value == '/work/build' else Path(value)
                with patch('pathlib.Path', side_effect=local_path), patch.dict(os.environ, {'GNUPGHOME': str(root/'gnupg')}), patch('subprocess.run', side_effect=vendor_command), patch('urllib.request.urlopen', side_effect=AssertionError('network must remain unused')):
                    message = 'unexpected release key' if failure == 'key' else 'package index hash mismatch'
                    with self.assertRaisesRegex(RuntimeError, message):
                        exec(compile(source, 'fetch-assistant.py', 'exec', optimize=1), {'__name__': '__main__'})


if __name__ == '__main__':
    unittest.main()
