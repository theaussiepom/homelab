"""Synthetic image handoff and refusal evidence must fail before VM admission."""
from contextlib import redirect_stdout
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer_ci', ROOT / 'scripts/installer_ci.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
spec = importlib.util.spec_from_file_location('installer_ci_workflow', ROOT / 'scripts/workflow.py')
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)
ENV = {'GITHUB_RUN_ID': '123', 'GITHUB_SHA': 'a' * 40, 'GITHUB_REPOSITORY': 'fixture/framework'}


class ImageHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, ENV).start()

    def build(self, profile):
        folder, image = ci.layout(self.root, profile)
        folder.mkdir(parents=True)
        image.write_bytes(b'invented immutable test image')
        receipt = {'schema': 'homelab-single-usb-build-v1', 'sha256': ci.digest(image),
                   'bytes': image.stat().st_size, 'environment': 'synthetic' if profile == 'fixture' else 'production',
                   'embedded_payload_readback': 'passed', 'native_answer_validation': 'passed static nonresolving placeholders',
                   'modified_squashfs_sha256': 'b' * 64, 'production_boot_or_erase_authorized': False}
        (folder / 'build-receipt.json').write_text(json.dumps(receipt))
        if profile == 'custom':
            (folder / 'readback/homelab').mkdir(parents=True)
            (folder / 'readback/homelab/config.json').write_text(json.dumps({'machine_uuid': '44444444-4444-4444-8444-444444444444'}))
            (self.root / 'evidence').mkdir()
            (self.root / 'evidence/final-metadata-verification.json').write_text(json.dumps({'all_other_vendor_metadata_preserved': True, 'modified_squashfs_sha256': 'b' * 64}))
        return folder, image, receipt

    def packet(self, profile):
        folder, image, receipt = self.build(profile)
        packet = self.root / 'packet'
        with redirect_stdout(io.StringIO()) as output:
            ci.stage(self.root, profile, packet)
        values = dict(line.split('=', 1) for line in output.getvalue().splitlines())
        shutil.rmtree(folder)
        return packet, values['manifest_sha256'], values['image_sha256']

    def test_both_profiles_restore_only_the_exact_build_files_in_a_fresh_job(self):
        for profile in ('fixture', 'custom'):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                packet, manifest, image = self.packet(profile)
                ci.restore(self.root, profile, packet, manifest, image)
                folder, target = ci.layout(self.root, profile)
                self.assertEqual(ci.digest(target), image)
                self.assertEqual(json.loads((folder / 'build-receipt.json').read_text())['sha256'], image)
                self.assertEqual((folder / 'readback/homelab/config.json').exists(), profile == 'custom')
                with self.assertRaisesRegex(ValueError, 'existing'):
                    ci.restore(self.root, profile, packet, manifest, image)

    def test_source_run_profile_hash_tampering_and_unsafe_packet_never_restore(self):
        for variant in ('run', 'source', 'repository', 'profile', 'manifest', 'image', 'receipt', 'extra', 'symlink', 'packet-symlink', 'missing-digest', 'wrong-image', 'missing-file', 'oversize', 'old-vm'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                packet, manifest, image = self.packet('fixture')
                if variant in ('run', 'source', 'repository', 'profile'):
                    value = json.loads((packet / 'manifest.json').read_text())
                    value[{'run':'run_id', 'source':'source_sha', 'repository':'repository', 'profile':'profile'}[variant]] = 'foreign'
                    (packet / 'manifest.json').write_text(json.dumps(value)); manifest = ci.digest(packet / 'manifest.json')
                if variant == 'manifest': (packet / 'manifest.json').write_text('{}')
                if variant == 'image': (packet / 'image.iso').write_bytes(b'changed')
                if variant == 'receipt': (packet / 'build-receipt.json').write_text('{}')
                if variant == 'extra': (packet / 'disk.raw').write_bytes(b'never restore')
                if variant == 'symlink':
                    (packet / 'image.iso').rename(packet / 'retained'); (packet / 'image.iso').symlink_to(packet / 'retained')
                    (packet / 'retained').rename(self.root / 'retained'); (packet / 'image.iso').unlink(); (packet / 'image.iso').symlink_to(self.root / 'retained')
                if variant == 'packet-symlink':
                    packet.rename(self.root / 'retained'); packet.symlink_to(self.root / 'retained', target_is_directory=True)
                if variant == 'missing-digest': manifest = ''
                if variant == 'wrong-image': image = '0' * 64
                if variant == 'missing-file': (packet / 'image.iso').unlink()
                if variant == 'oversize':
                    with (packet / 'build-receipt.json').open('wb') as stream: stream.truncate(1024**2 + 1)
                if variant == 'old-vm': (self.root / 'build/vm-tests').mkdir()
                with self.assertRaises((ValueError, OSError)):
                    ci.restore(self.root, 'fixture', packet, manifest, image)
                self.assertFalse(ci.layout(self.root, 'fixture')[1].exists())

    def test_changed_failed_or_noninvented_build_cannot_be_shared(self):
        for variant in ('hash', 'size', 'environment', 'readback', 'validation', 'authority', 'custom-uuid', 'metadata', 'stale-metadata'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                profile = 'custom' if variant in {'custom-uuid','metadata','stale-metadata'} else 'fixture'
                folder, image, receipt = self.build(profile)
                fields = {'hash': ('sha256', '0'*64), 'size': ('bytes', 1), 'environment': ('environment', 'foreign'),
                          'readback': ('embedded_payload_readback', 'failed'), 'validation': ('native_answer_validation','failed'),
                          'authority': ('production_boot_or_erase_authorized', True)}
                if variant in fields:
                    key, value = fields[variant]; receipt[key] = value; (folder / 'build-receipt.json').write_text(json.dumps(receipt))
                if variant == 'custom-uuid': (folder / 'readback/homelab/config.json').write_text('{}')
                if variant in {'metadata','stale-metadata'}:
                    (self.root / 'evidence/final-metadata-verification.json').write_text(json.dumps({'all_other_vendor_metadata_preserved':variant != 'metadata', 'modified_squashfs_sha256':'c'*64}))
                with self.assertRaises(ValueError): ci.stage(self.root, profile, self.root / 'packet')
                self.assertFalse((self.root / 'packet').exists())

    def test_context_and_nonregular_inputs_are_never_accepted(self):
        for values in ({'GITHUB_RUN_ID':''}, {'GITHUB_SHA':'bad'}, {'GITHUB_REPOSITORY':'bad'}):
            with patch.dict(os.environ, values), self.assertRaises(ValueError): ci.binding('fixture')
        with self.assertRaises(ValueError): ci.binding('unknown')
        with self.assertRaises(ValueError): ci.regular(self.root)
        empty = self.root / 'empty'; empty.touch()
        with self.assertRaises(ValueError): ci.regular(empty)


class VmEvidenceTests(unittest.TestCase):
    def test_every_case_requires_independent_expected_outcome_and_exact_image(self):
        for case, reason in ci.CASES.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, ENV):
                root = Path(temp)
                _, image = ci.layout(root, 'custom' if case == 'profile-wrong-machine' else 'fixture')
                image.parent.mkdir(parents=True); image.write_bytes(b'only this image')
                image_hash = ci.digest(image)
                folder = root / ('build/vm-tests/' + case + '-synthetic'); folder.mkdir(parents=True)
                record = {'case':case,'expected':'checked-and-stopped' if reason is None else 'refused',
                          'refusal_reason':reason,'expected_refusal_reason':reason,'reason_matches':True,
                          'image_sha256':image_hash,'production_host_accessed':False,'local_vm_exit':0,
                          'no_target_disk_writes':True,'disk_write_bytes':{'disk'+str(i):0 for i in range(4 if case == 'ambiguous-member' else 3)}}
                record['result'] = record['expected']
                receipt = folder / 'receipt.json'; receipt.write_text(json.dumps(record))
                with redirect_stdout(io.StringIO()): ci.verify(root, case, image_hash)
                for key, value in [('case','foreign'),('result','wrong'),('expected','wrong'),('image_sha256','0'*64),
                                   ('production_host_accessed',True),('local_vm_exit',True),('local_vm_exit',1),
                                   ('no_target_disk_writes',False),('reason_matches',False),('disk_write_bytes',{}),
                                   ('disk_write_bytes',{'disk0':0,'disk1':0,'disk2':1}),('disk_write_bytes',None)]:
                    bad = dict(record, **{key:value}); receipt.write_text(json.dumps(bad))
                    with self.subTest(field=key), self.assertRaises(ValueError): ci.verify(root, case, image_hash)
                if reason:
                    for value in (None, 'wrong reason'):
                        receipt.write_text(json.dumps(dict(record, refusal_reason=value)))
                        with self.assertRaises(ValueError): ci.verify(root, case, image_hash)
                receipt.write_text(json.dumps(record))
                image.write_bytes(b'changed after VM')
                with self.assertRaisesRegex(ValueError,'Image changed'): ci.verify(root,case,image_hash)
                with self.assertRaises(ValueError): ci.verify(root,'foreign',image_hash)

    def test_missing_or_ambiguous_case_evidence_fails(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, ENV):
            root = Path(temp); _, image = ci.layout(root, 'fixture')
            image.parent.mkdir(parents=True); image.write_bytes(b'fixture')
            for folder in ('other', 'matching-check-one', 'matching-check-two'):
                path = root / ('build/vm-tests/' + folder); path.mkdir(parents=True); (path / 'receipt.json').write_text('{}')
                with self.assertRaises(ValueError): ci.verify(root,'matching-check',ci.digest(image))


class InputAndCliTests(unittest.TestCase):
    def test_invented_inputs_are_private_and_never_overwrite_existing_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); shutil.copytree(ROOT / 'config', root / 'config')
            ci.custom_inputs(root)
            before = {path.name:path.read_bytes() for path in (root / '.local').iterdir()}
            self.assertEqual(len(before),5)
            hardware = json.loads(before['hardware.json'])
            self.assertTrue(all(disk['disk_serial'].startswith('CI-') for disk in hardware['disk_members'] + hardware['protected_disks']))
            self.assertFalse(json.loads(before['media-approval.json'])['production_boot_or_erase_authorized'])
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in (root / '.local').iterdir()))
            with self.assertRaises(ValueError): ci.custom_inputs(root)
            self.assertEqual(before, {path.name:path.read_bytes() for path in (root / '.local').iterdir()})

    def test_diagnostic_allowlist_excludes_disks_images_and_local_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); folder = root / 'build/vm-tests/case'; folder.mkdir(parents=True)
            (folder / 'receipt.json').write_text('receipt')
            (folder / 'console.log').write_bytes(b'console\xff')
            (folder / 'disk.raw').write_text('PRIVATE_DISK')
            (folder / 'image.iso').write_text('PRIVATE_IMAGE')
            (root / '.local').mkdir(); (root / '.local/root-recovery-password.hash').write_text('PRIVATE_INPUT')
            with redirect_stdout(io.StringIO()) as output: ci.evidence(root)
            self.assertIn('receipt',output.getvalue()); self.assertIn('console',output.getvalue())
            self.assertNotIn('PRIVATE_',output.getvalue())

    def test_cli_routes_the_five_actions_without_changing_their_inputs(self):
        for action, method in [('custom-inputs','custom_inputs'),('stage','stage'),('restore','restore'),('verify','verify'),('evidence','evidence')]:
            namespace = {'__name__':'import_fixture'}
            exec(compile((ROOT / 'scripts/installer_ci.py').read_bytes(),str(ROOT / 'scripts/installer_ci.py'),'exec'),namespace)
            with patch('sys.argv',['ci',action,'--profile','fixture','--packet','packet','--case','matching-check','--manifest-sha','a'*64,'--image-sha','b'*64]), patch.dict(namespace,{method:unittest.mock.Mock()}):
                namespace['main']()
                namespace[method].assert_called_once()
        with patch('sys.argv',['ci','evidence']), redirect_stdout(io.StringIO()):
            runpy.run_path(str(ROOT / 'scripts/installer_ci.py'),run_name='__main__')

    def test_dispatch_executes_only_one_whitelisted_case(self):
        for args in (['workflow','test-case','wrong-machine'], ['workflow','test-case'], ['workflow','test-case','unknown'], ['workflow','test-case','wrong-machine','extra']):
            with patch('sys.argv', args), patch.object(workflow,'run') as run:
                if len(args)==3 and args[2]=='wrong-machine':
                    workflow.main(); run.assert_called_once_with(workflow.ROOT / 'scripts/boot_test.py','wrong-machine')
                else:
                    with self.assertRaises(ValueError): workflow.main()
                    run.assert_not_called()
