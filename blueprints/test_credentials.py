"""Preflight the retained SSH key before binding persistent credentials."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import credentials


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for name in ("selected", "other"):
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "retained-" + name,
                    "-f",
                    str(self.root / name),
                ],
                check=True,
                capture_output=True,
            )
        self.directory = self.root / "credentials"
        self.directory.mkdir(mode=0o700)
        self.token = self.directory / "token"
        self.key = self.directory / "key"
        self.public = " ".join((self.root / "selected.pub").read_text().split()[:2])
        from test_component_plan import library, site
        import component_plan, component_packet
        spec, source = library(), site()
        spec['software'] = {'resolver': {'images': {'unbound': 'unbound'}}}
        spec['runtime_profiles'] = {'resolver': {'containers': {'unbound': {
            'memory_mib': 256, 'cpu_limit': 1, 'pids_limit': 128}}}}
        spec['app_profiles']['recursive'].update(software=['resolver'], runtime=['resolver'],
            health={'ready': {'type':'adapter','check':'readiness'}})
        source['contexts']['lab']['ssh_public_keys'] = [self.public]
        source['secret_sources']['token']['path'] = str(self.token)
        source['secret_sources']['ssh']['path'] = str(self.key)
        stack = self.root/'library'; stack.mkdir()
        (stack/'stack.json').write_text(json.dumps(spec))
        (stack/'images.json').write_text(json.dumps({'unbound': {
            'repository':'example/unbound','tag':'1','digest':'sha256:'+'a'*64}}))
        source_file=self.root/'site.json';source_file.write_text(json.dumps(source))
        self.value=component_packet.lower_plan(component_plan.resolve(stack,source_file))['resolver']
        self.packet = self.root / "packet.json"
        self.environment = {
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push",
            "PROXMOX_APP_TOKEN": "fixture@pve!applications=synthetic",
            "APPLICATION_SSH_KEY": (self.root / "selected").read_text(),
        }

    def save(self):
        self.packet.write_text(json.dumps(self.value))

    def test_command_line_binds_private_credentials_and_suppresses_failed_input(self):
        import os

        self.save()
        result = subprocess.run(
            [
                sys.executable,
                str(Path(credentials.__file__)),
                "--packet",
                str(self.packet),
            ],
            env=dict(os.environ, **self.environment),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["files_created"], 2)
        self.assertNotIn(
            self.environment["PROXMOX_APP_TOKEN"], result.stdout + result.stderr
        )
        failed = subprocess.run(
            [
                sys.executable,
                str(Path(credentials.__file__)),
                "--packet",
                str(self.root / "missing"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("Credential binding held", failed.stderr)

    def test_late_bootstrap_hold_blocks_current_recipe_before_credentials(self):
        import workflows
        job,_=workflows.phase_recipe()
        script=job['steps'][0]['run']
        self.assertIn('BOOTSTRAP-CD-HOLD.json',script)
        for marker in ('CONFIGURING','BOOTSTRAP-CD-HOLD.json'):
            for phase in ('infrastructure','preparation','independent_app'):
                with self.subTest(marker=marker,phase=phase):
                    case=self.root/(marker+'-'+phase);case.mkdir()
                    (case/marker).write_text('synthetic late hold')
                    result=subprocess.run(['bash','-e','-c',script.replace(
                        '/var/lib/homelab-bootstrap',str(case))],capture_output=True)
                    self.assertNotEqual(result.returncode,0)
                    self.assertFalse(self.packet.exists())
                    self.assertEqual(list(self.directory.iterdir()),[])

    def test_unreviewed_push_disabled_and_old_packets_refuse_before_key_check(self):
        from unittest.mock import patch
        for field,value in [('GITHUB_REF','refs/heads/feature'),('GITHUB_EVENT_NAME','pull_request')]:
            self.save()
            with patch.object(credentials.subprocess,'run') as process,self.assertRaises(ValueError):
                credentials.bind(self.packet,dict(self.environment,**{field:value}))
            process.assert_not_called()
        for change in ({'enabled':False},{'schema':'homelab-guest-deployment-v2'}):
            original=dict(self.value);self.value.update(change);self.save()
            with patch.object(credentials.subprocess,'run') as process,self.assertRaises(ValueError):
                credentials.bind(self.packet,self.environment)
            process.assert_not_called();self.value=original
        self.assertEqual(list(self.directory.iterdir()),[])

    def test_matching_key_binds_once_without_rotation(self):
        self.save()
        self.assertEqual(
            credentials.bind(self.packet, self.environment)["files_created"], 2
        )
        before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        self.assertEqual(
            credentials.bind(self.packet, self.environment)["files_created"], 0
        )
        self.assertEqual(
            before, {p.name: p.read_bytes() for p in self.directory.iterdir()}
        )
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)

    def test_mismatched_key_is_refused_before_either_credential_is_written(self):
        cfg = json.loads(self.value["files"]["site.json"])
        cfg["ssh_public_keys"] = [
            " ".join((self.root / "other.pub").read_text().split()[:2])
        ]
        self.value["files"]["site.json"] = json.dumps(cfg)
        self.save()
        with self.assertRaises(ValueError):
            credentials.bind(self.packet, self.environment)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_unusable_private_key_is_refused_without_persistent_writes(self):
        self.save()
        self.environment["APPLICATION_SSH_KEY"] = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid\n-----END OPENSSH PRIVATE KEY-----\n"
        )
        with self.assertRaises(ValueError):
            credentials.bind(self.packet, self.environment)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_encrypted_key_is_refused_without_prompting_or_persistent_writes(self):
        subprocess.run(
            [
                "ssh-keygen",
                "-p",
                "-P",
                "",
                "-N",
                "synthetic-passphrase",
                "-f",
                str(self.root / "selected"),
            ],
            check=True,
            capture_output=True,
        )
        self.environment["APPLICATION_SSH_KEY"] = (self.root / "selected").read_text()
        self.save()
        with self.assertRaises(ValueError):
            credentials.bind(self.packet, self.environment)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_existing_credential_drift_is_preserved(self):
        self.save()
        credentials.bind(self.packet, self.environment)
        self.token.write_text("different retained token")
        before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        with self.assertRaises(ValueError):
            credentials.bind(self.packet, self.environment)
        self.assertEqual(
            before, {p.name: p.read_bytes() for p in self.directory.iterdir()}
        )

    def test_aliased_credential_paths_refuse_before_partial_binding(self):
        cfg = json.loads(self.value["files"]["site.json"])
        cfg["paths"]["private_key"] = str(self.token)
        self.value["files"]["site.json"] = json.dumps(cfg)
        self.save()
        with self.assertRaises(ValueError):
            credentials.bind(self.packet, self.environment)
        self.assertEqual(list(self.directory.iterdir()), [])
