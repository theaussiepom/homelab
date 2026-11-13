"""Immutable input hashes and guest trust must fail closed on independent drift."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deployment_inputs as inputs
import guest_identity as identity
import test_guest_identity as identity_cases


class InputBindingTests(unittest.TestCase):
    def test_binding_tracks_all_external_authorities_and_source_bytes(self):
        import component_inputs
        import component_payload
        import component_process_fixtures as fixtures
        from private_io import write_new
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();fixtures.initialize(root)
            source=root/'applications';source.mkdir();(root/'common').mkdir()
            (source/'helper.py').write_text('first source')
            for name in ('__pycache__','.terraform','.work'):
                (source/name).mkdir();(source/name/'noise').write_text('ignored')
            cfg,site=component_inputs.prepare(root/'packet.json',root/'inputs',create=True)
            with patch.object(inputs,'SOURCE',source):
                before=inputs.binding(cfg,site)
                self.assertEqual(set(before['input_hashes']),{
                    str(path)for path in site.parent.iterdir()if path.is_file()and path.name!='component-prepared.json'}|{str(root/'ca')})
                for name in ('__pycache__','.terraform','.work'):(source/name/'noise').write_text('changed excluded bytes')
                self.assertEqual(inputs.binding(cfg,site),before)
                (source/'helper.py').write_text('changed source')
                self.assertNotEqual(inputs.binding(cfg,site)['source_sha256'],before['source_sha256'])
                current=inputs.binding(cfg,site)
                folder=component_inputs.app_directory(cfg,create=True)
                selected=component_payload.prepare(folder,cfg['deployment']['input_identity'],'database',{'private-input':b'only selected app'})
                self.assertEqual(inputs.binding(cfg,site),current)
                (selected.directory/'private-input').write_bytes(b'changed app input')
                with self.assertRaises(ValueError):selected.check()
                self.assertEqual(inputs.binding(cfg,site),current)

    def test_guest_identity_refusals_never_write_trust_or_completion(self):
        for scenario in (
            "ipv6",
            "guest",
            "interfaces",
            "private-mode",
            "lookup",
            "existing-ambiguous",
            "window",
            "actor",
            "scan",
        ):
            case = identity_cases.IdentityTests()
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cfg = case.setup_fixture(root)
                address = "198.18.100.42"
                if scenario == "ipv6":
                    address = "2001:db8::1"
                if scenario == "guest":
                    case.config["hostname"] = "unrelated"
                if scenario == "interfaces":
                    cfg["guest"]["interfaces"] = []
                if scenario == "private-mode":
                    (root / "hosts").chmod(0o644)
                if scenario == "window":
                    (root / "apply-window.json").write_text(
                        json.dumps({"plan_sha256": "different"})
                    )
                if scenario == "actor":
                    (root / "api").write_text("unscoped=synthetic")

                def command(args, **kwargs):
                    if args[0] == "ssh-keygen" and scenario in (
                        "lookup",
                        "existing-ambiguous",
                    ):
                        return subprocess.CompletedProcess(
                            args, 2 if scenario == "lookup" else 0, "", ""
                        )
                    if args[0] == "ssh-keyscan" and scenario == "scan":
                        return subprocess.CompletedProcess(args, 1, "", "")
                    return case.command(args, **kwargs)

                before = (root / "hosts").read_bytes()
                with (
                    patch.object(identity.subprocess, "run", side_effect=command),
                    self.assertRaises(ValueError),
                ):
                    identity.pin(cfg, root, address, case.fetch, case.persist)
                self.assertEqual((root / "hosts").read_bytes(), before)
                self.assertFalse((root / "host-key-evidence.json").exists())
