"""Prevent reintroducing the retired entrypoints or crossing execution boundaries."""

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ArchitectureTests(unittest.TestCase):
    def test_one_current_deployment_entrypoint_and_no_retired_compatibility_tree(self):
        for name in [
            "ordinary_cd.py",
            "foundation_cd.py",
            "automation_cd.py",
            "bitwarden_cd.py",
            "pegaprox_cd.py",
            "monitoring_cd.py",
            "restore.py",
            "site_config.py",
            "plan.py",
        ]:
            self.assertFalse((ROOT / name).exists(), name)
        self.assertFalse((ROOT / "templates/applications.yml").exists())
        self.assertTrue((ROOT / "deploy.py").is_file())
        workflow = (ROOT.parents[1] / ".github/workflows/guest-phase.yml").read_text()
        self.assertIn("proxmox/applications/deploy.py --phase", workflow)

    def test_adapters_and_custody_do_not_import_the_entrypoint_or_retired_controllers(
        self,
    ):
        retired = {
            "ordinary_cd",
            "foundation_cd",
            "automation_cd",
            "bitwarden_cd",
            "pegaprox_cd",
            "monitoring_cd",
            "restore",
            "site_config",
            "plan",
        }
        for path in ROOT.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                names = []
                if isinstance(node, ast.Import):
                    names = [x.name.split(".")[0] for x in node.names]
                if isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".")[0]]
                self.assertFalse(set(names) & retired, str(path))
                if path.name != "deploy.py":
                    self.assertNotIn("deploy", names, str(path))

    def test_definition_validation_and_custody_have_no_native_executor(self):
        for name in [
            "guest_contract.py",
            "deployment_state.py",
            "private_io.py",
            "plan_policy.py",
            "secret_contract.py",
        ]:
            source = (ROOT / name).read_text()
            imports = {
                n.name
                for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Import)
                for n in node.names
            }
            self.assertNotIn("subprocess", imports, name)
        text = (ROOT / "ansible/tasks/compose.yml").read_text()
        self.assertNotIn("ordinary_reconcile", text)
        self.assertNotIn("compose-bootstrap.yml", text)
        self.assertNotIn("node-red-settings.js", text)
        self.assertNotIn("mdns-route.sh", text)
