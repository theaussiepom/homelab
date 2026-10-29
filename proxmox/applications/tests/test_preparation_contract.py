"""Run only local admission assertions; never install packages or touch accounts."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest_contract
from fixtures import guest

ANSIBLE = str(Path(sys.executable).with_name("ansible-playbook"))
if not Path(ANSIBLE).is_file():
    ANSIBLE = shutil.which("ansible-playbook")


@unittest.skipUnless(ANSIBLE, "Local assertion fixture requires Ansible")
class PreparationContractTests(unittest.TestCase):
    def test_current_package_identity_contract_passes_the_real_admission_assertion(
        self,
    ):
        import yaml

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = guest(root)
            cfg["app"]["database"] = {
                "account_mode": "package",
                "user": "mysql",
                "group": "mysql",
            }
            guest_contract.validate(cfg)
            task = yaml.safe_load(
                (
                    Path(__file__).resolve().parents[1]
                    / "ansible/tasks/database-package-account.yml"
                ).read_text()
            )[0]
            playbook = root / "assert-only.json"
            playbook.write_text(
                json.dumps(
                    [
                        {
                            "hosts": "localhost",
                            "connection": "local",
                            "gather_facts": False,
                            "vars": {"app": cfg["app"]},
                            "tasks": [task],
                        }
                    ]
                )
            )
            result = subprocess.run(
                [ANSIBLE, "-i", "localhost,", str(playbook)],
                capture_output=True,
                text=True,
                env=dict(os.environ, ANSIBLE_LOCAL_TEMP=str(root / "ansible")),
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("changed=0", result.stdout)
