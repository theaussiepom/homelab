"""Current CLI boundaries and immutable stack preparation without native execution."""

import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import unittest
from unittest.mock import patch

APPS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APPS))
import deploy


class CurrentEntrypointTests(unittest.TestCase):
    def test_deployment_cli_dispatches_or_holds_without_private_output(self):
        for result in ({"status": "passed"}, ValueError("sensitive detail")):
            with (
                self.subTest(result=type(result).__name__),
                patch.object(
                    sys,
                    "argv",
                    ["deploy", "--phase", "infrastructure", "--packet", "packet.json"],
                ),
                patch.object(deploy.os, "umask"),
                patch.object(
                    deploy,
                    "run",
                    **(
                        {"side_effect": result}
                        if isinstance(result, Exception)
                        else {"return_value": result}
                    ),
                ),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                if isinstance(result, Exception):
                    with self.assertRaisesRegex(SystemExit, "Deployment held"):
                        deploy.main()
                    self.assertNotIn("sensitive", output.getvalue())
                else:
                    deploy.main()
                    self.assertEqual(json.loads(output.getvalue()), result)

    def test_pegaprox_cli_requires_exact_success_and_hides_private_output(self):
        for status, stdout in (
            (0, "PegaProx verification passed\n"),
            (1, "private"),
            (0, "unexpected"),
        ):
            with (
                self.subTest(status=status, stdout=stdout),
                patch(
                    "subprocess.run",
                    return_value=subprocess.CompletedProcess([], status, stdout, ""),
                ),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                if status == 0 and stdout.startswith("PegaProx verification passed"):
                    runpy.run_path(
                        str(APPS / "pegaprox_health.py"), run_name="__main__"
                    )
                else:
                    with self.assertRaisesRegex(SystemExit, "health contract failed"):
                        runpy.run_path(
                            str(APPS / "pegaprox_health.py"), run_name="__main__"
                        )
                    self.assertNotIn("private", output.getvalue())

    def test_template_cli_prepares_pinned_template_or_checks_readback(self):
        import monitoring_templates as templates

        document = templates.prepared("template_app_proxmox.yaml")
        for argv in (
            ["template", "--name", "template_app_proxmox.yaml"],
            ["template", "--check-readback"],
        ):
            with (
                patch.object(sys, "argv", argv),
                patch("sys.stdin", io.StringIO(json.dumps(document))),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                runpy.run_path(
                    str(APPS / "monitoring_templates.py"), run_name="__main__"
                )
                self.assertTrue(output.getvalue())
