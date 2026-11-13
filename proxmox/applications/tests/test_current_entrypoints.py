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
    def held(self, failure, *, diagnostic_failure=False):
        """Exercise the actual CLI handler; it must dispatch once and keep custody."""
        with (
            patch.object(sys, 'argv', ['deploy', '--phase', 'pbs-agent', '--packet', '/PRIVATE_SENTINEL/packet.json']),
            patch.object(deploy.os, 'umask'),
            patch.dict(deploy.os.environ, {'PRIVATE_SENTINEL':'credential-value'}),
            patch.object(deploy, 'run', side_effect=failure) as run,
            patch('sys.stdout', new_callable=io.StringIO) as output,
            patch('sys.stderr', new_callable=io.StringIO) as errors,
        ):
            with self.assertRaises(SystemExit) as stopped:
                if diagnostic_failure:
                    with patch.object(deploy, 'failure_diagnostic', side_effect=RuntimeError('PRIVATE_SENTINEL')):
                        deploy.main()
                else:
                    deploy.main()
            run.assert_called_once()
            text = str(stopped.exception.code)
            self.assertTrue(stopped.exception.__suppress_context__)
            self.assertTrue(text.startswith('Deployment held; preserve private inputs, state and all attempt evidence.'))
            self.assertIn('No automatic replay or restore.', text)
            for value in (text, output.getvalue(), errors.getvalue()):
                self.assertNotIn('PRIVATE_SENTINEL', value)
                self.assertNotIn('credential-value', value)
            return json.loads(text.splitlines()[-1])

    def test_held_failure_identifies_a_public_source_callsite_without_exception_contents(self):
        import private_io
        def fail(*args):
            private_io.require(False, 'PRIVATE_SENTINEL private path, request body and credential-value')
        diagnostic = self.held(fail)
        self.assertEqual(diagnostic['error_type'], 'ValueError')
        self.assertGreater(len(diagnostic['source']), 0)
        self.assertLessEqual(len(diagnostic['source']), 4)
        self.assertIn('private_io.py', [row['file'] for row in diagnostic['source']])
        for row in diagnostic['source']:
            self.assertEqual(set(row), {'file', 'line'})
            self.assertIn(row['file'], {path.name for path in APPS.glob('*.py')})
            self.assertIs(type(row['line']), int)
            self.assertGreater(row['line'], 0)

    def test_process_failures_custom_types_and_foreign_traceback_names_cannot_expose_values(self):
        private_type = type('PRIVATE_SENTINEL', (Exception,), {})
        failures = [(subprocess.CalledProcessError(1, ['PRIVATE_SENTINEL'], output='credential-value', stderr='PRIVATE_SENTINEL'),
                     'CalledProcessError'),
                    (subprocess.TimeoutExpired(['PRIVATE_SENTINEL'], 1, output='credential-value'), 'TimeoutExpired'),
                    (private_type('credential-value'), 'Exception')]
        for error, expected in failures:
            with self.subTest(error_type=expected):
                def fail(*args):
                    # A dynamic traceback filename beside real sources is not
                    # a public source file; no file is created or read here.
                    exec(compile('raise error', str(APPS/'PRIVATE_SENTINEL.py'), 'exec'), {'error':error})
                diagnostic = self.held(fail)
                self.assertEqual(diagnostic['error_type'], expected)
                self.assertTrue(all(row['file'] == 'deploy.py' for row in diagnostic['source']))

    def test_diagnostic_collection_failure_keeps_the_original_generic_hold(self):
        self.assertEqual(self.held(ValueError('PRIVATE_SENTINEL'), diagnostic_failure=True),
                         {'error_type':'Exception', 'source':[]})

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
                patch.object(sys, "argv", ["pegaprox_health.py"]),
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
