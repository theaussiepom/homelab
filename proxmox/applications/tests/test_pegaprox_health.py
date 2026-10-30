"""PegaProx deployment can verify an existing account but cannot bootstrap one."""

from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pegaprox_health as health
import pegaprox


class HealthTests(unittest.TestCase):
    def test_probe_is_read_only_and_has_no_initial_account_interface(self):
        self.assertNotIn("/api/auth/setup", health.CONTAINER_CODE)
        self.assertNotIn("/api/auth/login", health.CONTAINER_CODE)
        self.assertIn("state.get('initialized') is True", health.CONTAINER_CODE)
        self.assertEqual(
            pegaprox.health_checks()[0]["argv"],
            ["python3", "/opt/homelab-app/pegaprox-health.py"],
        )

    def test_probe_uses_fixed_container_argv_and_suppresses_private_failure_output(
        self,
    ):
        with patch.object(
            health.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, "PegaProx verification passed\n", ""
            ),
        ) as run:
            self.assertEqual(
                health.verify(["docker", "exec", "fixture"]),
                "PegaProx verification passed",
            )
            self.assertEqual(run.call_args.args[0][:3], ["docker", "exec", "fixture"])
            self.assertNotIn("input", run.call_args.kwargs)
        with patch.object(
            health.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 1, "sensitive response", "sensitive error"
            ),
        ):
            with self.assertRaisesRegex(ValueError, "PegaProx verification failed"):
                health.verify(["fixture"])

class ContainerProbeTests(unittest.TestCase):
    """Execute the production embedded probe with bounded, controlled HTTP responses."""
    def execute(self, health_response=(200, {'status':'ok','version':'fixture'}),
                auth_response=(401, {'authenticated':False,'initialized':True}), failure=None):
        import contextlib
        import io
        import json
        import urllib.error
        import urllib.request
        from unittest.mock import Mock
        calls = []
        class Response(io.BytesIO):
            def __init__(self, code, body):
                self.code = code
                super().__init__(body if isinstance(body, bytes) else json.dumps(body).encode())
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size):
                self_limit = 1048577
                if size != self_limit: raise AssertionError('Unbounded response')
                return super().read(size)
        def open_request(request, timeout):
            calls.append((request, timeout))
            if failure: raise failure
            code,body = health_response if request.full_url.endswith('/api/health') else auth_response
            if code == 401:
                raise urllib.error.HTTPError(request.full_url, code, 'Unauthorized', {}, Response(code,body))
            return Response(code, body)
        opener = Mock(open=Mock(side_effect=open_request))
        output = io.StringIO()
        with patch.object(urllib.request,'build_opener',return_value=opener) as build, \
             patch('time.monotonic',side_effect=[0,66]), patch('time.sleep') as sleep, \
             contextlib.redirect_stdout(output):
            exec(health.CONTAINER_CODE, {})
        return calls,build,sleep,output.getvalue()

    def test_http_get_only_proxy_disabled_closed_setup_success(self):
        calls,build,sleep,output = self.execute()
        self.assertEqual(output, 'PegaProx verification passed\n')
        self.assertEqual([request.full_url for request,_ in calls],
                         ['http://127.0.0.1:5000/api/health','http://127.0.0.1:5000/api/auth/check'])
        self.assertEqual([timeout for _,timeout in calls], [4,8])
        for request,_ in calls:
            self.assertEqual(request.get_method(),'GET')
            self.assertIsNone(request.data)
            self.assertEqual(request.get_header('Origin'),'http://127.0.0.1:5000')
        for args,kwargs in build.call_args_list:
            self.assertEqual(args[0].proxies,{})
            with self.assertRaisesRegex(RuntimeError,'Unexpected local redirect'):
                args[1].redirect_request(None,None,None,None,None,None)
        sleep.assert_not_called()

    def test_unready_malformed_oversized_or_unavailable_health_refuses_with_deadline(self):
        for response in [(500,{}),(200,{}),(200,[]),(200,{'status':'ok','version':''}),
                         (200,{'status':'ok','version':2}),(200,b'not JSON'),
                         (200,b'x'*1048577)]:
            with self.subTest(response=str(response)[:100]), self.assertRaisesRegex(RuntimeError,'did not become ready'):
                self.execute(health_response=response)
        for error in [OSError('unavailable'),RuntimeError('Unexpected local redirect')]:
            with self.subTest(error=error), self.assertRaisesRegex(RuntimeError,'did not become ready'):
                self.execute(failure=error)

    def test_auth_must_be_unauthenticated_initialized_and_exact_401(self):
        for response in [(200,{'authenticated':False,'initialized':True}),
                         (401,{}),(401,[]),(401,{'authenticated':True,'initialized':True}),
                         (401,{'authenticated':False,'initialized':False}),
                         (401,{'authenticated':False}), (401,b'not JSON'),
                         (401,b'x'*1048577)]:
            with self.subTest(response=str(response)[:100]), self.assertRaises((RuntimeError,ValueError)):
                self.execute(auth_response=response)
