"""The synthetic backend wait tolerates startup delay without accepting the wrong feed."""
import ast
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

SOURCE = Path(__file__).with_name('cloudflare_runtime_fixture.py')
URL = 'http://127.0.0.1:8080/ips'
FEED = {'success': True, 'result': {'ipv4_cidrs': ['198.18.71.0/24'], 'ipv6_cidrs': ['2400:cb00::/32']}}


class BackendReadinessTests(unittest.TestCase):
    """Use owned loopback sockets; never run Docker, contact a target or change middleware."""
    def script(self):
        """Read the exact script passed to docker exec from the actual fixture."""
        tree = ast.parse(SOURCE.read_text())
        return next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == 'BACKEND_READY' for target in node.targets))

    def endpoint(self, payload, delay=None, gate=None):
        """Bind a unique socket now; optionally begin accepting requests after a real delay."""
        raw = json.dumps(payload).encode()
        class Handler(BaseHTTPRequestHandler):
            """Serve only the synthetic feed path used by readiness admission."""
            def log_message(self, *args):
                """Keep the local fixture silent."""
            def do_GET(self):
                """Return the selected complete payload at the exact feed endpoint."""
                assert self.path == '/ips'
                self.send_response(200); self.send_header('Content-Length', str(len(raw)))
                self.end_headers(); self.wfile.write(raw)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler, bind_and_activate=False)
        server.server_bind()
        stopped, active = threading.Event(), threading.Event()
        def start():
            """Defer listen itself so early requests genuinely receive connection refused."""
            if gate: gate.wait()
            if not stopped.wait(delay):
                server.server_activate(); active.set(); server.serve_forever(poll_interval=.01)
        worker = threading.Thread(target=start, daemon=True) if delay is not None else None
        if worker: worker.start()
        def close():
            """Close only this test's socket and bounded server thread."""
            stopped.set()
            if gate: gate.set()
            if active.is_set(): server.shutdown()
            if worker: worker.join(timeout=2)
            server.server_close()
        self.addCleanup(close)
        return 'http://127.0.0.1:'+str(server.server_address[1])+'/ips'

    def run_script(self, url, budget=None):
        """Relocate only the fixture endpoint; optional fast tests scale the fixed budget."""
        source = self.script(); self.assertEqual(source.count(URL), 1)
        source = source.replace(URL, url)
        if budget is not None:
            self.assertEqual(source.count('time.monotonic()+25'), 1)
            source = source.replace('time.monotonic()+25', 'time.monotonic()+'+str(budget), 1)
        return subprocess.run([sys.executable, '-I', '-B', '-c', source], capture_output=True, timeout=30)

    def test_real_delayed_listen_refuses_one_shot_then_passes_bounded_wait(self):
        """Reproduce the old immediate-connect failure before the same server becomes ready."""
        gate = threading.Event(); url = self.endpoint(FEED, delay=.35, gate=gate)
        with self.assertRaises(urllib.error.URLError): urllib.request.urlopen(url, timeout=.1)
        gate.set()
        result = self.run_script(url)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_never_listening_backend_reaches_terminal_deadline(self):
        """A real bound but permanently non-listening socket cannot pass readiness."""
        url = self.endpoint(FEED)
        started = time.monotonic(); result = self.run_script(url, budget=.25)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'TimeoutError: Synthetic backend did not become ready', result.stderr)
        self.assertLess(time.monotonic()-started, 3)

    def test_wrong_or_incomplete_feed_is_not_accepted_as_ready(self):
        """A live HTTP listener must serve the exact expected synthetic feed."""
        for payload in ({}, {'success': False}, {**FEED, 'result': {'ipv4_cidrs': ['0.0.0.0/0'], 'ipv6_cidrs': []}}):
            with self.subTest(payload=payload):
                result = self.run_script(self.endpoint(payload, delay=0))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'AssertionError', result.stderr)

    def test_real_fixture_executes_wait_before_starting_proxy(self):
        """The deadline wraps backend readiness only; proxy and boundary checks remain later."""
        tree = ast.parse(SOURCE.read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'docker']
        ready = [node for node in calls if any(isinstance(arg, ast.Name) and arg.id == 'BACKEND_READY' for arg in node.args)]
        self.assertEqual(len(ready), 1)
        self.assertEqual([ast.literal_eval(arg) for arg in ready[0].args[:1]], ['exec'])
        proxy = next(node for node in calls if len(node.args)>3 and isinstance(node.args[3], ast.Name) and node.args[3].id == 'proxy')
        self.assertLess(ready[0].lineno, proxy.lineno)
