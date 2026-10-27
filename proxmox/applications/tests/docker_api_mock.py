"""Synthetic Docker API, with no host Docker socket or real container access."""
import http.server
import json
import threading
import os
import socketserver
from pathlib import Path
from urllib.parse import urlsplit


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_HEAD(self): self.reply({})
    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith('/v1.'):
            path = '/' + path.split('/', 2)[2]
        if path == '/version':
            value = {'ApiVersion': '1.41', 'MinAPIVersion': '1.24', 'Version': '23.0.3'}
        elif path == '/info':
            value = {'ID': 'fixture', 'Name': 'fixture-docker', 'Containers': 1, 'ContainersRunning': 1,
                'ContainersStopped': 0, 'ContainersPaused': 0, 'Images': 1, 'Driver': 'overlay2',
                'NCPU': 2, 'MemTotal': 1073741824, 'DockerRootDir': '/var/lib/docker',
                'ServerVersion': '23.0.3', 'OSType': 'linux', 'Architecture': 'amd64',
                'OperatingSystem': 'synthetic', 'KernelVersion': 'synthetic'}
        elif path == '/containers/json':
            value = [{'Id': 'c' * 64, 'Names': ['/fixture-app'], 'Image': 'fixture/app:1',
                'Created': 1700000000, 'State': 'running', 'Status': 'Up',
                'HostConfig': {'NetworkMode': 'bridge'}, 'NetworkSettings': {'Networks': {}}}]
        elif path.endswith('/stats'):
            value = {'read': '2026-01-01T00:00:00Z', 'pids_stats': {'current': 2},
                'memory_stats': {'usage': 1048576, 'limit': 1073741824, 'stats': {'active_anon': 1024, 'inactive_file': 0}},
                'cpu_stats': {'cpu_usage': {'total_usage': 2000000, 'usage_in_kernelmode': 1000, 'usage_in_usermode': 1000},
                              'system_cpu_usage': 200000000, 'online_cpus': 2, 'throttling_data': {}},
                'precpu_stats': {'cpu_usage': {'total_usage': 1000000}, 'system_cpu_usage': 100000000}, 'networks': {}}
        elif path.startswith('/containers/'):
            value = {'Id': 'c' * 64, 'Name': '/fixture-app', 'Names': ['/fixture-app'], 'Image': 'fixture/app:1',
                'Created': '2026-01-01T00:00:00Z', 'RestartCount': 2,
                'State': {'Status': 'running', 'Running': True, 'Paused': False, 'Restarting': False,
                          'OOMKilled': False, 'Dead': False, 'Pid': 1, 'ExitCode': 0, 'Error': '',
                          'StartedAt': '2026-01-01T00:00:00Z', 'FinishedAt': '0001-01-01T00:00:00Z',
                          'Health': {'Status': 'healthy', 'FailingStreak': 0}}}
        elif path == '/system/df':
            value = {'LayersSize': 1024, 'Images': [], 'Containers': [], 'Volumes': [], 'BuildCache': []}
        elif path == '/images/json': value = []
        else: value = {}
        self.reply(value)
    def reply(self, value):
        raw = json.dumps(value).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('API-Version', '1.41'); self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(raw)


def start():
    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
    Path('/mock-docker').mkdir(exist_ok=True)
    # The exact fixture Agent2 image runs as UID 1997/GID 1995.
    os.chown('/mock-docker', 0, 1995)
    os.chmod('/mock-docker', 0o750)
    server = Server('/mock-docker/docker.sock', Handler)
    os.chown('/mock-docker/docker.sock', 0, 1995)
    os.chmod('/mock-docker/docker.sock', 0o660)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
