"""Start the operator-selected latest image using invented state and no network.

No production paths, provider credentials, published ports or player commands.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid


def run(image):
    if image != 'ghcr.io/music-assistant/server:latest':
        raise ValueError('Use the requested Music Assistant latest image')
    name = 'music-synthetic-' + uuid.uuid4().hex[:10]
    state = {'server_id': '00000000000000000000000000000001', 'onboard_done': True,
             'providers': {}, 'players': {}, 'core': {
                 'webserver': {'domain': 'webserver', 'values': {'bind_ip': '127.0.0.1'}},
                 'streams': {'domain': 'streams', 'values': {'bind_ip': '127.0.0.1', 'publish_ip': '127.0.0.1'}}},
             'default_providers_setup': ['fanarttv', 'builtin', 'musicbrainz', 'theaudiodb',
                 'player_group', 'airplay', 'builtin_player', 'chromecast', 'lrclib',
                 'universal_player', 'sync_group', 'sendspin', 'coverartarchive', 'dlna', 'party']}
    seed = ("import json,os; from pathlib import Path; "
            "Path('/data/settings.json').write_text(" + repr(json.dumps(state)) + "); "
            "os.execv('/usr/local/bin/entrypoint.sh', ['/usr/local/bin/entrypoint.sh', '--data-dir', '/data', '--cache-dir', '/data/.cache'])")
    def docker(*args, **kwargs):
        return subprocess.run(['docker', *args], check=True, timeout=180, **kwargs)
    try:
        docker('run', '-d', '--name', name, '--platform', 'linux/amd64', '--pull', 'never',
               '--network', 'none', '--cpus', '2', '--memory', '1536m', '--pids-limit', '256',
               '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL',
               '--tmpfs', '/data:rw,nosuid,nodev,size=128m',
               '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=128m',
               '--entrypoint', 'python3', image, '-c', seed,
               stdout=subprocess.DEVNULL)
        probe = ("import importlib.metadata,json,urllib.request; "
                 "r=urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:8095/info',timeout=3); "
                 "assert r.status==200; assert isinstance(json.load(r),dict)")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            result = subprocess.run(['docker', 'exec', name, 'python3', '-c', probe],
                                    capture_output=True, timeout=10)
            if result.returncode == 0:
                identity = docker('inspect', '--format', '{{.Image}}', name, capture_output=True, text=True).stdout.strip()
                installed = docker('exec', name, 'python3', '-c', "import importlib.metadata; print(importlib.metadata.version('music-assistant'))", capture_output=True, text=True).stdout.strip()
                print(f'Tested image {identity}; installed version {installed}.')
                print('Synthetic latest Music Assistant local /info passed; '
                      'no LXC, provider, speaker or playback acceptance.')
                return
            if docker('inspect', '--format', '{{.State.Running}}', name,
                      capture_output=True, text=True).stdout.strip() != 'true':
                break
            time.sleep(1)
        # Only synthetic state exists in this container; bounded logs help diagnose it.
        logs = subprocess.run(['docker', 'logs', '--tail', '40', name], capture_output=True,
                              text=True, timeout=10)
        raise RuntimeError('Synthetic Music Assistant failed local readiness: ' + logs.stderr[-6000:])
    finally:
        subprocess.run(['docker', 'rm', '-f', '-v', name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stack', required=True, type=Path)
    args = parser.parse_args()
    cfg = json.loads(args.stack.read_text())
    run(cfg['services']['music_assistant']['image'])
