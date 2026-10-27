"""Run actual database configuration tasks without backups in disposable Docker.

This checks Ansible staging and data preservation, not systemd/LXC startup.
"""
import json
import configparser
import os
from pathlib import Path
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


require(Path('/.dockerenv').exists() and os.geteuid() == 0,
        'Run only as root inside a disposable Docker container')
TASKS = Path(__file__).resolve().parents[1] / 'ansible/tasks/database.yml'

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    config = root / 'server.conf'
    config.write_text('# synthetic server configuration\n')
    data = root / 'existing-database'
    data.write_bytes(b'existing rows must survive database CD\n')
    before = data.stat()
    playbook = root / 'server.yml'
    playbook.write_text(json.dumps([{'hosts': 'all', 'connection': 'local', 'gather_facts': False,
        'tasks': [{'ansible.builtin.import_tasks': str(TASKS)}]}]))
    variables = root / 'variables.json'
    command = ['ansible-playbook', '-i', 'localhost,', str(playbook), '--extra-vars', '@' + str(variables)]
    for kind, directory in [('mariadb', 'mysql'), ('postgresql', 'postgresql'), ('influxdb', 'influxdb')]:
        destination = Path('/etc') / directory / 'homelab-cd-fixture.conf'
        require(not destination.exists(), 'Use a fresh fixture container')
        destination.parent.mkdir(mode=0o700, exist_ok=True)
        settings = {'network_ready_interfaces':['eth0','eth1'], 'app': {'kind': kind, 'start_services': False, 'database': {
            'user': 'root', 'group': 'root', 'version_pattern': 'synthetic-native-1',
            'version_command': ['python3', '-c', 'print("synthetic-native-1")'],
            'config_files': [{'source': str(config), 'destination': str(destination)}]}}}
        variables.write_text(json.dumps(settings))
        for attempt in range(2):
            result = subprocess.run(command, capture_output=True, text=True)
            require(result.returncode == 0, result.stdout + result.stderr)
            if attempt:
                require('changed=0' in result.stdout, 'Repeated server staging must make no changes')
        require(destination.read_bytes() == config.read_bytes(), 'Server configuration differs')
        require(destination.stat().st_mode & 0o777 == 0o600, 'Server configuration must stay private')
        gate=configparser.ConfigParser(interpolation=None)
        gate.read('/etc/systemd/system/homelab-network-ready.service')
        require('network-online.target' not in gate['Unit']['After'].split(),
                'The bounded interface wait must not start after a separate network-online wait')
        require(gate['Service']['RemainAfterExit']=='yes', 'Readiness gate must retain successful startup state')
        require(gate['Service']['ExecStart'].split()==[
            '/usr/lib/systemd/systemd-networkd-wait-online','--ipv4','--timeout=30',
            '--interface=eth0:routable','--interface=eth1:routable'],
            'Management readiness cannot substitute for the required backend interface')
        require(data.read_bytes() == b'existing rows must survive database CD\n'
                and (data.stat().st_ino, data.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns),
                'Server staging changed existing data')
        # A stale restore configuration must fail before changing server config.
        settings['app']['database']['capture'] = {'path': '/missing/old-backup.sql'}
        variables.write_text(json.dumps(settings))
        config.write_text('# changed input must not reach the refused target\n')
        original = destination.read_bytes()
        result = subprocess.run(command, capture_output=True, text=True)
        require(result.returncode != 0, 'Database CD must refuse restore inputs')
        require(destination.read_bytes() == original, 'Refused restore inputs changed server config')
    print('Database server staging passed for all three engines: no backup needed, no-change repeat, data preserved, restore inputs refused; service startup not exercised')
