"""Reject an unreviewed existing routing unit before startup files change."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

assert Path('/.dockerenv').exists() and os.geteuid() == 0
unit = Path('/etc/systemd/system/homelab-ingress-routing.service')
dropin = unit.with_name(unit.name + '.d') / 'homelab-network-ready.conf'
assert not unit.exists() and not dropin.exists(), 'Use a fresh disposable fixture'
unit.write_text('unreviewed fixture routing unit\n')
before = (unit.read_bytes(), unit.stat().st_ino, unit.stat().st_mtime_ns)
gate = Path('/etc/systemd/system/homelab-network-ready.service')
with tempfile.TemporaryDirectory() as tmp:
    inventory = Path(tmp) / 'inventory.json'
    inventory.write_text(json.dumps({'application': {'hosts': {'fixture': {'ansible_connection': 'local'}}}}))
    variables = Path(tmp) / 'variables.json'
    variables.write_text(json.dumps({'app': {'kind': 'ingress', 'vmid': 212, 'hostname': 'fixture',
        'address': '192.0.2.33', 'mac': '02:00:00:00:00:33'},
        'network_ready_gate_sha256': hashlib.sha256(gate.read_bytes()).hexdigest(),
        'routing_unit_sha256': '0' * 64,
        'ansible_facts': {'hostname': 'fixture', 'all_ipv4_addresses': ['192.0.2.33'],
            'interfaces': ['eth0'], 'eth0': {'macaddress': '02:00:00:00:00:33'},
            'virtualization_type': 'lxc', 'distribution': 'Debian'}}))
    play = Path(__file__).resolve().parents[1] / 'ansible/ingress-network-startup.yml'
    result = subprocess.run(['ansible-playbook', '-i', str(inventory), str(play),
        '--extra-vars', '@' + str(variables)], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'Match the reviewed existing units before changing startup ordering' in result.stdout, result.stdout + result.stderr
    assert 'Prepare the routing service override directory' not in result.stdout
    assert not dropin.exists() and (unit.read_bytes(), unit.stat().st_ino, unit.stat().st_mtime_ns) == before
unit.unlink()
print('Actual Ansible ingress unit-hash rejection preserved startup files; no native service was exercised')
