"""Exercise real Ansible filesystem changes inside a disposable tools container.

Admission facts and the namespace readback are synthetic. systemctl and networkd
wait are recording stubs, so this proves task ordering, hash refusal and exact
file effects, not native LXC identity, network readiness or service startup.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PLAY = ROOT / 'ansible/network-update.yml'
GATE = Path('/etc/systemd/system/homelab-network-ready.service')
IDENTITY = Path('/etc/homelab-application.json')
HELPER = Path('/usr/lib/systemd/systemd-networkd-wait-online')
UNITS = {'identity': 'docker.service', 'db-tools': 'docker.service', 'postgresql': 'postgresql@.service',
         'mariadb': 'mariadb.service', 'influxdb': 'influxdb.service'}
CASES = ('identity', 'db-tools', 'postgresql', 'mariadb', 'influxdb', 'gate-drift', 'dependency-missing',
         'wrong-guest', 'privileged', 'missing-ipv4', 'wait-failed', 'process-changed')
STUB = '''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
path=Path(os.environ['NETWORK_UPDATE_FIXTURE_LOG'])
old=[json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
kind='wait' if Path(sys.argv[0]).name=='systemd-networkd-wait-online' else 'systemctl'
with path.open('a') as stream: stream.write(json.dumps([kind,*args])+'\\n')
if kind=='wait':
    assert args==['--ipv4','--timeout=30','--interface=eth0:routable','--interface=eth1:routable','--interface=eth2:routable'],args
    sys.exit(1 if os.environ.get('NETWORK_UPDATE_FIXTURE_FAILURE')=='wait-failed' else 0)
if args==['daemon-reload']: sys.exit(0)
if args[:1]==['show'] and any('MainPID' in arg for arg in args):
    count=sum(row[0]=='systemctl' and any('MainPID' in arg for arg in row) for row in old)
    pid=456 if count and os.environ.get('NETWORK_UPDATE_FIXTURE_FAILURE')=='process-changed' else 123
    print('MainPID='+str(pid)+'\\nActiveEnterTimestamp=Wed 2026-10-28 01:00:00 UTC\\nActiveEnterTimestampMonotonic=123000\\nActiveState=active')
    sys.exit(0)
if args[:1]==['show'] and args[-1:] == ['--value'] and args[-2] in ('--property=Requires','--property=After'):
    print('homelab-network-ready.service'); sys.exit(0)
print('Unexpected fixture service action: '+repr(args),file=sys.stderr); sys.exit(90)
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(path):
    info = path.stat()
    return path.read_bytes(), info.st_ino, info.st_mtime_ns, info.st_uid, info.st_gid, info.st_mode


def put(path, contents, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)
    path.chmod(mode)


def run_case(case, root):
    kind = case if case in UNITS else 'identity'
    unit = UNITS[kind]
    dropin = Path('/etc/systemd/system') / (unit + '.d') / 'homelab-network-ready.conf'
    unrelated = dropin.with_name('unrelated-fixture.conf')
    vendor = Path('/etc/systemd/system') / unit
    put(GATE, '[Service]\nType=oneshot\nExecStart=/usr/lib/systemd/systemd-networkd-wait-online --ipv4 --timeout=30 --interface=eth0:routable --interface=eth1:routable\nRemainAfterExit=yes\n')
    put(dropin, '[Unit]\nRequires=homelab-network-ready.service\nAfter=homelab-network-ready.service\n')
    dropin.parent.chmod(0o755)
    put(unrelated, '# preserve this separately owned override\n')
    put(vendor, '[Service]\nExecStart=/fixture/vendor-service\n')
    vmid = {'identity': 211, 'db-tools': 202, 'postgresql': 208, 'mariadb': 206, 'influxdb': 204}[kind]
    app = {'kind': kind, 'vmid': vmid, 'hostname': 'fixture', 'address': '192.0.2.20', 'mac': '02:00:00:00:00:20'}
    put(IDENTITY, json.dumps(dict(app, vmid=900) if case == 'wrong-guest' else app), 0o600)
    variables = {'app': app, 'network_ready_interfaces': ['eth0', 'eth1', 'eth2'],
        'network_ready_gate_sha256': sha(GATE), 'network_ready_dependency_sha256': sha(dropin),
        'postgresql_cluster_unit': 'postgresql@16-main.service',
        'network_update_uid_map': {'content': base64.b64encode(
            b'0 0 4294967295\n' if case == 'privileged' else b'0 100000 65536\n').decode()},
        'ansible_facts': {'hostname': 'fixture', 'all_ipv4_addresses': ['192.0.2.20', '198.51.100.20', '203.0.113.20'],
            'interfaces': ['eth0', 'eth1', 'eth2'], 'virtualization_type': 'lxc', 'distribution': 'Debian',
            **{f'eth{i}': {'macaddress': f'02:00:00:00:00:{20+i}', 'active': True,
                          'ipv4': {'address': address}} for i, address in enumerate(
                              ['192.0.2.20', '198.51.100.20', '203.0.113.20'])}}}
    if case == 'gate-drift': put(GATE, 'unreviewed change must survive\n')
    if case == 'dependency-missing': dropin.unlink()
    if case == 'missing-ipv4': variables['ansible_facts']['eth2'].pop('ipv4')
    before = {path: snapshot(path) for path in (GATE, unrelated, vendor) + ((dropin,) if dropin.exists() else ())}
    case_root = root / case; case_root.mkdir()
    inventory = case_root / 'inventory.json'
    inventory.write_text(json.dumps({'application': {'hosts': {'fixture': {'ansible_connection': 'local'}}}}))
    values = case_root / 'vars.json'; values.write_text(json.dumps(variables))
    log = case_root / 'commands.jsonl'
    environment = dict(os.environ, PATH=str(root / 'bin') + ':' + os.environ['PATH'], HOME='/tmp',
                       NETWORK_UPDATE_FIXTURE_LOG=str(log), NETWORK_UPDATE_FIXTURE_FAILURE=case,
                       ANSIBLE_LOCAL_TEMP=str(root / 'ansible-local'))
    result = subprocess.run(['ansible-playbook', '-i', str(inventory), str(PLAY), '--extra-vars', '@' + str(values)],
                            env=environment, capture_output=True, text=True, timeout=150, check=False)
    commands = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    success = case in UNITS
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    assert snapshot(unrelated) == before[unrelated] and snapshot(vendor) == before[vendor]
    assert all(not set(command) & {'start', 'restart', 'stop', 'reload', 'enable', 'disable'} for command in commands), commands
    if success or case == 'process-changed':
        assert '--interface=eth2:routable' in GATE.read_text()
        assert [command for command in commands if command[:2] == ['systemctl', 'daemon-reload']] == [['systemctl', 'daemon-reload']]
        assert sum(command[0] == 'wait' for command in commands) == 1
        if case == 'process-changed':
            assert 'Verify the application process and activation timestamps are unchanged' in result.stdout
    else:
        for path, content in before.items(): assert snapshot(path) == content, (case, path)
        assert not any('daemon-reload' in command for command in commands), commands
        if case == 'wait-failed': assert sum(command[0] == 'wait' for command in commands) == 1
        else: assert commands == [], commands
    print('Actual Ansible network-update fixture:', case, 'passed', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=CASES)
    args = parser.parse_args()
    assert Path('/.dockerenv').exists() and os.geteuid() == 0, 'Use the disposable tools container only'
    paths = {GATE, IDENTITY, HELPER}
    for unit in set(UNITS.values()):
        directory = Path('/etc/systemd/system') / (unit + '.d')
        paths.update({directory / 'homelab-network-ready.conf', directory / 'unrelated-fixture.conf',
                      Path('/etc/systemd/system') / unit})
    originals = {path: (path.read_bytes(), path.stat().st_mode & 0o777) for path in paths if path.exists()}
    try:
        with tempfile.TemporaryDirectory(prefix='homelab-network-update-fixture-') as temporary:
            root = Path(temporary); (root / 'bin').mkdir()
            put(root / 'bin/systemctl', STUB, 0o755)
            put(HELPER, STUB, 0o755)
            for case in ([args.case] if args.case else CASES): run_case(case, root)
    finally:
        for path in paths:
            if path in originals:
                value, mode = originals[path]; path.write_bytes(value); path.chmod(mode)
            elif path.exists(): path.unlink()
    print('Filesystem/task-order proof only; native services and network readiness were not exercised.')


if __name__ == '__main__':
    main()
