"""Check the exact Debian 13 Agent 2 binary/config without systemd or a target."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring

package = Path(sys.argv[1])
assert hashlib.sha256(package.read_bytes()).hexdigest() == 'd846b7f6b2eae0d5457decf6f0814df8169361d3335aa900d93e0eb838ab36e7'
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    subprocess.run(['dpkg-deb', '-x', str(package), str(root)], check=True)
    binary = root / 'usr/sbin/zabbix_agent2'
    version = subprocess.check_output([binary, '-V'], text=True)
    assert '7.0.32' in version
    Path('/etc/zabbix').mkdir(exist_ok=True)
    Path('/run/zabbix').mkdir(exist_ok=True)
    Path('/etc/zabbix/agent.psk').write_text('a' * 64 + '\n')
    config = root / 'agent.conf'
    config.write_text(monitoring.agent_config({'hostname': 'fixture-debian',
        'server_active': '198.18.30.50:10051', 'psk_identity': 'fixture-debian',
        'psk_path': '/etc/zabbix/agent.psk'}))
    subprocess.run([binary, '-T', '-c', config], check=True)
    # Docker has no syslog socket. Native systemd guests keep LogType=system.
    config.write_text(config.read_text().replace('LogType=system', 'LogType=console'))
    with (root / 'agent.log').open('w') as log:
        process = subprocess.Popen([binary, '-f', '-c', config], stdout=log, stderr=log)
        try:
            time.sleep(2)
            assert process.poll() is None, (root / 'agent.log').read_text()
            for name in ('tcp', 'tcp6'):
                for line in Path('/proc/net/' + name).read_text().splitlines()[1:]:
                    values = line.split()
                    assert not (values[1].split(':')[-1] == '2742' and values[3] == '0A'), 'Passive 10050 listener opened'
        finally:
            process.terminate(); process.wait(timeout=10)
    print('Exact Debian13 Agent2 7.0.32: valid active-only config, running process, no passive listener.')
