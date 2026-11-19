"""Send a small failure event to an optional, privately configured HA webhook."""
import ipaddress
import json
import re
import subprocess
import uuid

from private_io import encoded, private_directory, regular, require, write_new


def configuration(raw):
    """Accept only an HTTPS host, a pinned IPv4 address and a separate webhook ID."""
    value = json.loads(raw)
    require(isinstance(value, dict) and set(value) == {'host', 'address', 'webhook_id'},
            'Configure one private backup failure webhook')
    require(isinstance(value['host'], str)
            and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,63}', value['host'])
            and len(value['host']) <= 253 and '..' not in value['host'], 'Use a literal HTTPS hostname')
    require(isinstance(value['address'], str) and str(ipaddress.IPv4Address(value['address'])) == value['address'],
            'Pin the selected local IPv4 destination')
    require(isinstance(value['webhook_id'], str) and re.fullmatch(r'[0-9a-f]{32,64}', value['webhook_id']),
            'Use a dedicated random webhook identifier')
    return value


def install(path, raw):
    """Publish the optional secret separately from schedules and evidence."""
    value = encoded(configuration(raw))
    private_directory(path.parent.parent); private_directory(path.parent)
    try:
        existing = regular(path, private=True, limit=1024)
    except FileNotFoundError:
        write_new(path, value)
    else:
        require(existing == value, 'Rotate the installed backup webhook separately')


def send(schedule, diagnostic, *, execute=subprocess.run):
    """Post one notice over the pinned local path without exposing a secret in argv."""
    try:
        raw = regular(schedule.with_suffix('.webhook'), private=True, limit=1024)
    except FileNotFoundError:
        return 'not-configured'
    value = configuration(raw)
    url = 'https://' + value['host'] + '/api/webhook/' + value['webhook_id']
    payload = json.dumps({'event': 'homelab.backup.failed', 'event_id': uuid.uuid4().hex,
                          'group': schedule.stem.removeprefix('homelab-backup-'),
                          'stage': diagnostic['stage'], 'error_type': diagnostic['error_type']})
    config = 'url = ' + json.dumps(url) + '\ndata-binary = ' + json.dumps(payload) + '\n'
    result = execute(['/usr/bin/curl', '--disable', '--config', '-', '--noproxy', '*',
        '--proto', '=https', '--resolve', value['host'] + ':443:' + value['address'],
        '--header', 'Content-Type: application/json', '--silent', '--max-time', '8',
        '--output', '/dev/null', '--write-out', '%{http_code}'],
        input=config, text=True, capture_output=True, timeout=10, check=False,
        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    return 'submitted' if result.returncode == 0 and re.fullmatch(r'2[0-9]{2}', result.stdout) else 'failed'
