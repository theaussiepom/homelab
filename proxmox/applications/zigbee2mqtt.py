#!/usr/bin/env python3
"""Check a prepared Zigbee capture without converting it or opening the radio."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from urllib.parse import urlsplit


FILES = {'configuration.yaml', 'database.db', 'coordinator_backup.json'}
MAX_FILE_BYTES = 32 * 1024 * 1024


def byte_array(value, length):
    """Accept an exact byte sequence, excluding YAML booleans and floats."""
    return isinstance(value, list) and len(value) == length and all(
        type(item) is int and 0 <= item <= 255 for item in value)


def validate(cfg):
    """Bind one USB serial device, an MQTT identity and the prepared state."""
    required = {'serial_device', 'bind_address', 'frontend_port', 'adapter',
                'mqtt_server', 'mqtt_base_topic', 'state_sha256'}
    if not isinstance(cfg, dict) or set(cfg) != required:
        raise ValueError('Supply the closed Zigbee configuration and prepared state hashes')
    if not re.fullmatch(r'/dev/serial/by-id/usb-[A-Za-z0-9_-]+', str(cfg['serial_device'])):
        raise ValueError('Select one stable USB serial by-id path without wildcards')
    address = ipaddress.IPv4Address(cfg['bind_address'])
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
        raise ValueError('Select the guest backend listener address')
    if type(cfg['frontend_port']) is not int or not 1024 <= cfg['frontend_port'] <= 65535:
        raise ValueError('Select the existing frontend port explicitly')
    if not isinstance(cfg['adapter'], str) or not re.fullmatch(r'[a-z][a-z0-9_-]+', cfg['adapter']):
        raise ValueError('Select the preserved adapter driver explicitly')
    try:
        server = urlsplit(cfg['mqtt_server'])
        valid = (server.scheme in {'mqtt', 'mqtts'} and server.hostname and
                 not server.username and not server.password and not server.query and
                 not server.fragment and server.path in {'', '/'} and
                 (server.port is None or 1 <= server.port <= 65535))
    except (ValueError, TypeError):
        valid = False
    if not valid or any(c.isspace() for c in cfg['mqtt_server']):
        raise ValueError('Select an MQTT endpoint without embedding credentials')
    topic = cfg['mqtt_base_topic']
    if not isinstance(topic, str) or not topic or any(c in topic for c in '\x00\r\n+#'):
        raise ValueError('Preserve the existing literal MQTT base topic')
    hashes = cfg['state_sha256']
    if (not isinstance(hashes, dict) or not FILES <= set(hashes) or len(hashes) > 4 or any(
            not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*\.ya?ml', name) for name in set(hashes) - FILES) or any(
            not re.fullmatch(r'[0-9a-f]{64}', str(value)) for value in hashes.values())):
        raise ValueError('Hash the prepared configuration, device database and coordinator backup')
    return cfg


def check_configuration(data, cfg):
    """Require already prepared settings; CD must never generate a Zigbee network."""
    import yaml

    validate(cfg)
    try:
        value = yaml.safe_load(data)
        if not isinstance(value, dict):
            raise ValueError
        if (value['serial']['port'] != '/dev/ttyACM0' or
                value['serial']['adapter'] != cfg['adapter'] or
                value['mqtt']['server'] != cfg['mqtt_server'] or
                value['mqtt']['base_topic'] != cfg['mqtt_base_topic']):
            raise ValueError
        frontend = value['frontend']
        if (frontend.get('enabled') is not True or frontend.get('port') != cfg['frontend_port'] or
                frontend.get('host', '0.0.0.0') != '0.0.0.0'):
            raise ValueError
        identity = value['advanced']
        network_key = identity['network_key']
        # Zigbee2MQTT supports quoted file references for network_key only.
        # Resolve only from the separately hashed capture, never arbitrary disk.
        key_reference = isinstance(network_key, str) and re.fullmatch(r'!([A-Za-z0-9_][A-Za-z0-9_.-]*) ([^\s]+)', network_key)
        if not byte_array(network_key, 16) and not key_reference:
            raise ValueError
        pan_id = identity['pan_id']
        if type(pan_id) is not int or not 1 <= pan_id <= 65534 or not byte_array(identity['ext_pan_id'], 8):
            raise ValueError
        if key_reference:
            filename, key = key_reference.groups()
            if not filename.endswith(('.yaml', '.yml')):
                filename += '.yaml'
            return filename, key
    except (yaml.YAMLError, KeyError, TypeError, AttributeError, ValueError):
        raise ValueError('Prepare and review the preserved Zigbee settings outside CD; no conversion or new network is allowed') from None


def check_bytes(files, cfg):
    """Bind all required bytes and validate any captured network-key reference."""
    validate(cfg)
    if set(files) != set(cfg['state_sha256']):
        raise ValueError('The prepared Zigbee state is incomplete')
    for name, data in files.items():
        if not data or len(data) > MAX_FILE_BYTES or hashlib.sha256(data).hexdigest() != cfg['state_sha256'][name]:
            raise ValueError('Prepared Zigbee state does not match its reviewed hashes')
    reference = check_configuration(files['configuration.yaml'], cfg)
    expected = FILES | ({reference[0]} if reference else set())
    if set(files) != expected:
        raise ValueError('Capture and hash exactly the required files and any referenced network-key file')
    if reference:
        import yaml
        try:
            if not byte_array(yaml.safe_load(files[reference[0]])[reference[1]], 16):
                raise ValueError
        except (yaml.YAMLError, KeyError, TypeError, ValueError):
            raise ValueError('The captured network-key reference must contain a preserved 16-byte key') from None


def check_archive(path, cfg):
    """Read required members only, before the existing generic restore can run."""
    validate(cfg)
    files, names = {}, set()
    with tarfile.open(path) as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or '..' in name.parts or not name.parts or
                    name.parts[0] != 'zigbee2mqtt' or str(name) in names or
                    not (member.isdir() or member.isfile())):
                raise ValueError('Use one Zigbee data tree without links, duplicate paths or other services')
            names.add(str(name))
            if str(name) in {'zigbee2mqtt/' + item for item in cfg['state_sha256']}:
                if not member.isfile() or not 0 < member.size <= MAX_FILE_BYTES:
                    raise ValueError('Required Zigbee state must be bounded regular files')
                files[name.name] = archive.extractfile(member).read(MAX_FILE_BYTES + 1)
    check_bytes(files, cfg)


def check_directory(root, cfg):
    """Inspect restored files read-only, before Compose may start the radio."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Use the restored Zigbee directory')
    files = {}
    validate(cfg)
    for name in cfg['state_sha256']:
        path = root / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_FILE_BYTES:
            raise ValueError('Required Zigbee state must be bounded regular files')
        files[name] = path.read_bytes()
    check_bytes(files, cfg)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    check_directory(args.directory, json.loads(args.config.read_text()))
    print(json.dumps({'prepared_state': 'matched', 'configuration_changed': False,
                      'radio_opened': False}))


if __name__ == '__main__':
    main()
