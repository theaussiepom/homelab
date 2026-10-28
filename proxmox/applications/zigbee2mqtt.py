#!/usr/bin/env python3
"""Check a prepared Zigbee capture without converting it or opening the radio."""
import argparse
import hashlib
import ipaddress
import json
import os
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


def directory_files(root, cfg):
    """Read bounded regular state files without opening the radio."""
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
    return files


def check_directory(root, cfg):
    """Keep the original exact-capture check for unadmitted data."""
    check_bytes(directory_files(root, cfg), cfg)


def fingerprint(value):
    """Bind canonical facts without storing network key material in a receipt."""
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def network_identity(files, cfg):
    """Allow live counters/settings while sealing key, PAN identities and channel."""
    import yaml
    reference=check_configuration(files['configuration.yaml'],cfg)
    advanced=yaml.safe_load(files['configuration.yaml'])['advanced']
    key=advanced['network_key']
    if reference:
        name,field=reference
        if name not in files or hashlib.sha256(files[name]).hexdigest()!=cfg['state_sha256'].get(name):
            raise ValueError('The admitted network-key file changed')
        try:key=yaml.safe_load(files[name])[field]
        except (yaml.YAMLError,KeyError,TypeError):raise ValueError('The admitted key reference is invalid') from None
        if not byte_array(key,16):raise ValueError('The admitted key reference is invalid')
    return fingerprint({'key':key,'pan':advanced['pan_id'],'extended_pan':advanced['ext_pan_id'],
                        'channel':advanced.get('channel')})


def private_receipt(path):
    """Read only a bounded regular receipt owned privately by this operator."""
    info=path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or
            stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=65536):
        raise ValueError('Preserve the private regular startup/restore receipt')
    return json.loads(path.read_text())


def check_start(root,cfg,receipt,restore_receipt,capture_sha256,admit=False):
    """Admit exact first-start bytes once; never rewind mutable live state later."""
    root=Path(root);receipt=Path(receipt);restore_receipt=Path(restore_receipt)
    if not re.fullmatch(r'[0-9a-f]{64}',capture_sha256):raise ValueError('Bind the selected restore capture')
    restored=private_receipt(restore_receipt)
    if restored!={'state':'complete','sha256':capture_sha256,'destination':str(root.parent)}:
        raise ValueError('The complete restore receipt must match this capture and data directory')
    files=directory_files(root,cfg)
    expected={'schema':1,'capture_sha256':capture_sha256,'selection_sha256':fingerprint(cfg),
              'network_identity_sha256':network_identity(files,cfg)}
    if receipt.is_symlink():raise ValueError('The startup admission receipt must not be a link')
    if receipt.exists():
        if private_receipt(receipt)!=expected:
            raise ValueError('Admitted network identity or selected capture facts changed; preserve live data and review')
        return False
    check_bytes(files,cfg)
    if not admit:return False
    # Written before Compose: a failed first attempt may already mutate state.
    # This admits initial bytes, not startup success; controller HOLD still applies.
    fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(expected,stream,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    directory=os.open(receipt.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--admission-receipt', type=Path)
    parser.add_argument('--restore-receipt', type=Path)
    parser.add_argument('--capture-sha256')
    parser.add_argument('--admit-first-start', action='store_true')
    args = parser.parse_args()
    cfg=json.loads(args.config.read_text());created=False
    if args.admission_receipt:
        if not args.restore_receipt or not args.capture_sha256:
            parser.error('Startup admission requires the selected restore receipt and capture SHA256')
        created=check_start(args.directory,cfg,args.admission_receipt,args.restore_receipt,
                            args.capture_sha256,args.admit_first_start)
    else:
        if args.admit_first_start:parser.error('Select the private startup admission receipt')
        check_directory(args.directory,cfg)
    print(json.dumps({'prepared_state': 'matched-or-admitted', 'configuration_changed': False,
                      'radio_opened': False,'admission_created':created}))


if __name__ == '__main__':
    main()
