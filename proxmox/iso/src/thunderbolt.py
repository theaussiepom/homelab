#!/usr/bin/python3
"""Authorise explicitly selected Thunderbolt identities on their selected host."""
import argparse
from pathlib import Path
import re
import subprocess
import time

THUNDERBOLT_PROFILE = None
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')


def validate_devices(devices):
    if type(devices) is not list or len(devices) > 2:
        raise ValueError('Explicit Thunderbolt device list required')
    for item in devices:
        if type(item) is not dict or set(item) != {'unique_id', 'mac'}:
            raise ValueError('Unexpected Thunderbolt device fields')
        if not isinstance(item['unique_id'], str) or not UUID.fullmatch(item['unique_id']):
            raise ValueError('Literal Thunderbolt unique ID required')
        if not isinstance(item['mac'], str) or not MAC.fullmatch(item['mac']):
            raise ValueError('Literal Thunderbolt Ethernet MAC required')
    if len({x['unique_id'] for x in devices}) != len(devices) or len({x['mac'] for x in devices}) != len(devices):
        raise ValueError('Duplicate Thunderbolt identity or MAC')


def wait_for_adapter(bus, unique_id, deadline):
    while True:
        matches = []
        for path in bus.glob('*'):
            try:
                if (path / 'unique_id').read_text().strip().lower() == unique_id:
                    matches.append(path)
            except FileNotFoundError:
                continue
        if len(matches) > 1:
            raise ValueError('Ambiguous approved Thunderbolt identity')
        if matches:
            return matches[0]
        if time.monotonic() >= deadline:
            raise ValueError('Approved Thunderbolt device is missing')
        time.sleep(0.2)


def wait_for_mac(net, mac, deadline):
    while True:
        matches = []
        for path in net.glob('*'):
            try:
                if (path / 'address').read_text().strip().lower() == mac:
                    matches.append(path)
            except FileNotFoundError:
                continue
        if len(matches) > 1:
            raise ValueError('Ambiguous Thunderbolt Ethernet MAC')
        if matches:
            return
        if time.monotonic() >= deadline:
            raise ValueError('Approved Thunderbolt Ethernet MAC did not appear')
        time.sleep(0.2)


def authorize(profile, root=Path('/'), timeout=20):
    if type(profile) is not dict or set(profile) != {'machine_uuid', 'devices'}:
        raise ValueError('Explicit host-bound Thunderbolt profile required')
    validate_devices(profile['devices'])
    if not profile['devices']:
        return
    if not isinstance(profile['machine_uuid'], str) or not UUID.fullmatch(profile['machine_uuid']):
        raise ValueError('Literal machine UUID required')
    if (root / 'sys/class/dmi/id/product_uuid').read_text().strip().lower() != profile['machine_uuid']:
        raise ValueError('wrong machine UUID')
    if not (root / 'sys/firmware/efi').is_dir():
        raise ValueError('UEFI installer boot required')
    bus = root / 'sys/bus/thunderbolt/devices'
    for item in profile['devices']:
        deadline = time.monotonic() + timeout
        adapter = wait_for_adapter(bus, item['unique_id'], deadline)
        domain = re.fullmatch(r'([0-9]+)-[0-9]+(?:\.[0-9]+)*', adapter.name)
        if domain is None:
            raise ValueError('Unexpected Thunderbolt device location')
        state = (adapter / 'authorized').read_text().strip()
        newly_authorized = False
        if state == '0':
            security = (bus / ('domain' + domain[1]) / 'security').read_text().strip()
            if security != 'user':
                raise ValueError('Unapproved Thunderbolt security mode; existing secure trust is required')
            # Re-read the identity immediately before the one permitted write.
            if (adapter / 'unique_id').read_text().strip().lower() != item['unique_id']:
                raise ValueError('Thunderbolt identity changed before authorisation')
            (adapter / 'authorized').write_text('1\n')
            newly_authorized = True
        elif state != '1':
            raise ValueError('Unexpected Thunderbolt authorisation state')
        try:
            if (adapter / 'authorized').read_text().strip() != '1':
                raise ValueError('Thunderbolt authorisation did not take effect')
            wait_for_mac(root / 'sys/class/net', item['mac'], deadline)
        except Exception as validation_error:
            if newly_authorized:
                try:
                    # Do not revoke a pre-existing grant or a replacement device.
                    if (adapter / 'unique_id').read_text().strip().lower() != item['unique_id']:
                        raise ValueError('Thunderbolt identity changed before revocation')
                    (adapter / 'authorized').write_text('0\n')
                    if (adapter / 'authorized').read_text().strip() != '0':
                        raise ValueError('Thunderbolt revocation did not take effect')
                except Exception as revoke_error:
                    raise RuntimeError('New Thunderbolt authorisation could not be revoked; '
                                       'access may remain: ' + str(revoke_error)) from validation_error
            raise


def settle_devices():
    subprocess.run(['udevadm', 'settle', '--timeout=20'], check=True, timeout=25)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    try:
        if args.manifest_sha256:
            # Verify the complete embedded payload before granting device access.
            from launch import validate_config, verify_media
            cfg = verify_media(Path('/cdrom'), args.manifest_sha256)
            validate_config(cfg)
            profile = {'machine_uuid': cfg['machine_uuid'], 'devices': cfg.get('thunderbolt_devices', [])}
        else:
            profile = THUNDERBOLT_PROFILE
        authorize(profile)
        if profile['devices']:
            settle_devices()
            print('Approved Thunderbolt adapter and Ethernet MAC verified.', flush=True)
    except Exception as error:
        if args.manifest_sha256:
            from launch import hold
            hold('HOMELAB_REFUSED: ' + str(error))
        raise


if __name__ == '__main__':
    main()
