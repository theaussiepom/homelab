#!/usr/bin/env python3
"""Bind synthetic installer jobs to one immutable same-run image and VM receipt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat

CASES = {
    'matching-check': None,
    'wrong-machine': 'wrong machine UUID',
    'missing-member': 'missing, ambiguous or conflicting disk identity: LAB-NEW-B',
    'ambiguous-member': 'missing, ambiguous or conflicting disk identity: LAB-NEW-A',
    'cancel-install': 'installation was not explicitly confirmed',
    'profile-wrong-machine': 'wrong machine UUID',
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024**2), b''):
            result.update(block)
    return result.hexdigest()


def regular(path, limit=1024**2):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit,
            'Expected a bounded regular CI input: ' + path.name)
    return path


def binding(profile):
    require(profile in {'fixture', 'custom'}, 'Unknown synthetic CI profile')
    run, head, repo = (os.environ.get(key, '') for key in
                       ('GITHUB_RUN_ID', 'GITHUB_SHA', 'GITHUB_REPOSITORY'))
    require(re.fullmatch('[1-9][0-9]*', run) and re.fullmatch('[0-9a-f]{40}', head)
            and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo),
            'Require the identified same-run source context')
    return {'profile': profile, 'run_id': run, 'source_sha': head, 'repository': repo}


def layout(root, profile):
    environment = 'fixture' if profile == 'fixture' else 'production'
    folder = root / ('build/single-usb-' + environment)
    return folder, folder / ('Proxmox-9.2-1-' + environment + '.iso')


def custom_inputs(root):
    """Exercise normal config validation with invented values, never site inputs."""
    local = root / '.local'
    local.mkdir(mode=0o700, exist_ok=True)
    require(not local.is_symlink() and not any(local.iterdir()),
            'CI custom inputs require a fresh empty .local directory')
    hardware = json.loads((root / 'config/fixture-hardware.json').read_text())
    for field in ('schema', 'environment', 'runtime_sha256'):
        hardware.pop(field)
    hardware['machine_uuid'] = '44444444-4444-4444-8444-444444444444'
    for index, disk in enumerate(hardware['disk_members'] + hardware['protected_disks']):
        disk['disk_serial'] = 'CI-' + str(index)
        disk['disk_by_id'] = '/dev/disk/by-id/nvme-CI-' + str(index) + '_1'
    site = json.loads((root / 'config/fixture-site.json').read_text())
    site.update(fqdn='pve.ci.example.org', mailto='operator@ci.example.org')
    approval = {'approved_by': 'CI invented-input build only',
                'scope': 'build-and-prepare-removable-media-only',
                'production_boot_or_erase_authorized': False}
    files = {name: (json.dumps(value, indent=2) + '\n').encode() for name, value in
             {'hardware.json': hardware, 'site.json': site, 'media-approval.json': approval}.items()}
    files['root-ssh.pub'] = (root / 'config/fixture-ssh.pub').read_bytes()
    files['root-recovery-password.hash'] = ('$6$synthetic$' + 'A' * 86 + '\n').encode()
    for name, data in files.items():
        with (local / name).open('xb') as stream:
            os.chmod(stream.fileno(), 0o600)
            stream.write(data)


def stage(root, profile, packet):
    identity = binding(profile)
    folder, image = layout(root, profile)
    receipt = json.loads(regular(folder / 'build-receipt.json').read_text())
    regular(image, 8 * 1024**3)
    image_hash = digest(image)
    require(receipt.get('schema') == 'homelab-single-usb-build-v1'
            and receipt.get('sha256') == image_hash and receipt.get('bytes') == image.stat().st_size
            and receipt.get('environment') == ('synthetic' if profile == 'fixture' else 'production')
            and receipt.get('embedded_payload_readback') == 'passed'
            and receipt.get('native_answer_validation') == 'passed static nonresolving placeholders'
            and receipt.get('production_boot_or_erase_authorized') is False,
            'Build receipt does not qualify this synthetic image')
    files = {'image.iso': image, 'build-receipt.json': folder / 'build-receipt.json'}
    if profile == 'custom':
        config = regular(folder / 'readback/homelab/config.json')
        require(json.loads(config.read_text()).get('machine_uuid') == '44444444-4444-4444-8444-444444444444',
                'Expected invented custom machine identity')
        metadata = json.loads(regular(root / 'evidence/final-metadata-verification.json').read_text())
        require(metadata.get('all_other_vendor_metadata_preserved') is True
                and metadata.get('modified_squashfs_sha256') == receipt.get('modified_squashfs_sha256'),
                'Custom image metadata verification is missing or stale')
        files['config.json'] = config
    packet.mkdir(mode=0o700)
    for name, source in files.items():
        shutil.copyfile(source, packet / name)
    manifest = dict(identity, schema='homelab-synthetic-ci-image-v1',
                    files={name: digest(packet / name) for name in files})
    (packet / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')
    print('image_sha256=' + image_hash)
    print('manifest_sha256=' + digest(packet / 'manifest.json'))


def restore(root, profile, packet, expected_manifest, expected_image):
    identity = binding(profile)
    require(re.fullmatch('[0-9a-f]{64}', expected_manifest)
            and re.fullmatch('[0-9a-f]{64}', expected_image), 'Missing immutable build-job digests')
    require(packet.is_dir() and not packet.is_symlink(), 'Expected an image packet directory')
    manifest_path = regular(packet / 'manifest.json')
    require(digest(manifest_path) == expected_manifest, 'Changed CI image manifest')
    manifest = json.loads(manifest_path.read_text())
    files = {'image.iso', 'build-receipt.json'} | ({'config.json'} if profile == 'custom' else set())
    require(manifest == dict(identity, schema='homelab-synthetic-ci-image-v1', files=manifest.get('files'))
            and isinstance(manifest.get('files'), dict) and set(manifest['files']) == files
            and {path.name for path in packet.iterdir()} == files | {'manifest.json'},
            'Foreign run, source, profile or unexpected packet files')
    for name in files:
        path = regular(packet / name, 8 * 1024**3 if name == 'image.iso' else 1024**2)
        require(digest(path) == manifest['files'][name], 'Changed CI image packet file: ' + name)
    require(manifest['files']['image.iso'] == expected_image, 'Changed build-job image identity')
    folder, image = layout(root, profile)
    require(not folder.exists() and not folder.is_symlink()
            and not (root / 'build/vm-tests').exists(), 'Refuse existing build or VM evidence')
    folder.mkdir(parents=True, mode=0o700)
    shutil.copyfile(packet / 'image.iso', image)
    shutil.copyfile(packet / 'build-receipt.json', folder / 'build-receipt.json')
    if profile == 'custom':
        readback = folder / 'readback/homelab'
        readback.mkdir(parents=True)
        shutil.copyfile(packet / 'config.json', readback / 'config.json')


def verify(root, case, expected_image):
    require(case in CASES, 'Unknown installer scenario')
    profile = 'custom' if case == 'profile-wrong-machine' else 'fixture'
    binding(profile)
    _, image = layout(root, profile)
    require(re.fullmatch('[0-9a-f]{64}', expected_image) and digest(regular(image, 8 * 1024**3)) == expected_image,
            'Image changed before or during the VM case')
    receipts = list((root / 'build/vm-tests').glob('*/receipt.json'))
    require(len(receipts) == 1 and receipts[0].parent.name.startswith(case + '-'),
            'Require exactly one receipt for the selected scenario')
    record = json.loads(regular(receipts[0]).read_text())
    expected = 'checked-and-stopped' if case == 'matching-check' else 'refused'
    reason = CASES[case]
    writes = record.get('disk_write_bytes')
    require(record.get('case') == case and record.get('result') == record.get('expected') == expected
            and record.get('image_sha256') == expected_image
            and record.get('production_host_accessed') is False
            and type(record.get('local_vm_exit')) is int and record['local_vm_exit'] == 0
            and record.get('no_target_disk_writes') is True and record.get('reason_matches') is True
            and isinstance(writes, dict) and set(writes) == {'disk' + str(i) for i in range(4 if case == 'ambiguous-member' else 3)}
            and all(type(value) is int and value == 0 for value in writes.values())
            and (reason is None or (record.get('expected_refusal_reason') == reason
                 and isinstance(record.get('refusal_reason'), str) and reason in record['refusal_reason'])),
            'Scenario did not establish the expected refusal/stop, exact image and zero disk writes')
    print('Passed synthetic installer scenario: ' + case + '; image ' + expected_image)


def evidence(root):
    """Print only bounded build/VM diagnostics, never disks or local config."""
    for pattern in ('evidence/source-tests*.json', 'evidence/final-metadata-verification.json',
                    'evidence/latest-build-command-failure.json', 'build/single-usb-*/build-receipt.json',
                    'build/single-usb-*/native-validation.txt', 'build/single-usb-*/boot-record.txt',
                    'build/vm-tests/*/receipt.json', 'build/vm-tests/*/argv.json', 'build/vm-tests/*/console.log'):
        for path in sorted(root.glob(pattern)):
            regular(path, 16 * 1024**2)
            print('Evidence: ' + str(path.relative_to(root)))
            with path.open('rb') as stream:
                print(stream.read(256 * 1024).decode(errors='replace'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['custom-inputs', 'stage', 'restore', 'verify', 'evidence'])
    parser.add_argument('--root', type=Path, default=Path('proxmox/iso'))
    parser.add_argument('--profile', choices=['fixture', 'custom'])
    parser.add_argument('--packet', type=Path)
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--manifest-sha', default='')
    parser.add_argument('--image-sha', default='')
    args = parser.parse_args()
    if args.action == 'custom-inputs':
        custom_inputs(args.root)
    elif args.action == 'stage':
        stage(args.root, args.profile, args.packet)
    elif args.action == 'restore':
        restore(args.root, args.profile, args.packet, args.manifest_sha, args.image_sha)
    elif args.action == 'verify':
        verify(args.root, args.case, args.image_sha)
    else:
        evidence(args.root)


if __name__ == '__main__':
    main()
