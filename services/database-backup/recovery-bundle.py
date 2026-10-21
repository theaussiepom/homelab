#!/usr/bin/python3
"""Native backup post-hook. Protected artifacts only; no secret-bearing output."""
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time


def checked(argv, *, env=None, stdout=subprocess.PIPE, timeout=180):
    result = subprocess.run(argv, env=env, stdout=stdout, stderr=subprocess.PIPE,
                            timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"subcommand_failed_rc_{result.returncode}")
    return result.stdout


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def main():
    os.umask(0o077)
    route = sys.argv[1]
    hook = sys.argv[2:]
    if route not in {'nas', 's3'} or len(hook) != 11:
        raise RuntimeError('invalid_hook_context')
    if hook[0] != '0' or hook[1:4] != ['mysql', 'mariadb', 'phpmyadmin'] or hook[10] != '0':
        raise RuntimeError('upstream_dump_or_transfer_not_successful')
    destination = Path('/backup/database-recovery/configs')
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination, 0o700)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = f'recovery-configs_{route}_{stamp}.tar.zst'
    archive = destination / name
    partial = destination / (name + '.partial')
    receipt = {'observed_at': stamp, 'route': route, 'status': 'started',
               'primary_backup': hook[7], 'secret_values_emitted': False}
    receipt_path = destination / f'receipt-{route}-{stamp}.json'

    def save():
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
        os.chmod(receipt_path, 0o600)

    save()
    try:
        manifest_path = Path('/recovery-source/manifest.json')
        manifest = json.loads(manifest_path.read_text())
        with tempfile.TemporaryDirectory(prefix='db-recovery-', dir='/tmp') as scratch:
            scratch_path = Path(scratch)
            users = scratch_path / 'mariadb-users.sql'
            child_env = dict(os.environ)
            child_env['MYSQL_PWD'] = os.environ['DB01_PASS']
            with users.open('wb') as output:
                checked(['mariadb-dump', '--host=' + os.environ['DB01_HOST'],
                         '--user=' + os.environ['DB01_USER'],
                         '--system=users', '--replace', '--skip-lock-tables'],
                        env=child_env, stdout=output, timeout=120)
            if users.stat().st_size == 0:
                raise RuntimeError('empty_users_export')

            uncompressed = scratch_path / 'recovery.tar'
            inventory = []
            with tarfile.open(uncompressed, 'w') as tar:
                tar.add(users, arcname='mariadb/users-and-grants.sql', recursive=False)
                for item in manifest['sources']:
                    source = Path(item['container_path'])
                    if not source.exists() or source.is_symlink():
                        raise RuntimeError('recovery_source_missing_or_symlink')
                    members = sorted(source.rglob('*')) if source.is_dir() else [source]
                    for member in members:
                        if member.is_symlink():
                            raise RuntimeError('recovery_source_symlink_requires_review')
                        if not member.is_file():
                            continue
                        before = member.stat()
                        if before.st_size > 32 * 1024 * 1024:
                            raise RuntimeError('unexpected_large_config_source')
                        content = member.read_bytes()
                        after = member.stat()
                        if (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size):
                            raise RuntimeError('configuration_changed_during_capture')
                        relative = member.relative_to(source) if source.is_dir() else Path(member.name)
                        archive_name = str(Path('configuration') / item['label'] / relative)
                        tar_info = tarfile.TarInfo(archive_name)
                        tar_info.size = len(content)
                        tar_info.mode = 0o600
                        tar_info.mtime = int(before.st_mtime)
                        tar.addfile(tar_info, io.BytesIO(content))
                        inventory.append({'label': item['label'], 'relative': str(relative),
                                          'source_uid': before.st_uid, 'source_gid': before.st_gid,
                                          'source_mode': oct(before.st_mode & 0o7777),
                                          'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
                bundle_manifest = {'format': 1, 'captured_at': stamp,
                                   'restore_warning': 'Contains credentials and password hashes; keep protected',
                                   'configuration': inventory, 'source_mapping': manifest['sources'],
                                   'mariadb_users_sha256': digest(users),
                                   'deployment_metadata': manifest['deployment_metadata']}
                encoded = (json.dumps(bundle_manifest, indent=2) + '\n').encode()
                tar_info = tarfile.TarInfo('manifest.json')
                tar_info.mode = 0o600
                tar_info.size = len(encoded)
                tar.addfile(tar_info, io.BytesIO(encoded))
            with partial.open('xb') as output:
                checked(['zstd', '-q', '-3', '-c', str(uncompressed)], stdout=output)
            checked(['zstd', '-q', '-t', str(partial)])
            sha = digest(partial)
            partial.rename(archive)
            checksum = destination / (name + '.sha256')
            checksum.write_text(f'{sha}  {name}\n')
            receipt.update(archive=name, sha256=sha, bytes=archive.stat().st_size,
                           config_file_count=len(inventory), users_export_complete=True)
            if route == 's3':
                s3env = dict(os.environ)
                s3env.update(AWS_ACCESS_KEY_ID=os.environ['DB10_S3_KEY_ID'],
                             AWS_SECRET_ACCESS_KEY=os.environ['DB10_S3_KEY_SECRET'],
                             AWS_EC2_METADATA_DISABLED='true', AWS_PAGER='')
                endpoint = os.environ.get('DB10_S3_PROTOCOL', 'https') + '://' + os.environ['DB10_S3_HOST']
                bucket = os.environ['DB10_S3_BUCKET']
                prefix = os.environ['DB10_S3_PATH'].strip('/')
                if not prefix or prefix in {'.', '..'}:
                    raise RuntimeError('unsafe_remote_prefix')
                key = prefix + '/' + name
                aws = ['aws', '--endpoint-url', endpoint, '--cli-connect-timeout', '10', '--cli-read-timeout', '60']
                checked(aws + ['s3', 'cp', str(archive), f's3://{bucket}/{key}',
                               '--only-show-errors', '--metadata', 'sha256=' + sha], env=s3env, timeout=300)
                checked(aws + ['s3', 'cp', str(checksum), f's3://{bucket}/{key}.sha256',
                               '--only-show-errors'], env=s3env, timeout=120)
                head = json.loads(checked(aws + ['s3api', 'head-object', '--bucket', bucket,
                                               '--key', key, '--output', 'json'], env=s3env))
                if head['ContentLength'] != archive.stat().st_size or head.get('Metadata', {}).get('sha256') != sha:
                    raise RuntimeError('remote_object_metadata_mismatch')
                receipt['s3_object_metadata_verified'] = True
            receipt['status'] = 'complete'
            save()
            # This directory is exclusive to this hook. Failed .partial files stay
            # for investigation; only known completed artifacts age out.
            cutoff = time.time() - 7 * 86400
            for pattern in ['recovery-configs_*.tar.zst', 'recovery-configs_*.tar.zst.sha256', 'receipt-*.json']:
                for old in destination.glob(pattern):
                    if old.is_file() and old.stat().st_mtime < cutoff:
                        old.unlink()
            print('[INFO] Protected database recovery bundle completed: ' + route)
    except Exception as error:
        receipt.update(status='failed', error_class=type(error).__name__)
        save()
        print('[ERROR] Protected database recovery bundle failed; inspect protected receipt', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
