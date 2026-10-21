#!/usr/bin/env python3
"""Later-run helper INSIDE the backup container; S3 reads, protected local writes."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def utc(value):
    parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise RuntimeError('not_before_requires_explicit_timezone')
    return parsed.astimezone(datetime.timezone.utc)


def private_json(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    os.chmod(path, 0o600)


def digest(path, algorithm):
    h = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


class Destination:
    def __init__(self, job):
        def field(name, fallback=None):
            return os.environ.get(f'DB{job}_{name}', os.environ.get(f'DEFAULT_{name}', fallback))
        # Retrieval always verifies HTTPS certificates, independently of the
        # native job's legacy skip-verification setting; never inherit it.
        if field('S3_PROTOCOL', 'https') != 'https':
            raise RuntimeError('https_s3_endpoint_required')
        self.bucket = field('S3_BUCKET')
        self.prefix = field('S3_PATH', '').strip('/')
        if not self.bucket or not self.prefix or any(p in {'', '.', '..'} for p in self.prefix.split('/')):
            raise RuntimeError('unexpected_s3_destination_configuration')
        self.env = dict(os.environ, AWS_ACCESS_KEY_ID=field('S3_KEY_ID'),
                        AWS_SECRET_ACCESS_KEY=field('S3_KEY_SECRET'),
                        AWS_EC2_METADATA_DISABLED='true', AWS_PAGER='')
        self.argv = ['aws', '--endpoint-url', 'https://' + field('S3_HOST'),
                     '--cli-connect-timeout','10','--cli-read-timeout','60','--output','json']
        self.checksum = field('CHECKSUM', 'MD5').lower()

    def call(self, args, timeout=180):
        result = subprocess.run(self.argv + ['s3api', *args], env=self.env,
                                capture_output=True, timeout=timeout)
        if result.returncode:
            # AWS diagnostics may reveal endpoints; retain no raw output.
            raise RuntimeError('s3_read_failed')
        return json.loads(result.stdout or b'{}')

    def objects(self):
        result = self.call(['list-objects-v2','--bucket',self.bucket,
                            '--prefix',self.prefix + '/'])
        return [obj for obj in result.get('Contents', [])
                if obj['Key'].rsplit('/',1)[0] == self.prefix]

    def download(self, key, target, max_bytes):
        head = self.call(['head-object','--bucket',self.bucket,'--key',key])
        size = head['ContentLength']
        if not 0 < size <= max_bytes:
            raise RuntimeError('object_size_outside_reviewed_bounds')
        if shutil.disk_usage(target.parent).free < size + 1024**3:
            raise RuntimeError('insufficient_destination_capacity')
        if target.exists() or target.is_symlink():
            raise RuntimeError('download_destination_already_exists')
        result = self.call(['get-object','--bucket',self.bucket,'--key',key,
                            '--if-match',head['ETag'],str(target)],timeout=1800)
        os.chmod(target,0o600)
        if target.stat().st_size != size or result.get('ETag') != head['ETag']:
            raise RuntimeError('download_length_or_etag_mismatch')
        return head


def select(objects, pattern, not_before):
    candidates = [o for o in objects if re.fullmatch(pattern, o['Key'].rsplit('/',1)[-1])
                  and utc(o['LastModified']) >= not_before]
    if not candidates:
        raise RuntimeError('no_new_matching_s3_archive')
    return max(candidates,key=lambda obj:(utc(obj['LastModified']),obj['Key']))


def verify(destination, selected, output, local_name, algorithm, max_bytes, require_metadata=False):
    key = selected['Key']
    name = key.rsplit('/',1)[-1]
    if algorithm not in {'md5','sha1','sha256','sha512'}:
        raise RuntimeError('unsupported_native_checksum_algorithm')
    sidecar = output / (local_name + '.' + algorithm)
    archive = output / (local_name + '.partial')
    destination.download(key + '.' + algorithm, sidecar, 65536)
    checksum_text = sidecar.read_text().strip()
    match = re.fullmatch(r'([0-9a-fA-F]+)(?:[ \t]+\*?(.+))?',checksum_text)
    if not match or len(match[1]) != hashlib.new(algorithm).digest_size * 2:
        raise RuntimeError('unrecognized_checksum_sidecar')
    if match[2] and Path(match[2]).name != name:
        raise RuntimeError('checksum_sidecar_filename_mismatch')
    head = destination.download(key, archive, max_bytes)
    if digest(archive,algorithm) != match[1].lower():
        raise RuntimeError('download_checksum_mismatch')
    sha256 = digest(archive,'sha256')
    if require_metadata and head.get('Metadata',{}).get('sha256') != sha256:
        raise RuntimeError('download_sha256_metadata_mismatch')
    checked = subprocess.run(['zstd','-q','-t',str(archive)],capture_output=True,timeout=1800)
    if checked.returncode:
        raise RuntimeError('download_compression_integrity_failed')
    final = output / local_name
    archive.rename(final)
    verified_checksum = output / (local_name + '.verified.sha256')
    with verified_checksum.open('x') as stream:
        stream.write(sha256 + '  ' + local_name + '\n')
    return {'path':str(final),'remote_archive_basename':name,'bytes':final.stat().st_size,
            'sha256':sha256,'native_checksum_algorithm':algorithm,'native_checksum_verified':True,
            'compression_verified':True,'sha256_metadata_verified':require_metadata,
            'tls_certificate_verification':True,
            'verified_sha256_sidecar':str(verified_checksum),
            's3_last_modified':head['LastModified']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--not-before',required=True,help='UTC/offset timestamp before the selected authorized jobs began')
    parser.add_argument('--scope',choices=['both','postgresql','recovery','influxdb'],default='both')
    args = parser.parse_args()
    not_before = utc(args.not_before)
    os.umask(0o077)
    root = Path('/backup/database-recovery/s3-verification')
    if any(path.is_symlink() for path in [Path('/backup'),root.parent,root]):
        raise RuntimeError('verification_path_must_not_be_symlinked')
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if root.is_symlink() or root.resolve() != root:
        raise RuntimeError('verification_root_must_not_be_symlinked')
    os.chmod(root,0o700)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    output = root / stamp
    output.mkdir(mode=0o700,exist_ok=False)
    receipt = {'at':stamp,'status':'started','not_before':not_before.isoformat(),
               'secret_values_emitted':False,'s3_write_operations':False,'restore_test_performed':False}
    private_json(output/'started.json',receipt)
    try:
        receipt['scope'] = args.scope
        if args.scope in ('both','postgresql'):
            pg = Destination('08')
            pg_object = select(pg.objects(),r'pgsql_all_[A-Za-z0-9_.-]+\.sql\.zst',not_before)
            receipt['postgresql'] = verify(pg,pg_object,output,'job08-postgresql.sql.zst',
                                           pg.checksum,64*1024**3)
        if args.scope in ('both','recovery'):
            config = Destination('10')
            config_object = select(config.objects(),r'recovery-configs_s3_[0-9TZ.]+\.tar\.zst',not_before)
            receipt['recovery_configuration'] = verify(config,config_object,output,
                        'job10-recovery-configs.tar.zst','sha256',512*1024**2,require_metadata=True)
        if args.scope == 'influxdb':
            if os.environ.get('DB06_NAME','').upper() != 'ALL':
                raise RuntimeError('influxdb_s3_job_not_configured_for_all_buckets')
            influx = Destination('06')
            influx_object = select(influx.objects(),r'influx2_all_[A-Za-z0-9_.-]+\.tar\.zst',not_before)
            receipt['influxdb'] = verify(influx,influx_object,output,
                        'job06-influxdb.tar.zst',influx.checksum,64*1024**3)
            receipt['influxdb'].update(native_job_scope='ALL',
                        bucket_contents_verified=False,restore_test_performed=False)
        receipt['status'] = 'verified_downloads'
        private_json(output/'verified.json',receipt)
        print(json.dumps(receipt,indent=2))
    except Exception as error:
        receipt.update(status='failed',error_class=type(error).__name__,
                       reason=str(error) if isinstance(error,RuntimeError) else 'inspect_protected_verification_context')
        private_json(output/'failed.json',receipt)
        print(json.dumps(receipt,indent=2))
        raise SystemExit(1)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status':'failed','error_class':type(error).__name__,
                          'reason':str(error) if isinstance(error,RuntimeError) else 'inspect_protected_verification_context'}))
        raise SystemExit(1)
