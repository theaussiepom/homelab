#!/usr/bin/env python3
"""Build-time patch for the exact pinned backup framework; fail on source drift."""
import hashlib
from pathlib import Path
import sys

EXPECTED_SHA256 = '7b57d7e15261856a6622aacb69c14d45c8bc2d52d18ad5734071a8101739b44b'
BEGIN = '    ### Post Script Support\n'
END = '    ### Post Backup Custom Script Support\n'
REPLACEMENT = '''    ### Post Script Support
    # Preserve the native executable-path hook interface, but do not report a
    # successful job when a dump, move, missing hook or hook execution failed.
    if [ -n "${backup_job_post_script}" ] ; then
        local post_script_exit=0
        if [ "${master_exit_code:-0}" != "0" ]; then
            post_script_exit=1
        elif var_true "${backup_job_post_script_x_verify}" || [ -x "${backup_job_post_script}" ]; then
            "${backup_job_post_script}" "${exit_code}" "${dbtype}" "${backup_job_db_host}" "${1}" "${dbbackup_start_time}" "${dbbackup_finish_time}" "${dbbackup_total_time}" "${backup_job_filename}" "${filesize}" "${checksum_value}" "${move_exit_code}" || post_script_exit=$?
        else
            post_script_exit=126
        fi
        if [ "${post_script_exit}" != "0" ]; then
            exitcode_backup=1
            master_exit_code=1
            exit_code=1
            write_log error "Post-backup coverage hook failed or was skipped after an upstream failure"
        fi
    fi

'''


def patch(original):
    if hashlib.sha256(original).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError('pinned_backup_framework_source_changed')
    text = original.decode()
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise RuntimeError('post_script_source_anchor_changed')
    # These are the backup and move failure branches of check_exit_code.
    marker = '                    master_exit_code=1\n'
    if text.count(marker) != 2:
        raise RuntimeError('native_failure_source_anchor_changed')
    text = text.replace(marker, marker + '                    exitcode_backup=1\n')
    sidecar = '                    silent run_as_user ${play_fair} aws ${PARAM_AWS_ENDPOINT_URL} s3 cp ${temporary_directory}/*.${checksum_extension} s3://${backup_job_s3_bucket}/${backup_job_s3_path}/ ${s3_ssl} ${s3_ca_cert} ${backup_job_s3_extra_opts}\n'
    if text.count(sidecar) != 1:
        raise RuntimeError('s3_checksum_move_source_anchor_changed')
    text = text.replace(sidecar, sidecar.rstrip('\n') + ' || move_exit_code=$?\n')
    start, finish = text.index(BEGIN), text.index(END)
    return (text[:start] + REPLACEMENT + text[finish:]).encode()


if __name__ == '__main__':
    path = Path(sys.argv[1] if len(sys.argv) > 1 else '/assets/functions/10-db-backup')
    path.write_bytes(patch(path.read_bytes()))
