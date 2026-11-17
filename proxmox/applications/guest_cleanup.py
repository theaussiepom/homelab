#!/usr/bin/env python3
"""Finish a guest job without changing deployment ownership or recovery authority."""
import argparse
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace

import cleanup_files as files
import component_current as current
import component_generation as generation
import component_guest
import component_inputs
from component_payload import AppPayload, _directory, MANIFEST
from custody_records import no_markers
from deployment_state import DeploymentAttempt, bootstrap_closed, custody_paths
from private_io import read_json, regular, require, sync

HISTORY_LIMIT = 20
LOG_LIMIT = 1024
FINISHED = 'job-finished.json'
RETIRING = 'cleanup-retiring.json'
HISTORY = 'job-history.json'
OPERATION = r'ordinary-[1-9][0-9]*-[1-9][0-9]*'


def epoch(path):
    require(re.fullmatch(OPERATION, path.name), 'Require an ordinary cleanup identity')
    return tuple(map(int, path.name.removeprefix('ordinary-').split('-')))


def input_directory(binding, parent, vmid):
    generation.component_binding(binding)
    directory = Path(binding['app_inputs_directory']).parent
    require(binding['vmid'] == vmid and directory.parent == parent
            and directory.name == binding['input_identity']
            and binding['app_inputs_directory'] == str(directory/'applications'),
            'Cleanup inputs must belong to this guest and generation')
    return directory


def summary(operation, marker, outcome):
    """Private bounded log tails; no exception values or logs go to Actions output."""
    tails = []
    for path in [operation/'infrastructure.log', *operation.glob('*/application.log')]:
        if not path.exists() and not path.is_symlink():
            continue
        # Inventory validates ownership/type, then open without following links.
        files.inventory(path.parent, path.name)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            info = os.fstat(stream.fileno())
            stream.seek(max(0, info.st_size - LOG_LIMIT))
            tails = sorted([*tails, (info.st_mtime_ns, str(path.relative_to(operation)),
                                   stream.read(LOG_LIMIT).decode('utf-8', errors='replace'))])[-8:]
    return {'operation': operation.name, 'outcome': outcome,
            'run_number': marker['run_number'], 'site_revision': marker['site_revision'],
            'logs': {name: tail for _, name, tail in tails}}


def remember(work, record):
    path = work/HISTORY
    history = read_json(path, private=True) if path.exists() or path.is_symlink() else []
    require(isinstance(history, list) and len(history) <= HISTORY_LIMIT,
            'Preserve unexpected cleanup history')
    history = [row for row in history if row['operation'] != record['operation']] + [record]
    history.sort(key=lambda row: epoch(Path(row['operation'])))
    files.replace(path, history[-HISTORY_LIMIT:])


def bulk(operation, phases):
    """Only controller-generated downloads, plan and phase scratch are disposable."""
    targets = ['tofu', 'guest.tfplan', 'infrastructure.log', *phases]
    for name in targets:
        path = operation/name
        if path.exists() or path.is_symlink():
            entries = files.inventory(operation, name)
            # A surprise backend or recovery artifact is never scratch, even
            # when somebody placed it inside a generated directory.
            require(not any('tfstate' in Path(item).name and item != 'tofu/.terraform/terraform.tfstate'
                            or 'HOLD' in Path(item).name or 'VERIFYING' in Path(item).name
                            for item in entries), 'Preserve state or recovery markers in scratch')
            files.remove(operation, entries)


def recovery_history(work, operations):
    """Recovery references span generations; this finalizer never retires them."""
    roots = [work/current.NAME, *work.glob('recovery-*'), *work.glob('operator-recovery-*'),
             *work.glob('infrastructure-admission*')]
    records = ('rollback-baseline.json', 'rollback-ready.json', 'controls-before.json',
               'forward-failure.json', 'infrastructure-invocation.json', 'infrastructure-admission.json')
    return any(current.exists(path) for path in roots) or any(
        current.exists(operation/name) for operation in operations for name in records)


def retire(work, operation, parent, protected, canonical, record, binding):
    """Seal exact deletion identities before retiring superseded source evidence."""
    ticket = operation/RETIRING
    if ticket.exists() or ticket.is_symlink():
        selected = read_json(ticket, private=True)
        require(isinstance(selected, dict) and set(selected) == {'operation', 'input', 'files', 'inputs'}
                and selected['operation'] == operation.name, 'Preserve unexpected cleanup retirement')
    else:
        directory = input_directory(binding, parent, canonical['binding']['vmid'])
        inputs = {}
        if directory not in protected:
            with _directory(directory):
                cfg = read_json(directory/'site.json', private=True)
            component_inputs.static(cfg, directory/'site.json')
            applications = directory/'applications'
            if applications.exists() or applications.is_symlink():
                with _directory(applications):
                    for app in applications.iterdir():
                        require(app.name in cfg['deployment']['payload_phases'].values(),
                                'Preserve an unselected application input owner')
                        with _directory(app) as descriptor:
                            manifest = regular(MANIFEST, private=True, dir_fd=descriptor)
                        AppPayload(app, directory.name, app.name, manifest).check()
            inputs = files.inventory(parent, directory.name)
        entries = files.inventory(work, operation.name)
        # Inventory includes only deployment-owned top-level names. Runtime,
        # imported data and independent backup records are not inferred here.
        allowed = {'complete.json', 'infrastructure-complete.json', 'plan.json', 'apply-window.json', 'host-key-evidence.json',
                   'host-device.json', 'host-device-check.log', 'host-device-attach.log',
                   'nfs-attachment.json', FINISHED}
        for name in entries:
            leaf = Path(name).relative_to(operation.name)
            require(str(leaf) == '.' or len(leaf.parts) == 1 and
                    (leaf.name in allowed or re.fullmatch(r'[a-z][a-z0-9_-]{0,62}-(started|complete)\.json', leaf.name)),
                    'Preserve unknown files in a superseded operation')
        selected = {'operation': operation.name, 'input': directory.name,
                    'files': entries, 'inputs': inputs}
        remember(work, record)
        files.replace(ticket, selected)
    require(operation != Path(canonical['operation']) and epoch(operation) < epoch(Path(canonical['operation']))
            and re.fullmatch('[0-9a-f]{64}', selected['input'])
            and operation.name in selected['files'] and len(selected['files']) > 1
            and all(name == operation.name or Path(name).parent == Path(operation.name) for name in selected['files'])
            and all(name == selected['input'] or name.startswith(selected['input']+'/') for name in selected['inputs']),
            'Retire only older confined ordinary generations')
    require(not selected['inputs'] or parent/selected['input'] not in protected,
            'Preserve inputs referenced by current or unresolved custody')
    if selected['inputs']:
        files.remove(parent, selected['inputs'])
    # The ticket remains until every inventoried child is removed. Excluding the
    # root permits retry after interruption without manufacturing a receipt.
    children = {name: value for name, value in selected['files'].items() if name != operation.name}
    # Validate against the ticket as well, without scheduling its removal.
    actual = files.inventory(work, operation.name)
    require(actual[operation.name] == selected['files'][operation.name]
            and set(actual) <= set(selected['files']) | {operation.name+'/'+RETIRING},
            'Preserve unexpected files during retirement')
    for name in sorted(children, reverse=True):
        files.remove(operation, {Path(name).name: children[name]})
    ticket.unlink()
    operation.rmdir()
    sync(work)


def locked(cfg, outcome):
    root = Path(cfg['paths']['state_root']); work = root/str(cfg['guest']['vmid'])
    parent = Path(cfg['deployment']['input_directory']).parent
    attempt = DeploymentAttempt(cfg, None, cfg['deployment']['phases'])
    attempt._select_run()
    no_markers(root)
    no_markers(work, own_ordinary=True)
    for directory in [*root.glob('database-network-cutover-*'), *root.glob('database-server-cutover-*'),
                      *work.glob('database-*')]:
        with _directory(directory):
            no_markers(directory)
    require(not ((work/'.terraform.tfstate.lock.info').exists()
                 or (work/'.terraform.tfstate.lock.info').is_symlink()), 'Preserve an active backend lock')
    hold = read_json(attempt.hold, private=True) if attempt.hold.exists() or attempt.hold.is_symlink() else None
    if hold is not None:
        require(Path(hold['operation']).parent == work and hold['workflow'] == attempt.workflow,
                'Preserve foreign deployment hold ownership')
        epoch(Path(hold['operation']))
    attempt.receipt = current.owner_path(work)
    canonical = None
    if attempt.receipt.exists() or attempt.receipt.is_symlink():
        # Inspect the current configuration, not potentially rejected new inputs.
        value = read_json(attempt.receipt, private=True)
        directory = input_directory(value['binding'], parent, attempt.vmid)
        with _directory(directory):
            current_cfg = read_json(directory/'site.json', private=True)
        canonical = generation.previous(SimpleNamespace(work=work, receipt=attempt.receipt,
            vmid=attempt.vmid, cfg=current_cfg))[0]
    operations = sorted((path for path in work.iterdir() if re.fullmatch(OPERATION, path.name)), key=epoch)
    # Keep every historical input generation while recovery or a reviewed
    # checkpoint owns references between them. Bulk cleanup remains independent
    # of final acceptance, rollback and reconciliation.
    preserve_history = recovery_history(work, operations)
    protected = {Path(cfg['deployment']['input_directory'])}
    if canonical is not None:
        protected.add(input_directory(canonical['binding'], parent, attempt.vmid))
    if hold is not None:
        protected.add(input_directory(hold['binding'], parent, attempt.vmid))
    candidates = []
    for operation in operations:
        with _directory(operation):
            no_markers(operation)
        ticket = operation/RETIRING
        if ticket.exists() or ticket.is_symlink():
            if preserve_history:
                continue
            require(canonical is not None, 'Cleanup retirement needs current ownership')
            require(hold is None or hold.get('operation') != str(operation),
                    'Preserve a held retirement operation')
            candidates.append((operation, None, None)); continue
        complete = operation/'complete.json'
        terminal = operation/FINISHED
        marker = read_json(complete, private=True) if complete.exists() else (
            read_json(terminal, private=True)['marker'] if terminal.exists() else
            hold if hold is not None and hold.get('operation') == str(operation) else None)
        if marker is None:
            # Legacy unclassified failures need a reviewed conversion. Retain
            # their referenced inputs even if another operation shares them.
            for path in [*operation.glob('*-started.json'), *operation.glob('infrastructure-complete.json'),
                         *operation.glob('plan.json')]:
                protected.add(input_directory(read_json(path, private=True)['binding'], parent, attempt.vmid))
            continue
        directory = input_directory(marker['binding'], parent, attempt.vmid)
        require(marker['operation'] == str(operation) and marker['workflow'] == attempt.workflow
                and type(marker['run_number']) is int and marker['run_number'] > 0,
                'Preserve foreign ordinary operation ownership')
        generation.fingerprint(marker['site_revision'], 40)
        own = operation == attempt.operation and marker['run_number'] == attempt.run_number
        finished = terminal.exists()
        passed = complete.exists() and generation.component_success(marker, operation)
        if own:
            require(marker['site_revision'] == attempt.site_revision, 'Preserve changed job source')
            record = summary(operation, marker, 'passed' if passed else 'incomplete' if outcome == 'success' else outcome)
            if finished:
                prior = read_json(terminal, private=True)
                require(prior['marker']['binding'] == marker['binding'], 'Preserve the finished job binding')
                record['logs'] = dict(list({**prior['summary']['logs'], **record['logs']}.items())[-8:])
            files.replace(terminal, {'marker': marker, 'summary': record})
            finished = True
        elif finished:
            record = read_json(terminal, private=True)['summary']
        elif passed:
            record = summary(operation, marker, 'passed')
            files.replace(terminal, {'marker': marker, 'summary': record})
        else:
            protected.add(directory); continue
        # End-of-job markers permit reclaiming failed downloads on the next
        # finalizer. A HOLD is never interpreted as completion or removed.
        remember(work, record)
        with _directory(directory):
            phases = list(marker['phase_inputs']) if passed else read_json(directory/'site.json', private=True)['deployment']['phases']
        bulk(operation, phases)
        held = hold is not None and hold.get('operation') == str(operation)
        if not preserve_history and canonical is not None and epoch(operation) < epoch(Path(canonical['operation'])) and not held:
            candidates.append((operation, record, marker['binding']))
        else:
            protected.add(directory)
    pending_inputs = [input_directory(binding, parent, attempt.vmid) if binding is not None else
                      parent/read_json(operation/RETIRING, private=True)['input']
                      for operation, _, binding in candidates]
    for index, (operation, record, binding) in enumerate(candidates):
        retire(work, operation, parent, protected | set(pending_inputs[index+1:]), canonical, record, binding)
    return {'status': 'cleaned', 'retired': len(candidates)}


def run(packet, outcome, *, inputs=Path('/var/lib/homelab-inputs/ordinary')):
    require(outcome in {'success', 'failure', 'cancelled'}, 'Require the actual job outcome')
    if not packet.exists() and not packet.is_symlink():
        return {'status': 'no_packet'}
    cfg, _ = component_guest.packet(read_json(packet, private=True), inputs)
    bootstrap_closed()
    root = Path(cfg['paths']['state_root']); work = root/str(cfg['guest']['vmid'])
    if not work.exists() and not work.is_symlink():
        return {'status': 'no_attempt'}
    with ExitStack() as opened:
        opened.enter_context(_directory(root)); opened.enter_context(_directory(work))
        for path, shared in custody_paths(root, work):
            # No lock replacement or new deployment custody during cleanup.
            regular(path, private=True)
            stream = opened.enter_context(os.fdopen(os.open(path, os.O_RDWR | os.O_NOFOLLOW), 'r+'))
            fcntl.flock(stream, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        return locked(cfg, outcome)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet', required=True, type=Path)
    parser.add_argument('--outcome', required=True)
    args = parser.parse_args()
    try:
        os.umask(0o077)
        print(json.dumps(run(args.packet, args.outcome)))
    except Exception:
        raise SystemExit('Guest cleanup deferred; preserve custody. The next job retries eligible leftovers.') from None


if __name__ == '__main__':
    main()
