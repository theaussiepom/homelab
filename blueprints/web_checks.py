"""Run one final, secret-free controller job through ordinary guest admission."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import html
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compile as compiler
import component_workflows
import deploy
import routed_checks
from deployment_state import bootstrap_closed
from private_io import encoded, require, write_new


def job_results(raw, guests):
    """Accept only result enums; never forward job outputs or credential values."""
    require(isinstance(raw, str) and len(raw.encode()) <= 65536, 'Bound prerequisite results')
    value = json.loads(raw)
    require(isinstance(value, dict) and set(value) <= set(guests) | {'validate', 'selection', '_backup'}
            and all(result in ('success', 'failure', 'skipped', 'cancelled') for result in value.values()),
            'Use only selected prerequisite job results')
    return value


def endpoint(row, owner, label, result):
    return {'guest': owner, 'label': label, 'exposure': row['exposure'], 'host': row['host'],
            'port': row['port'], 'path': row['path'], **({'check': row['mode']} if 'mode' in row else {}), **result}


def check_owner(owner, metadata, rows, packet, results, global_jobs, executor, execute):
    """One guest retains its existing custody while its endpoints share the pool."""
    needs = metadata.get('row_needs', [metadata['needs']] * len(rows))
    require(len(needs) == len(rows), 'Account for every check prerequisite')
    blocked = {}
    for index, required in enumerate(needs):
        unavailable = {key: results.get(key, 'missing') for key in [*global_jobs, *required]
                       if results.get(key) != 'success'}
        if unavailable:
            blocked[index] = {'status': 'blocked', 'cause': 'prerequisite_not_successful',
                              'prerequisites': unavailable}
    if len(blocked) == len(rows):
        return [endpoint(row, owner, metadata['name'], blocked[index]) for index, row in enumerate(rows)]
    try:
        try:
            value = execute('http-checks', packet, route_executor=executor, **({'blocked_routes': blocked} if blocked else {}))
        except routed_checks.VerificationFailure as error:
            value = error.diagnostic
        details = value.get('endpoints')
        require(isinstance(details, list) and len(details) == len(rows)
                and all(isinstance(item, dict) and item.get('endpoint') == index
                    and item.get('exposure') == rows[index]['exposure']
                    and (item.get('status') in ('passed', 'failed') if index not in blocked else item.get('status') == 'blocked')
                    for index,item in enumerate(details)),
                'Account for every admitted endpoint result')
        fields = {'status', 'attempts', 'stage', 'cause', 'http_status'}
        return [endpoint(row, owner, metadata['name'], blocked.get(index) or
                         {key: value for key,value in result.items() if key in fields})
                for index, (row, result) in enumerate(zip(rows, details, strict=True))]
    except Exception as error:
        try:
            diagnostic = deploy.failure_diagnostic(error)
        except Exception:
            diagnostic = {'error_type': 'Exception', 'source': []}
        return [endpoint(row, owner, metadata['name'], {'status': 'blocked',
            'cause': 'admission_refused', 'admission': diagnostic}) for row in rows]


def run(stack, site, disabled, raw_results, *, environment=os.environ, execute=deploy.run):
    """Compile intent, then retain the normal current-run/receipt/lock checks."""
    require(environment.get('GITHUB_EVENT_NAME') == 'push'
            and environment.get('GITHUB_REF') == 'refs/heads/main', 'Only protected main checks deployed routes')
    require(not any(value and (key.startswith('HOMELAB_APP_SECRET_') or key in
            ('PBS_API_TOKEN', 'APPLICATION_SSH_KEY', 'PROXMOX_APP_TOKEN', 'PROXMOX_NFS_SSH_KEY'))
            for key,value in environment.items()), 'Do not supply deployment credentials to read-only checks')
    bootstrap_closed()
    plan = compiler.resolve_plan(stack, compiler.site_path(site), compiler.parse_disabled(disabled), admit=True)
    graph = component_workflows.model(plan)
    selected = graph.get('checks')
    results = job_results(raw_results, plan.resolved['guests'])
    if selected is None:
        return {'status': 'not_selected', 'endpoints': [], 'credentialed_login': False}
    packets = compiler.lower_plan(plan)
    global_jobs = ['selection', *(['_backup'] if 'backup' in graph else []),
                   *(['validate'] if 'validate' in results else [])]
    collected = {}
    with tempfile.TemporaryDirectory(prefix='homelab-web-checks-', dir=environment['RUNNER_TEMP']) as temporary:
        with ThreadPoolExecutor(max_workers=routed_checks.CONCURRENCY) as probes:
            with ThreadPoolExecutor(max_workers=routed_checks.CONCURRENCY) as owners:
                pending = {}
                for owner, metadata in selected['owners'].items():
                    packet = Path(temporary)/(owner+'.json')
                    write_new(packet, encoded(packets[owner]))
                    rows = plan.resolved['routed_checks'][owner]['rows']
                    pending[owners.submit(check_owner, owner, metadata, rows, packet,
                        results, global_jobs, probes, execute)] = owner
                for future in as_completed(pending):
                    owner = pending[future]
                    try:
                        collected[owner] = future.result()
                    except Exception:
                        collected[owner] = [endpoint(row, owner, selected['owners'][owner]['name'],
                            {'status': 'blocked', 'cause': 'owner_check_failed'})
                            for row in plan.resolved['routed_checks'][owner]['rows']]
    endpoints = [row for owner in selected['owners'] for row in collected[owner]]
    require(len(endpoints) == selected['endpoint_count'], 'Report every selected endpoint and alias')
    counts = {key: sum(row['status'] == key for row in endpoints) for key in ('passed', 'failed', 'blocked')}
    return {'status': 'passed' if counts['passed'] == len(endpoints) else 'failed',
            'endpoints': endpoints, 'counts': counts, 'credentialed_login': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stack', type=Path, required=True)
    parser.add_argument('--site-root', type=Path, required=True)
    parser.add_argument('--disabled', default='[]')
    parser.add_argument('--results', required=True)
    args = parser.parse_args()
    try:
        os.umask(0o077)
        value = run(args.stack, args.site_root, args.disabled, args.results)
        for row in value['endpoints']:
            print(json.dumps(row, sort_keys=True))
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            def cell(text):
                return html.escape(str(text)[:1024]).replace('|', '&#124;').replace('\n', ' ').replace('\r', ' ')
            lines = ['## Web endpoints', '', '| Status | Guest | Check | Endpoint | Cause |', '| --- | --- | --- | --- | --- |']
            for row in value['endpoints']:
                target = 'https://' + row['host'] + ':' + str(row['port']) + row['path']
                lines.append('| ' + ' | '.join(cell(item) for item in
                    (row['status'], row['guest'], row.get('check', ''), target, row.get('cause', ''))) + ' |')
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
                summary.write('\n'.join(lines) + '\n')
        print(json.dumps({key: item for key,item in value.items() if key != 'endpoints'}, sort_keys=True))
        return 0 if value['status'] in ('passed', 'not_selected') else 1
    except Exception:
        print(json.dumps({'status': 'failed', 'stage': 'configuration', 'cause': 'check_inputs_refused'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
