"""Early protected Backup job: verify PBS and maintain the one controller schedule."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import compile as compiler
import component_packet
import backup_setup
from private_io import require, digest, encoded


def descriptor(plan):
    plan.check()
    selected = plan.resolved.get('backup', {})
    require(selected.get('mode') == 'scheduled-recovery', 'Select a complete operational backup job')
    inventories = [json.loads(packet['files']['site.json'])['app'].get('backup', {})
                   for packet in component_packet.lower_plan(plan).values()]
    inventories = [value for value in inventories if 'job' in value]
    coverage = {value['job']['group']['member']: digest(encoded(value)) for value in inventories}
    require(coverage == selected['group']['coverage'], 'Bind all enrolled members, including disabled guests')
    first = inventories[0]['job']['destination']
    require(all({key: item for key, item in value['job']['destination'].items()
                 if key not in ('auth_id', 'backup_id')} ==
                {key: item for key, item in first.items() if key not in ('auth_id', 'backup_id')}
                for value in inventories), 'Use one declared PBS management destination')
    return {'schedule': selected['group'], 'destination': first,
            'datastore_path': selected['management']['datastore_path']}


def run(stack, site, disabled, *, environment=os.environ):
    require(environment.get('GITHUB_EVENT_NAME') == 'push' and environment.get('GITHUB_REF') == 'refs/heads/main',
            'Only protected main CD may maintain the backup schedule')
    plan = compiler.resolve_plan(stack, compiler.site_path(site), compiler.parse_disabled(disabled), admit=True)
    value = descriptor(plan)
    return backup_setup.install(value['schedule'], destination=value['destination'],
        datastore_path=value['datastore_path'], token=environment.get('PBS_API_TOKEN', ''))


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stack',type=Path,required=True)
    parser.add_argument('--site-root',type=Path,required=True)
    parser.add_argument('--disabled',default='[]')
    args=parser.parse_args()
    try:
        result=run(args.stack,args.site_root,args.disabled)
    except Exception:
        raise SystemExit('Backup setup stopped; preserve protected records and review the failed boundary.') from None
    print(json.dumps(result))


if __name__=='__main__':main()
