"""Protected Backup job: compile public intent, bind existing credentials, then activate."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
import compile as compiler
import component_packet
import credentials
import backup_activation
from private_io import require, write_new, encoded


def descriptor(plan):
    plan.check()
    selected = plan.resolved.get('backup', {})
    require(selected.get('mode') == 'scheduled-recovery', 'Select a complete operational backup job')
    packets = component_packet.lower_plan(plan)
    coverage = {}; enabled = []
    for packet in packets.values():
        cfg = json.loads(packet['files']['site.json'])
        inventory = cfg['app'].get('backup', {})
        if 'job' in inventory:
            member=inventory['job']['group']['member']
            coverage[member] = inventory
            if packet['enabled']:
                enabled.append(member)
    return {'schedule':selected['group'], 'datastore_path':selected['management']['datastore_path'],
            'coverage':coverage,'enabled':enabled}, packets


def run(stack, site, disabled, *, environment=os.environ):
    require(environment.get('GITHUB_EVENT_NAME') == 'push' and environment.get('GITHUB_REF') == 'refs/heads/main',
            'Only protected main CD may provision backup clients')
    plan = compiler.resolve_plan(stack,compiler.site_path(site),compiler.parse_disabled(disabled),admit=True)
    value, packets = descriptor(plan)
    if not value['enabled']:
        return {'status':'not_selected','changed':False}
    # Disabled members use their genuine previous deployment and existing credentials.
    # Never turn a disabled packet into an enabled deployment to load a credential.
    with tempfile.TemporaryDirectory(prefix='homelab-backup-inputs-',dir=environment['RUNNER_TEMP']) as temporary:
        for name,packet in packets.items():
            if packet['enabled'] and 'job' in json.loads(packet['files']['site.json'])['app'].get('backup', {}):
                path=Path(temporary)/(name+'.json');write_new(path,encoded(packet))
                credentials.bind(path,environment)
    token = environment.get('PBS_API_TOKEN','')
    return backup_activation.activate(value,token)


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
        raise SystemExit('Backup activation stopped; preserve protected enrollment records and review the failed boundary.') from None
    print(json.dumps(result))


if __name__=='__main__':main()
