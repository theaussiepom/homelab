#!/usr/bin/env python3
"""Read-only namespace and peer continuity checks for one ordinary Compose phase."""
import argparse
import json
import re
import subprocess
import sys


def require(ok):
    if not ok:
        raise ValueError('Preserve unexpected component runtime ownership')


def name(value):
    require(isinstance(value, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', value))
    return value


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
    require(result.returncode == 0 and not result.stderr and len(result.stdout.encode()) <= 65536)
    return result.stdout.strip()


def container(project, service):
    value = command(['docker','ps','--all','--quiet','--no-trunc','--filter',
        'label=com.docker.compose.project='+name(project),'--filter',
        'label=com.docker.compose.service='+name(service)])
    if not value:
        return None
    require(re.fullmatch('[0-9a-f]{64}',value))
    # Formatting projects only public identity/state, never environment values.
    raw = command(['docker','inspect','--type=container','--format',
        '{{json .Config.Labels}}\n{{json .State.StartedAt}}\n{{json .RestartCount}}',value])
    projection = json.loads('['+raw.replace('\n', ',', 2)+']')
    require(isinstance(projection,list) and len(projection)==3 and isinstance(projection[0],dict)
        and projection[0].get('com.docker.compose.project')==project
        and projection[0].get('com.docker.compose.service')==service
        and isinstance(projection[1],str) and type(projection[2]) is int and projection[2]>=0)
    return {'id':value,'started':projection[1],'restarts':projection[2]}


def project_services(project):
    """Inspect only this project's public container/service identities."""
    raw=command(['docker','ps','--all','--no-trunc','--filter',
        'label=com.docker.compose.project='+name(project),'--format',
        '{{.ID}} {{.Label "com.docker.compose.service"}}'])
    rows=raw.splitlines() if raw else []
    require(len(rows)<=128)
    services,identities=set(),set()
    for row in rows:
        parts=row.split(' ')
        require(len(parts)==2 and re.fullmatch('[0-9a-f]{64}',parts[0]))
        identity,service=parts;name(service)
        require(identity not in identities and service not in services)
        identities.add(identity);services.add(service)
    return services


def inspect(value, *, after=False):
    require(isinstance(value,dict) and set(value)=={'project','services','peers','lifecycle','previously_owned'})
    name(value['project'])
    require(value['lifecycle'] in ('fresh','retained') and type(value['previously_owned']) is bool)
    for key in ('services','peers'):
        require(isinstance(value[key],list) and len(value[key])<=64 and len(value[key])==len(set(value[key])))
        for service in value[key]:name(service)
    require(value['services'] and not set(value['services'])&set(value['peers']))
    require(project_services(value['project'])<=set(value['services'])|set(value['peers']))
    selected={service:container(value['project'],service) for service in value['services']}
    require(after or value['lifecycle']!='fresh' or value['previously_owned'] or not any(selected.values()))
    require(not after or all(selected.values()))
    return {'peers':{service:container(value['project'],service) for service in value['peers']}}


def verify(value):
    require(isinstance(value,dict) and set(value)=={'selection','before'})
    result=inspect(value['selection'], after=True)
    require(result==value['before'])
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['before','after'])
    args=parser.parse_args()
    raw=sys.stdin.buffer.read(1024*1024+1);require(len(raw)<=1024*1024)
    value=json.loads(raw)
    if args.mode=='before':
        result=inspect(value)
    else:
        result=verify(value)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Component ownership check held; preserve the existing runtime.') from None
