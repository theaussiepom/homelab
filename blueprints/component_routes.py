"""Render typed HTTP publications into existing provider discovery annotations."""
import copy

import discovery
from component_sources import require


def route(plan, row):
    require(row['type'] == 'http', 'component.exposure')
    target = row['target']
    selected = {'host': row['hosts'][0], 'middlewares': copy.deepcopy(row.get('middlewares', []))}
    if len(row['hosts']) > 1:
        selected['aliases'] = row['hosts'][1:]
    if target.get('internal') == 'dashboard':
        selected['service'] = 'api@internal'
    else:
        selected['url'] = target['protocol'] + '://' + target['address'] + ':' + str(target['port'])
    if 'transport' in row:
        selected['transport'] = row['transport']
    auth = [key for key in selected['middlewares'] if plan.resolved['middlewares'][key]['type'] == 'forward-auth']
    require(len(auth) <= 1, 'component.authentication')
    if auth:
        selected['authentik_forward_auth'] = auth[0]
    return selected


def provider_routes(plan, guest_id):
    plan.check()
    result = {}
    for routes in plan.resolved['routes'].values():
        for key, row in routes.items():
            target = row['target']
            if target.get('app') not in plan.resolved['apps'] or target.get('internal'):
                continue
            if plan.resolved['apps'][target['app']]['guest'] == guest_id:
                require(key not in result, 'component.exposure-conflict')
                result[key] = route(plan, row)
    discovery.validate_routes(result)
    return result
