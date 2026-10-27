"""Preview automation routing from site data; never deploy or change a service."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re

import discovery
import foundation
import site_config


def preview(base, cfg):
    site_config.validate(base)
    if (not isinstance(cfg, dict) or set(cfg) != {'schema', 'vmid', 'backend_address', 'homeassistant_host', 'node_red_host'}
            or cfg['schema'] != 'homelab-automation-routes-v1' or type(cfg['vmid']) is not int
            or not 100 <= cfg['vmid'] <= 999999999 or cfg['vmid'] in {4914, 4915, 4920}):
        raise ValueError('Use the closed automation routing configuration')
    existing = site_config.render(base)
    guest_ids = existing['bootstrap.json']['service_discovery']['guests']
    ids = [base['runner']['vmid'], base['dns']['vmid'], *guest_ids,
           *(guest['vmid'] for guest in base['databases'].values())]
    if cfg['vmid'] in ids:
        raise ValueError('Automation must have its own unused declared guest ID')
    address = ipaddress.IPv4Address(cfg['backend_address'])
    backend = ipaddress.IPv4Network(base['networks']['backend']['cidr'])
    selected = [guest['interfaces']['backend']['address'] for guest in base['guests'].values()]
    selected.append(base['databases']['postgresql']['address'])
    if address not in backend or address in (backend.network_address, backend.broadcast_address) or str(address) in selected:
        raise ValueError('Select a distinct automation address on the declared backend network')
    hosts = [cfg['homeassistant_host'], cfg['node_red_host']]
    for host in hosts:
        if (not isinstance(host, str) or len('_acme-challenge.' + host) > 253
                or re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', host) is None
                or sum(host.endswith('.' + zone) for zone in base['domains']['redirect']) != 1):
            raise ValueError('Use a selected-zone hostname with a valid ACME challenge name')
    protected_hosts = {base['domains']['identity'], base['domains']['db_tools'],
                       *(row['name'] for row in base['domains']['preserve'])}
    if len(set(hosts)) != 2 or set(hosts) & protected_hosts:
        raise ValueError('Automation routes cannot collide with each other, login endpoints or preserved DNS names')
    routes = [{'name':'homeassistant', 'host':hosts[0], 'url':f'http://{address}:8123'},
              {'name':'node-red', 'host':hosts[1], 'url':f'http://{address}:1880', 'login':'authentik'}]
    identity = base['guests']['identity']['interfaces']['backend']['address']
    outpost = {'name':'node-red-outpost', 'host':hosts[1], 'url':f'http://{identity}:9000', 'login':'outpost'}
    # Validate these exact data contracts through the same compiler as OpenTofu.
    for kind, ip, rows in [('automation', address, routes), ('identity', identity, [outpost])]:
        discovery.labels({'guest':{'interfaces':[{'ipv4':str(ip) + '/24'}]},
                          'app':{'kind':kind, 'discovery_routes':rows}})
    origin = foundation.private_authentik_origin(f'http://{identity}:9000')
    frontend = base['guests']['ingress']['interfaces']['frontend']['address']
    return {'schema':'homelab-automation-routing-preview-v1', 'deployable':False,
            'automation_discovery_routes':routes, 'identity_additional_discovery_route':outpost,
            'ingress_foundation_settings':{'authentik_url':origin},
            'ingress_additional_rules':[site_config.rule('out', str(port), 'Automation backend only',
                                       'destination', str(address) + '/32') for port in (8123, 1880)],
            'discovery_guest_ids':sorted([*guest_ids, cfg['vmid']]),
            'dns_records':dict.fromkeys(hosts, frontend),
            'acme_exceptions':['_acme-challenge.' + host for host in hosts],
            'existing_authentik_settings_to_reconcile':{
                'embedded_outpost_authentik_host':'https://' + base['domains']['identity'] + '/',
                'node_red_provider_external_host':'https://' + hosts[1] + '/'},
            'remaining_inputs':['complete guest/network/resource profile and bootstrap grants',
                                'coherent capture and verified custom image archives',
                                'HA helper/mount and application endpoint adaptations',
                                'reviewed existing outpost/provider reconciliation through CD',
                                'NAS protection for new writes and exclusive-writer cutover']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--foundation', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = preview(site_config.read(args.foundation), site_config.read(args.config))
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
