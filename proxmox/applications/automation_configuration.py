"""Derive bootstrap additions from the same automation guest used by CD."""
import argparse
import copy
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bootstrap'))
import bootstrap_cd
import deploy
import render
import site_config


def validate_inputs(foundation, automation):
    """Validate ordinary bindings without replaying a bootstrap scope change."""
    site_config.require(set(automation) == {'schema', 'enabled', 'site', 'stack', 'discovery_previous_guests'}
                        and automation['schema'] == 'homelab-automation-deployment-v1'
                        and type(automation['enabled']) is bool, 'Use the closed automation site configuration')
    previous = automation['discovery_previous_guests']
    site_config.require(isinstance(previous, list) and 1 <= len(previous) <= 31
                        and all(type(v) is int and 100 <= v <= 999999999 for v in previous)
                        and len(previous) == len(set(previous)),
                        'Declare the finite previous discovery scope')
    base = site_config.render(foundation)
    cfg, stack = automation['site'], automation['stack']
    vmid = deploy.validate(cfg, stack)
    initial = base['bootstrap.json']['service_discovery']['guests']
    site_config.require(previous[:len(initial)] == initial and vmid not in previous,
                        'Preserve the commissioned discovery prefix and this guest separate from its previous scope')
    render.compose(stack)
    if 'node_red_oidc' in stack:
        oidc=stack['node_red_oidc']
        expected_identity='https://' + foundation['domains']['identity']
        routes=[row for row in cfg['app'].get('discovery_routes',[]) if row.get('name') == 'node-red']
        site_config.require(oidc['identity_url'].rstrip('/') == expected_identity
                            and len(routes) == 1 and routes[0].get('login') == 'oidc'
                            and oidc['node_red_url'].rstrip('/') == 'https://' + routes[0]['host'],
                            'Native Node-RED OIDC must use the commissioned identity origin and routed Node-RED host')
    if 'frontend_routing' in cfg['app']:
        frontend=foundation['networks']['frontend']
        policy=cfg['app']['frontend_routing']
        site_config.require(policy['gateway'] == frontend['gateway'] and any(
            nic['ipv4'] == policy['address'] and nic['bridge'] == frontend['bridge']
            and nic.get('vlan') == frontend.get('vlan') for nic in cfg['guest']['interfaces']),
            'Automation reply routing must use the reviewed foundation frontend network and gateway')
    site_config.require(cfg['site'] == base['bindings.json']['site']
                        and cfg['paths'] == dict(site_config.PATHS, backup_source=foundation['runner']['backup_source'])
                        and cfg['ssh_public_keys'] == foundation['ssh_public_keys']
                        and cfg['app']['kind'] == stack['kind'] == 'automation'
                        and cfg['app']['memory_mib'] == stack['guest_memory_mib'],
                        'Automation must reuse this foundation host, runner paths, SSH key and guest budget')
    return base, cfg, stack, vmid


def compile_config(foundation, automation, bootstrap=None):
    """Append this guest to the reviewed, already composed bootstrap inputs."""
    base, cfg, stack, vmid = validate_inputs(foundation, automation)
    original = base['bootstrap.json']
    boot = copy.deepcopy(original if bootstrap is None else bootstrap)
    bootstrap_cd.validate(boot)
    # Existing scoped application/bridge declarations may already extend the
    # original foundation. Preserve those declarations and its immutable host,
    # runner and API identity; native CD still checks the exact live owner hash.
    variable = {'applications', 'application_networks', 'private_bridges',
                'service_discovery', 'service_discovery_extension'}
    site_config.require(all(boot.get(k) == v for k, v in original.items() if k not in variable)
                        and boot['applications'][:len(original['applications'])] == original['applications']
                        and all(boot['service_discovery'][k] == original['service_discovery'][k]
                                for k in ('vmid', 'address'))
                        and boot['service_discovery']['guests'][:len(original['service_discovery']['guests'])]
                            == original['service_discovery']['guests'],
                        'Retained bootstrap must preserve the commissioned foundation identity and allocations')
    site_config.require(vmid not in {row['vmid'] for row in boot['applications']}
                        and vmid not in (foundation['runner']['vmid'], foundation['dns']['vmid']),
                        'Automation must select its own new application identity')
    boot['applications'].append({'vmid': vmid, 'hostname': cfg['guest']['hostname']})
    previous = automation['discovery_previous_guests']
    site_config.require(previous == boot['service_discovery']['guests'],
                        'The previous discovery scope must match the commissioned foundation')
    import provider_access
    original_owner = copy.deepcopy(provider_access.owner(boot))
    boot['service_discovery']['guests'] = [*previous, vmid]
    boot['service_discovery_extension'] = {
        'owner_sha256': provider_access.owner_sha256(original_owner), 'guests': [vmid]}
    boot['application_networks'] = [*boot.get('application_networks', []),
                                  *[{'vmid': vmid, 'bridge': nic['bridge'], 'vlan': nic.get('vlan')}
                                    for nic in cfg['guest']['interfaces']]]
    # This validates the plan structure only. Bootstrap CD independently checks
    # the existing live bridges, original owner record and exact effective ACLs.
    bootstrap_cd.validate(boot)
    return {'bootstrap.json': boot, 'dns-settings.json': dns_settings(base, cfg)}


def dns_settings(base, cfg):
    dns=base['dns-settings.json']
    if 'mqtt_hostname' in cfg['app']:
        import foundation_dns
        address=cfg['app'].get('frontend_routing',{}).get('address',cfg['app']['address']).split('/')[0]
        dns['extra_records']={cfg['app']['mqtt_hostname']:address}
        site_config.require('mqtt_previous_address' in cfg['app'],'Declare the reviewed previous MQTT DNS binding')
        dns['extra_records_before']={cfg['app']['mqtt_hostname']:cfg['app']['mqtt_previous_address']}
        foundation_dns.configure(dns)
    return dns


def compile_dns(foundation, automation):
    """Select central DNS records without creating another discovery extension."""
    base, cfg, _, _ = validate_inputs(foundation, automation)
    return dns_settings(base, cfg)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--foundation', required=True, type=Path)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--bootstrap', type=Path, help='Reviewed composed bootstrap inputs to preserve')
    parser.add_argument('--dns-only', action='store_true', help='Render central DNS without bootstrap changes')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    foundation, automation = site_config.read(args.foundation), site_config.read(args.config)
    site_config.require(not (args.dns_only and args.bootstrap), 'Separate DNS selection from bootstrap composition')
    value = ({'dns-settings.json': compile_dns(foundation, automation)} if args.dns_only else
             compile_config(foundation, automation, site_config.read(args.bootstrap) if args.bootstrap else None))
    args.output.mkdir(mode=0o700)
    for name, content in value.items():
        with os.fdopen(os.open(args.output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
            json.dump(content, stream, sort_keys=True, indent=2); stream.write('\n')


if __name__ == '__main__': main()
