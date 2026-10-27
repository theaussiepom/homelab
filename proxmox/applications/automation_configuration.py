"""Derive bootstrap additions from the same automation guest used by CD."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bootstrap'))
import bootstrap_cd
import deploy
import render
import site_config


def compile_config(foundation, automation):
    site_config.require(set(automation) == {'schema', 'enabled', 'site', 'stack', 'discovery_previous_guests'}
                        and automation['schema'] == 'homelab-automation-deployment-v1'
                        and type(automation['enabled']) is bool, 'Use the closed automation site configuration')
    base = site_config.render(foundation)
    cfg, stack = automation['site'], automation['stack']
    vmid = deploy.validate(cfg, stack)
    render.compose(stack)
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
    boot = base['bootstrap.json']
    site_config.require(vmid not in {row['vmid'] for row in boot['applications']}
                        and vmid not in (foundation['runner']['vmid'], foundation['dns']['vmid']),
                        'Automation must select its own new application identity')
    boot['applications'].append({'vmid': vmid, 'hostname': cfg['guest']['hostname']})
    previous = automation['discovery_previous_guests']
    site_config.require(previous == boot['service_discovery']['guests'],
                        'The previous discovery scope must match the commissioned foundation')
    boot['service_discovery']['guests'] = sorted([*previous, vmid])
    boot['service_discovery_extension'] = {'previous_guests': previous}
    boot['application_networks'] = [{'vmid': vmid, 'bridge': nic['bridge'], 'vlan': nic.get('vlan')}
                                    for nic in cfg['guest']['interfaces']]
    # This validates the plan structure only. Bootstrap CD independently checks
    # the existing live bridges, original owner record and exact effective ACLs.
    bootstrap_cd.validate(boot)
    dns=base['dns-settings.json']
    if 'mqtt_hostname' in cfg['app']:
        import foundation_dns
        address=cfg['app'].get('frontend_routing',{}).get('address',cfg['app']['address']).split('/')[0]
        dns['extra_records']={cfg['app']['mqtt_hostname']:address}
        site_config.require('mqtt_previous_address' in cfg['app'],'Declare the reviewed previous MQTT DNS binding')
        dns['extra_records_before']={cfg['app']['mqtt_hostname']:cfg['app']['mqtt_previous_address']}
        foundation_dns.configure(dns)
    return {'bootstrap.json': boot, 'dns-settings.json': dns}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--foundation', required=True, type=Path)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    value = compile_config(site_config.read(args.foundation), site_config.read(args.config))
    args.output.mkdir(mode=0o700)
    for name, content in value.items():
        with os.fdopen(os.open(args.output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
            json.dump(content, stream, sort_keys=True, indent=2); stream.write('\n')


if __name__ == '__main__': main()
