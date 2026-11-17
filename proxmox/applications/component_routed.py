"""Execute bounded read-only route checks without altering ordinary receipts."""
import copy
import json
import os
from pathlib import Path
import re
import sys

import component_inputs
import component_input_secrets
import network_endpoints
import proxmox_guest
import routed_checks
from commands import quiet
from private_io import private_directory, require, write, write_new, encoded

SOURCE = Path(__file__).resolve().parent


def configuration(cfg):
    selected = cfg['app']['route_checks']
    require(isinstance(selected, dict) and set(selected) == {'mode', 'rows'}
            and selected['mode'] in ('inline', 'deferred'), 'Use explicit routed check mode and rows')
    routed_checks.validate(selected['rows'])
    addresses = network_endpoints.addresses(cfg['guest'])
    if selected['mode'] == 'inline':
        require(all(row[key] in addresses for row in selected['rows']
                    for key in ('source_address', 'resolver_source')), 'Keep inline checks on this guest')
    else:
        require(len({row['source_address'] for row in selected['rows']}) == 1
                and all(row['resolver_source'] == row['source_address'] for row in selected['rows']),
                'Keep deferred checks on one declared controller address')
    return selected


def run(cfg, site, work, operation, expected, *, executor=None, historical=False):
    selected = configuration(cfg)
    require(executor is None or selected['mode'] == 'deferred', 'Parallel checks run only on the controller')
    def bound():
        if historical:
            import component_generation
            from private_io import sha
            selected, _ = component_generation.sealed_inputs(expected)
            return selected == cfg and all(sha(path) == wanted for path, wanted in expected['input_hashes'].items())
        return component_inputs.binding(cfg, site) == expected
    require(type(historical) is bool and bound(), 'Route inputs changed before checks')
    directory = operation/'http-checks'
    if selected['mode'] == 'deferred' and not historical:
        # Ordinary completion stays immutable; this job has separate evidence.
        directory = work/('http-checks-' + operation.name.removeprefix('ordinary-'))
    directory.mkdir(mode=0o700)
    private_directory(directory)
    write_new(directory/'selection.json', encoded({'binding': expected, 'operation':str(operation), **selected}))
    environment = {key:value for key,value in os.environ.items()
                   if key != 'PBS_API_TOKEN' and not key.startswith(component_input_secrets.PREFIX)}
    if executor is not None:
        result = routed_checks.parallel(selected['rows'], executor)
        write_new(directory/'checks.log', encoded(result))
        require(bound(), 'Route inputs changed during checks')
        if result['status'] != 'passed':
            raise routed_checks.VerificationFailure(result)
        write_new(directory/'complete.json', encoded({'binding': expected, 'operation': str(operation), **result}))
        return result
    if selected['mode'] == 'deferred':
        command = [sys.executable, str(SOURCE/'routed_checks.py'), json.dumps(selected['rows'])]
    else:
        proxmox_guest.dhcp_admission(cfg)
        proxmox_guest.guest_trust(cfg, work)
        # Execute the pinned stdlib helpers in memory on the admitted guest.
        # No installed helper/runtime namespace or permanent target file is added.
        code = ("import sys,types; m=types.ModuleType('dns_records'); exec(" +
                repr((SOURCE/'dns_records.py').read_text()) + ",m.__dict__); sys.modules['dns_records']=m;\n" +
                (SOURCE/'routed_checks.py').read_text())
        variables = {'app':copy.deepcopy(cfg['app']), 'route_check_argv':['python3','-c',code,json.dumps(selected['rows'])]}
        write(directory/'variables.json', variables)
        write(directory/'inventory.json', {'application':{'hosts':{cfg['app']['hostname']:{
            'ansible_host':cfg['app']['address'], 'ansible_user':'root'}}}})
        from ansible_guest import ansible_environment
        environment = ansible_environment(cfg, environment)
        command = ['ansible-playbook','-i',str(directory/'inventory.json'),'--private-key',cfg['paths']['private_key'],
                   str(SOURCE/'ansible/component-route-checks.yml'),'--extra-vars','@'+str(directory/'variables.json')]
    quiet(command, environment, directory/'checks.log')
    require(bound(), 'Route inputs changed during checks')
    if selected['mode'] == 'inline':
        counts = re.findall(r'changed=(\d+)', (directory/'checks.log').read_text())
        require(counts and all(value == '0' for value in counts), 'Route checks must be read-only')
    result = {'status':'passed', 'changed':False, 'routed_endpoints':len(selected['rows']), 'credentialed_login':False}
    write_new(directory/'complete.json', encoded({'binding':expected, 'operation':str(operation), **result}))
    return result
