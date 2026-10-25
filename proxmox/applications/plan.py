#!/usr/bin/env python3
"""Limit an ordinary OpenTofu saved plan to one selected application guest."""
import argparse
import json
from pathlib import Path

RESOURCES = {
    'module.guest.proxmox_virtual_environment_container.guest': 'vm_id',
    'module.guest.proxmox_virtual_environment_firewall_options.guest': 'container_id',
    'module.guest.proxmox_virtual_environment_firewall_rules.guest': 'container_id',
}
PROTECTED = {900, 4914, 4915, 4920}


def check_plan(value, node, vmid):
    """Reject deletion, replacement, adoption and every unrelated resource."""
    if type(vmid) is not int or vmid < 100 or vmid in PROTECTED:
        raise ValueError('Choose an unused application guest; the controller and retained guests are protected')
    rows = value.get('resource_changes', [])
    if {r.get('address') for r in rows} != set(RESOURCES) or len(rows) != len(RESOURCES):
        raise ValueError('The plan must contain only the selected guest and its firewall resources')
    for row in rows:
        change = row['change']
        if change['actions'] not in (['create'], ['update'], ['no-op']):
            raise ValueError('Destruction and replacement require a separate decision')
        key = RESOURCES[row['address']]
        if not isinstance(change.get('after'), dict):
            raise ValueError('The selected target must be known in the saved plan')
        for side in ('before', 'after'):
            data = change.get(side)
            if data is not None and (str(data.get(key)) != str(vmid) or data.get('node_name') != node):
                raise ValueError('The plan changes a different guest or Proxmox node')


def main():
    """Check a private JSON plan without printing its contents."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    parser.add_argument('--node', required=True)
    parser.add_argument('--vmid', required=True, type=int)
    args = parser.parse_args()
    check_plan(json.loads(args.plan.read_text()), args.node, args.vmid)
    print(json.dumps({'status': 'passed', 'scope': 'one application guest; no deletions'}))


if __name__ == '__main__':
    main()
