"""Saved-plan policy for one additive firewall update on an existing guest."""
import ipaddress
import re
RESOURCES = {
    'module.guest.proxmox_virtual_environment_container.guest':'vm_id',
    'module.guest.proxmox_virtual_environment_firewall_options.guest':'container_id',
    'module.guest.proxmox_virtual_environment_firewall_rules.guest':'container_id'}
RULES = list(RESOURCES)[-1]
PRIVATE = tuple(ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def require(value):
    if not value: raise ValueError('The saved firewall plan exceeds its declared additive scope')


def provider_rules(rows):
    result=[]
    for row in rows:
        require(set(row) == {'direction','proto','port','destination','comment'} and row['direction'] == 'out'
                and row['proto'] == 'tcp' and isinstance(row['port'],str)
                and re.fullmatch(r'[0-9]+(?:,[0-9]+){0,15}',row['port'])
                and all(1 <= int(v) <= 65535 for v in row['port'].split(',')))
        destination=ipaddress.IPv4Network(row['destination'])
        require(destination.prefixlen == 32 and any(destination.subnet_of(network) for network in PRIVATE)
                and not destination.network_address.is_loopback and not destination.network_address.is_link_local
                and not destination.network_address.is_unspecified and not destination.network_address.is_multicast)
        result.append(dict(type='out',action='ACCEPT',proto=row['proto'],dport=row['port'],dest=row['destination'],comment=row['comment']))
    return result


def check_plan(value,node,vmid,additions,completed=False):
    require(type(vmid) is int and vmid >= 100 and vmid not in {900,4914,4915,4920}
            and not value.get('errored') and value.get('complete',True) is True
            and not value.get('deferred_changes') and not value.get('resource_drift'))
    rows=value.get('resource_changes',[])
    require(len(rows) == 3 and {r.get('address') for r in rows} == set(RESOURCES))
    expected=provider_rules(additions)
    require(1 <= len(expected) <= 16)
    def unknown(v):
        if isinstance(v,dict):return any(unknown(i) for i in v.values())
        if isinstance(v,list):return any(unknown(i) for i in v)
        return bool(v)
    for row in rows:
        change=row['change'];before=change.get('before');after=change.get('after')
        require(isinstance(before,dict) and isinstance(after,dict) and not unknown(change.get('after_unknown',{}))
                and row.get('mode','managed') == 'managed' and not row.get('previous_address')
                and not row.get('deposed') and 'importing' not in row and 'importing' not in change)
        key=RESOURCES[row['address']]
        require(all(str(v.get(key)) == str(vmid) and v.get('node_name') == node for v in (before,after)))
        if row['address'] != RULES or completed:
            require(change['actions'] == ['no-op'] and before == after)
        else:
            require(change['actions'] == ['update'] and {k:v for k,v in before.items() if k!='rule'} ==
                    {k:v for k,v in after.items() if k!='rule'} and after['rule'][:len(before['rule'])] == before['rule']
                    and len(after['rule']) == len(before['rule'])+len(expected))
        if row['address'] == RULES:
            require(len(after['rule']) >= len(expected))
            for actual,wanted in zip(after['rule'][-len(expected):],expected):
                require(all(actual.get(k) == v for k,v in wanted.items()) and all(
                    v in (None,'') or k=='enabled' and v is True or k=='log' and v=='nolog'
                    for k,v in actual.items() if k not in wanted))
