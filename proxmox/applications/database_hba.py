"""Pure existing PostgreSQL prefixes, shared by component and receipt-era callers."""
import ipaddress

from private_io import require


def monitoring(original, source):
    require(ipaddress.IPv4Address(source).is_private,
            'Use the declared private monitoring database source')
    return ('# Root Zabbix: dedicated storage and local statistics only\n'
            'host postgres zbx_monitor 127.0.0.1/32 scram-sha-256\n'
            'host zabbix zabbix 127.0.0.1/32 scram-sha-256\n'
            'hostssl zabbix zabbix ' + source + '/32 scram-sha-256\n'
            'hostnossl zabbix zabbix ' + source + '/32 reject\n' + original)


def administrators(original, values):
    if not values:
        return original
    import database_admin
    require('# homelab managed administrator accounts' not in original,
            'Preserve the original HBA source outside the owned account prefix')
    rows = ['# homelab managed administrator accounts']
    for key, item in sorted(values.items()):
        database_admin.name(key)
        database_admin.name(item['username'])
        owner = database_admin.owner(item['owner'])
        require(owner['engine'] == 'postgresql' and owner['username'] == item['username'],
                'Bind the administrator HBA to its PostgreSQL account owner')
        user, source = item['username'], owner['source_address']
        rows.extend([f'hostssl all,replication {user} {source}/32 scram-sha-256',
                     f'local all,replication {user} reject',
                     f'host all,replication {user} 0.0.0.0/0 reject',
                     f'host all,replication {user} ::/0 reject'])
    return '\n'.join(rows)+'\n'+original
