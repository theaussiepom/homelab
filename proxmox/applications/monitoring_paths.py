"""One owner for paths installed by the managed monitoring component."""
DIRECTORY = '/etc/zabbix'
STATE = '/var/lib/homelab-monitoring'
PATHS = {'directory': DIRECTORY, 'state': STATE,
    'configuration': DIRECTORY + '/zabbix_agent2.conf', 'key': DIRECTORY + '/agent.psk',
    'receipt': STATE + '/agent.json', 'hold': STATE + '/AGENT-HOLD'}
RECOVERY = {'zabbix-agent-' + name: {'path': PATHS[key], 'kind': 'file'}
    for name, key in [('configuration', 'configuration'), ('key', 'key'), ('ownership', 'receipt')]}
