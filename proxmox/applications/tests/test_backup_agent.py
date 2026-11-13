"""The runtime receiver validates an inventory, never claims a backup exists."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_agent


def fixture():
    owner = {'node': 'example-node', 'vmid': 610, 'hostname': 'example'}
    inventory = {'schema': backup_agent.SCHEMA, 'profile': 'pbs', 'owner': owner,
        'configuration': {'ssh': {'path': '/etc/ssh', 'kind': 'directory'}},
        'managed_volumes': {'data': {'path': '/srv/example', 'include': True}},
        'applications': {'app': {'adapter': 'unbound', 'runtime_files': ['/opt/homelab-app/app.json'],
            'storage': {'config': {'path': '/srv/example/config', 'kind': 'directory', 'include': True,
                                 'category': 'configuration', 'capture': 'files'},
                        'state': {'path': '/srv/example/state', 'kind': 'directory', 'include': True,
                                  'category': 'state', 'capture': 'application-export'},
                        'database': {'path': '/srv/example/database', 'kind': 'directory', 'include': False,
                                     'category': 'database', 'capture': 'database-export'},
                        'logs': {'path': '/srv/example/logs', 'kind': 'directory', 'include': False,
                                 'reason': 'transient'}},
            'configuration': {'native': {'path': '/etc/example', 'kind': 'directory'}},
            'databases': [{'connection': 'database', 'type': 'postgresql', 'target': {'app': 'db'}}]}}}
    return {'site': {'node': owner['node']}, 'guest': {'vmid': owner['vmid'], 'hostname': owner['hostname'],
            'volumes': {'data': {'path': '/srv/example', 'backup': True}}},
        'deployment': {'applications': {'app': {'id': 'app', 'adapter': 'unbound'}}},
        'app': {'packages': ['proxmox-backup-client=4.2.8-1'], 'backup': inventory}}


class BackupAgentTests(unittest.TestCase):
    def test_closed_inventory_renders_without_reading_sources_or_opening_network(self):
        cfg = fixture(); before = copy.deepcopy(cfg)
        value = backup_agent.configuration(cfg)
        self.assertEqual(value['package'], 'proxmox-backup-client=4.2.8-1')
        self.assertEqual(json.loads(value['inventory']), cfg['app']['backup'])
        self.assertEqual(cfg, before)
        self.assertNotIn('complete', value['inventory'])

    def test_receiver_refuses_foreign_identities_missing_apps_and_unclassified_data(self):
        changes = [lambda v: v['app']['backup'].update(schema='other'),
            lambda v: v['app']['backup'].update(command='PRIVATE_SENTINEL'),
            lambda v: v['app']['backup']['owner'].update(vmid=611),
            lambda v: v['app']['backup']['applications'].clear(),
            lambda v: v['app']['backup']['applications']['app'].update(adapter='mariadb'),
            lambda v: v['app']['backup']['applications']['app'].update(runtime_files='not-a-list'),
            lambda v: v['app']['backup']['applications']['app']['runtime_files'].append('/bad/../file'),
            lambda v: v['app']['backup']['applications']['app'].update(databases={}),
            lambda v: v['app']['backup']['applications']['app']['storage']['state'].update(kind='device'),
            lambda v: v['app']['backup']['applications']['app']['storage']['state'].update(capture='files'),
            lambda v: v['app']['backup']['applications']['app']['storage']['database'].update(include=True),
            lambda v: v['app']['backup']['applications']['app']['storage']['logs'].update(include=True),
            lambda v: v['app']['backup']['applications']['app']['storage']['logs'].update(reason='unknown'),
            lambda v: v['app']['backup']['applications']['app']['databases'][0].update(type='shell'),
            lambda v: v['app']['backup'].update(configuration=[]),
            lambda v: v['app']['backup']['configuration']['ssh'].update(path='/'),
            lambda v: v['app']['backup']['configuration']['ssh'].update(kind='device'),
            lambda v: v['app']['backup']['managed_volumes']['data'].update(include=False),
            lambda v: v['app'].update(packages=[]),
            lambda v: v['app'].update(packages=['proxmox-backup-client=latest'])]
        for change in changes:
            cfg = fixture(); change(cfg)
            with self.subTest(case=changes.index(change)), self.assertRaises(ValueError) as caught:
                backup_agent.configuration(cfg)
            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))


if __name__ == '__main__': unittest.main()
