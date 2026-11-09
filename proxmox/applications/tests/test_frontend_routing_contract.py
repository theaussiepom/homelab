"""Render real routing tasks and refuse foreign paths/units without executing them."""
import base64
import configparser
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ingress_routing

ANSIBLE = Path(__file__).resolve().parents[1] / 'ansible'


def tasks(blocks):
    """Traverse Ansible's actual imported blocks without running an executor."""
    from ansible.playbook.block import Block
    for block in blocks:
        for task in block.block:
            if isinstance(task, Block):
                yield from tasks([task])
            else:
                yield task


class FrontendRoutingContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Keep Ansible's own controller temporary files inside an owned fixture."""
        temporary = tempfile.TemporaryDirectory(prefix='frontend-routing-contract-')
        cls.addClassCleanup(temporary.cleanup)
        boundary = patch.dict(os.environ, {
            'ANSIBLE_LOCAL_TEMP': str(Path(temporary.name).resolve()),
            'ANSIBLE_CONFIG': str(ANSIBLE / 'ansible.cfg')})
        boundary.start(); cls.addClassCleanup(boundary.stop)

    def setUp(self):
        """Load actual playbook syntax while denying task/process/network execution."""
        for target in ('ansible.executor.task_executor.TaskExecutor.run',
                       'subprocess.Popen', 'socket.create_connection', 'socket.socket.connect'):
            boundary = patch(target, side_effect=AssertionError('No native task/process/network'))
            boundary.start(); self.addCleanup(boundary.stop)
        from ansible.plugins.loader import init_plugin_loader
        from ansible.parsing.dataloader import DataLoader
        from ansible.inventory.manager import InventoryManager
        from ansible.vars.manager import VariableManager
        from ansible.playbook import Playbook
        from ansible.utils.collection_loader import AnsibleCollectionConfig
        if AnsibleCollectionConfig.collection_finder is None:
            init_plugin_loader()
        self.loader = DataLoader()
        inventory = InventoryManager(loader=self.loader, sources=['fixture,'])
        inventory.add_group('application'); inventory.add_host('fixture', group='application')
        self.host = inventory.get_host('fixture')
        self.manager = VariableManager(loader=self.loader, inventory=inventory)
        self.play = Playbook.load(str(ANSIBLE / 'component-preparation.yml'),
            variable_manager=self.manager, loader=self.loader).get_plays()[0]
        self.rows = list(tasks(self.play.tasks))
        self.settings = {'address': '10.88.40.33/24', 'gateway': '10.88.40.1',
                         'mac': '02:00:00:00:40:33'}

    def one(self, name):
        """Select a uniquely named actual task, never an invented test implementation."""
        return next(task for task in self.rows if task.name == name)

    def template(self, task, values):
        """Use Ansible's real trusted templating for task arguments and assertions."""
        from ansible.template import Templar
        variables = self.manager.get_vars(play=self.play, host=self.host, task=task)
        variables.update(copy.deepcopy(values))
        return Templar(loader=self.loader, variables=variables)

    def evaluate(self, task, expression, values):
        """Evaluate one actual conditional with explicit synthetic inputs."""
        from ansible.template import trust_as_template
        return self.template(task, values).evaluate_expression(trust_as_template(expression))

    def that(self, name, values):
        """Evaluate every assertion from the real task, preserving undefined failures."""
        task = self.one(name)
        expressions = task.args['that']
        if isinstance(expressions, str): expressions = [expressions]
        return all(self.evaluate(task, expression, values) for expression in expressions)

    def test_selection_and_preparation_only_mutation_keep_other_guests_untouched(self):
        """The existing source selection gates configuration and later verification."""
        ready = self.one('Verify existing frontend reply routing without changing it')
        install = self.one('Install the selected add-only frontend helper')
        for selected in (False, True):
            for preparation in (False, True):
                values = {'app': {'frontend_routing': self.settings} if selected else {}}
                if preparation: values['component_preparation_app'] = values['app']
                admitted = all(self.evaluate(install, expression, values) for expression in install.when)
                self.assertEqual(admitted, selected and preparation)
                self.assertEqual(all(self.evaluate(ready, expression, values) for expression in ready.when), selected)

    def test_existing_paths_refuse_symlinks_foreign_owners_modes_and_hardlinks(self):
        """Do not repair foreign metadata or follow a file outside the fixed owner."""
        task = self.one('Inspect the fixed owned frontend paths without following links')
        self.assertIs(task.args['follow'], False)
        self.assertEqual({row['path'] for row in task.loop}, {
            '/opt/homelab-app', '/opt/homelab-app/ingress-routing.py',
            '/opt/homelab-app/frontend-routing.json', '/etc/systemd/system/homelab-frontend-routing.service'})
        name = 'Refuse foreign frontend paths or file ownership'
        for row in task.loop:
            status = {'exists': True, 'islnk': False, 'uid': 0, 'gid': 0,
                      'mode': row['modes'][0], 'nlink': 1,
                      'isdir': row['kind'] == 'directory', 'isreg': row['kind'] == 'file'}
            self.assertTrue(self.that(name, {'item': {'item': row, 'stat': status}}))
            self.assertTrue(self.that(name, {'item': {'item': row, 'stat': {'exists': False}}}))
            changes = [('islnk', True), ('uid', 1000), ('gid', 1000), ('mode', '0777')]
            changes += [('isdir', False)] if row['kind'] == 'directory' else [('isreg', False), ('nlink', 2)]
            for key, value in changes:
                with self.subTest(path=row['path'], key=key):
                    self.assertFalse(self.that(name, {'item': {'item': row, 'stat': dict(status, **{key: value})}}))

    def test_existing_settings_are_preserved_and_new_settings_use_actual_validator(self):
        """Keep the selected tuple and existing bytes instead of converting an owner."""
        name = 'Preserve the selected frontend address gateway and MAC'
        values = {'app': {'frontend_routing': self.settings}, 'frontend_settings_before': {
            'content': base64.b64encode(json.dumps(self.settings).encode()).decode()}}
        self.assertTrue(self.that(name, values))
        for key, value in [('address', '10.88.40.34/24'), ('gateway', '10.88.40.2'),
                           ('mac', '02:00:00:00:40:34')]:
            bad = copy.deepcopy(values); bad['app']['frontend_routing'][key] = value
            self.assertFalse(self.that(name, bad))
        task = self.one('Create selected frontend settings without replacing existing bytes')
        raw = self.template(task, values).template(task.args['content'])
        self.assertEqual(json.loads(raw), self.settings)
        self.assertEqual(ingress_routing.validate(json.loads(raw))[0], '10.88.40.33')
        self.assertIs(task.args['force'], False); self.assertIs(task.args['follow'], False)
        self.assertEqual(task.args['mode'], '0600')

    def test_boot_unit_orders_actual_networking_before_add_only_frontend_service(self):
        """Network-online alone cannot reproduce the required interface setup order."""
        task = self.one('Install the frontend boot service after actual interface setup')
        unit = configparser.ConfigParser(interpolation=None)
        unit.read_string(task.args['content'])
        self.assertEqual(unit['Unit']['Requires'], 'networking.service')
        self.assertIn('networking.service', unit['Unit']['After'].split())
        self.assertIn('network-online.target', unit['Unit']['After'].split())
        self.assertEqual(unit['Unit']['Before'], 'docker.service')
        self.assertNotIn('docker.service', unit['Unit']['Wants'].split())
        self.assertEqual(dict(unit['Service']), {'type': 'oneshot',
            'execstart': '/usr/bin/python3 /opt/homelab-app/ingress-routing.py --config /opt/homelab-app/frontend-routing.json --apply',
            'remainafterexit': 'yes'})
        readiness = self.one('Require the actual Debian interface setup to have completed')
        self.assertEqual(readiness.args['argv'], ['/usr/bin/systemctl', 'is-active', 'networking.service'])
        self.assertIs(readiness.changed_when, False)
        self.assertLess(self.rows.index(readiness), self.rows.index(task))

    def test_effective_unit_refuses_overrides_and_partial_or_stale_loading(self):
        """An exact owned fragment must be loaded without silently deleting drop-ins."""
        from ansible.errors import AnsibleUndefinedVariable
        from ansible.modules.systemd_service import parse_systemctl_show
        name = 'Preserve unexpected frontend overrides rather than executing them'
        # The pinned systemd_service module omits an empty DropInPaths array.
        status = parse_systemctl_show([
            'FragmentPath=/etc/systemd/system/homelab-frontend-routing.service',
            'NeedDaemonReload=no', 'Type=oneshot', 'RemainAfterExit=yes', 'Restart=no'])
        self.assertNotIn('DropInPaths', status)
        query = {'rc': 0, 'stdout': '', 'stderr': ''}
        values = {'frontend_loaded_unit': {'status': status}, 'frontend_dropins': query}
        self.assertTrue(self.that(name, values))
        for key, value in [('FragmentPath', '/run/foreign.service'),
                           ('NeedDaemonReload', 'yes'), ('Type', 'simple'),
                           ('RemainAfterExit', 'no'), ('Restart', 'always')]:
            self.assertFalse(self.that(name, dict(values,
                frontend_loaded_unit={'status': dict(status, **{key: value})})))
        for key, value in [('rc', 1), ('stdout', '/run/override.conf'), ('stderr', 'warning')]:
            self.assertFalse(self.that(name, dict(values, frontend_dropins=dict(query, **{key: value}))))
        missing = dict(status); del missing['FragmentPath']
        with self.assertRaises(AnsibleUndefinedVariable):
            self.that(name, dict(values, frontend_loaded_unit={'status': missing}))
        load = self.one('Load the selected frontend unit without starting a service')
        self.assertEqual(load.action, 'ansible.builtin.systemd_service')
        self.assertEqual(load.args, {'name': 'homelab-frontend-routing.service', 'daemon_reload': True})

    def test_native_dropin_array_omission_uses_explicit_read_only_property_query(self):
        """Request the actual empty property rather than inventing module output."""
        query = self.one('Read frontend overrides explicitly instead of assuming module status contains empty arrays')
        self.assertEqual(query.args['argv'], ['/usr/bin/systemctl', 'show', '--property=DropInPaths',
                                             '--value', 'homelab-frontend-routing.service'])
        self.assertIs(query.changed_when, False)
        self.assertFalse(query.failed_when)
        self.assertLess(self.rows.index(self.one('Load the selected frontend unit without starting a service')),
                        self.rows.index(query))
        self.assertLess(self.rows.index(query), self.rows.index(
            self.one('Reconcile only missing declared frontend routes and read them back')))

    def test_immediate_reconcile_and_enable_never_restart_a_workload(self):
        """Perform a single add-only reconcile and retain a separate read-only check."""
        apply = self.one('Reconcile only missing declared frontend routes and read them back')
        verify = self.one('Verify existing frontend reply routing without changing it')
        expected = ['python3', '/opt/homelab-app/ingress-routing.py', '--config', '/opt/homelab-app/frontend-routing.json']
        self.assertEqual(apply.args['argv'], expected + ['--apply'])
        self.assertEqual(verify.args['argv'], expected)
        for changed in (False, True):
            self.assertIs(self.evaluate(apply, apply.changed_when,
                {'frontend_reconciled': {'stdout': json.dumps({'changed': changed})}}), changed)
        self.assertIs(verify.changed_when, False)
        enable = self.one('Enable the verified frontend boot service without restarting workloads')
        self.assertEqual(enable.args, {'name': 'homelab-frontend-routing.service', 'enabled': True, 'state': 'started'})
        self.assertLess(self.rows.index(apply), self.rows.index(enable))
        self.assertLess(self.rows.index(enable), self.rows.index(verify))
        routed = [task for task in self.rows if task.name in {apply.name, enable.name,
                  'Load the selected frontend unit without starting a service'}]
        self.assertTrue(all('restarted' not in str(task.args) and 'docker.service' not in str(task.args) for task in routed))


if __name__ == '__main__':
    unittest.main()
