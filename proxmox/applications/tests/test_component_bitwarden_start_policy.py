"""Real Ansible task/argv rendering; no task, Docker or connection executes."""
import copy
import itertools
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ANSIBLE = Path(__file__).resolve().parents[1] / 'ansible'
COMPOSE = ANSIBLE / 'tasks/component-compose.yml'
sys.path[:0] = [str(ANSIBLE.parent), str(ANSIBLE.parents[2] / 'blueprints')]
import component_runtime
from test_component_edges import descriptor, guest


def tasks(blocks):
    from ansible.playbook.block import Block
    for block in blocks:
        for task in block.block:
            if isinstance(task, Block):
                yield from tasks([task])
            else:
                yield task


class BitwardenStartPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='vault-start-policy-')
        cls.addClassCleanup(temporary.cleanup)
        boundary = patch.dict(os.environ, {
            'ANSIBLE_LOCAL_TEMP': str(Path(temporary.name).resolve()),
            'ANSIBLE_CONFIG': str(ANSIBLE / 'ansible.cfg')})
        boundary.start(); cls.addClassCleanup(boundary.stop)

    def setUp(self):
        # Resolve the executor import before denying processes: Ansible's
        # platform setup may locate libc during import, never during a task.
        for target in ('ansible.executor.task_executor.TaskExecutor.run',
                       'subprocess.Popen', 'socket.create_connection', 'socket.socket.connect'):
            boundary = patch(target, side_effect=AssertionError('No task/process/connection execution'))
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
        self.play = Playbook.load(str(ANSIBLE / 'component-reconcile.yml'),
            variable_manager=self.manager, loader=self.loader).get_plays()[0]
        include = next(t for t in tasks(self.play.tasks)
                       if t.name == 'Reconcile the selected Compose services')
        self.compose = self.included(include, COMPOSE)
        self.rows = list(tasks([self.compose]))
        self.start = self.one(self.rows, "Start only this application's owned services")
        self.ready_include = self.one(self.rows, 'Preserve the vault database login')
        self.ready = self.included(self.ready_include, ANSIBLE / 'tasks/component-bitwarden-ready.yml')

    def included(self, include, path):
        from ansible.playbook.block import Block
        return Block.load(self.loader.load_from_file(str(path), trusted_as_template=True),
            play=self.play, task_include=include, variable_manager=self.manager, loader=self.loader)

    def one(self, rows, name):
        return next(t for t in rows if t.name == name)

    def template(self, task, values):
        from ansible.template import Templar
        variables = self.manager.get_vars(play=self.play, host=self.host, task=task)
        variables.update(copy.deepcopy(values))
        return Templar(loader=self.loader, variables=variables)

    def evaluate(self, task, expression, values):
        from ansible.template import trust_as_template
        return self.template(task, values).evaluate_expression(trust_as_template(expression))

    def argv(self, adapter, *, services=None, overlay=False, changes=None):
        values = {'component_application': {'adapter': adapter},
                  'component_compose_file': '/opt/homelab-app/owned-compose.yml',
                  'component_services': services or ['selected'],
                  'component_runtime_install': {}, 'component_environment_install': {},
                  'component_driver_install': {}}
        if overlay:
            values['component_environment_file'] = '/opt/homelab-app/owned-environment.yml'
        values.update(changes or {})
        fact = self.one(self.rows, "Select this application's Compose files")
        # The first task with this name is an include, the second is set_fact.
        fact = next(t for t in self.rows if t.name == fact.name and t.action == 'ansible.builtin.set_fact')
        values['component_compose_argv'] = self.template(fact, values).template(fact.args['component_compose_argv'])
        return self.template(self.start, values).template(self.start.args['argv'])

    def test_normal_selected_digest_uses_common_pull_policy_without_start_override(self):
        app = descriptor('bitwarden')
        rendered = component_runtime._bitwarden(app, guest('bitwarden'))['bitwarden']
        self.assertEqual(rendered['image'], app['software_selection']['images']['bitwarden']['image'])
        self.assertEqual(rendered['pull_policy'], 'missing')
        self.assertEqual(rendered['healthcheck'], {
            'test': ['CMD-SHELL', 'curl -fsSo /dev/null http://localhost:8080']})
        argv = self.argv(app['adapter'], services=['owned-vault'])
        self.assertEqual(argv, ['docker', 'compose', '-f', '/opt/homelab-app/owned-compose.yml',
            'up', '-d', '--wait', '--wait-timeout', '180', '--remove-orphans=false',
            '--no-deps', 'owned-vault'])
        self.assertNotIn('peer', argv)

    def test_database_before_start_guard_remains_and_no_image_mapper_task_exists(self):
        self.assertLess(self.rows.index(self.ready_include), self.rows.index(self.start))
        self.assertEqual(self.ready_include.args['_raw_params'], 'component-bitwarden-ready.yml')
        self.assertTrue(self.evaluate(self.ready_include, self.ready_include.when[0], {'component_bitwarden': {}}))
        self.assertFalse(self.evaluate(self.ready_include, self.ready_include.when[0], {}))
        rows=list(tasks([self.ready]))
        self.assertEqual([t.action for t in rows],['ansible.builtin.copy','ansible.builtin.include_tasks'])
        check=self.one(rows,'Verify the retained vault database before startup')
        self.assertEqual(check.args['_raw_params'],'bitwarden-database.yml')
        settings={'schema':'homelab-bitwarden-runtime-v2'};environment={'only':'synthetic'}
        values={'component_bitwarden':{'settings':settings,'environment':environment}}
        self.assertEqual(self.template(check,values).template(check.vars['bitwarden_settings']),settings)
        self.assertEqual(self.template(check,values).template(check.vars['bitwarden_environment']),environment)
        self.assertTrue(all('image'not in str(t.args)for t in rows))

    def test_other_adapters_and_owned_service_recreation_argv_remain_exact(self):
        for adapter, overlay, flags in itertools.product(sorted(component_runtime.HANDLERS), (False, True),
                                                        itertools.product((False, True), repeat=3)):
            with self.subTest(adapter=adapter, overlay=overlay, changed=flags):
                changes = {key: {'changed': flag} for key, flag in zip(
                    ('component_runtime_install', 'component_environment_install', 'component_driver_install'), flags)}
                argv = self.argv(adapter, services=['owned-a', 'owned-b'], overlay=overlay, changes=changes)
                expected = ['docker', 'compose', '-f', '/opt/homelab-app/owned-compose.yml']
                if overlay:
                    expected += ['-f', '/opt/homelab-app/owned-environment.yml']
                expected += ['up', '-d', '--wait', '--wait-timeout', '180', '--remove-orphans=false', '--no-deps']
                if any(flags):
                    expected += ['--force-recreate']
                expected += ['owned-a', 'owned-b']
                self.assertEqual(argv, expected)
                self.assertNotIn('peer', argv)

    def test_private_validation_peer_verification_and_health_controls_are_preserved(self):
        config = self.one(self.rows, 'Validate without emitting private configuration')
        self.assertTrue(config.no_log); self.assertIs(config.changed_when, False)
        self.assertTrue(self.start.no_log)
        self.assertEqual(set(self.start.register), {'component_start'})
        self.assertEqual(self.start.changed_when, "'Started' in component_start.stderr or 'Created' in component_start.stderr or 'Recreated' in component_start.stderr")
        peer = self.one(self.rows, 'Verify peer continuity')
        self.assertGreater(self.rows.index(peer), self.rows.index(self.start))
        self.assertTrue(peer.no_log); self.assertIs(peer.changed_when, False)
        health = self.one(list(tasks(self.play.tasks)), 'Check this application')
        self.assertTrue(health.no_log); self.assertIs(health.changed_when, False)
        self.assertEqual(health.failed_when, "component_health.rc != 0 or (item.expect | default('')) not in component_health.stdout")
        for name in ('Install only the selected private environment', 'Install selected runtime files',
                     'Keep the factory-password frontend guest-local until configuration'):
            self.assertTrue(self.one(self.rows, name).no_log)


if __name__ == '__main__':
    unittest.main()
