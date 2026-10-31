"""Explicit named contracts preserve per-guest values through every workflow edge."""

import json
from pathlib import Path
import re
import tempfile
import unittest

import yaml
import workflows

ROOT = Path(__file__).resolve().parents[1]
COMMON = {'APPLICATION_SSH_KEY', 'PROXMOX_APP_TOKEN'}
OWNED = {
    'automation': {'AUTOMATION_NODE_RED_API_TOKEN'},
    'identity': {'FOUNDATION_AUTHENTIK_POSTGRES_PASSWORD', 'FOUNDATION_AUTHENTIK_SECRET_KEY', 'FOUNDATION_AUTHENTIK_SMTP_PASSWORD'},
    'db-tools': {'FOUNDATION_PGADMIN_OAUTH_SECRET'},
    'ingress': {'FOUNDATION_CLOUDFLARE_DNS_TOKEN'},
}
SMTP = 'FOUNDATION_AUTHENTIK_SMTP_PASSWORD'
ALL_NAMES = COMMON | set().union(*OWNED.values())
ALIASES = {
    'NODE_RED_API_TOKEN': 'AUTOMATION_NODE_RED_API_TOKEN',
    'AUTHENTIK_SECRET_KEY': 'FOUNDATION_AUTHENTIK_SECRET_KEY',
    'AUTHENTIK_POSTGRES_PASSWORD': 'FOUNDATION_AUTHENTIK_POSTGRES_PASSWORD',
    'AUTHENTIK_SMTP_PASSWORD': 'FOUNDATION_AUTHENTIK_SMTP_PASSWORD',
    'PGADMIN_OAUTH_SECRET': 'FOUNDATION_PGADMIN_OAUTH_SECRET',
    'CLOUDFLARE_DNS_TOKEN': 'FOUNDATION_CLOUDFLARE_DNS_TOKEN',
}


def call(values, job, target):
    """Model named presence separately from values; no platform/native execution."""
    declarations = target['on']['workflow_call']['secrets']
    forwarding = job['secrets']
    if not isinstance(forwarding, dict) or not set(forwarding) <= set(declarations):
        raise ValueError('Named forwarding must match declared secrets')
    if not {name for name, flags in declarations.items() if flags['required']} <= set(forwarding):
        raise ValueError('Missing required caller secret name')
    result = {}
    for name, expression in forwarding.items():
        match = re.fullmatch(r'\$\{\{ secrets\.([A-Z_]+) \}\}', expression)
        if not match or match[1] != name:
            raise ValueError('Forward each named secret from its same fixed source')
        result[name] = values.get(name, '')
    return result


class NamedSecretWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        spec = {'schema': 'homelab-stack-v2', 'values': {}, 'routes': {},
                'guests': {name: {'depends_on': [], 'prerequisites': []} for name in workflows.compiler.CATALOGUE}}
        (self.root / 'stack.json').write_text(json.dumps(spec))
        phase = self.root / '.github/workflows/phase.yml'
        phase.parent.mkdir(parents=True)
        phase.write_text('jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@' + '1' * 40 + '\n')
        self.models = workflows.models(self.root)
        self.framework = {'on': workflows.workflow_call(phase=True)}

    def test_checked_in_framework_contract_and_generic_wrappers_match_one_authority(self):
        actual = yaml.load((ROOT / '.github/workflows/guest-phase.yml').read_text(), Loader=yaml.BaseLoader)
        expected = yaml.load(yaml.safe_dump(workflows.workflow_call(phase=True)), Loader=yaml.BaseLoader)
        self.assertEqual(actual['on'], expected)
        for target in [self.models['deploy.yml'], self.models['phase.yml'], self.framework]:
            declared = target['on']['workflow_call']['secrets']
            self.assertEqual(set(declared), ALL_NAMES)
            self.assertEqual({name for name, flags in declared.items() if flags['required']}, COMMON)
        self.assertEqual(actual['jobs']['run']['environment'], '${{ inputs.environment_name }}')
        self.assertNotIn('secrets', self.models['deploy.yml']['jobs']['selection'])
        self.assertNotIn('environment', self.models['deploy.yml']['jobs']['selection'])

    def test_all_declared_guests_keep_effective_step_only_secret_values(self):
        self.assertEqual(set(self.models) - {"deploy.yml", "phase.yml"},
                         {"guest-" + name + ".yml" for name in workflows.compiler.CATALOGUE})
        for smtp_present in (False, True):
            available = {name: 'invented-' + name for name in ALL_NAMES}
            available.update(PEGAPROX_ADMIN_PASSWORD='unselected', PEGAPROX_DB_KEY='unselected')
            names = ALL_NAMES if smtp_present else ALL_NAMES - {SMTP}
            private_map = {name: '${{ secrets.' + name + ' }}' for name in names}
            aggregate = call(available, {'secrets': private_map}, self.models['deploy.yml'])
            for guest, blueprint in workflows.compiler.CATALOGUE.items():
                with self.subTest(guest=guest, smtp_present=smtp_present):
                    required_scope = COMMON | OWNED.get(guest, set())
                    guest_model = self.models['guest-' + guest + '.yml']
                    declarations = guest_model['on']['workflow_call']['secrets']
                    self.assertEqual(set(declarations), required_scope)
                    self.assertEqual({name for name, flags in declarations.items() if flags['required']}, required_scope - {SMTP})
                    guest_values = call(aggregate, self.models['deploy.yml']['jobs'][guest], guest_model)
                    self.assertEqual(set(guest_values), required_scope)
                    self.assertEqual(set(guest_model['jobs']), {'deploy'})
                    job = guest_model['jobs']['deploy']
                    for index, phase in enumerate(['infrastructure', 'preparation', *blueprint['applications']]):
                        steps = job['steps'][6 + index * 3:9 + index * 3]
                        self.assertNotIn('secrets', job)
                        self.assertEqual(set(job['env']), {'HOMELAB_DEPLOYMENT_WORKFLOW'})
                        credential = steps[1]['env']
                        self.assertEqual({key for key in credential if key not in {'GUEST', 'PHASE'}}, COMMON)
                        final_values = {key: guest_values.get(key, '') for key in COMMON}
                        for key, expression in steps[2]['env'].items():
                            if key in {'GUEST', 'PHASE'}: continue
                            match = re.fullmatch(r"\$\{\{ '([a-z0-9-]+)' == '([a-z-]+)' && (?:secrets\.([A-Z_]+)|'') \|\| '' \}\}", expression)
                            self.assertIsNotNone(match)
                            actual_guest, owner, selected_name = match.groups()
                            name = ALIASES[key]
                            self.assertEqual(actual_guest, guest)
                            self.assertIn(name, OWNED[owner])
                            if selected_name is None:
                                self.assertNotEqual(actual_guest, owner)
                                self.assertNotIn(name, required_scope)
                            else:
                                self.assertEqual(selected_name, name)
                                self.assertIn(name, required_scope)
                            final_values[name] = guest_values.get(name, '') if actual_guest == owner else ''
                        self.assertEqual(set(final_values), ALL_NAMES)
                        expected_present = required_scope & names
                        self.assertEqual({name for name, value in final_values.items() if value}, expected_present)
                        self.assertEqual({name: final_values[name] for name in expected_present},
                                         {name: available[name] for name in expected_present})
                        self.assertEqual(steps[0]['env']['PHASE'], phase)
                        self.assertEqual(steps[0]['env']['GUEST'], guest)
                        self.assertEqual(final_values[SMTP], available[SMTP] if smtp_present and guest == 'identity' else '')

    def test_missing_name_is_refused_but_empty_values_remain_runtime_admission(self):
        guest = self.models['guest-automation.yml']
        job = dict(self.models['deploy.yml']['jobs']['automation'])
        job['secrets'] = dict(job['secrets'])
        job['secrets'].pop('AUTOMATION_NODE_RED_API_TOKEN')
        with self.assertRaisesRegex(ValueError, 'Missing required caller secret name'):
            call({}, job, guest)
        forwarded = call({}, self.models['deploy.yml']['jobs']['automation'], guest)
        self.assertEqual(set(forwarded.values()), {''})
        # Existing runtime binding still rejects empty selected-kind token values.
        import sys
        sys.path.insert(0, str(ROOT / 'proxmox/applications'))
        import runtime_secrets
        with self.assertRaisesRegex(ValueError, 'retained Node-RED'):
            runtime_secrets.prepare_stack({'app': {'kind': 'automation'}}, {'services': {'node_red': {}}}, self.root, forwarded)
        for invalid in ['inherit', {'PEGAPROX_DB_KEY': '${{ secrets.PEGAPROX_DB_KEY }}'}, {'APPLICATION_SSH_KEY': '${{ secrets.PROXMOX_APP_TOKEN }}'}]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                call({}, {'secrets': invalid}, self.framework)
