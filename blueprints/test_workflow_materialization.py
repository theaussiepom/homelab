"""Direct guest jobs preserve the frozen native recipe and the full declared graph."""

import copy
import hashlib
import itertools
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml
import workflows

DEPENDENCIES = {
    "dns": [], "ingress": ["dns"], "postgresql": ["dns"], "mariadb": ["dns"], "influxdb": ["dns"],
    "identity": ["postgresql", "ingress"], "db-tools": ["postgresql", "ingress", "identity"],
    "automation": ["ingress", "identity", "mariadb", "influxdb"],
    "bitwarden": ["ingress", "mariadb"], "pegaprox": ["dns"], "zigbee2mqtt": ["automation"],
}
PHASES = {
    guest: ["infrastructure", "preparation", *applications]
    for guest, applications in {
        "dns": ["unbound", "pihole"], "ingress": ["traefik"], "postgresql": ["postgresql"],
        "mariadb": ["mariadb"], "influxdb": ["influxdb"], "identity": ["authentik"],
        "db-tools": ["pgadmin"], "automation": ["mqtt", "homeassistant", "node_red"],
        "bitwarden": ["bitwarden"], "pegaprox": ["pegaprox"], "zigbee2mqtt": ["zigbee2mqtt"],
    }.items()
}
OWNED_SECRETS = {
    "automation": {"AUTOMATION_NODE_RED_API_TOKEN"},
    "identity": {"FOUNDATION_AUTHENTIK_POSTGRES_PASSWORD", "FOUNDATION_AUTHENTIK_SECRET_KEY", "FOUNDATION_AUTHENTIK_SMTP_PASSWORD"},
    "db-tools": {"FOUNDATION_PGADMIN_OAUTH_SECRET"},
    "ingress": {"FOUNDATION_CLOUDFLARE_DNS_TOKEN"},
}
APP_LABELS = {"unbound": "Unbound", "pihole": "Pi-hole", "mqtt": "MQTT", "homeassistant": "Home Assistant", "node_red": "Node-RED"}
FROZEN_LEAF_SHA256 = "796acf6dc7cf5bea710a75e78d540ea5540ddbe7e18ed9aa5846a785b86ec6ac"


def fixture(root):
    (root / "stack.json").write_text(json.dumps({"schema": "homelab-stack-v2", "values": {}, "routes": {},
        "guests": {name: {"depends_on": needs, "prerequisites": []} for name, needs in DEPENDENCIES.items()}}))
    phase = root / ".github/workflows/phase.yml"; phase.parent.mkdir(parents=True)
    phase.write_text("jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@" + "1" * 40 + "\n")
    selected = root / 'guests/automation/profile.json'; selected.parent.mkdir(parents=True)
    selected.write_text(json.dumps({'config': {'app': {'service_health_checks': {'mqtt': []}}}}))


def legacy_models(root):
    catalogue = {name: copy.deepcopy(workflows.compiler.CATALOGUE[name]) for name in DEPENDENCIES}
    with patch.object(workflows.compiler, 'CATALOGUE', catalogue):
        return workflows.models(root)


def document(path):
    value = yaml.safe_load(path.read_text())
    if True in value: value["on"] = value.pop(True)
    return value


def phase_steps(guest, phase):
    """Read actual selected action; substitute inputs without the production binder."""
    steps = document(workflows.PHASE_RECIPE.parents[1]/'actions/guest-phase/action.yml')['runs']['steps']
    for step in steps:
        for key,value in step.get('env',{}).items():
            value=value.replace('${{ inputs.guest }}',guest).replace('${{ inputs.phase }}',phase)
            value=value.replace('inputs.guest',repr(guest))
            value=re.sub(r'inputs\.([A-Z_]+)',r'secrets.\1',value)
            step['env'][key]=value
    return steps


class MaterializationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); fixture(self.root)
        # Keep this exact old11-service equivalence oracle while new catalogue
        # members have their own current-graph tests. The old shared broker stays selected.
        catalogue = {name: copy.deepcopy(workflows.compiler.CATALOGUE[name]) for name in DEPENDENCIES}
        original = patch.object(workflows.compiler, 'CATALOGUE', catalogue)
        original.start(); self.addCleanup(original.stop)
        self.original = document(workflows.PHASE_RECIPE)
        self.models = workflows.models(self.root)

    def expected_phase(self, guest, phase, display):
        return {'name': display, 'uses': 'example/framework/.github/actions/guest-phase@' + '1'*40,
                'timeout-minutes': 45, 'with': {'guest': guest, 'phase': phase,
                'disabled': '${{ inputs.disabled }}', **{key: '${{ secrets.' + key + ' }}'
                    for key in {'APPLICATION_SSH_KEY', 'PROXMOX_APP_TOKEN'} | OWNED_SECRETS.get(guest, set())}}}

    def verify(self, models):
        jobs = phases_count = phase_bodies = 0
        self.assertEqual(set(models), {"deploy.yml", "phase.yml"} | {"guest-" + g + ".yml" for g in PHASES})
        deploy = copy.deepcopy(models["deploy.yml"])
        self.assertEqual(deploy["name"], "Deployment")
        self.assertEqual(deploy["jobs"]["selection"]["name"], "Check guests")
        self.assertEqual(deploy["jobs"]["selection"]["steps"][0]["name"], "Check guests")
        # The requested guest label changes no frozen deployment operation.
        self.assertEqual(deploy["jobs"]["automation"]["name"], "Home Automation")
        deploy["jobs"]["automation"]["name"] = "Automation"
        self.assertEqual(deploy['jobs']['zigbee2mqtt']['name'], 'Radios')
        deploy['jobs']['zigbee2mqtt']['name'] = 'Zigbee2MQTT'
        # Only these human labels differ from the frozen pre-fallback parent.
        deploy["name"] = "HomeLab stack"
        deploy["jobs"]["selection"]["name"] = "Validate guest selection"
        deploy["jobs"]["selection"]["steps"][0]["name"] = "Reject invalid exclusions before the guest graph"
        for name, doc, expected in (
            ("deploy.yml", deploy, "25e75b272d2b8ee77d72025da7af8fb69851e7749c2ad71aa58898e26015d33c"),
            ("phase.yml", models["phase.yml"], "b5b1a7ca44fbe22dbf860dc057e02154789dd68b8149161fe9c98729e501165b"),
        ):
            raw = workflows.HEADER + yaml.safe_dump(doc, sort_keys=False, width=1000, allow_unicode=True)
            self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(), expected, name)
        names = ("Check readiness", "Get settings", "Choose services", "Get services", "Choose tools", "Get tools")
        for guest, phases in PHASES.items():
            workflow = models["guest-" + guest + ".yml"]
            self.assertEqual(set(workflow), {"name", "on", "permissions", "defaults", "jobs"})
            expected_call = copy.deepcopy(self.original["on"])
            for key in ("guest", "phase"): expected_call["workflow_call"]["inputs"].pop(key)
            scope = {"APPLICATION_SSH_KEY", "PROXMOX_APP_TOKEN"} | OWNED_SECRETS.get(guest, set())
            expected_call["workflow_call"]["secrets"] = {key: {"required": key != "FOUNDATION_AUTHENTIK_SMTP_PASSWORD"} for key in scope}
            self.assertEqual(workflow["on"], expected_call)
            self.assertEqual(list(workflow["jobs"]), ["deploy"])
            self.assertEqual(workflow["defaults"], self.original["defaults"])
            self.assertEqual(workflow["permissions"], self.original["permissions"])
            self.assertEqual(models["deploy.yml"]["jobs"][guest]["needs"], ["selection", *DEPENDENCIES[guest]])
            job = workflow["jobs"]["deploy"]
            expected = copy.deepcopy(self.original["jobs"]["run"])
            expected["name"] = workflows.compiler.CATALOGUE[guest]['name']
            expected["timeout-minutes"] = 45 * len(phases)
            expected["if"] = expected["if"].replace("inputs.guest", repr(guest))
            expected['steps'] = [{'name': 'Setup',
                'uses': 'example/framework/.github/actions/guest-setup@' + '1'*40, 'timeout-minutes':45}]
            names = dict(workflows.compiler.CATALOGUE[guest]['application_names'],
                         **workflows.compiler.CATALOGUE[guest].get('optional_applications',{}))
            for phase in phases:
                display = {'infrastructure':'Infrastructure','preparation':'Prepare'}.get(phase, names.get(phase))
                expected['steps'].append(self.expected_phase(guest, phase, display))
                phases_count += 1; phase_bodies += 3
            self.assertEqual(job, expected)
            self.assertFalse({'uses','with','secrets','needs'} & set(job))
            self.assertEqual(len(job['steps']), 1 + len(phases))
            self.assertTrue(all('if' not in s and 'continue-on-error' not in s and 'env' not in s for s in job['steps']))
            jobs += 1
        self.assertEqual((jobs, phases_count, phase_bodies), (11, 36, 108))

    def test_all11_guest_jobs_preserve36_ordered_phases_and_qualified_setup(self):
        self.assertEqual(hashlib.sha256(workflows.PHASE_RECIPE.read_bytes()).hexdigest(), FROZEN_LEAF_SHA256)
        self.verify(self.models)
        self.assertEqual(sum(len(w['jobs']['deploy']['steps']) for n,w in self.models.items() if n.startswith('guest-')),47)

    def test_all2048_exclusion_subsets_match_the_existing_selection_gate(self):
        step = self.models["deploy.yml"]["jobs"]["selection"]["steps"][0]
        code = step["run"].split("\n", 1)[1].rsplit("PYCODE", 1)[0]
        valid = 0
        for flags in itertools.product((False, True), repeat=11):
            disabled = [name for name, flag in zip(DEPENDENCIES, flags) if flag]
            enabled = set(DEPENDENCIES) - set(disabled)
            expected = all(set(DEPENDENCIES[name]) <= enabled for name in enabled)
            with patch.dict(os.environ, dict(step["env"], DISABLED=json.dumps(disabled))):
                try: exec(code, {})
                except SystemExit: actual = False
                else: actual = True
            self.assertEqual(actual, expected); valid += actual
        self.assertEqual(valid, 81)

    def test_mutations_cannot_pass_the_independent_execution_equivalence_oracle(self):
        mutations = [
            lambda m: m['guest-dns.yml']['jobs']['deploy'].update(needs='infrastructure'),
            lambda m: m['guest-dns.yml']['jobs']['deploy'].update({'if':'true'}),
            lambda m: m['guest-dns.yml']['jobs']['deploy'].update({'runs-on':'ubuntu-latest'}),
            lambda m: m['guest-dns.yml']['jobs']['deploy'].update(environment='other'),
            lambda m: m['guest-dns.yml']['jobs']['deploy'].update({'timeout-minutes':90}),
            lambda m: m['guest-automation.yml']['jobs']['deploy'].update({'timeout-minutes':45}),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'][0].pop('timeout-minutes'),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'][0].update({'timeout-minutes':90}),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'][2].pop('timeout-minutes'),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'][2].update({'timeout-minutes':90}),
            lambda m: m['guest-dns.yml']['permissions'].update(contents='write'),
            lambda m: m['guest-dns.yml']['defaults']['run'].update(shell='sh'),
            lambda m: m['guest-dns.yml']['on']['workflow_call']['secrets'].update(UNRELATED_SECRET={'required':True}),
            lambda m: m['phase.yml']['jobs']['run'].update(uses='example/other@main'),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'][-1].update(run='true'),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'][-1]['with'].update(phase='unbound'),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'].pop(),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'].insert(2,m['guest-dns.yml']['jobs']['deploy']['steps'].pop(1)),
            lambda m: m['deploy.yml']['jobs']['automation'].update(needs=['selection']),
            lambda m: m['guest-automation.yml']['jobs']['deploy']['env'].update(NODE_RED_API_TOKEN='unexpected'),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'][2].update({'if':'always()'}),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'][2].update({'continue-on-error':True}),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'][0].update(uses='example/framework/.github/actions/guest-setup@main'),
            lambda m: m['guest-dns.yml']['jobs']['deploy']['steps'][1]['with'].update(FOREIGN='${{ secrets.FOREIGN }}'),
        ]
        for index, mutate in enumerate(mutations):
            model = copy.deepcopy(self.models); mutate(model)
            with self.subTest(index=index), self.assertRaises(AssertionError): self.verify(model)

    def test_selected_undeclared_secret_cannot_be_folded_to_empty(self):
        with self.assertRaisesRegex(ValueError, "selected application credential"):
            workflows.bind_phase("${{ inputs.guest == 'dns' && secrets.AUTOMATION_NODE_RED_API_TOKEN || '' }}", "dns", "pihole")

    def test_unsupported_recipe_structure_policy_or_context_requires_explicit_review(self):
        mutations = [
            lambda d: d.update(env={"UNRELATED": "value"}),
            lambda d: d.update(concurrency="other"),
            lambda d: d["defaults"]["run"].update(shell="sh"),
            lambda d: d["permissions"].update(contents="write"),
            lambda d: d["jobs"].update(extra=copy.deepcopy(d["jobs"]["run"])),
            lambda d: d["jobs"]["run"].update(concurrency="other"),
            lambda d: d["jobs"]["run"]["env"].update(NEW_SECRET="value"),
            lambda d: d["jobs"]["run"].update({"if": "true"}),
            lambda d: d["jobs"]["run"].update(steps=[]),
            lambda d: d["jobs"]["run"]["steps"][0].update({"if": "true"}),
            lambda d: d["jobs"]["run"]["steps"][7]["env"].update(NEW_SECRET="value"),
            lambda d: d["jobs"]["run"]["steps"][7].update(env=None),
            lambda d: d["jobs"]["run"]["steps"][0].update(run="${{ inputs.guest }}"),
            lambda d: d["jobs"]["run"]["steps"][1].update(uses="actions/checkout@main"),
            lambda d: d["jobs"]["run"]["steps"][1].update({"with": None}),
            lambda d: d["jobs"]["run"]["steps"][0].update(run='echo "$GITHUB_JOB"'),
            lambda d: d["jobs"]["run"]["steps"][6]["env"].update(DISABLED="${{ needs.previous.outputs.value }}"),
            lambda d: d["jobs"]["run"]["steps"][6]["env"].update(GUEST="${{ inputs.guest[0] }}"),
            lambda d: d.update({True: d["on"]}),
            lambda d: d["jobs"]["run"]["steps"][2].update(run="true"),
        ]
        path = self.root / "recipe.yml"
        with patch.object(workflows, "PHASE_RECIPE", path):
            for index, mutate in enumerate(mutations):
                doc = copy.deepcopy(self.original); mutate(doc); path.write_text(yaml.safe_dump(doc))
                with self.subTest(index=index), self.assertRaises(ValueError): workflows.phase_recipe()
            path.write_text("[]")
            with self.assertRaises(ValueError): workflows.phase_recipe()
            path.unlink()
            with self.assertRaises(ValueError): workflows.phase_recipe()
            path.symlink_to(workflows.__file__)
            with self.assertRaises(ValueError): workflows.phase_recipe()
        path.unlink(); path.write_text(yaml.safe_dump(self.original))
        with patch.object(workflows, "PHASE_RECIPE", path):
            self.assertEqual(workflows.phase_recipe(check_actions=False), (self.original["jobs"]["run"], self.original["defaults"]))

    def test_shared_action_bytes_keep_the_leaf_commands_and_actual_step_secret_boundaries(self):
        setup=document(workflows.PHASE_RECIPE.parents[1]/'actions/guest-setup/action.yml')
        phase=document(workflows.PHASE_RECIPE.parents[1]/'actions/guest-phase/action.yml')
        for actual,expected in zip(setup['runs']['steps'],self.original['jobs']['run']['steps'][:6],strict=True):
            actual=copy.deepcopy(actual);actual.pop('name',None);actual.pop('shell',None)
            expected=copy.deepcopy(expected);expected.pop('name',None)
            self.assertEqual(actual,expected)
        steps=phase['runs']['steps']
        self.assertNotIn('env',steps[0]);self.assertNotIn('env',setup)
        self.assertEqual(steps[0]['run'],self.original['jobs']['run']['steps'][0]['run'])
        for actual,expected in zip(steps[1:],self.original['jobs']['run']['steps'][6:],strict=True):
            self.assertEqual(actual['run'],expected['run'])
            self.assertEqual(actual['env'],{key:value.replace('secrets.','inputs.') for key,value in expected['env'].items()})
            self.assertEqual(actual['shell'],'bash')
        self.assertEqual(set(steps[1]['env']),{'GUEST','PHASE','DISABLED'})
        self.assertEqual(set(steps[2]['env']),{'GUEST','PHASE','APPLICATION_SSH_KEY','PROXMOX_APP_TOKEN'})
        self.assertNotIn('APPLICATION_SSH_KEY',steps[3]['env'])
        self.assertNotIn('PROXMOX_APP_TOKEN',steps[3]['env'])
        self.assertEqual(set(phase['inputs'])-{'guest','phase','disabled'},set(workflows.secret_declarations()))
        # Regeneration drift must fail before materializing any guest job.
        path=self.root/'.github/workflows/guest-phase.yml';path.write_text(yaml.safe_dump(self.original))
        for name,value in [('guest-setup',setup),('guest-phase',phase)]:
            action=path.parents[1]/'actions'/name/'action.yml';action.parent.mkdir(parents=True);action.write_text(yaml.safe_dump(value))
        with patch.object(workflows,'PHASE_RECIPE',path):
            self.assertEqual(workflows.phase_recipe()[0],self.original['jobs']['run'])
            action=path.parents[1]/'actions/guest-phase/action.yml'
            phase['runs']['steps'][0]['env']={'APPLICATION_SSH_KEY':'${{ inputs.APPLICATION_SSH_KEY }}'}
            action.write_text(yaml.safe_dump(phase))
            with self.assertRaisesRegex(ValueError,'shared actions identical'):workflows.phase_recipe()

    def test_actual_flat_and_nested_setup_pins_are_closed_and_secret_free(self):
        import subprocess
        script=document(workflows.PHASE_RECIPE.parents[1]/'actions/guest-setup/action.yml')['runs']['steps'][2]['run']
        directory=self.root/'.github/workflows';directory.mkdir(exist_ok=True,parents=True)
        output=self.root/'selection-output';pin='owner/recipes/.github/workflows/deploy.yml@'+'a'*40
        for raw in ['jobs:\n  deploy:\n    uses: '+pin+'\n','env:\n  HOMELAB_STACK_SOURCE: '+pin+'\n']:
            (directory/'deploy.yml').write_text(raw);output.write_text('')
            result=subprocess.run(['bash','-e','-o','pipefail','-c',script],cwd=self.root,env=dict(os.environ,GITHUB_OUTPUT=str(output)),capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(output.read_text(),'repository=owner/recipes\nrevision='+'a'*40+'\n')
        for raw in ['', 'jobs:\n  deploy:\n    uses: '+pin.replace('a'*40,'main')+'\n',
                    'env:\n  HOMELAB_STACK_SOURCE: '+pin+'\njobs:\n  deploy:\n    uses: '+pin+'\n']:
            (directory/'deploy.yml').write_text(raw);output.write_text('')
            result=subprocess.run(['bash','-e','-o','pipefail','-c',script],cwd=self.root,env=dict(os.environ,GITHUB_OUTPUT=str(output)),capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertEqual(output.read_text(),'')
