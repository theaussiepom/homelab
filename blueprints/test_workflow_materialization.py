"""Direct guest jobs preserve the frozen native recipe and the full declared graph."""

import copy
import hashlib
import itertools
import json
import os
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
FROZEN_LEAF_SHA256 = "0834cf04bf9f8b0429100a1bec4f57e1be9eb2ed71a64b9e5b4b88d9ea152802"


def fixture(root):
    (root / "stack.json").write_text(json.dumps({"schema": "homelab-stack-v2", "values": {}, "routes": {},
        "guests": {name: {"depends_on": needs, "prerequisites": []} for name, needs in DEPENDENCIES.items()}}))
    phase = root / ".github/workflows/phase.yml"; phase.parent.mkdir(parents=True)
    phase.write_text("jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@" + "1" * 40 + "\n")


def document(path):
    value = yaml.safe_load(path.read_text())
    if True in value: value["on"] = value.pop(True)
    return value


class MaterializationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); fixture(self.root)
        self.original = document(workflows.PHASE_RECIPE)
        self.models = workflows.models(self.root)

    def expected_phase(self, guest, phase, display):
        # Independent approved-substitution oracle; no production binder reuse.
        result = copy.deepcopy(self.original["jobs"]["run"]["steps"][6:])
        for step in result: step["env"].update(GUEST=guest, PHASE=phase)
        for key, expression in result[2]["env"].items():
            if key not in {"GUEST", "PHASE"}:
                owner = expression.split(" == '", 1)[1].split("'", 1)[0]
                result[2]["env"][key] = (
                    expression.replace("inputs.guest", repr(guest)) if guest == owner
                    else "${{ " + repr(guest) + " == " + repr(owner) + " && '' || '' }}"
                )
        for step, name in zip(result, ("Check inputs", "Load credentials", display)):
            step["name"] = name
        return result

    def verify(self, models):
        jobs = phases_count = phase_bodies = 0
        self.assertEqual(set(models), {"deploy.yml", "phase.yml"} | {"guest-" + g + ".yml" for g in PHASES})
        deploy = copy.deepcopy(models["deploy.yml"])
        self.assertEqual(deploy["name"], "Deployment")
        self.assertEqual(deploy["jobs"]["selection"]["name"], "Check guests")
        self.assertEqual(deploy["jobs"]["selection"]["steps"][0]["name"], "Check guests")
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
            expected["name"] = "Deploy"
            expected["if"] = expected["if"].replace("inputs.guest", repr(guest))
            expected["steps"] = expected["steps"][:6]
            for step, name in zip(expected["steps"], names): step["name"] = name
            for phase in phases:
                display = {"infrastructure": "Update container", "preparation": "Prepare service"}.get(phase)
                if display is None:
                    display = ({"unbound": "Deploy resolver", "pihole": "Deploy DNS", "mqtt": "Deploy MQTT", "homeassistant": "Deploy Home Assistant", "node_red": "Deploy Node-RED"}[phase] if len(phases) > 3 else "Deploy service")
                expected["steps"].extend(self.expected_phase(guest, phase, display))
                phases_count += 1; phase_bodies += 3
            self.assertEqual(job, expected)
            self.assertFalse({"uses", "with", "secrets", "needs"} & set(job))
            self.assertEqual([s["id"] for s in job["steps"] if "id" in s], ["stack", "framework"])
            self.assertEqual(len(job["steps"]), 6 + 3 * len(phases))
            self.assertTrue(all("if" not in s and "continue-on-error" not in s for s in job["steps"]))
            jobs += 1
        self.assertEqual((jobs, phases_count, phase_bodies), (11, 36, 108))

    def test_all11_guest_jobs_preserve36_ordered_phases_and_qualified_setup(self):
        self.assertEqual(hashlib.sha256(workflows.PHASE_RECIPE.read_bytes()).hexdigest(), FROZEN_LEAF_SHA256)
        self.verify(self.models)
        self.assertEqual(sum(sum("run" in s for s in w["jobs"]["deploy"]["steps"]) for n, w in self.models.items() if n.startswith("guest-")), 141)

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
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"].update(needs="infrastructure"),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"].update({"if": "true"}),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"].update({"runs-on": "ubuntu-latest"}),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"].update(environment="other"),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"].update({"timeout-minutes": 90}),
            lambda m: m["guest-dns.yml"]["permissions"].update(contents="write"),
            lambda m: m["guest-dns.yml"]["defaults"]["run"].update(shell="sh"),
            lambda m: m["guest-dns.yml"]["on"]["workflow_call"]["secrets"].update(UNRELATED_SECRET={"required": True}),
            lambda m: m["phase.yml"]["jobs"]["run"].update(uses="example/other@main"),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"].update(uses="./.github/workflows/phase.yml"),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"]["steps"][-1].update(run="true"),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"]["steps"][-1]["env"].update(PHASE="unbound"),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"]["steps"].pop(),
            lambda m: m["deploy.yml"]["jobs"]["automation"].update(needs=["selection"]),
            lambda m: m["guest-automation.yml"]["jobs"]["deploy"]["env"].update(NODE_RED_API_TOKEN="unexpected"),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"]["steps"][2].update(id="other"),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"]["steps"][3]["with"].update(ref="main"),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"]["steps"][3]["with"].update({"persist-credentials": True}),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"]["steps"][9].update({"if": "always()"}),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"]["steps"][9].update({"continue-on-error": True}),
            lambda m: m["guest-dns.yml"]["jobs"]["deploy"]["steps"].extend(copy.deepcopy(m["guest-dns.yml"]["jobs"]["deploy"]["steps"][:6])),
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
            self.assertEqual(workflows.phase_recipe(), (self.original["jobs"]["run"], self.original["defaults"]))
