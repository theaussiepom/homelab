"""Pure compiler boundaries, independent of any target or private input."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "blueprint_compiler", Path(__file__).with_name("compile.py")
)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class CompilerTests(unittest.TestCase):
    def test_disabled_defaults_empty_and_new_guests_participate_automatically(self):
        spec = {"guests": {"dns": {"depends_on": []}}}
        self.assertEqual(c.selection(spec), ["dns"])
        spec["guests"]["new"] = {"depends_on": ["dns"]}
        self.assertEqual(c.selection(spec), ["dns", "new"])
        self.assertEqual(c.selection(spec, []), ["dns", "new"])
        self.assertEqual(c.selection(spec, ["new"]), ["dns"])
        self.assertEqual(c.selection(spec, ["dns", "new"]), [])
        for raw, expected in (("", []), ("[]", []), ('["dns"]', ["dns"])):
            with self.subTest(raw=raw):
                self.assertEqual(c.parse_disabled(raw), expected)
        for raw in ("null", "true", "{}", '"dns"'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                c.parse_disabled(raw)

    def test_central_values_preserve_types_and_input_slot(self):
        self.assertEqual(
            c.substitute(
                {"x": "https://${host}/${inputs}", "y": 1}, {"host": "example.invalid"}
            ),
            {"x": "https://example.invalid/${inputs}", "y": 1},
        )
        with self.assertRaises(ValueError):
            c.substitute("${missing}", {})

    def test_duplicate_json_and_ambiguous_workflow_selections_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "input.json"
            path.write_text('{"x":1,"x":2}')
            with self.assertRaises(ValueError):
                c.read(path)
            pin = "uses: owner/repo/.github/workflows/deploy.yml@" + "a" * 40 + "\n"
            path.write_text(pin)
            self.assertEqual(
                c.workflow_selection(path, "deploy.yml")["revision"], "a" * 40
            )
            path.write_text(pin + pin)
            with self.assertRaises(ValueError):
                c.workflow_selection(path, "deploy.yml")

    def test_dependency_closure_does_not_serialize_independent_guests(self):
        spec = {
            "guests": {
                "dns": {"depends_on": []},
                "a": {"depends_on": ["dns"]},
                "b": {"depends_on": ["dns"]},
            }
        }
        self.assertEqual(c.selection(spec, ["b"]), ["dns", "a"])
        self.assertEqual(c.selection(spec), ["dns", "a", "b"])
        for disabled in [["dns"], ["unknown"], ["dns", "dns"], [1], [[]], {}]:
            with self.assertRaises(ValueError):
                c.selection(spec, disabled)

    def test_image_identity_keeps_recorded_tag_and_digest_separate(self):
        value = {
            "repository": "example/service",
            "tag": "1.2.3",
            "digest": "sha256:" + "1" * 64,
        }
        self.assertEqual(
            c.image(value)["image"], "example/service:1.2.3@sha256:" + "1" * 64
        )
        value["digest"] = "latest"
        with self.assertRaises(ValueError):
            c.image(value)
        self.assertEqual(
            c.image(
                {
                    "repository": "ghcr.io/bitwarden/lite",
                    "tag": "latest",
                    "digest": None,
                }
            ),
            {"image": "ghcr.io/bitwarden/lite:latest"},
        )

    def test_blueprints_have_one_preparation_per_guest_and_no_fake_vm_support(self):
        for name, row in c.CATALOGUE.items():
            self.assertEqual(row["platform"], "debian-lxc")
            self.assertEqual(
                row["capabilities"],
                (
                    ["linux"]
                    if name in ["postgresql", "mariadb", "influxdb"]
                    else ["linux", "docker"]
                ),
            )
        self.assertEqual(c.CATALOGUE["identity"]["applications"], ["authentik"])
        self.assertEqual(c.CATALOGUE["dns"]["applications"], ["unbound", "pihole"])

    def test_admission_requires_real_image_identity_and_writer_fencing(self):
        from unittest.mock import patch
        import copy

        catalogue = {"dns": {"capabilities": ["linux", "docker"]}}
        spec = {
            "routes": {},
            "values": {},
            "guests": {"dns": {"prerequisites": [], "depends_on": []}},
        }
        cfg = {
            "guest": {"vmid": 6101},
            "ssh_public_keys": ["ssh-ed25519 reviewed-fixture"],
            "app": {"exclusive_writer_confirmed": True, "service_health_checks": {}},
        }
        for scenario in ("accepted", "placeholder", "writer"):
            desired = copy.deepcopy(cfg)
            packet = {
                "files": {"site.json": "0" * 64 if scenario == "placeholder" else "{}"}
            }
            if scenario == "writer":
                desired["app"]["exclusive_writer_confirmed"] = False
            overlay = {
                "schema": "homelab-site-v3",
                "routes": {},
                "values": {},
                "common": {},
                "guests": {},
                "images": {},
                "accepted": {},
            }
            with (
                self.subTest(scenario=scenario),
                patch.object(c, "CATALOGUE", catalogue),
                patch.object(c, "manifest", return_value=spec),
                patch.object(c, "_resolve_guest", return_value=(desired, None, {})),
                patch.object(c, "_compile_guest", return_value=(desired, packet)),
                patch.object(c.connections, "validate") as links,
            ):
                if scenario == "accepted":
                    self.assertEqual(
                        c.compile_stack(Path("/synthetic"), overlay, admit=True),
                        {"dns": packet},
                    )
                else:
                    with self.assertRaises(ValueError):
                        c.compile_stack(Path("/synthetic"), overlay, admit=True)
                links.assert_called_once_with({"dns": desired}, external_routes={})

    def test_root_monitoring_route_is_derived_once_and_cannot_be_overridden(self):
        from unittest.mock import patch
        import copy
        from test_root_monitoring import composition, VALUES
        original=composition()
        original['ingress']=(original['ingress'][0],{},original['ingress'][2])
        spec={'guests':{name:{'depends_on':[],'prerequisites':[]} for name in original},'routes':{},'values':dict(VALUES,**{'domains.monitoring':'zabbix.example.invalid'})}
        overlay={'schema':'homelab-site-v3','zabbix':None,'values':{},'common':{},'guests':{},'images':{},'accepted':{},'routes':{}}
        for override in (False,True):
            resolved=copy.deepcopy(original);selected=copy.deepcopy(overlay)
            if override:selected['routes']['zabbix']={}
            with patch.object(c,'manifest',return_value=spec),patch.object(c,'_resolve_guest',side_effect=lambda root,overlay,name,spec:resolved[name]),patch.object(c,'_compile_guest',side_effect=lambda name,cfg,stack,files,enabled:(cfg,{'enabled':name in enabled})),patch.object(c.routes,'bind',return_value=[]) as routes,patch.object(c.service_bindings,'bind'),patch.object(c.connections,'validate'):
                if override:
                    with self.assertRaisesRegex(ValueError,'derived'):c.compile_stack(Path('/synthetic'),selected)
                else:
                    packets=c.compile_stack(Path('/synthetic'),selected)
                    self.assertTrue(packets['monitoring']['enabled'])
                    self.assertEqual(routes.call_args.args[1]['zabbix'],{'target':{'endpoint':'monitoring.zabbix.web'},'host':'zabbix.example.invalid','middlewares':['security-headers','management-clients']})
