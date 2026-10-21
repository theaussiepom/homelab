import copy
import unittest
from unittest.mock import patch

import macvlan as m


NET = {"network_id": "net-id", "parent_ifindex": 11, "parent_address": "aa:bb:cc:dd:ee:ff",
       "parent_link": "ens1", "parent_linkinfo": {}}
CONFIG = {"network": "macvlan_100", "parent": "ens1.100", "nas_mount": "/mnt/nas/docker",
          "nas_source": "10.254.253.2:/volume1/docker-beast", "nas_probe_file": "/mnt/nas/docker/homelab/README.md",
          "containers": [
              {"name": "hass", "project": "automation", "service": "homeassistant", "static_ipv4": "10.254.253.242", "ready_port": 8123, "dependency": "nodered"},
              {"name": "nodered", "project": "automation", "service": "node-red", "static_ipv4": "10.254.253.244", "ready_port": 1880}]}


def container(entry, running=True):
    return {"Id": entry["name"] + "-id", "Image": "sha256:old-image", "Name": "/" + entry["name"],
            "Config": {"Labels": {"com.docker.compose.project": entry["project"], "com.docker.compose.service": entry["service"]}, "Env": ["PRIVATE=not-emitted"]},
            "HostConfig": {"RestartPolicy": {"Name": "always"}, "Mounts": [{"Type": "volume", "Source": "docker", "Target": "/data"}]},
            "Mounts": [{"Type": "volume", "Source": "/var/lib/docker/volumes/docker/_data", "Destination": "/data", "RW": True}],
            "State": {"Running": running, "Restarting": False, "Pid": 123 if running else 0, "StartedAt": "old-start", "FinishedAt": "old-finish"},
            "NetworkSettings": {"SandboxID": "old-sandbox", "Networks": {"macvlan_100": {
                "NetworkID": "net-id", "IPAddress": entry["static_ipv4"] if running else "", "IPAMConfig": {"IPv4Address": entry["static_ipv4"]},
                "IPPrefixLen": 24 if running else 0, "Gateway": "10.254.253.1" if running else "", "Aliases": [entry["name"]], "GwPriority": 0,
                "DriverOpts": None, "Links": None}, "mqtt": {"NetworkID": "mqtt-id", "Aliases": [entry["name"]], "IPAMConfig": {"IPv4Address": "10.0.2.10"}, "IPAddress": "10.0.2.10"}}}}


class Harness:
    def __init__(self, dependency_running=True):
        self.entries = {e["name"]: e for e in CONFIG["containers"]}
        self.containers = {n: container(e, n != "nodered" or dependency_running) for n,e in self.entries.items()}
        self.missing = {"hass"}
        self.commands, self.events = [], []
        self.fail_restart = False
        self.fail_stop = False
        self.fail_ready = False
        self.conflict_dependency = False

    def inspect(self, name):
        return copy.deepcopy(self.containers[name.removesuffix("-id")])

    def interface(self, identity, ip):
        return None if identity["name"] in self.missing else "eth2"

    def run(self, argv, timeout=15):
        self.commands.append(argv)
        if argv[0] != "docker":
            raise AssertionError(argv)
        action = argv[1]
        name = argv[-1].removesuffix("-id")
        value = self.containers[name]
        if action == "stop":
            if self.fail_stop:
                raise m.RecoveryError("command_timeout")
            value["State"].update(Running=False, Pid=0, FinishedAt="our-stop")
            value["NetworkSettings"]["Networks"]["macvlan_100"].update(IPAddress="", IPPrefixLen=0, Gateway="")
        elif action in ("restart", "start"):
            if self.fail_restart and action == "restart":
                raise m.RecoveryError("command_timeout")
            value["State"].update(Running=True, Pid=234, StartedAt="new-start", FinishedAt="")
            value["NetworkSettings"]["SandboxID"] = "new-sandbox"
            value["NetworkSettings"]["Networks"]["macvlan_100"].update(IPAddress=self.entries[name]["static_ipv4"], IPPrefixLen=24, Gateway="10.254.253.1")
            value["NetworkSettings"]["Networks"]["mqtt"].update(IPAddress="10.0.2.99", IPAMConfig={"IPv4Address": "10.0.2.99"})
            self.missing.discard(name)
        else:
            raise AssertionError(argv)
        return name + "\n"

    def ready(self, before, entry, cfg, network):
        if entry["name"] == "hass" and self.fail_ready:
            if self.conflict_dependency:
                self.containers["nodered"]["Image"] = "sha256:somebody-changed-it"
            raise m.RecoveryError("readiness_timeout")
        now = m._entry_identity(self.inspect(before["id"]), entry, cfg, network)
        if not m._preserved(before, now):
            raise m.RecoveryError("post_restart_identity_conflict")
        return now, {"kernel_address": True, "stats": True, "listener": True, "routes": True, "multicast": True}

    def record(self, phase, detail):
        self.events.append((phase, copy.deepcopy(detail)))

    def patches(self):
        return [patch.object(m, "_network_guard", side_effect=lambda config: copy.deepcopy(NET)),
                patch.object(m, "_inspect", side_effect=self.inspect), patch.object(m, "_interface", side_effect=self.interface),
                patch.object(m, "_nas"), patch.object(m, "_run", side_effect=self.run), patch.object(m, "_wait_ready", side_effect=self.ready),
                patch.object(m, "_readiness", return_value={"kernel_address":True,"stats":True,"listener":True,"routes":True,"multicast":True})]


class MacvlanTests(unittest.TestCase):
    def use(self, harness):
        for p in harness.patches():
            p.start()
            self.addCleanup(p.stop)

    def candidate(self):
        result = m.observe(CONFIG)
        self.assertFalse(result["healthy"])
        self.assertEqual(len(result["candidates"]), 1)
        self.assertTrue(all(x["reason"] == "enrolled_container_not_running" for x in result["issues"]))
        return result["candidates"][0]

    def test_healthy_no_candidate_and_no_mutation(self):
        h = Harness(); h.missing.clear(); self.use(h)
        self.assertTrue(m.observe(CONFIG)["healthy"])
        self.assertEqual(h.commands, [])

    def test_present_address_with_broken_stats_is_report_only(self):
        h = Harness(); h.missing.clear(); self.use(h)
        with patch.object(m, "_readiness", return_value={"kernel_address":True,"stats":False,"listener":True,"routes":True,"multicast":True}):
            observed = m.observe(CONFIG)
        self.assertFalse(observed["healthy"])
        self.assertEqual(observed["candidates"], [])
        self.assertEqual(observed["issues"][0]["reason"], "present_address_readiness_degraded")
        self.assertEqual(h.commands, [])

    def test_missing_declared_address_proposes_only_enrolled_running_container(self):
        h = Harness(dependency_running=False); self.use(h)
        c = self.candidate()
        self.assertEqual(c["name"], "hass")
        self.assertEqual(c["key"], "macvlan:automation:homeassistant:macvlan_100")
        self.assertNotIn("not-emitted", str(c))

    def test_wrong_project_is_report_only(self):
        h = Harness(); h.containers["hass"]["Config"]["Labels"]["com.docker.compose.project"] = "wrong"; self.use(h)
        result = m.observe(CONFIG)
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["issues"][0]["reason"], "container_identity_conflict")

    def test_wrong_declared_ip_is_report_only(self):
        h = Harness(); h.containers["hass"]["NetworkSettings"]["Networks"]["macvlan_100"]["IPAMConfig"] = None; self.use(h)
        result = m.observe(CONFIG)
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["issues"][0]["reason"], "static_address_conflict")

    def test_changed_pid_aborts_before_mutation(self):
        h = Harness(); self.use(h); c = self.candidate(); h.containers["hass"]["State"]["Pid"] = 999
        result = m.repair(c, CONFIG, h.record)
        self.assertEqual(result["reason"], "container_changed_since_observation")
        self.assertEqual(h.commands, [])

    def test_changed_network_generation_aborts_before_mutation(self):
        h = Harness(); self.use(h); c = self.candidate(); c["network_identity"]["parent_ifindex"] = 99
        result = m.repair(c, CONFIG, h.record)
        self.assertEqual(result["reason"], "network_changed_since_observation")
        self.assertEqual(h.commands, [])

    def test_recovered_before_action_is_noop(self):
        h = Harness(); self.use(h); c = self.candidate(); h.missing.clear()
        result = m.repair(c, CONFIG, h.record)
        self.assertTrue(result["ok"]); self.assertFalse(result["changed"])
        self.assertEqual(h.commands, [])

    def test_nas_failure_blocks_all_mutations(self):
        h = Harness(); self.use(h); c = self.candidate()
        with patch.object(m, "_nas", side_effect=m.RecoveryError("command_timeout_unreaped", orphan_pid=1234)):
            result = m.repair(c, CONFIG, h.record)
        self.assertEqual(result["orphan_pid"], 1234); self.assertFalse(result["ok"])
        self.assertNotIn("deferred", result)
        self.assertEqual(h.commands, [])

    def test_observation_waits_for_nas_then_exposes_candidate_after_recovery(self):
        h = Harness(); self.use(h)
        with patch.object(m, "_nas", side_effect=m.RecoveryError("command_timeout")):
            observed = m.observe(CONFIG)
        self.assertFalse(observed["healthy"])
        self.assertEqual(observed["candidates"], [])
        self.assertEqual(observed["issues"][0]["reason"], "nas_prerequisite_unavailable")
        result = m.repair(self.candidate(), CONFIG, h.record)
        self.assertTrue(result["success"])

    def test_observation_retains_orphan_pid_for_parent_halt(self):
        h = Harness(); self.use(h)
        with patch.object(m, "_nas", side_effect=m.RecoveryError("command_timeout_unreaped", orphan_pid=1234)):
            observed = m.observe(CONFIG)
        self.assertEqual(observed["candidates"], [])
        self.assertEqual(observed["issues"][0]["orphan_pid"], 1234)
        self.assertEqual(h.commands, [])

    def test_nas_race_before_mutation_defers_and_can_later_repair(self):
        h = Harness(); self.use(h); c = self.candidate()
        with patch.object(m, "_nas", side_effect=m.RecoveryError("command_timeout")):
            result = m.repair(c, CONFIG, h.record)
        self.assertTrue(result["deferred"])
        self.assertFalse(result["mutation_attempted"])
        self.assertFalse(result["changed"])
        self.assertFalse(result["success"])
        self.assertEqual(h.commands, [])
        self.assertTrue(m.repair(c, CONFIG, h.record)["success"])

    def test_nas_failure_after_dependency_stop_never_defers(self):
        h = Harness(); self.use(h); c = self.candidate()
        with patch.object(m, "_nas", side_effect=[None, m.RecoveryError("command_timeout"), None]):
            result = m.repair(c, CONFIG, h.record)
        self.assertNotIn("deferred", result)
        self.assertTrue(result["mutation_attempted"])
        self.assertFalse(result["success"])
        self.assertTrue(result["dependency_restored"])
        self.assertEqual([x[1] for x in h.commands], ["stop", "start"])

    def test_dependency_stopped_then_target_restarted_then_dependency_restored(self):
        h = Harness(); self.use(h)
        result = m.repair(self.candidate(), CONFIG, h.record)
        self.assertTrue(result["ok"]); self.assertTrue(result["dependency_restored"])
        self.assertTrue(result["success"])
        self.assertEqual(h.commands, [["docker","stop","--timeout","60","nodered-id"], ["docker","restart","--timeout","60","hass-id"], ["docker","start","nodered-id"]])
        phases = [x[0] for x in h.events]
        self.assertLess(phases.index("dependency_stop_prepared"), phases.index("dependency_stopped"))
        self.assertLess(phases.index("restart_prepared"), phases.index("restart_returned"))
        self.assertLess(phases.index("dependency_start_prepared"), phases.index("dependency_start_returned"))

    def test_initially_stopped_dependency_is_not_started(self):
        h = Harness(dependency_running=False); self.use(h)
        result = m.repair(self.candidate(), CONFIG, h.record)
        self.assertTrue(result["ok"])
        self.assertEqual(h.commands, [["docker","restart","--timeout","60","hass-id"]])

    def test_restart_failure_still_restores_owned_dependency_without_retry(self):
        h = Harness(); h.fail_restart = True; self.use(h)
        result = m.repair(self.candidate(), CONFIG, h.record)
        self.assertFalse(result["ok"]); self.assertTrue(result["dependency_restored"])
        self.assertFalse(result["success"])
        self.assertEqual([x[1] for x in h.commands], ["stop","restart","start"])

    def test_readiness_failure_still_restores_owned_dependency(self):
        h = Harness(); h.fail_ready = True; self.use(h)
        result = m.repair(self.candidate(), CONFIG, h.record)
        self.assertFalse(result["ok"]); self.assertTrue(result["dependency_restored"])

    def test_dependency_identity_change_blocks_start_and_reports_pending(self):
        h = Harness(); h.fail_ready = True; h.conflict_dependency = True; self.use(h)
        result = m.repair(self.candidate(), CONFIG, h.record)
        self.assertFalse(result["ok"]); self.assertIn("pending_dependency", result)
        self.assertEqual(result["dependency_error"], "dependency_identity_changed")
        self.assertEqual([x[1] for x in h.commands], ["stop","restart"])

    def test_stop_timeout_does_not_restart_target_or_duplicate_running_dependency(self):
        h = Harness(); h.fail_stop = True; self.use(h)
        result = m.repair(self.candidate(), CONFIG, h.record)
        self.assertFalse(result["ok"])
        self.assertEqual([x[1] for x in h.commands], ["stop"])

    def test_preservation_rejects_image_mount_or_policy_changes(self):
        e = CONFIG["containers"][0]; old = container(e)
        before = m._entry_identity(old, e, CONFIG, NET)
        for mutate in [lambda x:x.update(Image="new-image"), lambda x:x["Mounts"][0].update(Source="/other"), lambda x:x["HostConfig"]["RestartPolicy"].update(Name="no")]:
            new = copy.deepcopy(old); mutate(new)
            self.assertFalse(m._preserved(before, m._entry_identity(new, e, CONFIG, NET)))

    def test_dynamic_lease_change_permitted_static_change_rejected(self):
        e = CONFIG["containers"][0]; old = container(e); before = m._entry_identity(old, e, CONFIG, NET)
        new = copy.deepcopy(old); new["NetworkSettings"]["Networks"]["mqtt"].update(IPAddress="10.0.2.99",IPAMConfig={"IPv4Address":"10.0.2.99"})
        self.assertTrue(m._preserved(before,m._entry_identity(new,e,CONFIG,NET)))
        new["NetworkSettings"]["Networks"]["macvlan_100"]["IPAddress"] = "10.254.253.99"
        with self.assertRaisesRegex(m.RecoveryError,"static_address_conflict"):
            m._entry_identity(new,e,CONFIG,NET)

    def test_readiness_uses_declared_overlay_bind_separately_from_lan(self):
        e = copy.deepcopy(CONFIG["containers"][0]); e.update(static_networks={"underground":"198.18.200.7"}, ready_network="underground")
        ident = {"pid":123}
        with patch.object(m,"_interface",return_value="eth2"), patch.object(m,"_stats",return_value=True), \
             patch.object(m,"_run",return_value="") as cmd, patch.object(m,"_json",return_value=[{"dst":"default"}]):
            checks = m._readiness(ident,e)
        self.assertTrue(all(checks.values()))
        self.assertEqual(cmd.call_args.args[0][-2:], ["198.18.200.7","8123"])

    def test_undeclared_readiness_network_rejected(self):
        config = copy.deepcopy(CONFIG); config["containers"][0]["ready_network"] = "undeclared"
        with self.assertRaisesRegex(m.RecoveryError,"readiness_network_not_declared"):
            m._cfg(config)

    def test_readiness_does_not_hide_unreaped_listener_probe(self):
        with patch.object(m,"_interface",return_value="eth2"), patch.object(m,"_stats",return_value=True), \
             patch.object(m,"_run",side_effect=m.RecoveryError("command_timeout_unreaped",orphan_pid=456)):
            with self.assertRaises(m.RecoveryError) as caught:
                m._readiness({"pid":123},CONFIG["containers"][0])
        self.assertEqual(caught.exception.details["orphan_pid"],456)


if __name__ == "__main__":
    unittest.main()
