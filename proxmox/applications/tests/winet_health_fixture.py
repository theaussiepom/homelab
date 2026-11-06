"""Run real upstream Node/MQTT health against isolated online/offline/auth fixtures."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import winet

image = sys.argv[1]
prefix = "winet-health-" + uuid.uuid4().hex[:12]
network = prefix + "-network"


def run(*argv, check=True):
    return subprocess.run(["docker", *argv], capture_output=True, text=True, timeout=30, check=check)


names = []
try:
    run("network", "create", "--internal", network)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "options.json"
        path.write_text(json.dumps({"winet_host": "198.19.107.23", "winet_user": "fixture",
                                   "winet_pass": "fixture-only", "mqtt_url": "mqtt://fixture:1883", "ssl": True}))
        path.chmod(0o600)
        results = {}
        for mode in ("online", "offline", "missing", "denied", "flap", "recover"):
            server = prefix + "-" + mode
            names.append(server)
            run("run", "-d", "--name", server, "--network", network, "--network-alias", "fixture",
                "--memory", "256m", "--pids-limit", "128", "--entrypoint", "node",
                "--health-cmd", "exit 0" if mode in {"online", "recover"} else "exit 1",
                "--health-interval", "1s", "--health-retries", "1",
                "-v", str(Path(__file__).with_name("winet_health_broker.cjs")) + ":/tmp/broker.cjs:ro",
                image, "/tmp/broker.cjs", mode)
            for _ in range(20):
                if "fixture-ready" in run("logs", server).stdout:
                    break
                time.sleep(0.5)
            else:
                raise AssertionError("Broker fixture startup failed")
            started = time.monotonic()
            result = run("run", "--rm", "--network", network, "--memory", "256m", "--pids-limit", "128",
                         "--entrypoint", "node", "-v", str(path) + ":/data/options.json:ro", image, "-e", winet.HEALTH, check=False)
            assert result.returncode == (0 if mode in {"online", "recover"} else 1), (mode, result.returncode)
            assert run("inspect", server, "--format", "{{.State.Running}}").stdout.strip() == "true"
            events = [json.loads(line) for line in run("logs", server).stdout.splitlines() if line.startswith("{")]
            connected = [e for e in events if e["event"] == "connect"]
            subscribed = [e for e in events if e["event"] == "subscribe"]
            sent = [e for e in events if e["event"] == "availability"]
            assert connected and connected[0]["accepted"] == (mode != "denied"), (mode, events)
            if mode == "denied":
                assert not subscribed and not sent
            else:
                assert len(subscribed) == 1 and set(subscribed[0]["topics"]) == {
                    "winet-extractor/198_19_107_23/status", "winet-extractor/198_19_107_23/availability"}
                if mode == "missing":
                    assert not sent and time.monotonic() - started >= 8
                elif mode in {"flap", "recover"}:
                    assert [e["value"] for e in sent] == ["online", "offline", "online"] + (["online"] if mode == "recover" else [])
                else:
                    assert len(sent) == 2
                    assert [e["value"] for e in sent] == ["online", "offline" if mode == "offline" else "online"]
            expected_status = "healthy" if mode in {"online", "recover"} else "unhealthy"
            for _ in range(10):
                status = run("inspect", server, "--format", "{{json .State.Health.Status}}").stdout.strip()
                if status == json.dumps(expected_status):
                    break
                time.sleep(0.5)
            else:
                raise AssertionError((mode, status))
            assert ('"healthy"' in status) == (expected_status == "healthy")
            results[mode] = {"exit": result.returncode, "broker_state_proved": True,
                             "docker_health_comparison_proved": True}
            run("rm", "-f", server)
        print(json.dumps({"image": image, "results": results, "external_network": False,
                          "actual_upstream_health_runtime": True, "physical_inverter_tested": False}))
finally:
    for name in names:
        run("rm", "-f", name, check=False)
    run("network", "rm", network, check=False)
