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
        for mode in ("online", "offline", "missing", "denied"):
            server = prefix + "-" + mode
            names.append(server)
            run("run", "-d", "--name", server, "--network", network, "--network-alias", "fixture",
                "--memory", "256m", "--pids-limit", "128", "--entrypoint", "node",
                "-v", str(Path(__file__).with_name("winet_health_broker.cjs")) + ":/tmp/broker.cjs:ro",
                image, "/tmp/broker.cjs", mode)
            for _ in range(20):
                if "fixture-ready" in run("logs", server).stdout:
                    break
                time.sleep(0.5)
            else:
                raise AssertionError("Broker fixture startup failed")
            result = run("run", "--rm", "--network", network, "--memory", "256m", "--pids-limit", "128",
                         "--entrypoint", "node", "-v", str(path) + ":/data/options.json:ro", image, "-e", winet.HEALTH, check=False)
            assert result.returncode == (0 if mode == "online" else 1), (mode, result.returncode)
            results[mode] = result.returncode
            run("rm", "-f", server)
        print(json.dumps({"image": image, "results": results, "external_network": False,
                          "actual_upstream_health_runtime": True, "physical_inverter_tested": False}))
finally:
    for name in names:
        run("rm", "-f", name, check=False)
    run("network", "rm", network, check=False)
