"""Exercise the production renderer and upstream API play against disposable data.

No published ports, host network, Docker socket in a service, or production
credentials. The fixture overrides only address publication and runtime mounts.
"""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from urllib.request import Request, urlopen
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring
import monitoring_fixture_tls as fixture_tls
import render


def api(method, params, token=None):
    headers = {"Content-Type": "application/json-rpc"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(
        "http://zabbix_web:8080/api_jsonrpc.php",
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers=headers,
    )
    with urlopen(request, timeout=10) as response:
        value = json.load(response)
    if "error" in value:
        raise ValueError(str(value["error"]))
    return value["result"]


def wait_for(function, message, seconds=180):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            value = function()
            if value:
                return value
        except (OSError, ValueError):
            pass
        time.sleep(2)
    raise RuntimeError(message)


def client():
    root = Path("/fixture")
    assert (
        wait_for(
            lambda: api("apiinfo.version", {}), "Zabbix schema/API did not become ready"
        )
        == monitoring.VERSIONS["version"]
    )
    password = (root / "admin-password").read_text()
    inventory = {
        "monitoring_api": {
            "hosts": {
                "zabbix_web": {
                    "ansible_host": "zabbix_web",
                    "ansible_user": "Admin",
                    "ansible_httpapi_use_ssl": False,
                    "ansible_httpapi_port": 8080,
                }
            }
        }
    }
    http_password = "zabbix"
    variables = {
        "ansible_httpapi_use_ssl": False,
        "monitoring_initial_password": True,
        "monitoring_admin_password": "{{ lookup('ansible.builtin.env', 'FIXTURE_ADMIN_PASSWORD') }}",
        "monitoring_hosts": [
            {
                "hostname": "fixture-linux",
                "psk_identity": "fixture-linux",
                "psk": "{{ lookup('ansible.builtin.env', 'FIXTURE_AGENT_PSK') }}",
            },
            {
                "hostname": "fixture-wrong",
                "psk_identity": "fixture-wrong",
                "psk": "{{ lookup('ansible.builtin.env', 'FIXTURE_EXPECTED_WRONG_HOST_PSK') }}",
            },
        ],
        "monitoring_proxmox": {
            "hostname": "fixture-pve-api",
            "address": "pve.example.invalid",
            "token_id": "fixture@pve!monitoring",
            "token_secret": "fixture-secret",
        },
    }

    def configure(pass_number):
        (root / "inventory.json").write_text(json.dumps(inventory))
        result = subprocess.run(
            [
                "ansible-playbook",
                "-i",
                str(root / "inventory.json"),
                str(
                    Path(__file__).resolve().parents[1]
                    / "ansible/monitoring-configure.yml"
                ),
                "-e",
                json.dumps(
                    dict(
                        variables,
                        ansible_httpapi_pass="{{ lookup('ansible.builtin.env', 'FIXTURE_HTTP_PASSWORD') }}",
                    )
                ),
            ],
            env=dict(
                os.environ,
                FIXTURE_ADMIN_PASSWORD=password,
                FIXTURE_HTTP_PASSWORD=http_password,
                FIXTURE_AGENT_PSK=(root / "agent.psk").read_text().strip(),
                FIXTURE_EXPECTED_WRONG_HOST_PSK=(root / "wrong-expected.psk")
                .read_text()
                .strip(),
            ),
            capture_output=True,
            text=True,
        )
        (root / f"api-pass-{pass_number}.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            print(result.stdout + result.stderr)
            raise RuntimeError("Upstream Zabbix configuration play failed")
        return result.stdout

    configure(1)
    http_password = password
    variables["monitoring_initial_password"] = False
    second = configure(2)
    assert "changed=0" in second, second
    token = api("user.login", {"username": "Admin", "password": password})
    pve_host = api(
        "host.get",
        {"filter": {"host": ["fixture-pve-api"]}, "output": ["hostid"]},
        token,
    )[0]
    http_items = []
    for method in ("item.get", "itemprototype.get"):
        http_items.extend(
            api(
                method,
                {
                    "hostids": [pve_host["hostid"]],
                    "filter": {"type": 19},
                    "output": ["verify_peer", "verify_host"],
                },
                token,
            )
        )
    assert len(http_items) == 7 and all(
        row["verify_peer"] == "1" and row["verify_host"] == "1" for row in http_items
    )
    resources = api(
        "item.get",
        {
            "hostids": [pve_host["hostid"]],
            "filter": {"key_": ["proxmox.cluster.resources"]},
            "output": ["history"],
        },
        token,
    )
    assert len(resources) == 1 and resources[0]["history"] in ("1h", "3600")
    hosts = api(
        "host.get", {"filter": {"host": ["fixture-linux"]}, "output": "extend"}, token
    )
    assert len(hosts) == 1 and hosts[0]["tls_accept"] == "2"
    hostid = hosts[0]["hostid"]
    # Ask the standard template for frequent fixture samples; do not change
    # the source template or install a custom production polling item.
    item = api(
        "item.get",
        {"hostids": [hostid], "filter": {"key_": "system.uptime"}, "output": "extend"},
        token,
    )[0]
    api("item.update", {"itemid": item["itemid"], "delay": "1s"}, token)
    (root / "start-agent").write_text("ready")

    def samples():
        result = api(
            "item.get",
            {
                "itemids": [item["itemid"]],
                "output": ["lastclock", "lastvalue", "state"],
            },
            token,
        )
        return (
            result[0]
            if int(result[0]["lastclock"]) > 0 and float(result[0]["lastvalue"]) > 0
            else None
        )

    wait_for(samples, "No authenticated active Agent 2 sample arrived")
    (root / "test-wrong-key").write_text("ready")
    wait_for(
        lambda: (root / "wrong-key-tested").exists(), "Wrong-key test was not run", 90
    )
    assert "unknown PSK identity" not in (root / "wrong-agent.log").read_text()
    wrong_log = (root / "wrong-agent.log").read_text().lower()
    assert any(
        word in wrong_log
        for word in ["alert decrypt error", "bad record mac", "binder does not verify"]
    ), wrong_log
    # A separate incorrect-key hostname is admitted with a known key; it must
    # never receive data when the agent presents a different key.
    bad_hostid = api(
        "host.get", {"filter": {"host": ["fixture-wrong"]}, "output": ["hostid"]}, token
    )[0]["hostid"]
    bad = api(
        "item.get",
        {
            "hostids": [bad_hostid],
            "filter": {"key_": "system.uptime"},
            "output": ["lastclock"],
        },
        token,
    )
    assert bad and all(int(row["lastclock"]) == 0 for row in bad), bad
    result = {
        "version": monitoring.VERSIONS["version"],
        "fresh_schema": True,
        "official_templates": True,
        "second_configuration_changed": 0,
        "active_psk_data": True,
        "wrong_psk_rejected": True,
        "native_proxmox_verified": False,
        "trusted_api_ca": True,
        "untrusted_ca_and_hostname_rejected": True,
    }
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


def mock_pve():
    import ssl
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = b'{"data":{"version":"fixture"}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = HTTPServer(("0.0.0.0", 8006), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/fixture/proxmox-ca.pem", "/fixture/ca-key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def docker(*args, **kwargs):
    return subprocess.run(
        ["docker", *args], check=True, timeout=kwargs.pop("timeout", 180), **kwargs
    )


def main(args):
    from test_monitoring import fixture

    project = "homelab-zabbix-fixture-" + uuid.uuid4().hex[:10]
    root = args.output.resolve() / project
    root.mkdir(parents=True, mode=0o755)
    cfg = fixture(root)
    cfg["monitoring"]["postgresql_host"] = "postgres"
    document = render.compose(cfg)
    document.pop("name")
    document["networks"] = {"default": {"internal": True}}
    document["services"]["zabbix_server"]["networks"] = {
        "default": {"aliases": ["zabbix-server"]}
    }
    for name, service in document["services"].items():
        service.pop("ports", None)
        service["platform"] = "linux/amd64"
        service["volumes"] = [f"{root}/password:/run/secrets/database-password:ro"]
        service["depends_on"] = {"postgres": {"condition": "service_healthy"}}
    docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        "linux/amd64",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-v",
        f"{root}:/fixture",
        args.tools_image,
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=pve.example.invalid",
        "-addext",
        "subjectAltName=DNS:pve.example.invalid",
        "-keyout",
        "/fixture/ca-key.pem",
        "-out",
        "/fixture/proxmox-ca.pem",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    document["services"]["zabbix_server"]["volumes"].append(
        f"{root}/proxmox-ca.pem:/var/lib/zabbix/ssl/ssl_ca/proxmox-ca.pem:ro"
    )
    document["services"]["pve"] = {
        "image": args.tools_image,
        "platform": "linux/amd64",
        "networks": {"default": {"aliases": ["pve.example.invalid"]}},
        "volumes": [
            f"{root}:/fixture:ro",
            f"{Path(__file__).resolve().parents[3]}:/src:ro",
        ],
        "command": [
            "python3",
            "/src/proxmox/applications/tests/monitoring_fixture.py",
            "--mock-pve",
        ],
    }
    # The isolated DB initializes only its selected DB with a non-superuser
    # owner. Zabbix never gets the PostgreSQL cluster administrator password.
    (root / "database.sql").write_text(
        "CREATE ROLE zabbix LOGIN PASSWORD 'synthetic-fixture-password' NOSUPERUSER NOCREATEDB NOCREATEROLE;\nCREATE DATABASE zabbix OWNER zabbix;\n"
    )
    document["services"]["postgres"] = {
        "image": monitoring.VERSIONS["fixture_postgresql"],
        "platform": "linux/amd64",
        "environment": {"POSTGRES_PASSWORD": "synthetic-postgres-admin"},
        "volumes": [
            f"{root}/database.sql:/docker-entrypoint-initdb.d/01-zabbix.sql:ro"
        ],
        "tmpfs": ["/var/lib/postgresql/data:rw,nosuid,nodev,size=512m"],
        "healthcheck": {
            "test": ["CMD", "pg_isready", "-U", "postgres"],
            "interval": "2s",
            "retries": 60,
        },
    }
    fixture_tls.apply(document["services"]["postgres"],fixture_tls.prepare(root))
    (root / "agent.psk").write_text(secrets.token_hex(32) + "\n")
    (root / "wrong.psk").write_text(secrets.token_hex(32) + "\n")
    (root / "wrong-expected.psk").write_text(secrets.token_hex(32) + "\n")
    (root / "admin-password").write_text(secrets.token_urlsafe(32))
    (root / "agent.conf").write_text(
        monitoring.agent_config(
            {
                "hostname": "fixture-linux",
                "server_active": "zabbix-server:10051",
                "psk_identity": "fixture-linux",
                "psk_path": "/etc/zabbix/agent.psk",
            }
        )
        .replace("LogType=system", "LogType=console")
        .replace("/run/zabbix/agent.sock", "/tmp/agent.sock")
    )
    (root / "wrong.conf").write_text(
        (root / "agent.conf").read_text().replace("fixture-linux", "fixture-wrong")
    )
    # Container users need read access only to synthetic fixture files.
    for file in root.iterdir():
        if file.is_file(): file.chmod(0o644)
    compose = root / "compose.json"
    compose.write_text(json.dumps(document))
    command = ["compose", "-p", project, "-f", str(compose)]
    client_name = project + "-client"
    containers = [client_name, project + "-agent", project + "-wrong"]
    try:
        docker(
            *command,
            "up",
            "-d",
            "--wait",
            "--wait-timeout",
            "180",
            stdout=subprocess.DEVNULL,
        )
        docker(
            *command,
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "postgres",
            "-d",
            "zabbix",
            "-c",
            "ANALYZE",
            stdout=subprocess.DEVNULL,
        )

        # Read the exact image's generated server setting, then use its actual
        # CA directory for positive and negative libcurl TLS checks.
        def ca_setting():
            result = subprocess.run(
                [
                    "docker",
                    *command,
                    "exec",
                    "-T",
                    "zabbix_server",
                    "grep",
                    "^SSLCALocation=",
                    "/etc/zabbix/zabbix_server.conf",
                ],
                capture_output=True,
                text=True,
            )
            return (
                result.stdout.strip().split("=", 1)[1]
                if result.returncode == 0
                else None
            )

        configured_ca = wait_for(
            ca_setting, "The server entrypoint did not prepare its CA configuration"
        )
        assert configured_ca == "/var/lib/zabbix/ssl/ssl_ca_internal/"

        def trusted_tls():
            result = subprocess.run(
                [
                    "docker",
                    *command,
                    "exec",
                    "-T",
                    "zabbix_server",
                    "curl",
                    "--noproxy",
                    "*",
                    "--max-time",
                    "10",
                    "--silent",
                    "--show-error",
                    "--capath",
                    configured_ca,
                    "https://pve.example.invalid:8006/api2/json/version",
                ],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0 and "fixture" in result.stdout

        wait_for(trusted_tls, "The image did not trust the selected Proxmox CA")
        for ca, url in [
            ("/tmp", "https://pve.example.invalid:8006/"),
            (configured_ca, "https://pve:8006/"),
        ]:
            bad_tls = subprocess.run(
                [
                    "docker",
                    *command,
                    "exec",
                    "-T",
                    "zabbix_server",
                    "curl",
                    "--noproxy",
                    "*",
                    "--max-time",
                    "10",
                    "--silent",
                    "--show-error",
                    "--capath",
                    ca,
                    url,
                ],
                capture_output=True,
                text=True,
            )
            assert bad_tls.returncode == 60, bad_tls.stderr
        (root / "tls-result.json").write_text(
            json.dumps(
                {
                    "trusted_ca": True,
                    "untrusted_ca_rejected": True,
                    "wrong_hostname_rejected": True,
                }
            )
        )
        docker(
            "run",
            "-d",
            "--platform",
            "linux/amd64",
            "--name",
            client_name,
            "--network",
            project + "_default",
            "-v",
            f"{root}:/fixture",
            "-v",
            f"{Path(__file__).resolve().parents[3]}:/src:ro",
            "-v",
            f"{args.collections.resolve()}:/collections:ro",
            "-e",
            "ANSIBLE_COLLECTIONS_PATH=/collections",
            "-e",
            "ANSIBLE_LOCAL_TEMP=/tmp/ansible",
            args.tools_image,
            "python3",
            "/src/proxmox/applications/tests/monitoring_fixture.py",
            "--client",
            stdout=subprocess.DEVNULL,
        )
        wait_for(
            lambda: (root / "start-agent").exists()
            or docker(
                "inspect",
                "-f",
                "{{.State.Running}}",
                client_name,
                capture_output=True,
                text=True,
            ).stdout.strip()
            == "false",
            "API configuration did not complete",
            600,
        )
        if not (root / "start-agent").exists():
            docker("logs", client_name)
            raise RuntimeError("Fixture client stopped before agent admission")
        agent = monitoring.VERSIONS["fixture_agent"]
        docker(
            "run",
            "-d",
            "--platform",
            "linux/amd64",
            "--name",
            project + "-agent",
            "--network",
            project + "_default",
            "-v",
            f"{root}/agent.conf:/etc/zabbix/zabbix_agent2.conf:ro",
            "-v",
            f"{root}/agent.psk:/etc/zabbix/agent.psk:ro",
            "--entrypoint",
            "/usr/sbin/zabbix_agent2",
            agent,
            "-f",
            "-c",
            "/etc/zabbix/zabbix_agent2.conf",
            stdout=subprocess.DEVNULL,
        )
        wait_for(
            lambda: (root / "test-wrong-key").exists(),
            "Authenticated agent test did not complete",
        )
        # Both identities were admitted together before positive data arrived,
        # so the rejection tests a wrong key rather than a new cache identity.
        docker(
            "run",
            "-d",
            "--platform",
            "linux/amd64",
            "--name",
            project + "-wrong",
            "--network",
            project + "_default",
            "-v",
            f"{root}/wrong.conf:/etc/zabbix/zabbix_agent2.conf:ro",
            "-v",
            f"{root}/wrong.psk:/etc/zabbix/agent.psk:ro",
            "--entrypoint",
            "/usr/sbin/zabbix_agent2",
            agent,
            "-f",
            "-c",
            "/etc/zabbix/zabbix_agent2.conf",
            stdout=subprocess.DEVNULL,
        )

        def rejected_key():
            log = docker("logs", project + "-wrong", capture_output=True, text=True)
            text = log.stdout + log.stderr
            (root / "wrong-agent.log").write_text(text)
            return any(
                word in text.lower()
                for word in [
                    "alert decrypt error",
                    "bad record mac",
                    "binder does not verify",
                ]
            )

        wait_for(
            rejected_key, "The wrong PSK did not produce a TLS decryption rejection", 90
        )
        (root / "wrong-key-tested").write_text("complete")
        wait_for(
            lambda: (root / "result.json").exists()
            or docker(
                "inspect",
                "-f",
                "{{.State.Running}}",
                client_name,
                capture_output=True,
                text=True,
            ).stdout.strip()
            == "false",
            "Fixture did not finish",
            60,
        )
        if not (root / "result.json").exists():
            docker("logs", client_name)
            raise RuntimeError("Fixture client rejected the final PSK evidence")
        print((root / "result.json").read_text())
    finally:
        for name in containers:
            result = subprocess.run(
                ["docker", "logs", name], capture_output=True, text=True
            )
            (root / (name + ".log")).write_text(result.stdout + result.stderr)
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        result = subprocess.run(
            ["docker", *command, "logs", "--no-color"], capture_output=True, text=True
        )
        (root / "services.log").write_text(result.stdout + result.stderr)
        docker(
            *command, "down", "--volumes", "--remove-orphans", stdout=subprocess.DEVNULL
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", action="store_true")
    parser.add_argument("--mock-pve", action="store_true")
    parser.add_argument("--collections", type=Path)
    parser.add_argument("--tools-image", default="homelab-app-test")
    parser.add_argument("--output", type=Path, default=Path(".work/monitoring-fixture"))
    args = parser.parse_args()
    mock_pve() if args.mock_pve else client() if args.client else main(args)
