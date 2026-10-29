"""Run pinned Traefik and its unmodified Proxmox plugin against synthetic HTTPS.

Only loopback inside a Docker network namespace is used: no published ports,
Docker socket mounts, live PVE access, real tokens, or application data. Fetch
the pinned upstream source before running this fixture; --plugin-source accepts
its checkout or extracted archive and verifies all source bytes before use.
"""

import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile

IMAGE = (
    "traefik@sha256:1336e85aaed293bd63d005086e0dd013b04078b26aaeb1c18b26a2f928af7e65"
)
MODULE = "github.com/NX211/traefik-proxmox-provider"
PLUGIN_COMMIT = "e35cce5af139328b8e424836a0b32638ed777016"
PLUGIN_TREE_SHA256 = "b1154d92f81ef7c1b85b2f572735839b82c352f4e1fc5da8d398301e63bfc247"
PLUGIN_ARCHIVE_SHA256 = (
    "9e3b91e0ba79fc27dd2587e8b92db725a424a9c21cb17cfcf07b1ef6e354efd7"
)
TOKEN = "PVEAPIToken=fixture@pve!discovery=synthetic-not-a-secret"
SERVICES = {
    211: ("authentik", "sso.example.invalid", 9000),
    202: ("pgadmin", "pgadmin.example.invalid", 8080),
    200: ("node-red", "flows.example.invalid", 1880),
    212: ("influxdb", "influx.example.invalid", 8086),
}


def source_digest(root):
    digest = hashlib.sha256()
    files = sorted(
        path
        for path in root.rglob("*")
        if ".git" not in path.relative_to(root).parts and path.is_file()
    )
    if any(path.is_symlink() for path in files):
        raise ValueError("Plugin fixture source must not contain symlinks")
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def verify_archive(path):
    if (
        path.stat().st_size > 2 * 1024 * 1024
        or hashlib.sha256(path.read_bytes()).hexdigest() != PLUGIN_ARCHIVE_SHA256
    ):
        raise ValueError("Catalog ZIP differs from the pinned archive bytes")
    files = {}
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            if item.is_dir():
                continue
            parts = PurePosixPath(item.filename).parts
            if (
                len(parts) < 2
                or ".." in parts
                or item.filename.startswith("/")
                or item.file_size > 1024 * 1024
            ):
                raise ValueError("Unexpected catalog archive member")
            name = "/".join(parts[1:])
            if name in files:
                raise ValueError("Duplicate catalog archive member")
            files[name] = archive.read(item)
    digest = hashlib.sha256()
    for name, value in sorted(files.items()):
        digest.update(name.encode() + b"\0" + value + b"\0")
    if digest.hexdigest() != PLUGIN_TREE_SHA256:
        raise ValueError("Catalog archive code differs from the tested commit tree")


def notes(name, host, port):
    # Notes are compiled by production discovery.labels on the controller. Only
    # the transport addresses and ACME are adapted to this offline namespace.
    return json.loads(Path("/fixture/notes.json").read_text())[name]


def fixture_notes():
    from discovery import labels

    notes_data = {}
    for name, host, port in SERVICES.values():
        compiled = labels(
            {
                "guest": {"interfaces": [{"ipv4": "10.88.30.21/24"}]},
                "routes": {name: {"host": host, "url": f"http://10.88.30.21:{port}",
                                  **({"middlewares": ["local-clients", "security-headers"]} if name == "influxdb" else {})}},
            }
        )
        if name == "node-red":
            compiled.update(
                labels(
                    {
                        "guest": {"interfaces": [{"ipv4": "10.88.30.21/24"}]},
                        "routes": {
                            "homeassistant": {
                                "host": "ha.example.invalid",
                                "url": "http://10.88.30.21:8123",
                            }
                        },
                    }
                )
            )
        if name == "authentik":
            compiled.update(
                labels(
                    {
                        "guest": {"interfaces": [{"ipv4": "10.88.30.21/24"}]},
                        "routes": {
                            "tls-app": {
                                "host": "tls-app.example.invalid",
                                "url": "https://10.88.30.21:9443",
                                "transport": "app-ca",
                            }
                        },
                    }
                )
            )
        # No ACME endpoint, credentials or real private destination in a fixture.
        compiled = {
            key: value.replace("10.88.30.21", "127.0.0.1")
            for key, value in compiled.items()
            if not key.endswith(".tls.certresolver")
        }
        notes_data[name] = "\n".join(
            f"{key}: {value}" for key, value in sorted(compiled.items())
        )
    return notes_data


def serve():
    calls = []
    lock = threading.Lock()

    class Backend(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/ws" and self.headers.get("Upgrade") == "websocket":
                import base64

                accept = base64.b64encode(
                    hashlib.sha1(
                        (
                            self.headers["Sec-WebSocket-Key"]
                            + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                        ).encode()
                    ).digest()
                ).decode()
                self.send_response(101)
                self.send_header("Connection", "Upgrade")
                self.send_header("Upgrade", "websocket")
                self.send_header("Sec-WebSocket-Accept", accept)
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "backend": self.server.server_port,
                        "path": self.path,
                        "host": self.headers.get("Host"),
                        "proto": self.headers.get("X-Forwarded-Proto"),
                        "user": self.headers.get("X-authentik-username"),
                        "authorization": self.headers.get("Authorization"),
                        "cookie": self.headers.get("Cookie"),
                    }
                ).encode()
            )

        def log_message(self, *args):
            pass

    class PVE(BaseHTTPRequestHandler):
        def send_json(self, status, payload):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())

        def do_GET(self):
            if self.path == "/fixture/requests":
                with lock:
                    return self.send_json(200, list(calls))
            if self.path == "/fixture/reset":
                with lock:
                    calls.clear()
                    return self.send_json(200, [])
            with lock:
                calls.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "authorized": self.headers.get("Authorization") == TOKEN,
                    }
                )
            if self.headers.get("Authorization") != TOKEN:
                return self.send_json(401, {"error": "Synthetic token required"})
            data = {
                "/api2/json/version": {"release": "fixture-only"},
                "/api2/json/nodes": [{"node": "fixture"}],
                "/api2/json/nodes/fixture/qemu": [],
                "/api2/json/nodes/fixture/lxc": [
                    {"vmid": vmid, "name": value[0], "status": "running"}
                    for vmid, value in SERVICES.items()
                ]
                + [
                    {"vmid": 213, "name": "stopped", "status": "stopped"},
                    {"vmid": 214, "name": "disabled", "status": "running"},
                ],
                "/api2/json/nodes/fixture/lxc/214/config": {
                    "description": "traefik.enable: false"
                },
            }
            for vmid, value in SERVICES.items():
                data[f"/api2/json/nodes/fixture/lxc/{vmid}/config"] = {
                    "description": notes(*value)
                }
            if self.path in data:
                return self.send_json(200, {"data": data[self.path]})
            # The pinned plugin asks a QEMU-agent endpoint even for LXCs. Deny
            # it: passing routes must use the declared backend URL, not discovery.
            return self.send_json(404, {"error": "No such synthetic API endpoint"})

        def reject_mutation(self):
            with lock:
                calls.append(
                    {"method": self.command, "path": self.path, "authorized": False}
                )
            self.send_json(405, {"error": "Read-only fixture"})

        do_POST = do_PUT = do_DELETE = do_PATCH = reject_mutation

        def log_message(self, *args):
            pass

    for port in (9000, 8080, 1880, 8123, 8086):
        server = ThreadingHTTPServer(("127.0.0.1", port), Backend)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    api = ThreadingHTTPServer(("127.0.0.1", 8006), PVE)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/fixture/server.pem", "/fixture/server.key")
    backend_tls = ThreadingHTTPServer(("127.0.0.1", 9443), Backend)
    backend_tls.socket = context.wrap_socket(backend_tls.socket, server_side=True)
    threading.Thread(target=backend_tls.serve_forever, daemon=True).start()
    api.socket = context.wrap_socket(api.socket, server_side=True)
    threading.Thread(target=api.serve_forever, daemon=True).start()

    class Catalog(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/public/download/" + MODULE + "/v0.7.0":
                self.send_error(404)
                return
            payload = Path("/fixture/plugin.zip").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    class CatalogProxy(BaseHTTPRequestHandler):
        def do_CONNECT(self):
            if self.path != "plugins.traefik.io:443":
                self.send_error(403)
                return
            self.connection.settimeout(10)
            self.send_response(200, "Connection Established")
            self.end_headers()
            # This explicitly synthetic proxy never forwards traffic. It lets
            # the real pinned downloader verify the supplied archive offline.
            with context.wrap_socket(self.connection, server_side=True) as secured:
                Catalog(secured, self.client_address, self.server)
            self.close_connection = True

        def log_message(self, *args):
            pass

    if Path("/fixture/plugin.zip").exists():
        catalog = ThreadingHTTPServer(("127.0.0.1", 9999), CatalogProxy)
        threading.Thread(target=catalog.serve_forever, daemon=True).start()
    threading.Event().wait()


def request(host, path, headers=None, peer="127.0.0.1"):
    context = ssl.create_default_context(cafile="/fixture/ca.pem")
    conn = http.client.HTTPSConnection("127.0.0.1", 8443, timeout=3, context=context,
                                      source_address=(peer, 0))
    try:
        conn.request("GET", path, headers={"Host": host, **(headers or {})})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def api_calls(reset=False):
    conn = http.client.HTTPSConnection(
        "127.0.0.1",
        8006,
        timeout=3,
        context=ssl.create_default_context(cafile="/fixture/ca.pem"),
    )
    try:
        conn.request("GET", "/fixture/reset" if reset else "/fixture/requests")
        response = conn.getresponse()
        assert response.status == 200, response.status
        return json.loads(response.read())
    finally:
        conn.close()


def check():
    for attempt in range(90):
        try:
            if request("sso.example.invalid", "/ready")[0] == 200:
                break
        except (OSError, ssl.SSLError):
            pass
        if attempt == 89:
            raise RuntimeError("Synthetic provider startup exceeded 45 seconds")
        time.sleep(0.5)
    for name, host, port in SERVICES.values():
        paths = ["/"]
        if name == "authentik":
            paths += [
                "/application/o/pgadmin4/.well-known/openid-configuration",
                "/application/o/authorize/?client_id=synthetic",
            ]
        elif name == "node-red":
            paths += [
                "/auth/login",
                "/auth/strategy",
                "/auth/strategy/callback?code=synthetic",
            ]
        elif name == "pgadmin":
            paths += ["/oauth2/authorize?code=synthetic"]
        for path in paths:
            status, headers, body = request(host, path)
            assert status == 200, (host, path, status)
            assert json.loads(body) == {
                "backend": port,
                "path": path,
                "host": host,
                "proto": "https",
                "user": None,
                "authorization": None,
                "cookie": None,
            }
            assert headers.get("X-Fixture-Policy") == "notes-discovery"
            assert headers.get("Strict-Transport-Security") == "max-age=31536000"
            assert (
                "Location" not in headers
            ), "Native application paths must reach their own login handler"
    native = {"Authorization": "Token synthetic-only", "Cookie": "native=synthetic"}
    status, _, body = request("influx.example.invalid", "/api/v2/query?org=synthetic", native)
    observed = json.loads(body)
    assert status == 200 and observed["backend"] == 8086
    assert observed["authorization"] == native["Authorization"]
    assert observed["cookie"] == native["Cookie"]
    for headers in ({}, {"X-Forwarded-For": "127.0.0.1", "CF-Connecting-IP": "127.0.0.1"}):
        assert request("influx.example.invalid", "/", headers, peer="127.0.0.2")[0] == 403
    status, _, body = request("ha.example.invalid", "/auth/authorize")
    assert status == 200 and json.loads(body)["backend"] == 8123
    for host, port in (
        ("nas.example.invalid", 9000),
        ("nas-alias.example.invalid", 9000),
        ("external-tls.example.invalid", 9443),
        ("tls-app.example.invalid", 9443),
    ):
        status, headers, body = request(host, "/login?next=ui")
        assert status == 200, (host, status, body)
        assert json.loads(body)["backend"] == port
        assert headers.get("X-Fixture-Policy") == "notes-discovery"
    for host in ("wrong-ca.example.invalid", "wrong-name.example.invalid"):
        assert request(host, "/")[0] == 500, host
    assert request("private.example.invalid", "/")[0] == 403
    assert (
        request(
            "matter.example.invalid",
            "/ws",
            {
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": base64.b64encode(bytes(range(16))).decode(),
            },
        )[0]
        == 101
    )
    for host in (
        "unrouted.example.invalid",
        "stopped.example.invalid",
        "disabled.example.invalid",
    ):
        assert request(host, "/")[0] == 404, host
    calls = api_calls()
    assert calls and all(
        call["method"] == "GET" and call["authorized"] for call in calls
    ), calls
    paths = {call["path"] for call in calls}
    for vmid in SERVICES:
        assert f"/api2/json/nodes/fixture/lxc/{vmid}/config" in paths
        assert (
            f"/api2/json/nodes/fixture/qemu/{vmid}/agent/network-get-interfaces"
            in paths
        )
    assert "/api2/json/nodes/fixture/lxc/213/config" not in paths
    print(
        "Provider fixture passed: pinned plugin discovers four synthetic guests; "
        "HA and Node-RED native login paths, external HTTP/TLS/aliases, Notes TLS transports, CA/SNI rejection, middleware denial, spoofed-peer denial, Influx native headers/cookies and WebSocket upgrade verified. "
        "Native PVE and real login remain unverified."
    )


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, timeout=180, **kwargs)


def certificate_files(root):
    def openssl(*args):
        subprocess.run(
            ["openssl", *args],
            check=True,
            timeout=20,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    (root / "ca.cnf").write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\n"
        "[dn]\n[ca]\nbasicConstraints=critical,CA:true\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
    )
    for name in ("ca", "wrong-ca"):
        openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            f"/CN=Homelab synthetic provider {name}",
            "-config",
            str(root / "ca.cnf"),
            "-keyout",
            str(root / f"{name}.key"),
            "-out",
            str(root / f"{name}.pem"),
        )
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=127.0.0.1",
        "-keyout",
        str(root / "server.key"),
        "-out",
        str(root / "server.csr"),
    )
    (root / "server.ext").write_text(
        "subjectAltName=IP:127.0.0.1,DNS:sso.example.invalid,DNS:plugins.traefik.io\n"
        "extendedKeyUsage=serverAuth\n"
    )
    openssl(
        "x509",
        "-req",
        "-in",
        str(root / "server.csr"),
        "-CA",
        str(root / "ca.pem"),
        "-CAkey",
        str(root / "ca.key"),
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        str(root / "server.ext"),
        "-out",
        str(root / "server.pem"),
    )
    for path in root.iterdir():
        path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools-image", default="homelab-app-test")
    parser.add_argument(
        "--plugin-source",
        type=Path,
        required=True,
        help=f"Unmodified source at {MODULE}@{PLUGIN_COMMIT}",
    )
    parser.add_argument(
        "--plugin-archive",
        type=Path,
        help="Exact catalog ZIP; also prove the production downloader accepts only the pinned hash",
    )
    args = parser.parse_args()
    plugin_source = args.plugin_source.resolve(strict=True)
    if source_digest(plugin_source) != PLUGIN_TREE_SHA256:
        raise ValueError("Plugin source differs from the pinned v0.7.0 source tree")
    if args.plugin_archive:
        verify_archive(args.plugin_archive)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from foundation import PLUGIN_ARCHIVE_SHA256 as production_hash

        if production_hash != PLUGIN_ARCHIVE_SHA256:
            raise ValueError("Production and proven archive pins differ")
    names = []
    with tempfile.TemporaryDirectory(prefix="homelab-provider-fixture-") as tmp:
        root = Path(tmp)
        certificate_files(root)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        notes_data = fixture_notes()
        (root / "notes.json").write_text(json.dumps(notes_data))
        if args.plugin_archive:
            (root / "plugin.zip").write_bytes(args.plugin_archive.read_bytes())
        from discovery import shared

        dynamic = shared(
            {
                "routes": {
                    "nas": {
                        "host": "nas.example.invalid",
                        "aliases": ["nas-alias.example.invalid"],
                        "url": "http://198.18.30.21:9000",
                    },
                    "external-tls": {
                        "host": "external-tls.example.invalid",
                        "url": "https://198.18.30.21:9443",
                        "transport": "app-ca",
                    },
                    "wrong-ca": {
                        "host": "wrong-ca.example.invalid",
                        "url": "https://198.18.30.21:9443",
                        "transport": "wrong-ca",
                    },
                    "wrong-name": {
                        "host": "wrong-name.example.invalid",
                        "url": "https://198.18.30.21:9443",
                        "transport": "wrong-name",
                    },
                    "private": {
                        "host": "private.example.invalid",
                        "url": "http://198.18.30.21:9000",
                        "middlewares": ["private-clients"],
                    },
                    "matter": {
                        "host": "matter.example.invalid",
                        "url": "http://198.18.30.21:9000",
                    },
                },
                "middlewares": {
                    "local-clients": {"ipAllowList": {"sourceRange": ["127.0.0.1/32"]}},
                    "private-clients": {
                        "ipAllowList": {"sourceRange": ["198.18.0.0/15"]}
                    },
                    "compression": {"compress": {}},
                },
                "transports": {
                    "app-ca": {
                        "ca_file": "/trust/ca.pem",
                        "server_name": "sso.example.invalid",
                    },
                    "wrong-ca": {
                        "ca_file": "/trust/wrong.pem",
                        "server_name": "sso.example.invalid",
                    },
                    "wrong-name": {
                        "ca_file": "/trust/ca.pem",
                        "server_name": "wrong.example.invalid",
                    },
                },
            }
        )
        # Only synthetic namespace adaptations follow the production renderer.
        for router in dynamic["http"]["routers"].values():
            router["tls"] = {}
        for service in dynamic["http"]["services"].values():
            for backend in service["loadBalancer"]["servers"]:
                backend["url"] = backend["url"].replace("198.18.30.21", "127.0.0.1")
        for key, transport in dynamic["http"]["serversTransports"].items():
            transport["rootCAs"] = [
                "/fixture/wrong-ca.pem" if key == "wrong-ca" else "/fixture/ca.pem"
            ]
        dynamic["http"]["middlewares"]["security-headers"]["headers"].update(
            {
                "customResponseHeaders": {"X-Fixture-Policy": "notes-discovery"},
                "stsSeconds": 31536000,
            }
        )
        dynamic["tls"]["stores"] = {
            "default": {
                "defaultCertificate": {
                    "certFile": "/fixture/server.pem",
                    "keyFile": "/fixture/server.key",
                }
            }
        }
        (root / "dynamic.yml").write_text(json.dumps(dynamic))
        static = {
            "entryPoints": {"websecure": {"address": ":8443"}},
            "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
            "experimental": {"localPlugins": {"proxmox": {"moduleName": MODULE}}},
            "providers": {
                "file": {"filename": "/fixture/dynamic.yml"},
                "plugin": {
                    "proxmox": {
                        "pollInterval": "5s",
                        "apiEndpoint": "https://127.0.0.1:8006",
                        "apiTokenId": "fixture@pve!discovery",
                        "apiToken": "synthetic-not-a-secret",
                        "apiLogging": "info",
                        "apiValidateSSL": "true",
                    }
                },
            },
        }
        (root / "static.json").write_text(json.dumps(static))
        try:
            backend_name = "homelab-provider-backends-" + uuid.uuid4().hex[:10]
            names.append(backend_name)
            common = [
                "run",
                "-d",
                "--platform",
                "linux/amd64",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--cpus",
                "1",
                "--memory",
                "384m",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=32m",
                "-v",
                f"{root}:/fixture:ro",
            ]
            docker(
                *common,
                "--name",
                backend_name,
                "--network",
                "none",
                "--entrypoint",
                "python3",
                "-v",
                f"{Path(__file__).resolve()}:/fixture.py:ro",
                args.tools_image,
                "/fixture.py",
                "serve",
                stdout=subprocess.DEVNULL,
            )
            # A deliberately unrelated CA must prevent the real provider from
            # reading even /version. This checks the plugin's TLS setting, not
            # just Python's certificate validation.
            for trusted in (False, True):
                proxy_name = "homelab-provider-proxy-" + uuid.uuid4().hex[:10]
                names.append(proxy_name)
                ca = "ca.pem" if trusted else "wrong-ca.pem"
                docker(
                    *common,
                    "--name",
                    proxy_name,
                    "--network",
                    "container:" + backend_name,
                    "-e",
                    f"SSL_CERT_FILE=/fixture/{ca}",
                    "-e",
                    "SSL_CERT_DIR=/fixture/no-certs",
                    "-v",
                    f"{plugin_source}:/plugins-local/src/{MODULE}:ro",
                    IMAGE,
                    "--configFile=/fixture/static.json",
                    stdout=subprocess.DEVNULL,
                )
                if trusted:
                    docker("exec", backend_name, "python3", "/fixture.py", "check")
                else:
                    for attempt in range(90):
                        result = docker(
                            "logs", proxy_name, capture_output=True, text=True
                        )
                        if (
                            "certificate signed by unknown authority"
                            in result.stdout + result.stderr
                        ):
                            break
                        if attempt == 89:
                            raise RuntimeError(
                                "Provider did not reject the untrusted PVE certificate within 45 seconds"
                            )
                        time.sleep(0.5)
                    docker(
                        "exec",
                        backend_name,
                        "python3",
                        "/fixture.py",
                        "check-untrusted",
                    )
                    print(
                        "Provider rejected the unrelated PVE CA with TLS verification enabled."
                    )
                docker("rm", "-f", proxy_name, stdout=subprocess.DEVNULL)
                names.remove(proxy_name)
            if args.plugin_archive:
                for correct_hash in (False, True):
                    docker("exec", backend_name, "python3", "/fixture.py", "reset-api")
                    remote = json.loads(json.dumps(static))
                    remote["experimental"] = {
                        "abortOnPluginFailure": True,
                        "plugins": {
                            "proxmox": {
                                "moduleName": MODULE,
                                "version": "v0.7.0",
                                "hash": (
                                    PLUGIN_ARCHIVE_SHA256 if correct_hash else "0" * 64
                                ),
                            }
                        },
                    }
                    (root / "remote.json").write_text(json.dumps(remote))
                    proxy_name = "homelab-provider-archive-" + uuid.uuid4().hex[:10]
                    names.append(proxy_name)
                    docker(
                        *common,
                        "--name",
                        proxy_name,
                        "--network",
                        "container:" + backend_name,
                        "-e",
                        "SSL_CERT_FILE=/fixture/ca.pem",
                        "-e",
                        "SSL_CERT_DIR=/fixture/no-certs",
                        "-e",
                        "HTTPS_PROXY=http://127.0.0.1:9999",
                        "--tmpfs",
                        f"/plugins-storage:rw,nosuid,nodev,size=8m,uid={os.getuid()},gid={os.getgid()},mode=0700",
                        IMAGE,
                        "--configFile=/fixture/remote.json",
                        stdout=subprocess.DEVNULL,
                    )
                    if correct_hash:
                        docker("exec", backend_name, "python3", "/fixture.py", "check")
                    else:
                        for attempt in range(90):
                            logs = docker(
                                "logs", proxy_name, capture_output=True, text=True
                            )
                            running = docker(
                                "inspect",
                                "--format",
                                "{{.State.Running}}",
                                proxy_name,
                                capture_output=True,
                                text=True,
                            ).stdout.strip()
                            if (
                                "invalid hash for plugin" in logs.stdout + logs.stderr
                                and running == "false"
                            ):
                                break
                            if attempt == 89:
                                raise RuntimeError(
                                    "Pinned downloader did not fail closed on the wrong archive hash"
                                )
                            time.sleep(0.5)
                        docker(
                            "exec",
                            backend_name,
                            "python3",
                            "/fixture.py",
                            "check-untrusted",
                        )
                        print(
                            "Pinned production downloader rejected the wrong ZIP hash before any PVE API read."
                        )
                    docker("rm", "-f", proxy_name, stdout=subprocess.DEVNULL)
                    names.remove(proxy_name)
                print(
                    "Pinned production downloader accepted only the verified catalog ZIP and routed the synthetic guests."
                )
        except Exception:
            for name in names:
                subprocess.run(
                    ["docker", "logs", "--tail", "60", name], check=False, timeout=20
                )
            raise
        finally:
            for name in reversed(names):
                subprocess.run(
                    ["docker", "rm", "-f", name],
                    check=False,
                    timeout=30,
                    stdout=subprocess.DEVNULL,
                )


if __name__ == "__main__":
    if sys.argv[1:] == ["serve"]:
        serve()
    elif sys.argv[1:] == ["check"]:
        check()
    elif sys.argv[1:] == ["check-untrusted"]:
        assert not api_calls(), "The untrusted plugin must not reach the API"
    elif sys.argv[1:] == ["reset-api"]:
        api_calls(reset=True)
    else:
        main()
