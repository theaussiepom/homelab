#!/usr/bin/env python3
"""Generic TCP/HTTP/WebSocket handshakes from a container's network namespace."""
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys


def jrun(argv):
    return json.loads(subprocess.run(argv, check=True, capture_output=True, text=True, timeout=10).stdout)


def exchange(check):
    ipaddress.ip_address(check["address"])
    if type(check["port"]) is not int or not 1 <= check["port"] <= 65535:
        raise ValueError("Invalid port")
    protocol = check.get("protocol", "tcp")
    if protocol not in ("tcp", "http", "websocket"):
        raise ValueError("Unsupported protocol")
    path = check.get("path", "/")
    if not path.startswith("/") or re.search(r"[\r\n\x00 ]", path):
        raise ValueError("Invalid HTTP path")
    with socket.create_connection((check["address"], check["port"]), timeout=3) as client:
        if protocol == "tcp":
            return {"healthy": True, "protocol": protocol}
        authority = check["address"] + ":" + str(check["port"])
        key = base64.b64encode(os.urandom(16)).decode()
        headers = [f"GET {path} HTTP/1.1", "Host: " + authority]
        if protocol == "websocket":
            headers += ["Connection: Upgrade", "Upgrade: websocket", "Sec-WebSocket-Version: 13",
                        "Sec-WebSocket-Key: " + key]
        else:
            headers += ["Connection: close"]
        client.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
        response = b""
        while b"\r\n\r\n" not in response and len(response) < 16384:
            piece = client.recv(2048)
            if not piece:
                break
            response += piece
        rows = response.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1").split("\r\n")
        code = int(rows[0].split()[1])
        if protocol == "http":
            return {"healthy": code in check.get("statuses", [200]), "protocol": protocol, "http_status": code}
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        # Header field names are case-insensitive, but the accept token is case-sensitive.
        fields = {line.split(":", 1)[0].lower(): line.split(":", 1)[1].strip() for line in rows[1:] if ":" in line}
        return {"healthy": code == 101 and fields.get("sec-websocket-accept") == expected,
                "protocol": protocol, "http_status": code}


def check_one(check):
    for value in (check["source"], check["target"], check["network"]):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value):
            raise ValueError("Invalid declared service name")
    container = jrun(["docker", "inspect", check["source"]])[0]
    if not container["State"]["Running"]:
        return {"healthy": False, "reason": "source_stopped"}
    network = jrun(["docker", "network", "inspect", "-v", check["network"]])[0]
    tasks = [task for service in network.get("Services", {}).values() for task in service.get("Tasks", [])
             if task.get("Name") == check["target"]]
    if len(tasks) != 1:
        return {"healthy": False, "reason": "target_not_unique"}
    namespace = container["NetworkSettings"]["SandboxKey"]
    if not namespace.startswith("/var/run/docker/netns/") or ".." in namespace:
        raise ValueError("Invalid source namespace")
    with open(namespace, "rb") as handle:
        params = {**check, "address": tasks[0]["EndpointIP"].split("/")[0]}
        result = subprocess.run(["nsenter", "--net=/proc/self/fd/" + str(handle.fileno()), "--",
                                 "/usr/bin/python3", str(Path(__file__).resolve()), "--exchange", json.dumps(params)],
                                pass_fds=(handle.fileno(),), capture_output=True, text=True, timeout=8)
        if result.returncode:
            return {"healthy": False, "reason": "probe_failed"}
        return json.loads(result.stdout)


def observe(config):
    result = []
    for check in config.get("probes", []):
        try:
            outcome = check_one(check)
        except Exception as exc:
            outcome = {"healthy": False, "reason": type(exc).__name__}
        result.append({"name": check["name"], **outcome})
    return result


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--exchange":
    try:
        print(json.dumps(exchange(json.loads(sys.argv[2]))))
    except Exception as error:
        print(json.dumps({"healthy": False, "reason": type(error).__name__}))
