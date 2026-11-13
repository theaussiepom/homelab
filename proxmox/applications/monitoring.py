"""Closed clean Zabbix stack and active-only native agent configuration."""

import hashlib
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit

ROOT = Path(__file__).with_name("monitoring")
VERSIONS = json.loads((ROOT / "versions.json").read_text())


def require(value, message):
    if not value:
        raise ValueError(message)


def text(value):
    require(
        isinstance(value, str)
        and bool(value)
        and not any(c in value for c in "\r\n\x00"),
        "Expected a single nonempty monitoring value",
    )
    return value


def saml_settings(value):
    """Supply only the public SAML trust and external HTTPS origin."""
    require(isinstance(value, dict) and set(value) - {"default_login"} == {
        "public_url", "idp_signing_certificate"},
        "Select the public SAML URL and one IdP signing certificate")
    require(isinstance(value.get("default_login", "zabbix"), str)
            and value.get("default_login", "zabbix") in {"zabbix", "saml"},
            "Choose the normal Zabbix or SAML login entry")
    url = urlsplit(text(value["public_url"]))
    require(url.scheme == "https" and url.hostname
            and url.netloc == url.hostname
            and re.fullmatch(r"[a-z0-9][a-z0-9.-]*", url.hostname)
            and url.path in {"", "/"} and not url.query and not url.fragment,
            "Use the external HTTPS Zabbix origin without credentials or parameters")
    cert = value["idp_signing_certificate"]
    require(isinstance(cert, str) and len(cert.encode()) <= 65536
            and cert.count("-----BEGIN CERTIFICATE-----") == 1
            and cert.count("-----END CERTIFICATE-----") == 1
            and cert.strip().startswith("-----BEGIN CERTIFICATE-----")
            and cert.strip().endswith("-----END CERTIFICATE-----")
            and "PRIVATE KEY" not in cert and "\x00" not in cert,
            "Provide one public IdP certificate, never a private key")
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=cert)
    except ssl.SSLError:
        raise ValueError("Provide a valid X509 IdP signing certificate") from None
    return {"strict": True, "baseurl": value["public_url"].rstrip("/") + "/",
            "use_proxy_headers": False,
            "idp": {"x509certMulti": {"signing": [cert]}}}




def check_templates():
    for name, expected in VERSIONS["templates"].items():
        require(
            hashlib.sha256((ROOT / "templates" / name).read_bytes()).hexdigest()
            == expected,
            "The pinned official template changed; review its source and digest",
        )






def service_configuration(m, services, *, mount, timezone='Etc/UTC',
                          server_service='zabbix_server', server_ports=None, web_ports=None):
    """Pure protocol/service transformation; no private runtime file reads."""
    require(isinstance(server_service, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', server_service),
            'Use the exact owned monitoring server service name')
    database = {
        "DB_SERVER_HOST": m["postgresql_host"],
        "DB_SERVER_PORT": "5432",
        "POSTGRES_USER": m["postgresql_user"],
        "POSTGRES_DB": m["postgresql_database"],
        "POSTGRES_PASSWORD_FILE": "/run/secrets/database-password",
        "ZBX_DBTLSCONNECT": "required",
        "TZ": timezone.replace("$", "$$"),
    }
    for service in services.values():
        service['environment'] = dict(database)
        service['volumes'] = [mount('database-password', '/run/secrets/database-password')]
    server, web = services["zabbix_server"], services["zabbix_web"]
    server["environment"].update(
        {"ZBX_STARTREPORTWRITERS": "0", "ZBX_STARTBROWSERPOLLERS": "0"}
    )
    server['volumes'].append(mount('proxmox-ca.pem', '/var/lib/zabbix/ssl/ssl_ca/proxmox-ca.pem'))
    server["ports"] = server_ports if server_ports is not None else [m["bind_address"] + ":10051:10051"]
    web["environment"].update(
        {
            "ZBX_SERVER_HOST": server_service,
            "ZBX_SERVER_PORT": "10051",
            "PHP_TZ": timezone,
            "ZBX_DB_ENCRYPTION": "true",
        }
    )
    if "saml" in m:
        web["environment"]["ZBX_SSO_SETTINGS"] = json.dumps(
            saml_settings(m["saml"]), sort_keys=True, separators=(",", ":"))
        if m["saml"].get("default_login") == "saml":
            web['volumes'].append(mount('saml-login.php', '/usr/share/zabbix/local/app/views/general.login.php'))
    web["ports"] = web_ports if web_ports is not None else [m["bind_address"] + ":8080:8080", "127.0.0.1:8081:8080"]
    web["depends_on"] = {server_service: {"condition": "service_started"}}
    return services




def agent_config(value):
    require(
        set(value) == {"hostname", "server_active", "psk_identity", "psk_path"},
        "Use the closed active agent configuration",
    )
    for key in value:
        text(value[key])
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value["hostname"]),
        "Invalid agent hostname",
    )
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value["psk_identity"]),
        "Invalid PSK identity",
    )
    require(
        re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]*:10051", value["server_active"]),
        "Use one active server on TCP 10051",
    )
    require(
        value["psk_path"] == "/etc/zabbix/agent.psk", "Use the selected agent PSK path"
    )
    return (
        "LogType=system\nHostname="
        + value["hostname"]
        + "\nServerActive="
        + value["server_active"]
        + "\nTLSConnect=psk\nTLSPSKIdentity="
        + value["psk_identity"]
        + "\nTLSPSKFile="
        + value["psk_path"]
        + "\nDenyKey=system.run[*]\n"
        "ControlSocket=/run/zabbix/agent.sock\n"
    )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-config", type=Path, required=True)
    args = parser.parse_args()
    print(
        agent_config(
            json.loads(
                sys.stdin.read()
                if str(args.agent_config) == "-"
                else args.agent_config.read_text()
            )
        ),
        end="",
    )
