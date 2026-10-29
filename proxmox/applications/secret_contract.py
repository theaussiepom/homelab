"""Fixed foundation secret names, sources and runtime filenames; no secret values."""

from dataclasses import dataclass
from private_io import require


@dataclass(frozen=True)
class SecretBinding:
    filename: str
    environment: str | None
    required: bool = True

    @property
    def runtime_path(self):
        return "/run/secrets/" + self.filename


BINDINGS = {
    "identity": {
        "secret_key": SecretBinding("authentik-secret-key", "AUTHENTIK_SECRET_KEY"),
        "postgresql_password": SecretBinding(
            "postgresql-password", "AUTHENTIK_POSTGRES_PASSWORD"
        ),
        "smtp_password": SecretBinding(
            "smtp-password", "AUTHENTIK_SMTP_PASSWORD", required=False
        ),
    },
    "db-tools": {
        "oauth_client_secret": SecretBinding(
            "oauth-client-secret", "PGADMIN_OAUTH_SECRET"
        )
    },
    "ingress": {
        "cloudflare_dns_token": SecretBinding(
            "cloudflare-dns-token", "CLOUDFLARE_DNS_TOKEN"
        ),
        "proxmox_token": SecretBinding("proxmox-token", None),
    },
}


def validate_names(kind, selected):
    require(
        kind in BINDINGS and isinstance(selected, dict),
        "Select foundation secret file references",
    )
    bindings = BINDINGS[kind]
    require(
        {key for key, binding in bindings.items() if binding.required}
        <= selected.keys()
        and selected.keys() <= bindings.keys(),
        "Supply only the selected foundation secret file references",
    )
    return {key: bindings[key] for key in selected}
