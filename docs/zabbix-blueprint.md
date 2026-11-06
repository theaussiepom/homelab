# Zabbix blueprint

Use the canonical [root Zabbix reference](reference/zabbix.md) for
presence/null/server selection, monitoring profiles, explicit derived grants and
disabled-selection behavior. The site declares the actual Zabbix app and guest;
root presence does not create a fixed guest or allocation.

- [Zabbix database properties](reference/app-properties.md#authentik-and-zabbix).
- [SAML provider](reference/identity-and-secrets.md#saml) and
  [authentication policy](reference/policies.md#authentication-policies).
- [Deployment and verification](operations/deployment.md).

The existing local recovery form remains a native Zabbix/login contract; do not
confuse its availability with a tested real SAML session. Template import,
active PSKs, database/native plugin readiness and host history require their
own runtime/service evidence.
