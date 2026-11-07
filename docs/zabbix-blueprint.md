# Zabbix blueprint

Use the canonical [root Zabbix reference](reference/zabbix.md) for the effects of an omitted or null value, server selection, monitoring profiles, derived access rules and disabled guests. The site declares the actual Zabbix app and guest; root presence does not create a fixed guest or allocation.

- [Zabbix database properties](reference/app-properties.md#authentik-and-zabbix).
- [SAML provider](reference/identity-and-secrets.md#saml) and [authentication policy](reference/policies.md#authentication-policies).
- [Deployment and verification](operations/deployment.md).

The local recovery form remains part of Zabbix's own login behavior; do not confuse its availability with a tested real SAML session. Template import, active pre-shared keys (PSKs), database and native-plugin readiness, and host history each require their own checks against the running service.
