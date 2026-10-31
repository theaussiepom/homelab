# Third-party notices

The root MIT licence applies to original contributions in this repository. It does not replace the licences of third-party material. Retain the notices and licence texts below when redistributing that material. References to separately installed software or container images do not relicense those projects.

The Codex controller, tunnel and their bundled Moby/Docker security profiles are deferred from this initial publication. Their original source, licences and provenance remain preserved separately.

## Zabbix monitoring templates

`proxmox/applications/monitoring/templates/template_app_proxmox.yaml` and
`template_os_linux_active.yaml` are unmodified Zabbix 7.0.32 templates from
Zabbix SIA, upstream commit `0d6fa36d0a0df4552d8df07e5b13deb664089047`.
Their SHA256 digests are retained in `monitoring/versions.json`.
Source: https://github.com/zabbix/zabbix/tree/0d6fa36d0a0df4552d8df07e5b13deb664089047/templates
They are distributed under the GNU Affero General Public License v3.0;
the upstream licence text is retained beside them as `templates/COPYING`.
The repository's MIT licence does not replace that licence.

The four workload templates are also unmodified files from that same upstream
commit, verified byte-for-byte against these sources:

- [Docker](https://github.com/zabbix/zabbix/blob/0d6fa36d0a0df4552d8df07e5b13deb664089047/templates/app/docker/template_app_docker.yaml)
- [PostgreSQL active Agent2](https://github.com/zabbix/zabbix/blob/0d6fa36d0a0df4552d8df07e5b13deb664089047/templates/db/postgresql_agent2_active/template_db_postgresql_agent2_active.yaml)
- [MySQL active Agent2](https://github.com/zabbix/zabbix/blob/0d6fa36d0a0df4552d8df07e5b13deb664089047/templates/db/mysql_agent2_active/template_db_mysql_agent2_active.yaml)
- [InfluxDB HTTP](https://github.com/zabbix/zabbix/blob/0d6fa36d0a0df4552d8df07e5b13deb664089047/templates/db/influxdb_http/template_db_influxdb_http.yaml)

All six source files retain Zabbix's AGPLv3 licence and their exact SHA256 pins in
`monitoring/versions.json`. Prepared copies change the Proxmox template's HTTP TLS
and resource-history settings, derive a separately named active-only Docker
template with deterministic noncolliding UUIDs, and remove organization discovery
and its API-token macro from InfluxDB. PostgreSQL/MySQL active templates and the
Linux template are passed through unchanged. The vendored source files themselves
are never rewritten by preparation.
