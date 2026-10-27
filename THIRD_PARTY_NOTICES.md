# Third-party notices

The root MIT licence applies to original contributions in this repository. It does not replace the licences of third-party material. Retain the notices and licence texts below when redistributing that material. References to separately installed software or container images do not relicense those projects.

The Codex controller, tunnel and their bundled Moby/Docker security profiles are deferred from this initial publication. Their original source, licences and provenance remain preserved separately.

## Zabbix monitoring templates

The six files in `proxmox/applications/monitoring/templates/` are unmodified
Zabbix 7.0.32 templates: `template_app_proxmox.yaml`,
`template_os_linux_active.yaml`, `template_app_docker.yaml`,
`template_db_postgresql_agent2_active.yaml`, `template_db_mysql_agent2_active.yaml`
and `template_db_influxdb_http.yaml`, from
Zabbix SIA, upstream commit `0d6fa36d0a0df4552d8df07e5b13deb664089047`.
Their SHA256 digests are retained in `monitoring/versions.json`.
Source: https://github.com/zabbix/zabbix/tree/0d6fa36d0a0df4552d8df07e5b13deb664089047/templates
They are distributed under the GNU Affero General Public License v3.0;
the upstream licence text is retained beside them as `templates/COPYING`.
The repository's MIT licence does not replace that licence.
