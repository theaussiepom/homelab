# Separate web access from device communication

An application can need several network roles. A browser interface should use
the application network; MQTT, database queries, audio streams and Thread
communication keep their own declared interfaces. An endpoint advertises an
address. It does not move a socket or grant access by itself.

1. Add an explicit guest interface without renumbering existing slots or MACs.
2. Bind the application's web role and any published container port to it.
   Host-network services also need their real retained listener configuration
   adjusted separately; changing a route destination alone cannot do that.
3. Point the HTTP exposure at that endpoint. Keep its hostname, certificate,
   middleware and authentication selections intact.
4. Declare the ingress client's source interface and exact backend address/port
   in both directions. Remove obsolete web allowances. Keep DNS, certificate
   issuance, discovery APIs, monitoring and backups as distinct dependencies.
5. Inspect the resulting packet, saved infrastructure plan and allowed/denied
   traffic cases. Then deploy through the protected path and verify the actual
   listener, HTTPS login and device communication separately.

Home Assistant and retained Node-RED also support interface-bound web declarations. Actual socket checks refuse a wildcard or another network address. Prepare retained HA HTTP settings with the selected web IP and loopback before CD; prepare Node-RED’s maintained settings/health wrappers separately. The bound Node-RED runtime derives its non-secret NODE_RED_WEB_ADDRESS from the selected role and probes that address. Fresh Node-RED commissioning with its bound variant is not implemented. HA requires prepared HTTP settings before its socket check can pass.

Music Assistant supports an explicit `stream_interface` guest-interface role in addition
to `web_interface`. Without it, the original shared-address behaviour remains. With it,
retained settings must already match the selected web bind and original stream
bind/publish addresses. Its helper validates these settings without rewriting
provider accounts, library data or player configuration.

InfluxDB supports an optional separate `web_interface` role in addition to `service_interface`.
Because its web UI and database API use the same authenticated HTTP server,
this adds a fixed local systemd socket proxy, not another database or a
read-only UI. The database listener/configuration/data stay on `service_interface`.
The two roles must use different concrete IPv4 addresses and exactly the
`web_listener` and `backend_listener` interface listeners on TCP port 8086. The app owns only
`homelab-influxdb-web.socket` and `homelab-influxdb-web.service`; existing foreign
paths are refused. The socket starts after the network-ready gate and database,
using explicit late-start ordering rather than the early sockets target.
The existing `/usr/lib/systemd/systemd-socket-proxyd` must be executable.
Removing the optional role retires only the owned frontend definitions.

Restrict the web socket to explicitly approved clients with the guest firewall;
the socket unit does not filter sources. InfluxDB sees the proxy's local
connection, not the original client address, so database source-address rules
cannot distinguish those web clients. Keep InfluxDB authentication enabled and
review the effective firewall sources, destination and port before deployment.

The monitoring component resolves a published Zabbix web grant through its
actual exposure endpoint. Agent transport stays on the separate server endpoint.
Review the resulting ingress-to-web address and port before deployment; a unit
test of rule selection does not authorize a live network grant.

Do not route MQTT or Thread through an HTTP proxy. A browser-based MQTT Explorer
can listen on the application network while its server connects separately to
the broker. Matter controller WebSocket/OTBR management interfaces are also
separate from Thread's IPv6 backbone. Preserve fabric, dataset and radio state.
A concrete physical-host change requires that platform's supported interface and
service lifecycle; an LXC packet cannot configure a physical Pi or a switch.

[Network roles](../reference/networks.md) · [Adapter support](../reference/support.md)
