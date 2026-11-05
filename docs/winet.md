# WiNet

WiNet is an independent app, not an implicit part of a Zigbee guest.
The selected library defines its profile, image, limits and health contract.
The site binds broker/inverter connections, a physical source role, existing
options file and MQTT prefix.

[WiNet properties](reference/app-properties.md#pegaprox-and-winet) and
[connections](reference/connections.md) are the canonical authored syntax.
The existing closed options contract preserves credentials, encrypted inverter
transport, polling and MQTT identity. No authored entrypoint/environment bag,
multiple-inverter configuration or custom certificate override is provided.

WiNet's selected options mount does not expose Zigbee data or a coordinator.
Each app phase targets only its owned service with --no-deps. A readiness edge
must be declared when the selected profile supports it; co-location or a value
link does not invent an order.

An unselected service left in a selected Compose project refuses preflight.
It is not automatically removed. The real-image MQTT health fixture covers
online/offline/absent/denied states in isolation; actual deployment acceptance
also needs fresh telemetry and consumer state. Retained availability alone is
not freshness evidence.

[Documentation index](README.md)
