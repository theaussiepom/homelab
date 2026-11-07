# WiNet

WiNet is an independent app, not an implicit part of a Zigbee guest. The selected library defines its profile, image, limits and health-check requirements. The site binds broker/inverter connections, a physical source role, existing options file and MQTT prefix.

[WiNet properties](reference/app-properties.md#pegaprox-and-winet) and [connections](reference/connections.md) are the canonical authored syntax. The options file accepts only the defined settings and preserves credentials, encrypted inverter transport, polling and MQTT identity. Declarations cannot override the entrypoint, supply arbitrary environment variables, configure multiple inverters or select custom certificates.

WiNet's selected options mount does not expose Zigbee data or a coordinator. Each app phase targets only its owned service with --no-deps. To control startup order, declare a readiness dependency that the selected profile supports. Sharing a guest or referencing a value does not set an order.

Preflight rejects a selected Compose project if it still contains an unselected service. It is not automatically removed. The real-image MQTT health fixture covers online/offline/absent/denied states in isolation; actual deployment acceptance also needs fresh telemetry and consumer state. A retained availability message alone does not establish that the data is fresh.

[Documentation index](README.md)
