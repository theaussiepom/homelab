# Optional WiNet on a Zigbee guest

The Zigbee blueprint can also select the `winet` application. Declare its health
contract in the shared profile and include its service plus a closed `stack.winet`
object. The compiler, guest runner and generated workflow use the same explicit
application selection. A Zigbee-only composition remains supported. A private
overlay cannot silently add an application missing from the shared workflow.

WiNet runs after Zigbee2MQTT in the same guest job, with common preparation once.
Each application starts with `compose up --no-deps` targeting only its service.
Only the WiNet phase installs its private runtime options, so that file's changes
cannot force recreation of the coordinator container.

`stack.winet` contains `configuration_file`, `inverter_address`, `mqtt_server` and
`mqtt_prefix`. The named broker connection resolves `mqtt_server` and the container
host alias from the existing service publication. Credentials are in the external
controller-owned mode-0600 options JSON, whose digest joins the ordinary input
binding. Rendering never puts credentials in Compose or a public source file.

Only one inverter is supported here. The options must explicitly retain its
credentials, encrypted transport, polling, analytics/site-total settings and MQTT
identity. Unknown options, custom certificate fields, environment/entrypoint
overrides and unexpected endpoints are refused. The upstream runtime image is
supplied by the composition as an immutable registry digest; the framework does
not build or patch it.

The read-only options bind is the only WiNet file mount; no Zigbee data, radio
device or control socket is exposed. The health command subscribes to the vendor
publisher/inverter availability topics. An isolated real-image MQTT fixture covers
online, offline, absent and denied states. Actual deployment acceptance must also
observe fresh telemetry and Home Assistant state; retained online values alone do
not establish freshness.
