#!/bin/sh
# Preserve the existing HA startup route behaviour with a selected guest address.
set -eu
HA_IP="${HOMELAB_HA_IPV4:-${MACVLAN_PREFIX:?Set HOMELAB_HA_IPV4 or the legacy MACVLAN_PREFIX}.242}"
IFACE="$(ip -o -4 addr show | awk -v ip="$HA_IP" 'split($4, cidr, "/") && cidr[1] == ip {print $2; exit}')"
if [ -z "$IFACE" ]; then
    echo 'HA discovery address is not assigned to this guest; refusing startup' >&2
    exit 1
fi
# NET_ADMIN is confined to the selected automation guest's network namespace.
ip route replace 224.0.0.251/32 dev "$IFACE" scope link
ip -6 route replace ff02::fb dev "$IFACE" metric 0
echo 'HA IPv4/IPv6 mDNS routes configured on the selected interface'
