"""Permanent source suitability checks; native ownership remains a runtime gate."""
from urllib.parse import urlsplit
from site_values import synthetic_binding
from component_errors import at
from component_sources import require

def admit(resolver, enabled):
    """Source intent checks only; actual state/holds/evidence remain runtime gates."""
    for guest_id in enabled:
        with at('guests', guest_id, 'admission'):
            guest = resolver.guests[guest_id]
            context = resolver.site['contexts'][guest['context']]
            for nic in guest['provider_interfaces']:
                require(not synthetic_binding('interfaces.selected.ipv4', nic.get('ipv4_endpoint', nic['ipv4']))
                        and not synthetic_binding('gateways.selected', nic.get('gateway')),
                        'component.synthetic-binding')
            require(not synthetic_binding('addresses.api', resolver.endpoint(context['api_endpoint'])['address']),
                    'component.synthetic-binding')
            require(all(not synthetic_binding('addresses.dns', address) for address in guest['dns_servers']),
                    'component.synthetic-binding')
            keys = guest.get('ssh_public_keys', context['ssh_public_keys'])
            require(bool(keys) and all(key.startswith('ssh-ed25519 ') and
                    'AAAAAAAAAAAAAAAA' not in key for key in keys), 'component.ssh-key')
            for app in resolver.apps.values():
                if app['guest'] != guest_id:
                    continue
                for connection in app['resolved_connections'].values():
                    target = connection['target']['address']
                    require(not synthetic_binding('addresses.target', target)
                            and not synthetic_binding('domains.target', target), 'component.synthetic-binding')
                auth = app.get('authentication_resolved', {})
                for key in ('oidc_issuer', 'identity_url'):
                    if key in auth:
                        require(not synthetic_binding('domains.identity', urlsplit(auth[key]).hostname),
                                'component.synthetic-binding')
                for image in app['software_selection']['images'].values():
                    require('0' * 64 not in image['image'] and
                            '0' * 64 not in image.get('archive_sha256', ''), 'component.image-binding')
    for exposure in resolver.site['exposures'].values():
        if exposure['type'] == 'http':
            ingress = resolver.endpoint(exposure['ingress'])['app']
            active = resolver.apps[ingress]['guest'] in enabled
        else:
            active = resolver.apps[exposure['resolver']]['guest'] in enabled
        if active:
            target = resolver.endpoint(exposure['endpoint']).get('address')
            require(not synthetic_binding('addresses.backend', target)
                    and not synthetic_binding('domains.backend', target), 'component.synthetic-binding')
            for key in [exposure['domain'], *exposure.get('aliases', [])]:
                require(not synthetic_binding('domains.exposure', resolver.site['domains'][key]),
                        'component.synthetic-binding')
