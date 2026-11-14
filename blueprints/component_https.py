"""Assign declared HTTPS routes to existing jobs after their actual producers.

The graph is source-only. Checks use the controller's DNS and verified TLS;
there are no guest-specific probe scripts or a final aggregate job.
"""
import copy
from urllib.parse import urlsplit

from component_sources import require


def origin(host, port):
    return 'https://' + host.lower() + (':' + str(port) if port != 443 else '')


def checks(resolved, site, library):
    dependencies = copy.deepcopy(resolved['guest_dependencies'])
    pending, ordered = list(dependencies), []
    while pending:
        ready = [key for key in pending if set(dependencies[key]) <= set(ordered)]
        require(bool(ready), 'component.https-dependency-cycle')
        selected = ready[0]
        pending.remove(selected)
        ordered.append(selected)
    rank = {key: index for index, key in enumerate(ordered)}
    assigned = {key: [] for key in dependencies}
    apps, exposures = resolved['apps'], resolved.get('exposures', {})
    active = set(resolved['enabled'])
    for name, route in exposures.items():
        if route['type'] != 'http':
            continue
        target, ingress = route['target'], route['ingress_target']
        owner = target.get('guest', ingress['guest'])
        if owner not in active:
            continue
        producers = {owner, ingress['guest']}
        if 'resolver' in route:
            producers.add(apps[route['resolver']]['guest'])
        origins = [origin(host, ingress['port']) for host in route['hosts']]
        auth_origins = []
        forward_auth = False
        for key in route.get('middlewares', []):
            middleware = resolved['middlewares'][key]
            if middleware['type'] == 'forward-auth':
                forward_auth = True
                auth = apps.get(middleware['target'].get('app'), {})
                if auth:
                    producers.add(auth['guest'])
                    auth_origins.append(auth['origin_url'])
                else:
                    auth_origins.extend(row['origin'] for row in resolved.get('identity_providers', {}).values()
                                        if 'origin' in row)
            elif middleware['type'] == 'canonical-home-redirect':
                app = apps[middleware['app']]
                producers.add(app['guest'])
                origins.append(app['origin_url'])
        app = apps.get(target.get('app'), {})
        for connection in app.get('resolved_connections', {}).values():
            provider_app = apps.get(connection['target'].get('app'), {})
            if provider_app.get('adapter') == 'authentik':
                auth_origins.append(provider_app['origin_url'])
                producers.add(provider_app['guest'])
        if 'authentication' in app:
            policies = dict(library['policies']['authentication'], **site['policies']['authentication'])
            policy = policies[app['authentication']]
            provider = resolved['identity_providers'][policy['provider']]
            if 'origin' in provider:
                auth_origins.append(provider['origin'])
            else:
                # The retained SAML contract supplies a signing certificate only.
                # Allow configured identity frontends, never an arbitrary redirect.
                auth_origins.extend(row['origin_url'] for row in apps.values()
                                    if row.get('adapter') == 'authentik' and 'origin_url' in row)
        require(not forward_auth or bool(auth_origins), 'component.https-auth-origin')
        # Internal identity providers are producers; external ones remain supplied
        # prerequisites. A native gateway may use the same outpost relationship.
        for auth_origin in auth_origins:
            for other in exposures.values():
                if other['type'] == 'http' and auth_origin in [
                        origin(host, other['ingress_target']['port']) for host in other['hosts']]:
                    producers.add(other['target'].get('guest', other['ingress_target']['guest']))
                    producers.add(other['ingress_target']['guest'])
        require(producers <= active, 'component.https-disabled-dependency')
        # Later -> earlier edges cannot create a cycle, including DNS -> ingress
        # and an ingress dashboard protected by the later identity service.
        job = max(producers, key=rank.__getitem__)
        dependencies[job] = list(dict.fromkeys([*dependencies[job],
            *sorted(producers - {job}, key=rank.__getitem__)]))
        origins = [origin(urlsplit(value).hostname, urlsplit(value).port or 443) for value in origins]
        auth_origins = [origin(urlsplit(value).hostname, urlsplit(value).port or 443) for value in auth_origins]
        selected = target.get('http_check', {'path': '/'})
        for host in route['hosts']:
            assigned[job].append({'exposure': name, 'url': origin(host, ingress['port']) + selected['path'],
                'origins': list(dict.fromkeys(origins + auth_origins)),
                'auth_origins': list(dict.fromkeys(auth_origins)), 'require_auth': forward_auth,
                'contains': selected.get('contains')})
    return dependencies, assigned
