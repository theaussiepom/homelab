"""Bind immutable historical evidence to actual component subjects, never reads targets."""
import copy
import hashlib

import coordinated_contract
import initial_ordinary
import ordinary_failure
from site_values import synthetic_binding
from urllib.parse import urlsplit
from component_errors import at
from component_sources import require

ADAPTER_ROLES = {'postgresql': {'postgresql'}, 'mariadb': {'mariadb'}, 'identity': {'authentik'},
                 'db-tools': {'cloudbeaver'}, 'influxdb': {'influxdb'},
                 'automation': {'homeassistant', 'node_red'}, 'zigbee2mqtt': {'zigbee2mqtt'}}


def _admission(resolver, guest_id):
    subjects = [resolver.guests[guest_id], *[app for app in resolver.apps.values() if app['guest'] == guest_id]]
    result = {}
    for subject in subjects:
        for key, value in subject.get('admission', {}).items():
            require(key not in result or result[key] == value, 'component.evidence-conflict')
            result[key] = value
    return result


def bind(resolver):
    result = {}
    for guest_id, guest in resolver.guests.items():
        with at('guests', guest_id, 'admission'):
            selected = _admission(resolver, guest_id)
            context = resolver.site['contexts'][guest['context']]
            paths = {key: context['paths'][key] for key in
                     ('state_root', 'backup_mount', 'backup_directory', 'backup_source')}
            cfg = {'schema': 'homelab-component-guest-v1', 'site': {'node': context['node']},
                   'guest': {'vmid': guest['identity']['vmid']},
                   'app': {'vmid': guest['identity']['vmid']}, 'paths': paths}
            role = None
            if 'coordinated_custody' in selected:
                ref = selected['coordinated_custody']
                value = resolver.site['evidence'][ref['evidence']]['document']
                role = ref['member']
                cfg['coordinated_custody'] = copy.deepcopy(value)
                cfg['app']['kind'] = role
                cfg['paths']['coordinated_custody_inputs'] = '${inputs}'
                group = coordinated_contract.selection(cfg, allow_input_slot=True)
                files = {}
                for key in ('catalogue', 'acceptance'):
                    require(key in selected.get('assets', {}), 'component.evidence-asset')
                    evidence = resolver.site['evidence'][selected['assets'][key]]
                    text = evidence['text']
                    require(hashlib.sha256(text.encode()).hexdigest() == group[key]['sha256'],
                            'component.evidence-asset')
                    files[group[key]['file']] = text
                cfg['proof_files'] = files
            if 'initial_ordinary' in selected:
                ref = selected['initial_ordinary']
                value = resolver.site['evidence'][ref['evidence']]['document']
                require(isinstance(value.get('schema'), str) and value['schema'] in initial_ordinary.KINDS,
                        'component.evidence-role')
                initial_role = initial_ordinary.KINDS[value['schema']]
                require(role is None or role == initial_role, 'component.evidence-role')
                role = initial_role
                cfg['app']['kind'] = role
                cfg['initial_ordinary'] = copy.deepcopy(value)
                initial_ordinary.selection(cfg)
            if role is not None:
                adapters = {app['adapter'] for app in resolver.apps.values() if app['guest'] == guest_id}
                require(role in ADAPTER_ROLES and bool(adapters & ADAPTER_ROLES[role]), 'component.evidence-role')
            else:
                cfg['app']['kind'] = guest_id
            if 'reviewed_ordinary_failures' in selected:
                cfg['reviewed_ordinary_failures'] = copy.deepcopy(
                    resolver.site['evidence'][selected['reviewed_ordinary_failures']['evidence']]['document'])
                ordinary_failure.selection(cfg)
            if 'source_assertions' in selected:
                value = resolver.site['evidence'][selected['source_assertions']['evidence']]['document']
                require(value['guest'] == guest_id, 'component.evidence-subject')
                cfg['source_assertions'] = copy.deepcopy(value)
            result[guest_id] = cfg
    # Whole configured groups remain present even when a leaf is disabled. The
    # lookup uses immutable node/VMID membership, not new authoring/display IDs.
    for guest_id, cfg in result.items():
        group = cfg.get('coordinated_custody', {}).get('group')
        if group is None:
            continue
        own_context = resolver.guests[guest_id]['context']
        for role, member in group['members'].items():
            candidates = [key for key, value in result.items()
                          if value['guest']['vmid'] == member['vmid'] and value['site']['node'] == member['node']
                          and resolver.guests[key]['context'] == own_context]
            require(len(candidates) == 1, 'component.evidence-closure')
            peer = result[candidates[0]]
            require(peer['app']['kind'] == role and peer.get('coordinated_custody') == cfg['coordinated_custody'],
                    'component.evidence-closure')
    return result


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
            retained = [app for app in resolver.apps.values() if app['guest'] == guest_id
                        and app['lifecycle'] == 'retained' and app['identity']['services']]
            if retained:
                require(resolver.evidence[guest_id].get('source_assertions', {}).get(
                    'exclusive_writer_confirmed') is True, 'component.writer-assertion')
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
