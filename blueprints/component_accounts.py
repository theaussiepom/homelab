"""Lower explicit generated account links to the existing canonical owner tuples."""
import copy

import database_admin
import managed_credentials
from component_errors import at
from component_sources import require


def bind(resolver, accounts):
    result = {}
    for key, value in accounts.items():
        with at('accounts', key):
            consumer = resolver.apps[value['owner']]
            producer = resolver.apps[value['target_endpoint']['app']]
            source_guest, target_guest = resolver.guests[consumer['guest']], resolver.guests[producer['guest']]
            require(source_guest['context'] == target_guest['context'], 'component.account-placement-unsupported')
            matches = [row for row in consumer['resolved_connections'].values()
                       if isinstance(row.get('account'), dict) and row['account'] == value]
            require(bool(matches) and len({row['source_address'] for row in matches}) == 1,
                    'component.account-binding')
            context = resolver.site['contexts'][target_guest['context']]
            engine = producer['adapter']
            credential = value['credential_id']
            filename = managed_credentials.input_name(credential)
            if engine in ('postgresql', 'mariadb'):
                require(consumer['adapter'] == 'cloudbeaver', 'component.account-binding')
                owner = database_admin.owner({'node': context['node'], 'engine': engine,
                    'database_vmid': target_guest['identity']['vmid'],
                    'source_vmid': source_guest['identity']['vmid'],
                    'server_address': value['target_endpoint']['address'],
                    'source_address': matches[0]['source_address'], 'username': value['principal'],
                    'purpose': 'database-administration'})
                account = {'username': value['principal'], 'source_guest': consumer['guest'],
                    'credential_id': credential, 'credential_file': '${inputs}/applications/' + producer['id'] + '/' + filename,
                    'access': 'server-administration', 'transport': 'tls', 'owner': owner}
                producer.setdefault('database_administrators', {})[key] = account
                for role, connection in consumer['resolved_connections'].items():
                    if connection not in matches:
                        continue
                    require(role in consumer['settings']['managed_connections'], 'component.account-binding')
                    selected = consumer['settings']['managed_connections'][role]
                    require(selected.pop('account') == value, 'component.account-binding')
                    selected.update(account_id=key, username=value['principal'], credential_id=credential,
                        credential_file='${inputs}/applications/' + consumer['id'] + '/' + filename,
                        transport='tls', owner=copy.deepcopy(owner))
            else:
                require(engine == 'mqtt' and consumer['adapter'] == 'mqtt_explorer'
                        and consumer['guest'] == producer['guest'], 'component.account-placement-unsupported')
                # This preserves the current helper's same-guest owner contract.
                # Independent placement uses an explicit existing credential;
                # it never silently creates a broker account on another guest.
                owner = {'node': context['node'], 'vmid': source_guest['identity']['vmid'],
                    'hostname': source_guest['identity']['hostname'], 'purpose': 'mqtt-explorer',
                    'username': value['principal']}
                account = {'credential_id': credential, 'owner': owner,
                    'credential_file': '${inputs}/applications/' + consumer['id'] + '/' + filename}
                consumer['settings']['broker']['managed_credential'] = copy.deepcopy(account)
            result[key] = dict(copy.deepcopy(value), canonical_owner=copy.deepcopy(owner),
                               input_filename=filename)
    for app in resolver.apps.values():
        if app['adapter'] == 'cloudbeaver':
            database_admin.connections(app['settings'])
    return result
