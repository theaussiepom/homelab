"""Add only reviewed strict OAuth callbacks to an exact retained identity provider."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit
from uuid import UUID


def need(value):
    if not value:
        raise ValueError('Retained identity callback guard refused')


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()


def uri(value, callback=False):
    need(isinstance(value, str) and len(value) <= 2048 and '\\' not in value
         and not any(c.isspace() for c in value))
    url = urlsplit(value)
    need(url.scheme == 'https' and url.hostname and not url.username and not url.password
         and not url.query and not url.fragment and (not callback or url.path == '/oauth2/callback'))
    try:
        need(url.port is None or 1 <= url.port <= 65535)
    except ValueError:
        raise ValueError('Retained identity callback guard refused') from None


def validate(values):
    need(isinstance(values, list) and 1 <= len(values) <= 8)
    providers = set()
    for value in values:
        need(isinstance(value, dict) and set(value) == {'provider_id', 'application_id', 'client_id_sha256',
             'provider_metadata_sha256', 'application_metadata_sha256', 'policy_metadata_sha256',
             'existing_redirects', 'additions'} and type(value['provider_id']) is int
             and value['provider_id'] > 0 and value['provider_id'] not in providers)
        providers.add(value['provider_id'])
        need(isinstance(value['application_id'], str) and str(UUID(value['application_id'])) == value['application_id'])
        need(all(isinstance(value[k], str) and re.fullmatch('[0-9a-f]{64}', value[k])
                 for k in ('client_id_sha256', 'provider_metadata_sha256',
                           'application_metadata_sha256', 'policy_metadata_sha256')))
        old, new = value['existing_redirects'], value['additions']
        need(isinstance(old, list) and 1 <= len(old) <= 20 and isinstance(new, list) and 1 <= len(new) <= 4)
        seen = set()
        for row in old:
            need(isinstance(row, dict) and set(row) == {'matching_mode', 'url'} and row['matching_mode'] == 'strict')
            uri(row['url'])
            need(row['url'] not in seen)
            seen.add(row['url'])
        for url in new:
            uri(url, True)
            need(url not in seen)
            seen.add(url)
    return values


def policy_projection(value):
    need(isinstance(value, dict) and set(value) == {'policy_bindings', 'bound_groups', 'property_mappings'})
    need(all(isinstance(rows, list) and len(rows) <= 100 and
             all(isinstance(row, dict) and 'pk' in row for row in rows) for rows in value.values()))
    return {key: sorted(rows, key=lambda row: str(row['pk'])) for key, rows in value.items()}


def check(record, provider, application, policy):
    validate([record])
    expected = record['existing_redirects'] + [{'matching_mode': 'strict', 'url': url} for url in record['additions']]
    need(isinstance(provider, dict) and provider.get('pk') == record['provider_id']
         and provider.get('client_id_sha256') == record['client_id_sha256']
         and application.get('pk') == record['application_id'] and application.get('provider_id') == record['provider_id']
         and canonical({k: v for k, v in provider.items() if k != '_redirect_uris'}) == record['provider_metadata_sha256']
         and canonical(application) == record['application_metadata_sha256']
         and canonical(policy_projection(policy)) == record['policy_metadata_sha256']
         and provider.get('_redirect_uris') in (record['existing_redirects'], expected))
    return copy.deepcopy(expected)


def projection(provider, application, bindings, groups, mappings, scopes):
    """Hash expressions without executing them; never select or return user secrets."""
    value = dict(provider)
    value['client_id_sha256'] = canonical(value.pop('client_id'))
    policies = []
    for row in bindings:
        row = dict(row)
        row['user_binding_present'] = row.pop('user_id') is not None
        policies.append(row)
    properties = []
    for row in mappings:
        expression = row['expression']
        need(isinstance(expression, str) and len(expression.encode()) <= 65536)
        properties.append({'pk': str(row['pk']), 'name': row['name'], 'scope': scopes.get(str(row['pk'])),
            'expression_sha256': hashlib.sha256(expression.encode()).hexdigest(),
            'claim_labels_present': [k for k in ('preferred_username', 'email', 'email_verified', 'groups', 'name')
                                     if ('"' + k + '"') in expression or ("'" + k + "'") in expression],
            'expression_evaluated': False})
    # UUID conversion exactly matches the bounded original read, before hashing.
    return json.loads(json.dumps({'provider': value, 'application': application,
        'policy': {'policy_bindings': policies, 'bound_groups': groups, 'property_mappings': properties}}, default=str))


def apply_native(values):
    """One serializable transaction owns exact rows and changes only _redirect_uris."""
    from django.db import connection, transaction
    from authentik.core.models import Application, Group, PropertyMapping
    from authentik.providers.oauth2.models import OAuth2Provider, ScopeMapping
    from authentik.policies.models import PolicyBinding
    validate(values)
    need(connection.vendor == 'postgresql')
    changed = 0
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE, READ WRITE')
            cursor.execute("SET LOCAL statement_timeout = '10000ms'")
        for record in values:
            obj = OAuth2Provider.objects.select_for_update().get(pk=record['provider_id'])
            app = Application.objects.select_for_update().filter(pk=record['application_id']).values(
                'pk', 'name', 'slug', 'provider_id', 'policy_engine_mode', 'meta_launch_url').get()
            bindings = list(PolicyBinding.objects.select_for_update().filter(target_id=record['application_id']).values(
                'pk', 'policy_id', 'group_id', 'user_id', 'order', 'negate', 'enabled', 'timeout')[:101])
            groups = list(Group.objects.select_for_update().filter(pk__in=[r['group_id'] for r in bindings
                          if r['group_id'] is not None]).values('pk', 'name', 'parent_id', 'is_superuser')[:101])
            mapping_ids = list(obj.property_mappings.values_list('pk', flat=True)[:101])
            mappings = list(PropertyMapping.objects.select_for_update().filter(pk__in=mapping_ids).values('pk', 'name', 'expression')[:101])
            scopes = {str(pk): scope for pk, scope in ScopeMapping.objects.select_for_update().filter(pk__in=mapping_ids).values_list('pk', 'scope_name')}
            fields = ('pk', 'name', 'client_id', 'client_type', '_redirect_uris', 'sub_mode', 'issuer_mode',
                'include_claims_in_id_token', 'authentication_flow_id', 'authorization_flow_id',
                'invalidation_flow_id', 'signing_key_id')
            provider = {key: getattr(obj, key) for key in fields}
            current = projection(provider, app, bindings, groups, mappings, scopes)
            expected = check(record, current['provider'], current['application'], current['policy'])
            secret = obj.client_secret
            if obj._redirect_uris != expected:
                obj._redirect_uris = expected
                obj.save(update_fields=['_redirect_uris'])
                obj.refresh_from_db()
                need(obj.client_secret == secret and obj._redirect_uris == expected
                     and canonical({k: getattr(obj, k) for k in fields if k != '_redirect_uris'})
                     == canonical({k: provider[k] for k in fields if k != '_redirect_uris'}))
                changed += 1
    return {'callbacks': 'verified', 'providers': len(values), 'changed': changed}


SHELL = "import json,sys; v=json.loads(sys.stdin.read()); n={'__name__':'typed_identity_callbacks'}; exec(compile(v['source'],'identity_callbacks.py','exec'),n); print(json.dumps(n['apply_native'](v['configuration'])))"


def run(values, compose):
    validate(values)
    payload = json.dumps({'source': Path(__file__).read_text(), 'configuration': values})
    result = subprocess.run(['docker', 'compose', '-f', str(compose), 'exec', '-T',
        '-e', 'PGOPTIONS=-c default_transaction_read_only=on', 'server', 'python', 'manage.py', 'shell',
        '-c', SHELL], input=payload, text=True, capture_output=True, timeout=60, check=True)
    # Native framework startup may log, but its private output is never echoed.
    rows = [json.loads(row) for row in result.stdout.splitlines() if row.startswith('{"callbacks":')]
    need(len(result.stdout.encode()) <= 2 * 1024**2 and len(rows) == 1
         and set(rows[0]) == {'callbacks', 'providers', 'changed'} and rows[0]['callbacks'] == 'verified'
         and type(rows[0]['providers']) is int and rows[0]['providers'] == len(values)
         and type(rows[0]['changed']) is int and 0 <= rows[0]['changed'] <= len(values))
    return rows[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--compose', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(json.loads(args.config.read_text()), args.compose), sort_keys=True))


if __name__ == '__main__':
    main()
