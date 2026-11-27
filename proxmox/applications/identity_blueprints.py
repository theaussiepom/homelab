"""Apply selected file-backed registrations through Authentik's own worker."""
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
import time


def require(value):
    if not value:
        raise ValueError('Identity blueprint verification failed')


def strict_callback(provider, url, additional=()):
    urls = [*additional, url]
    legacy = [{'matching_mode': 'strict', 'url': value} for value in urls]
    modern = [dict(entry, redirect_uri_type='authorization') for entry in legacy]
    stored = provider._redirect_uris
    if stored == modern:
        return True
    # Older records omit the URI type. The installed model must resolve every entry to authorization.
    if not isinstance(stored, list) or len(stored) != len(urls) or any(
            row not in (old, new) for row, old, new in zip(stored, legacy, modern)):
        return False
    return [(entry.matching_mode, entry.url, entry.redirect_uri_type) for entry in provider.redirect_uris] == [
        ('strict', value, 'authorization') for value in urls]


def verify_registration(spec, secret, references, *, adopting=False):
    from authentik.core.models import Application, Group
    from authentik.policies.models import PolicyBinding
    from authentik.providers.oauth2.models import OAuth2Provider

    # Refuse ambiguous or cross-linked adoption before scheduling the importer.
    app = Application.objects.filter(slug=spec['slug']).first()
    providers = OAuth2Provider.objects.filter(client_id=spec['client_id'])
    require(providers.count() <= 1)
    provider = providers.first()
    group = Group.objects.filter(name=spec['admission_group'])
    require(group.count() <= 1 and not group.filter(is_superuser=True).exists())
    require(not OAuth2Provider.objects.filter(name=spec['provider_name']).exclude(client_id=spec['client_id']).exists())
    if provider:
        require(not Application.objects.filter(provider=provider).exclude(slug=spec['slug']).exists())
    if app:
        require(app.provider_id is None or provider is not None and app.provider_id == provider.pk)
        bindings = PolicyBinding.objects.filter(target=app)
        require(not bindings.exclude(group__name=spec['admission_group']).exists() and bindings.count() <= 1)
    if not (provider and app and group.exists()):
        require(not spec.get('retained'))
        require(not adopting or not (provider or app))
        return False
    binding = PolicyBinding.objects.filter(target=app, group=group.get(), policy=None, user=None,
                                          order=0, enabled=True, negate=False, failure_result=False)
    matches = (app.provider_id == provider.pk and app.name == spec['app_name']
            and app.policy_engine_mode == spec.get('policy_engine_mode', 'all')
            and app.meta_launch_url == spec['launch_url'] and binding.count() == 1
            and strict_callback(provider, spec['callback'], spec.get('additional_callbacks', ()))
            and provider.name == spec['provider_name'] and provider.client_type == 'confidential'
            and provider.sub_mode == 'hashed_user_id' and provider.issuer_mode == 'per_provider'
            and provider.include_claims_in_id_token and hmac.compare_digest(provider.client_secret.encode(), secret)
            and all(getattr(provider, field + '_id') == primary for field, primary in references['foreign'].items())
            and set(provider.property_mappings.values_list('pk', flat=True)) == references['scopes'])
    require(not adopting or matches)
    return matches


def forward_registration(spec, group, flows, scopes, *, adopting):
    from authentik.core.models import Application, Provider
    from authentik.policies.models import PolicyBinding
    from authentik.providers.proxy.models import ProxyProvider

    proxy = ProxyProvider.objects.filter(name=spec['provider_name']).first()
    app = Application.objects.filter(slug=spec['slug']).first()
    origin = spec['origin']
    same_host = ProxyProvider.objects.filter(external_host__iexact=origin) | ProxyProvider.objects.filter(
        external_host__istartswith=origin + '/')
    require(not same_host.exclude(pk=proxy.pk if proxy else None).exists())
    require(not Provider.objects.filter(name=spec['provider_name']).exclude(pk=proxy.pk if proxy else None).exists())
    if proxy:
        require(not Application.objects.filter(provider=proxy).exclude(slug=spec['slug']).exists())
        require(not proxy.outpost_set.exclude(managed='goauthentik.io/outposts/embedded', type='proxy').exists())
    if app:
        require(proxy is not None and app.provider_id == proxy.pk)
        bindings = PolicyBinding.objects.filter(target=app)
        require(bindings.count() <= 1 and not bindings.exclude(group=group, policy=None, user=None).exists())
    if not (app and proxy):
        require(not adopting or (app is None and proxy is None))
        return False
    matches = (app.name == spec['app_name'] and app.meta_launch_url == origin + '/'
               and app.policy_engine_mode == 'all'
               and bindings.filter(order=0, enabled=True, negate=False, failure_result=False).count() == 1
               and proxy.mode == 'forward_single' and proxy.external_host == origin
               and not any((proxy.internal_host, proxy.skip_path_regex, proxy.cookie_domain, proxy.basic_auth_enabled))
               and proxy.authentication_flow_id is None and not proxy.jwt_federation_sources.exists()
               and not proxy.jwt_federation_providers.exists()
               and proxy.intercept_header_auth and proxy.authorization_flow_id == flows[0]
               and proxy.invalidation_flow_id == flows[1] and set(proxy.property_mappings.values_list('pk', flat=True)) == scopes)
    require(not adopting or matches)
    return matches


def apply_forward_registration(spec, deadline):
    from authentik.core.models import Group
    from authentik.flows.models import Flow
    from authentik.outposts.models import Outpost
    from authentik.providers.oauth2.models import ScopeMapping
    from authentik.providers.proxy.models import ProxyProvider
    from django.core.exceptions import ObjectDoesNotExist
    from django.db import transaction

    # These are existing site objects. The blueprint never creates the group or alters its members.
    while True:
        try:
            group = Group.objects.get(name=spec['admission_group'])
            outpost = Outpost.objects.get(managed='goauthentik.io/outposts/embedded', type='proxy')
            flows = [Flow.objects.get(slug=spec[key]).pk for key in ('authorization_flow', 'invalidation_flow')]
            scopes = {ScopeMapping.objects.get(managed=scope).pk for scope in spec['scope_mappings']}
            break
        except ObjectDoesNotExist:
            if time.monotonic() + 2 >= deadline:
                raise TimeoutError('Identity registration dependency unavailable') from None
            time.sleep(2)

    def verify(*, adopting=False):
        return forward_registration(spec, group, flows, scopes, adopting=adopting)

    changed = apply_file(spec, deadline, 'forward', verify)
    proxy = ProxyProvider.objects.get(name=spec['provider_name'])
    if outpost.providers.filter(pk=proxy.pk).exists():
        return changed
    # The native outpost serializer replaces its provider list. Add just this verified edge.
    with transaction.atomic():
        outpost = Outpost.objects.select_for_update().get(pk=outpost.pk)
        proxy = ProxyProvider.objects.get(name=spec['provider_name'])
        require(verify() and not proxy.outpost_set.exclude(pk=outpost.pk).exists())
        if outpost.providers.filter(pk=proxy.pk).exists():
            return changed
        outpost.providers.add(proxy)
        require(outpost.providers.filter(pk=proxy.pk).exists())
        return True


def apply_saml_registration(spec, deadline):
    """Retain a single existing SAML application, provider, signing key and group grant."""
    import ssl
    from authentik.core.models import Application, Group, Provider
    from authentik.crypto.models import CertificateKeyPair
    from authentik.flows.models import Flow
    from authentik.policies.models import PolicyBinding
    from authentik.providers.saml.models import SAMLPropertyMapping, SAMLProvider

    def verify(*, adopting=False):
        app = Application.objects.get(slug=spec['slug'])
        provider = SAMLProvider.objects.get(name=spec['provider_name'])
        group = Group.objects.get(name=spec['admission_group'])
        key = CertificateKeyPair.objects.only('pk', 'certificate_data').get(name=spec['signing_key'])
        require(hashlib.sha256(ssl.PEM_cert_to_DER_cert(key.certificate_data)).hexdigest() == spec['certificate_sha256'])
        require(app.provider_id == provider.pk and provider.signing_kp_id == key.pk
                and not Provider.objects.filter(name=spec['provider_name']).exclude(pk=provider.pk).exists()
                and not Application.objects.filter(provider=provider).exclude(pk=app.pk).exists()
                and not SAMLProvider.objects.filter(acs_url=spec['attributes']['acs_url']).exclude(pk=provider.pk).exists()
                and not any((provider.is_backchannel, provider.backchannel_application_id, provider.encryption_kp_id,
                             provider.verification_kp_id, provider.name_id_mapping_id, provider.authn_context_class_ref_mapping_id)))
        binding = PolicyBinding.objects.get(target=app)
        require(binding.group_id == group.pk and binding.policy_id is None and binding.user_id is None
                and binding.order == 0 and binding.enabled and not binding.negate and not binding.failure_result)
        mappings = {SAMLPropertyMapping.objects.get(managed=ref).pk for ref in spec['mappings']}
        flows = {key: Flow.objects.get(slug=val).pk if val is not None else None for key, val in spec['flows'].items()}
        matches = (app.name == spec['application_name'] and app.policy_engine_mode == spec['policy_engine_mode']
                   and app.meta_launch_url == '' and all(getattr(provider, k) == v for k, v in spec['attributes'].items())
                   and all(getattr(provider, k + '_id') == v for k, v in flows.items())
                   and set(provider.property_mappings.values_list('pk', flat=True)) == mappings)
        require(not adopting or matches)
        return matches

    return apply_file(spec, deadline, 'saml', verify)


def apply_registration(spec, deadline):
    if spec.get('type') == 'saml':
        return apply_saml_registration(spec, deadline)
    if spec.get('type') == 'forward_single':
        return apply_forward_registration(spec, deadline)
    from authentik.crypto.models import CertificateKeyPair
    from authentik.flows.models import Flow
    from authentik.providers.oauth2.models import ScopeMapping

    slug = spec['slug']
    require(re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', slug) and len(slug) <= 63)
    secret = Path('/run/secrets/oidc-' + slug).read_bytes()
    require(0 < len(secret) <= 255 and all(33 <= byte <= 126 for byte in secret))
    from django.core.exceptions import ObjectDoesNotExist
    while True:
        try:
            references = {'foreign': {key: Flow.objects.get(slug=spec[key]).pk if spec[key] is not None else None for key in (
                          'authentication_flow', 'authorization_flow', 'invalidation_flow')},
                          'scopes': {ScopeMapping.objects.get(managed='goauthentik.io/providers/oauth2/scope-' + scope).pk
                                     for scope in ('openid', 'profile', 'email')}}
            references['foreign']['signing_key'] = CertificateKeyPair.objects.get(name=spec['signing_key']).pk
            break
        except ObjectDoesNotExist:
            if time.monotonic() + 2 >= deadline:
                raise TimeoutError('Identity registration dependency unavailable') from None
            time.sleep(2)
    def verify(*, adopting=False):
        return verify_registration(spec, secret, references, adopting=adopting)
    return apply_file(spec, deadline, 'oidc', verify)


def apply_file(spec, deadline, kind, verify):
    from authentik.blueprints.models import BlueprintInstance
    from authentik.blueprints.v1.tasks import apply_blueprint
    from authentik.lib.config import CONFIG

    slug = spec['slug']
    require(re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', slug) and len(slug) <= 63)
    name = 'homelab-' + kind + '-' + slug
    path = 'custom/' + name + '.yaml'
    contents = (Path(CONFIG.get('blueprints_dir')) / path).read_bytes()
    require(hashlib.sha512(contents).hexdigest() == spec['sha512'])
    existing = BlueprintInstance.objects.filter(path=path)
    require(existing.count() <= 1 and not existing.exclude(name=name).exists())
    previous_instance = existing.first()
    matches = verify(adopting=not (previous_instance and previous_instance.last_applied_hash))
    instance, _ = BlueprintInstance.objects.get_or_create(name=name, defaults={'path': path})
    require(instance.enabled and instance.path == path and not instance.context and not instance.content)
    if matches and instance.status == 'successful' and instance.last_applied_hash == spec['sha512']:
        return False
    previous = instance.last_applied
    apply_blueprint.send_with_options(args=(instance.pk,), rel_obj=instance)
    while time.monotonic() < deadline:
        instance.refresh_from_db()
        if instance.last_applied != previous:
            require(instance.status not in ('error', 'warning', 'orphaned'))
            if instance.status == 'successful' and instance.last_applied_hash == spec['sha512']:
                require(verify())
                return True
        time.sleep(2)
    raise TimeoutError('Identity blueprint worker timed out')


def reconcile(specs):
    deadline = time.monotonic() + 300
    result = []
    for spec in specs:
        try:
            changed = apply_registration(spec, deadline)
        except Exception:
            return {'failed': {'guest': spec['guest'], 'app': spec['app']}}
        result.append({'guest': spec['guest'], 'app': spec['app'], 'sha512': spec['sha512'], 'changed': changed})
    return {'registrations': result}


def main():
    import subprocess
    # Django reads only its pinned helper and the public registration contract from stdin.
    compose, service, records = sys.argv[1:]
    require(Path(compose).is_absolute() and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', service))
    data = json.loads(Path(records).read_bytes())
    code = ("import json,sys; v=json.load(sys.stdin); n={'__name__':'identity_blueprints'}; "
            "exec(compile(v['code'],'identity_blueprints.py','exec'),n); "
            "print('BLUEPRINT-RESULT '+json.dumps(n['reconcile'](v['specs'])))")
    command = ['docker', 'compose', '-f', compose, 'exec', '-T', service, 'python', 'manage.py', 'shell', '-c', code]
    process = subprocess.run(command, input=json.dumps({'code': Path(__file__).read_text(), 'specs': data}),
                             text=True, capture_output=True, timeout=330, check=True)
    rows = [json.loads(line.removeprefix('BLUEPRINT-RESULT ')) for line in process.stdout.splitlines()
            if line.startswith('BLUEPRINT-RESULT ')]
    require(len(rows) == 1 and isinstance(rows[0], dict))
    if 'failed' in rows[0]:
        failed = rows[0]['failed']
        require(any(failed == {'guest': row['guest'], 'app': row['app']} for row in data))
        print(json.dumps({'status': 'failed', **failed}), file=sys.stderr)
        return 1
    verified = rows[0]['registrations']
    require(len(verified) == len(data) and all(
        item == {'guest': spec['guest'], 'app': spec['app'], 'sha512': spec['sha512'], 'changed': item['changed']}
        and type(item['changed']) is bool for item, spec in zip(verified, data, strict=True)))
    print(json.dumps({'registrations': verified, 'changed': any(item['changed'] for item in verified)}))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        sys.exit('Identity blueprint verification failed')
