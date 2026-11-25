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


def strict_callback(provider, url):
    strict = {'matching_mode': 'strict', 'url': url}
    if provider._redirect_uris == [dict(strict, redirect_uri_type='authorization')]:
        return True
    # Upgraded providers may still store the two-field record. Require the
    # installed Authentik model to resolve it to the same authorization URI.
    if provider._redirect_uris != [strict]:
        return False
    return [(entry.matching_mode, entry.url, entry.redirect_uri_type) for entry in provider.redirect_uris] == [
        ('strict', url, 'authorization')]


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
        require(not adopting or not (provider or app))
        return False
    binding = PolicyBinding.objects.filter(target=app, group=group.get(), policy=None, user=None,
                                          order=0, enabled=True, negate=False, failure_result=False)
    matches = (app.provider_id == provider.pk and app.name == spec['app_name'] and app.policy_engine_mode == 'all'
            and app.meta_launch_url == spec['launch_url'] and binding.count() == 1
            and strict_callback(provider, spec['callback'])
            and provider.name == spec['provider_name'] and provider.client_type == 'confidential'
            and provider.sub_mode == 'hashed_user_id' and provider.issuer_mode == 'per_provider'
            and provider.include_claims_in_id_token and hmac.compare_digest(provider.client_secret.encode(), secret)
            and all(getattr(provider, field + '_id') == primary for field, primary in references['foreign'].items())
            and set(provider.property_mappings.values_list('pk', flat=True)) == references['scopes'])
    require(not adopting or matches)
    return matches


def apply_registration(spec, deadline):
    from authentik.blueprints.models import BlueprintInstance
    from authentik.blueprints.v1.tasks import apply_blueprint
    from authentik.crypto.models import CertificateKeyPair
    from authentik.flows.models import Flow
    from authentik.lib.config import CONFIG
    from authentik.providers.oauth2.models import ScopeMapping

    slug = spec['slug']
    require(re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', slug) and len(slug) <= 63)
    name = 'homelab-oidc-' + slug
    path = 'custom/' + name + '.yaml'
    contents = (Path(CONFIG.get('blueprints_dir')) / path).read_bytes()
    require(hashlib.sha512(contents).hexdigest() == spec['sha512'])
    secret = Path('/run/secrets/oidc-' + slug).read_bytes()
    require(0 < len(secret) <= 255 and all(33 <= byte <= 126 for byte in secret))
    from django.core.exceptions import ObjectDoesNotExist
    while True:
        try:
            references = {'foreign': {key: Flow.objects.get(slug=spec[key]).pk for key in (
                          'authentication_flow', 'authorization_flow', 'invalidation_flow')},
                          'scopes': {ScopeMapping.objects.get(managed='goauthentik.io/providers/oauth2/scope-' + scope).pk
                                     for scope in ('openid', 'profile', 'email')}}
            references['foreign']['signing_key'] = CertificateKeyPair.objects.get(name=spec['signing_key']).pk
            break
        except ObjectDoesNotExist:
            if time.monotonic() + 2 >= deadline:
                raise TimeoutError('Identity registration dependency unavailable') from None
            time.sleep(2)
    existing = BlueprintInstance.objects.filter(path=path)
    require(existing.count() <= 1 and not existing.exclude(name=name).exists())
    previous_instance = existing.first()
    matches = verify_registration(spec, secret, references,
                                  adopting=not (previous_instance and previous_instance.last_applied_hash))
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
                require(verify_registration(spec, secret, references))
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
