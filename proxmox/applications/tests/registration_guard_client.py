"""Run under manage.py shell only in the isolated registration_guard_fixture project."""
import json
import time
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from authentik.blueprints.models import BlueprintInstance
from authentik.blueprints.v1.importer import Importer
from authentik.core.models import Application, Group, Token, User
from authentik.flows.models import Flow
from authentik.outposts.models import Outpost
from authentik.policies.models import PolicyBinding
from authentik.providers.proxy.models import ProxyProvider


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def verify():
    # A clean server can report ready while default blueprints are still importing.
    deadline = time.monotonic() + 120
    while not (Flow.objects.filter(slug='default-provider-authorization-implicit-consent').exists()
               and Flow.objects.filter(slug='default-provider-invalidation-flow').exists()
               and Outpost.objects.filter(managed='goauthentik.io/outposts/embedded').exists()
               and User.objects.filter(username='akadmin').exists()):
        if time.monotonic() >= deadline:
            raise RuntimeError('Default Authentik fixture objects did not become ready')
        time.sleep(1)

    user = User.objects.get(username='akadmin')
    assert user.is_superuser
    token = Token.objects.create(identifier='registration-test-admin', user=user, intent='api')
    provider = ProxyProvider.objects.create(
        name='Managed fixture', external_host='https://managed.example.invalid', mode='forward_single',
        authorization_flow=Flow.objects.get(slug='default-provider-authorization-implicit-consent'),
        invalidation_flow=Flow.objects.get(slug='default-provider-invalidation-flow'))
    app = Application.objects.create(name='Managed', slug='managed', provider=provider)
    group = Group.objects.create(name='Registration test')
    binding = PolicyBinding.objects.create(target=app, group=group, order=0)
    free = Application.objects.create(name='Independent', slug='independent')
    outpost = Outpost.objects.get(managed='goauthentik.io/outposts/embedded')
    outpost.providers.add(provider)
    receipt = BlueprintInstance.objects.create(name='homelab-forward-managed',
                                              path='custom/homelab-forward-managed.yaml', enabled=False)
    http = build_opener(NoRedirect)

    def request(method, path, status, body=None, auth=True):
        data = None if body is None else json.dumps(body).encode()
        req = Request('http://ingress:8080' + path, data=data, method=method)
        req.add_header('Host', 'sso.example.invalid')
        req.add_header('Content-Type', 'application/json')
        if auth:
            req.add_header('Authorization', 'Bearer ' + token.key)
        try:
            response = http.open(req, timeout=12)
        except HTTPError as error:
            response = error
        with response:
            assert response.status == status, (method, path, response.status, status)
            if status == 403:
                assert json.loads(response.read()) == {'detail': 'registration managed in YAML'}

    api = '/api/v3/'
    request('GET', api + 'core/applications/managed/', 200)
    request('PATCH', api + 'core/applications/managed/', 403, {'name': 'Unexpected'})
    request('DELETE', api + f'providers/all/{provider.pk}/', 403)
    request('POST', api + 'policies/bindings/', 403, {'target': str(app.pk), 'group': str(group.pk), 'order': 10})
    request('DELETE', api + f'policies/bindings/{binding.pk}/', 403)
    request('PATCH', api + f'outposts/instances/{outpost.pk}/', 403, {'providers': []})
    request('PATCH', api + f'managed/blueprints/{receipt.pk}/', 403, {'enabled': True})
    request('PATCH', api + 'core/applications/independent/', 200, {'name': 'Independent updated'})
    request('POST', api + 'policies/bindings/', 201, {'target': str(free.pk), 'group': str(group.pk), 'order': 2})
    request('GET', '/if/flow/default-authentication-flow/', 200, auth=False)
    app.refresh_from_db()
    free.refresh_from_db()
    receipt.refresh_from_db()
    assert app.name == 'Managed' and free.name == 'Independent updated' and not receipt.enabled
    assert PolicyBinding.objects.filter(target=app).count() == 1 and outpost.providers.filter(pk=provider.pk).exists()
    document = {'version': 1, 'metadata': {'name': 'Fixture registration'}, 'entries': [{
        'model': 'authentik_core.application', 'identifiers': {'slug': 'managed'}, 'attrs': {'name': 'From YAML'}}]}
    assert Importer.from_string(json.dumps(document), {}).apply()
    app.refresh_from_db()
    assert app.name == 'From YAML' and app.provider_id == provider.pk
    print('Managed updates denied, independent edits accepted, sign-in page served and native blueprint applied.')


verify()
