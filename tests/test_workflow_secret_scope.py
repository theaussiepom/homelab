"""Evaluate actual workflow expressions and binding behavior with invented secrets."""

import copy
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
APPS = ROOT / 'proxmox/applications'
sys.path.insert(0, str(APPS))
sys.path.insert(0, str(APPS / 'tests'))
import runtime_secrets
from secret_contract import BINDINGS
from test_foundation import fixture as foundation_fixture
from test_render import fixture as compose_fixture

OWNERS = {
    'NODE_RED_API_TOKEN': ('automation', 'AUTOMATION_NODE_RED_API_TOKEN'),
    'AUTHENTIK_SECRET_KEY': ('identity', 'FOUNDATION_AUTHENTIK_SECRET_KEY'),
    'AUTHENTIK_POSTGRES_PASSWORD': ('identity', 'FOUNDATION_AUTHENTIK_POSTGRES_PASSWORD'),
    'AUTHENTIK_SMTP_PASSWORD': ('identity', 'FOUNDATION_AUTHENTIK_SMTP_PASSWORD'),
    'PGADMIN_OAUTH_SECRET': ('db-tools', 'FOUNDATION_PGADMIN_OAUTH_SECRET'),
    'CLOUDFLARE_DNS_TOKEN': ('ingress', 'FOUNDATION_CLOUDFLARE_DNS_TOKEN'),
}
CATALOGUE = json.loads((ROOT / 'blueprints/catalogue.json').read_text())['guests']


def workflow():
    return yaml.load((ROOT / '.github/workflows/guest-phase.yml').read_text(), Loader=yaml.BaseLoader)


def environment(guest, available):
    step = next(step for step in workflow()['jobs']['run']['steps'] if step.get('name') == 'Reconcile this phase')
    assert set(step['env']) == {'GUEST', 'PHASE', *OWNERS}
    result = {}
    for name in OWNERS:
        # GitHub's supported string-expression subset: missing Secrets and a
        # failed guest condition both yield ''. Never eval code or read Secrets.
        expression = step['env'][name]
        match = re.fullmatch(r"\$\{\{ inputs\.guest == '([a-z-]+)' && secrets\.([A-Z_]+) \|\| '' \}\}", expression)
        assert match, expression
        owner, secret = match.groups()
        assert (owner, secret) == OWNERS[name]
        result[name] = (available.get(secret, '') if guest == owner else '') or ''
    return result


@pytest.mark.parametrize('guest', sorted(CATALOGUE))
def test_every_catalogue_guest_phase_receives_only_its_own_values(guest):
    available = {secret: 'invented-' + secret for _, secret in OWNERS.values()}
    expected = {name: available[secret] if owner == guest else '' for name, (owner, secret) in OWNERS.items()}
    for phase in ['infrastructure', 'preparation', *CATALOGUE[guest]['applications']]:
        assert environment(guest, available) == expected, phase
        selected = {secret: available[secret] for owner, secret in OWNERS.values() if owner == guest}
        assert environment(guest, selected) == expected, phase
    assert environment(guest, {}) == dict.fromkeys(OWNERS, '')


def stack_for(root, kind):
    cfg = {'app': {'kind': kind}}
    stack = compose_fixture(kind) if kind == 'automation' else foundation_fixture(root, kind)
    if kind != 'automation':
        stack['foundation']['secret_files'] = {
            name: str(root / binding.filename)
            for name, binding in BINDINGS[kind].items()
            if name != 'smtp_password'
        }
    return cfg, stack


@pytest.mark.parametrize('kind', ['automation', 'identity', 'db-tools', 'ingress'])
def test_scoping_preserves_selected_inputs_and_missing_required_refusals(tmp_path, kind):
    cfg, stack = stack_for(tmp_path, kind)
    available = {secret: 'invented-' + secret for name, (owner, secret) in OWNERS.items() if owner == kind and name != 'AUTHENTIK_SMTP_PASSWORD'}
    selected = environment(kind, available)
    provider = tmp_path / 'provider.json'
    identity = 'root@pam!traefik-provider'
    provider.write_text(json.dumps({'schema': 'homelab-service-discovery-v1', 'identity': identity, 'token': identity + '=invented'}))
    provider.chmod(0o600)
    with patch.object(runtime_secrets, 'PROVIDER', provider):
        actual_stack = copy.deepcopy(stack)
        actual_files = runtime_secrets.prepare_stack(cfg, actual_stack, tmp_path, selected)
        full = {name: 'invented-' + secret for name, (_, secret) in OWNERS.items()}
        full_stack = copy.deepcopy(stack)
        full_files = runtime_secrets.prepare_stack(cfg, full_stack, tmp_path, full)
        assert (actual_stack, actual_files) == (full_stack, full_files)
        if kind == 'automation':
            assert actual_stack['services']['node_red']['environment']['NODE_RED_API_TOKEN'] == selected['NODE_RED_API_TOKEN']
        else:
            assert set(actual_files) == {BINDINGS[kind][name].filename for name in stack['foundation']['secret_files']}
        for name, (owner, secret) in OWNERS.items():
            if owner != kind or name == 'AUTHENTIK_SMTP_PASSWORD':
                continue
            missing = dict(available)
            missing.pop(secret)
            with pytest.raises(ValueError, match='retained Node-RED|foundation environment secret'):
                runtime_secrets.prepare_stack(cfg, copy.deepcopy(stack), tmp_path, environment(kind, missing))


def test_smtp_is_optional_until_explicitly_selected(tmp_path):
    cfg, stack = stack_for(tmp_path, 'identity')
    available = {secret: 'invented-' + secret for name, (owner, secret) in OWNERS.items() if owner == 'identity' and name != 'AUTHENTIK_SMTP_PASSWORD'}
    selected = environment('identity', available)
    extra = runtime_secrets.prepare_stack(cfg, copy.deepcopy(stack), tmp_path, selected)
    assert 'smtp-password' not in extra
    stack['foundation']['secret_files']['smtp_password'] = str(tmp_path / 'smtp-password')
    with pytest.raises(ValueError, match='foundation environment secret'):
        runtime_secrets.prepare_stack(cfg, copy.deepcopy(stack), tmp_path, selected)
    available['FOUNDATION_AUTHENTIK_SMTP_PASSWORD'] = 'invented-smtp'
    extra = runtime_secrets.prepare_stack(cfg, stack, tmp_path, environment('identity', available))
    assert extra['smtp-password'] == b'invented-smtp'


def test_existing_admission_and_shared_credential_binding_are_preserved():
    job = workflow()['jobs']['run']
    assert job['environment'] == '${{ inputs.environment_name }}'
    assert 'github.event.repository.private == true' in job['if']
    assert "github.event_name == 'push'" in job['if']
    assert "github.ref == 'refs/heads/main'" in job['if']
    binding = next(step for step in job['steps'] if step.get('name') == 'Bind existing credentials')
    assert binding['env']['PROXMOX_APP_TOKEN'] == '${{ secrets.PROXMOX_APP_TOKEN }}'
    assert binding['env']['APPLICATION_SSH_KEY'] == '${{ secrets.APPLICATION_SSH_KEY }}'
