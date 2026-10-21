"""Exercise reviewed admission expressions without any package or host actions."""
import re
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def environment():
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.tests['match'] = lambda value, pattern: isinstance(value, str) and re.match(pattern, value) is not None
    return env


@pytest.mark.parametrize('package,accepted', [
    ('postgresql-16=16.15-1.pgdg120+1', True),
    ('libc6:amd64=2:2.40~rc1-2', True),
    ('curl=', False), ('curl>=1', False), ('curl=1.*', False),
    ('curl=latest', False), ('curl', False), ('curl=1.0 extra', False),
    ('curl=1.0\\bad', False),
])
def test_exact_native_package_version(package, accepted):
    tasks = yaml.safe_load((ROOT/'ansible/roles/homelab_native_packages/tasks/main.yml').read_text())
    expression = tasks[1]['ansible.builtin.assert']['that'][-1]
    assert environment().compile_expression(expression)(homelab_native_packages=[package]) is accepted


@pytest.mark.parametrize('value,accepted', [(1000,True), (0,True), ('1000',False), (True,False),(-1,False)])
def test_identity_manifest_requires_canonical_numbers(value, accepted):
    tasks = yaml.safe_load((ROOT/'ansible/roles/homelab_identity_guard/tasks/main.yml').read_text())
    expression = tasks[1]['ansible.builtin.assert']['that'][0]
    assert environment().compile_expression(expression)(item={'uid':value}) is accepted
