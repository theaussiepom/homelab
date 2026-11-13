"""Pure workflow graph/selection over actual resolved component ownership.

No fixed guest catalogue, secret values, YAML configuration parser, target calls
or file writes belong here. The finite workflow-input extractor reads YAML nodes
only to retain the existing consumer's exact disabled-input syntax contract.
"""
import json
import re
from types import SimpleNamespace

import yaml

import component_secrets
import component_connections
from component_plan import RESERVED
from component_sources import identifier, require

FLAT_INPUTS = {'HOMELAB_STACK_SOURCE', 'HOMELAB_ENVIRONMENT_PREFIX', 'HOMELAB_RUNNER_LABELS',
               'HOMELAB_REPOSITORY', 'HOMELAB_DISABLED'}
REUSABLE_INPUTS = {'disabled', 'runner_labels', 'environment_name'}
AGENT_PHASE = 'zabbix-agent'
BACKUP_PHASE = 'pbs-agent'


def label(value):
    require(isinstance(value, str) and value.strip() and not any(ord(c) < 32 or ord(c) == 127 for c in value)
            and '${{' not in value and '}}' not in value, 'component.workflow-label')
    return value


def _literal_require(ok, message):
    if not ok:
        raise ValueError(message)


def _mapping(node, text):
    _literal_require(isinstance(node, yaml.MappingNode), 'Use workflow mappings')
    # Anchored/tagged mappings cannot turn an alias into the selected literal.
    _literal_require(text[node.start_mark.index:node.start_mark.index + 1] not in ('&', '!'), 'Use a single-quoted literal JSON disabled list')
    result = {}
    for key, value in node.value:
        _literal_require(isinstance(key, yaml.ScalarNode) and key.tag == 'tag:yaml.org,2002:str'
                and key.value not in result, 'Use unique declared stack workflow inputs')
        result[key.value] = value
    return result


def disabled_json(value):
    """Preserve omitted/blank means all; reject duplicate/non-string lists."""
    _literal_require(isinstance(value, str), 'Use a JSON disabled guest list')
    try:
        _literal_require(len(value.encode('utf-8')) <= 1024 * 1024, 'Use a JSON disabled guest list')
    except UnicodeError:
        _literal_require(False, 'Use a JSON disabled guest list')
    try:
        result = [] if value == '' else json.loads(value)
    except (ValueError, TypeError):
        _literal_require(False, 'Use a JSON disabled guest list')
    _literal_require(isinstance(result, list) and all(isinstance(row, str) for row in result)
            and len(result) == len(set(result)), 'Use a JSON disabled guest list')
    return result


def workflow_disabled(text):
    """Extract only existing flat-env or reusable-stack literal disabled syntax.

    This does not replace immutable source selection, settings or full generated
    workflow validation. Secret values are never loaded or constructed.
    """
    _literal_require(isinstance(text, str), 'Use bounded workflow source text')
    try:
        _literal_require(len(text.encode('utf-8')) <= 1024 * 1024, 'Use bounded workflow source text')
        root = yaml.compose(text, Loader=yaml.BaseLoader)
    except (yaml.YAMLError, UnicodeError):
        _literal_require(False, 'Use workflow mappings')
    workflow = _mapping(root, text)
    env = _mapping(workflow['env'], text) if 'env' in workflow else {}
    flat = 'HOMELAB_STACK_SOURCE' in env
    if flat:
        _literal_require(set(env) <= FLAT_INPUTS, 'Use unique declared stack workflow inputs')
        selected = env.get('HOMELAB_DISABLED')
        # Exactly one source location controls the selection; mixed call forms
        # must not hide a second conflicting disabled input.
        if 'jobs' in workflow:
            jobs = _mapping(workflow['jobs'], text)
            if 'stack' in jobs:
                stack = _mapping(jobs['stack'], text)
                _literal_require('with' not in stack, 'Use one declared disabled input location')
    else:
        _literal_require('jobs' in workflow, 'Use workflow mappings')
        jobs = _mapping(workflow['jobs'], text)
        _literal_require('stack' in jobs, 'Use workflow mappings')
        stack = _mapping(jobs['stack'], text)
        _literal_require('with' in stack, 'Use workflow mappings')
        inputs = _mapping(stack['with'], text)
        _literal_require(set(inputs) <= REUSABLE_INPUTS, 'Use unique declared stack workflow inputs')
        selected = inputs.get('disabled')
    if selected is None:
        return []
    _literal_require(isinstance(selected, yaml.ScalarNode) and selected.tag == 'tag:yaml.org,2002:str'
            and selected.style == "'" and text[selected.start_mark.index:selected.start_mark.index + 1] == "'",
            'Use a single-quoted literal JSON disabled list')
    return disabled_json(selected.value)


def selection(guests, dependencies, disabled, *, monitoring_guest=None):
    """Stable declared order; closure never creates another readiness edge."""
    require(isinstance(guests, (list, tuple)) and all(identifier(key) and key not in RESERVED for key in guests)
            and len(guests) == len(set(guests)), 'component.workflow-guest-id')
    require(isinstance(dependencies, dict) and set(dependencies) == set(guests), 'component.workflow-dependencies')
    for rows in dependencies.values():
        require(isinstance(rows, list) and all(isinstance(row, str) and row in dependencies for row in rows)
                and len(rows) == len(set(rows)), 'component.workflow-dependencies')
    require(isinstance(disabled, list) and all(isinstance(row, str) for row in disabled)
            and len(disabled) == len(set(disabled)) and set(disabled) <= set(guests), 'component.workflow-disabled')
    component_connections._acyclic(dependencies)
    active = [key for key in guests if key not in disabled]
    require(all(set(dependencies[key]) <= set(active) for key in active), 'component.workflow-disabled-dependency')
    require(monitoring_guest is None or monitoring_guest in guests, 'component.workflow-monitoring')
    require(monitoring_guest is None or not active or monitoring_guest in active, 'component.workflow-monitoring-selection')
    return active


def _ordered_apps(apps, dependencies, guest):
    local = [key for key, app in apps.items() if app['guest'] == guest]
    pending, done, result = local[:], set(), []
    while pending:
        ready = [key for key in pending if not (set(dependencies[key]) & set(local)) - done]
        require(bool(ready), 'component.workflow-application-cycle')
        selected = ready[0]
        pending.remove(selected); done.add(selected); result.append(selected)
    return result


def application_order(plan, guest):
    plan.check()
    require(guest in plan.resolved['guests'], 'component.reference')
    return _ordered_apps(plan.resolved['apps'], plan.resolved['app_dependencies'], guest)


def model(plan):
    """Return graph/phase metadata for the selected source Plan, never secrets.

    The caller owns recipe policies, source pins, generation and scalar secret
    forwarding. This helper provides no default/implicit composition.
    """
    plan.check()
    resolved = plan.resolved
    guests, apps = resolved['guests'], resolved['apps']
    dependencies = resolved['guest_dependencies']
    require(isinstance(guests, dict) and isinstance(apps, dict), 'component.workflow-plan')
    monitored = resolved.get('monitoring', {}).get('guest')
    planned = resolved['enabled']
    require(isinstance(planned, list) and all(isinstance(key, str) for key in planned)
            and len(planned) == len(set(planned)) and set(planned) <= set(guests), 'component.workflow-disabled')
    active = selection(list(guests), dependencies, [key for key in guests if key not in planned],
                       monitoring_guest=monitored)
    require(active == planned, 'component.workflow-guest-order')
    app_dependencies = resolved['app_dependencies']
    require(set(app_dependencies) == set(apps), 'component.workflow-dependencies')
    for key, app in apps.items():
        require(identifier(key) and app['guest'] in guests and isinstance(app_dependencies[key], list)
                and all(isinstance(row, str) and row in apps for row in app_dependencies[key]), 'component.workflow-application')
    resolver = SimpleNamespace(apps=apps, site=plan.site)
    operational_backup = resolved.get('backup', {}).get('mode') == 'scheduled-recovery'
    result = {'guest_order': active, 'dependencies': {key: list(rows) for key, rows in dependencies.items()},
              'monitoring_guest': monitored, 'guests': {}}
    for guest in active:
        guest_title = label(guests[guest]['display_name'])
        phases = [{'id': 'infrastructure', 'name': 'Infrastructure', 'application': None, 'inputs': {}},
                  {'id': 'preparation', 'name': 'Prepare', 'application': None, 'inputs': {}}]
        ids, secrets = {'infrastructure', 'preparation', AGENT_PHASE, BACKUP_PHASE}, []
        for app_id in _ordered_apps(apps, app_dependencies, guest):
            app = apps[app_id]; phase, title = app['identity']['phase'], app['display_name']
            require(identifier(phase) and phase not in RESERVED and phase not in ids, 'component.workflow-phase-id')
            label(title)
            ids.add(phase)
            inputs = component_secrets.action_inputs(resolver, app_id)
            require(isinstance(inputs, dict) and set(inputs) <= set(component_secrets.SLOTS.get(app['adapter'], {} ).values()),
                    'component.workflow-secret-slot')
            for selected in inputs.values():
                require(isinstance(selected, dict) and set(selected) == {'environment', 'workflow_secret'}
                        and all(isinstance(value, str) and re.fullmatch('[A-Z][A-Z0-9_]{0,127}', value)
                                for value in selected.values()), 'component.workflow-secret-slot')
                if selected['workflow_secret'] not in secrets:
                    secrets.append(selected['workflow_secret'])
            phases.append({'id': phase, 'name': title, 'application': app_id, 'inputs': inputs})
        if monitored is not None:
            phases.append({'id': AGENT_PHASE, 'name': 'Zabbix agent', 'application': None, 'inputs': {}})
        if 'backup' in guests[guest]:
            inputs = {'PBS_API_TOKEN': {'environment': 'PBS_API_TOKEN', 'workflow_secret': 'PBS_API_TOKEN'}} if operational_backup else {}
            phases.append({'id': BACKUP_PHASE, 'name': 'Backup', 'application': None, 'inputs': inputs})
            if operational_backup:
                secrets.append('PBS_API_TOKEN')
        result['guests'][guest] = {'name': guest_title,
                                  'needs': ['selection', *(['_backup'] if operational_backup and 'backup' in guests[guest] else []), *dependencies[guest]],
                                  'phases': phases, 'workflow_secrets': secrets}
    if operational_backup:
        result['backup'] = {'name':'Backup', 'needs':['selection'],
                            'environment':'backup', 'workflow_secrets':['PBS_API_TOKEN']}
    plan.check()
    return result
