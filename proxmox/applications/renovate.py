"""Fixed Mend Renovate CE settings and selected private scalar environment."""
import json
import re

from private_io import require

ROLES = {'accept_terms', 'license_key', 'github_app_id', 'github_app_key', 'database_password'}
VARIABLES = {'accept_terms': 'MEND_RNV_ACCEPT_TOS', 'license_key': 'MEND_RNV_LICENSE_KEY',
             'github_app_id': 'MEND_RNV_GITHUB_APP_ID', 'github_app_key': 'MEND_RNV_GITHUB_APP_KEY',
             'database_password': 'PGPASSWORD'}


def environment(app):
    """No secrets or implicit terms acceptance enter the source-rendered model."""
    value = app['settings']
    database = value['database']
    return {'MEND_RNV_PLATFORM': 'github', 'MEND_RNV_DATA_HANDLER_TYPE': 'postgresql',
        'PGHOST': database['host'], 'PGPORT': str(database['port']),
        'PGDATABASE': database['name'], 'PGUSER': database['user'],
        'MEND_RNV_AUTODISCOVER_FILTER': ','.join(value['repositories']),
        'MEND_RNV_API_ENABLED': 'false', 'MEND_RNV_ADMIN_API_ENABLED': 'false',
        'MEND_RNV_ENQUEUE_JOBS_ON_STARTUP': 'disabled',
        'MEND_RNV_CRON_JOB_SCHEDULER_ALL': '0 * * * *',
        'MEND_RNV_LOG_HISTORY_DIR': '/tmp/renovate-logs',
        'RENOVATE_BASE_DIR': '/tmp/renovate', 'RENOVATE_BINARY_SOURCE': 'install',
        'RENOVATE_CONFIG': json.dumps({'onboarding': False, 'requireConfig': 'required',
            'allowedPostUpgradeCommands': [], 'allowScripts': False,
            'force': {'automerge': False, 'platformAutomerge': False}}, separators=(',', ':')),
        'LOG_LEVEL': 'info', 'MEND_RNV_DEBUG_MODE': 'false'}


def scalar(raw):
    """Validate the same scalar before either database or worker preparation."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= 65536, 'Supply bounded Renovate inputs')
    try:
        value = raw.decode('utf-8')
    except UnicodeError:
        raise ValueError('Supply UTF-8 Renovate inputs') from None
    require(value.strip() and not any(char in value for char in '\r\n\x00'),
            'Supply scalar Renovate inputs; use base64:// for the App PEM')
    return value


def secrets(values):
    require(isinstance(values, dict) and set(values) == ROLES, 'Supply exactly the Mend CE secret roles')
    result = {}
    for role, raw in values.items():
        result[VARIABLES[role]] = scalar(raw)
    require(result['MEND_RNV_ACCEPT_TOS'] == 'y', 'Explicit Mend terms acceptance is required')
    require(re.fullmatch('[1-9][0-9]{0,19}', result['MEND_RNV_GITHUB_APP_ID']), 'Supply the real GitHub App ID')
    require(re.fullmatch(r'base64://[A-Za-z0-9+/]+={0,2}', result['MEND_RNV_GITHUB_APP_KEY']),
            'Supply the GitHub App PEM as a base64:// scalar')
    return result
