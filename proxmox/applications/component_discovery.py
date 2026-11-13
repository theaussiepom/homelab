"""Selected component caller for the existing read-only discovery admission."""
from pathlib import Path

import deployment_state
import discovery_scope
import runtime_secrets
from private_io import require


def verify(cfg, app, raw_record, api=None):
    require(isinstance(cfg, dict) and isinstance(app, dict) and app.get('adapter') == 'traefik'
            and isinstance(app.get('settings'), dict) and isinstance(app['settings'].get('provider'), dict),
            'Select the component-owned provider capability')
    provider = app['settings']['provider']
    require(discovery_scope.origin(provider['url']) == discovery_scope.origin(cfg['site']['api_endpoint'])
            and provider['ca_file'] == cfg['paths']['ca_file'],
            'Preserve the selected execution context API and public trust')
    # Same existing bootstrap marker guard. It does not create a directory or
    # claim atomicity beyond the enclosing ordinary deployment attempt locks.
    scope = provider.get('discovery')
    if scope is None:
        return {'status': 'not_selected', 'writes': False}
    protected=cfg['deployment']['protected_guests']
    scope = discovery_scope.selected_scope(scope,protected)
    deployment_state.bootstrap_closed(Path(scope['local_directory']).parent)
    require(isinstance(raw_record, bytes) and 0 < len(raw_record) <= 65536,
            'Supply the selected bounded retained provider record')
    def configured():
        token = runtime_secrets.retained_provider_token(raw_record, provider['token_id'])
        return provider['token_id']+'='+token
    return discovery_scope.verify_selection(cfg, scope, endpoint=provider['url'],
        token_id=provider['token_id'], ca_file=provider['ca_file'],
        read_configured=configured, api=api, protected_guests=protected)
