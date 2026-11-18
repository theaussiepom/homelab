"""Pure selected-byte input builders; no I/O, dispatch or credential creation."""
import json
import bitwarden_runtime
import winet
import mqtt_runtime
import pegaprox_oidc
from private_io import require,decode_json

ROLES={'bitwarden':'runtime_environment','winet':'options','pegaprox':'database_key','mqtt':'probe'}


def bind(app, values):
    """Return private rows/environment only to the owned immutable-payload caller."""
    require(isinstance(app,dict) and isinstance(app.get('adapter'),str) and app['adapter'] in ROLES and isinstance(values,dict),
            'Select one supported private app input builder')
    adapter=app['adapter'];role=ROLES[adapter]
    oidc = adapter == 'pegaprox' and 'authentication_resolved' in app
    roles = {role, 'client_secret', 'management_token'} if oidc else {role}
    require(set(values)==roles and all(isinstance(values[key],bytes) and 0<len(values[key])<=1024*1024 for key in roles),
            'Supply exactly this app selected raw input bytes')
    raw=values[role]
    if adapter=='mqtt':
        require(app.get('lifecycle')=='retained','Fresh broker configuration commissioning is not implemented')
        return {'files':mqtt_runtime.probe_files(decode_json(raw)),'environment':{}}
    if adapter=='bitwarden':
        require(app.get('lifecycle')=='retained','Fresh Bitwarden commissioning is not implemented')
        selected=app['settings']
        environment=bitwarden_runtime.environment_bytes(raw,selected['runtime'],selected['settings'])
        return {'files':[],'environment':environment}
    if adapter=='winet':
        options=winet.options_bytes(raw,app['settings'])
        return {'files':[{'path':'winet-options.json','content':json.dumps(options,sort_keys=True)+'\n',
                          'uid':0,'gid':0,'mode':'0600'}],'environment':{}}
    require(app.get('lifecycle')=='retained','Preserve the existing PegaProx key; no creation or bootstrap')
    # Existing admission is checksum/999:999/0600 parity, not a key-format parser.
    # Caller must inspect the existing target before any generic copy/start.
    return {'files':[{'path':'pegaprox-db-key','content':raw,'uid':999,'gid':999,'mode':'0600'}]
                    + (pegaprox_oidc.files(app, values) if oidc else []),
            'environment':{}}
