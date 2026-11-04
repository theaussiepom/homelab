"""Protected material fingerprints from this app's already supplied input bytes.

No path is opened, value is emitted, store is created or prior state compared.
The owning AppPayload caller keeps this map private and compares by role even
when a source ID changes. Existing adapter validation remains authoritative.
"""
import copy
import hashlib
import json
import re
from urllib.parse import urlsplit

import component_input_secrets
import mqtt_runtime
import runtime_secrets
import winet
from private_io import decode_json,require

ERROR='Invalid selected private material'


def _source(value):
    # slots() owns type/key/path/name structure; keep optional identity fields
    # finite too so this protected map cannot become a generic configuration bag.
    if 'source_id'in value:
        require(isinstance(value['source_id'],str)and re.fullmatch('[a-z][a-z0-9_-]{0,62}',value['source_id']),ERROR)
    if 'workflow_secret'in value:
        require(isinstance(value['workflow_secret'],str)and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',value['workflow_secret']),ERROR)
    require(all(isinstance(item,str)and 0<len(item)<=4096 and not any(char in item for char in '\r\n\x00')
                for item in value.values()),ERROR)
    return copy.deepcopy(value)


def _canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf-8')


def _material(app,role,raw):
    adapter=app['adapter']
    if adapter=='winet'and role=='options':
        value=winet.options_bytes(raw,app['settings'])
        endpoint=urlsplit(value['mqtt_url'])
        # Deliberately preserve the parser representation: no percent-decoding
        # equivalence or missing/empty inference beyond the existing contract.
        return _canonical({'winet_user':value['winet_user'],'winet_pass':value['winet_pass'],
                           'mqtt_username':endpoint.username,'mqtt_password':endpoint.password})
    if adapter=='mqtt'and role=='probe':
        value=decode_json(raw)
        mqtt_runtime.probe_files(value)
        return _canonical({'username':value['username'],'password':value['password']})
    if adapter=='traefik'and role=='proxmox_token':
        identity=app['settings']['provider']['token_id']
        secret=runtime_secrets.retained_provider_token(raw,identity)
        return _canonical({'identity':identity,'secret':secret})
    # Raw scalars, opaque Pega key and digest-authoritative Bitwarden env are
    # intentionally exact bytes. Do not trim, decode or reinterpret them here.
    return raw


def project(app,values):
    """Return role→closed source metadata + hash; supplied values never leave it."""
    require(isinstance(app,dict)and isinstance(app.get('adapter'),str)
            and isinstance(app.get('input_sources',{}),dict)and isinstance(values,dict),ERROR)
    sources=app.get('input_sources',{})
    try:
        component_input_secrets.slots(app['adapter'],sources)
        require(set(values)==set(sources),ERROR)
        result={}
        for role,source in sources.items():
            raw=values[role]
            limit=65536 if source['type']=='environment'else 1024*1024
            require(isinstance(raw,bytes)and 0<len(raw)<=limit,ERROR)
            identity=_source(source)
            result[role]={'source':identity,'material_sha256':hashlib.sha256(_material(app,role,raw)).hexdigest()}
        return result
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError):
        # Parser errors must not echo compound credentials or source contents.
        raise ValueError(ERROR)from None
