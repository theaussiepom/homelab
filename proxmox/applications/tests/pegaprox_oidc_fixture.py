#!/usr/bin/env python3
"""Pinned upgrade and native settings/token checks against invented disposable state."""
import json
from pathlib import Path
import subprocess
import sys

sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parent)]
import pegaprox_runtime_fixture as fixture
from test_pegaprox_oidc import configuration
import pegaprox_oidc_client

IMAGE='ghcr.io/pegaprox/pegaprox@sha256:3c8cb496769f05e8c37a6e9cb37a4700df2a37898c073b635c83d734014065f7'
BOOTSTRAP_CODE = r'''
"""One-time initial credential provisioning; run inside the explicitly selected manager."""
import json
import logging
import sys
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.error import HTTPError

logging.disable(logging.CRITICAL)
from pegaprox.utils.auth import create_api_token, revoke_api_token, list_user_tokens, load_users
from pegaprox.utils.rbac import load_custom_roles

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args): raise RuntimeError('Unexpected local API redirect')

def call(path,token,data=None):
    request=Request('http://127.0.0.1:5000'+path, data=None if data is None else json.dumps(data).encode(),
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'})
    try: response=build_opener(ProxyHandler({}),NoRedirect()).open(request,timeout=20)
    except HTTPError as error:response=error
    with response:
        raw=response.read(1048577)
        assert len(raw)<=1048576
        return response.code,json.loads(raw)

def provision(username):
    assert load_users()[username]['role']=='admin'
    assert not [row for row in list_user_tokens(username) if not row.get('revoked')], 'Preserve existing tokens'
    assert 'homelab_oidc_settings' not in load_custom_roles().get('global',{}), 'Preserve existing role'
    bootstrap=create_api_token(username,'One-time OIDC credential bootstrap',role='admin',expires_days=1)
    assert bootstrap.get('success') is True
    management=None
    try:
        status,created=call('/api/roles',bootstrap['token'],{'id':'homelab_oidc_settings',
            'name':'HomeLab OIDC settings','permissions':['admin.settings']})
        assert status==200 and created.get('success') is True, 'Role creation failed'
        management=create_api_token(username,'HomeLab OIDC settings',role='homelab_oidc_settings')
        assert management.get('success') is True, 'Management token creation failed'
        assert call('/api/settings/server',management['token'])[0]==200, 'Settings permission missing'
        assert call('/api/users',management['token'])[0]==403, 'Token has unexpected user administration access'
    except Exception:
        if management and management.get('success'):assert revoke_api_token(management['token_id'],username)
        raise
    finally:
        assert revoke_api_token(bootstrap['token_id'],username), 'Bootstrap revocation failed'
    return management

if __name__=='__main__':
    value=provision(json.load(sys.stdin)['username'])
    print('MANAGEMENT-CREDENTIAL '+json.dumps(value))
'''

TOKEN_CHECK_CODE = r"""
import json, logging, time
from types import SimpleNamespace
from unittest.mock import patch
import jwt
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from pegaprox.utils import oidc
logging.disable(logging.CRITICAL)
key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
wrong_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
jwk.update(kid='fixture-key',use='sig',alg='RS256')
keys = jwt.PyJWKSet.from_dict({'keys':[jwk]})
client = SimpleNamespace(get_jwk_set=lambda **kwargs:keys)
issuer = 'https://sso.example.invalid/application/o/manager/'
config = {'provider':'generic','client_id':'fixture','authority':issuer,
          'oidc_skip_jwt_verification':False,'oidc_skip_ssl_verify':False,'oidc_audiences':''}
now = int(time.time())
claims = {'sub':'fixture-user','preferred_username':'fixture-user','groups':['Managers'],
          'aud':'fixture','iss':issuer,'exp':now+300,'iat':now,'nbf':now-1,'nonce':'fixture-nonce'}
def decode(payload,signer=key,kid='fixture-key'):
 token=jwt.encode(payload,signer,algorithm='RS256',headers={'kid':kid})
 return oidc.oidc_decode_id_token(token,expected_nonce='fixture-nonce',config=config)
with patch.object(oidc,'get_oidc_endpoints',return_value={'issuer':issuer,'jwks':issuer+'jwks/'}),patch.object(oidc,'_oidc_jwks_client',return_value=client):
 assert decode(claims).get('sub')=='fixture-user'
 for field,value in [('aud','foreign'),('iss','https://foreign.invalid/'),('nonce','foreign'),
                     ('exp',now-600),('nbf',now+600),('azp','foreign')]:
  assert 'error' in decode(dict(claims,**{field:value})),field
 assert 'error' in decode(claims,signer=wrong_key),'bad signature accepted'
 assert 'error' in decode(claims,kid='unknown-key'),'unknown signing key accepted'
print('native-token-refusals-passed')
"""

def check(name,account):
    result=subprocess.run(['docker','exec','-i',name,'python3','-c',BOOTSTRAP_CODE],
        input=json.dumps({'username':account['username']}),capture_output=True,text=True,timeout=90)
    assert result.returncode==0, 'Disposable management credential provisioning failed'
    values=[json.loads(row.removeprefix('MANAGEMENT-CREDENTIAL ')) for row in result.stdout.splitlines()
            if row.startswith('MANAGEMENT-CREDENTIAL ')]
    assert len(values)==1
    value=configuration();value['management_token']=values[0]['token']
    # Exercise the real settings API; browser/IdP exchange remains a separate target check.
    value['settings']['oidc_enabled']=False
    code=Path(pegaprox_oidc_client.__file__).read_text()
    for applied,changed in [(False,True),(True,False)]:
        response=subprocess.run(['docker','exec','-i',name,'python3','-c',code],
            input=json.dumps({'configuration':value,'applied':applied}),capture_output=True,text=True,timeout=100)
        assert response.returncode==0, 'Native settings API reconciliation failed'
        assert json.loads(response.stdout)=={'changed':changed}
    result=subprocess.run(['docker','exec',name,'python3','-c',TOKEN_CHECK_CODE],capture_output=True,text=True,timeout=60)
    assert result.returncode==0 and result.stdout.strip()=='native-token-refusals-passed', 'Native token validation failed'

if __name__=='__main__':
    fixture.main(image=IMAGE,after_start=check)
