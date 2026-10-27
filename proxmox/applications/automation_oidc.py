"""Add one callback to the retained Node-RED OIDC provider, without new secrets."""
import argparse
import base64
import dataclasses
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlsplit


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(cfg):
    require(isinstance(cfg, dict) and set(cfg) == {'vmid','hostname','provider_id','client_id','slug','before','callback'},
            'Use the selected existing provider and callback only')
    require(type(cfg['vmid']) is int and cfg['vmid'] >= 100 and cfg['vmid'] not in {900,4914,4915,4920}
            and type(cfg['provider_id']) is int and cfg['provider_id'] > 0
            and all(isinstance(cfg[k],str) and cfg[k] and len(cfg[k]) <= 256 for k in ('hostname','client_id','slug')),
            'Select the commissioned identity guest and existing provider')
    require(isinstance(cfg['before'],list) and 1 <= len(cfg['before']) <= 16
            and all(set(row) == {'matching_mode','url'} and row['matching_mode'] == 'strict' for row in cfg['before']),
            'Retain only the exact existing strict callbacks')
    for url in [row['url'] for row in cfg['before']] + [cfg['callback']]:
        selected=urlsplit(url)
        require(selected.scheme == 'https' and selected.hostname and selected.username is None
                and selected.port is None and selected.path == '/auth/strategy/callback/'
                and not selected.query and not selected.fragment, 'Use an HTTPS native Node-RED callback')
    require(cfg['callback'] not in [row['url'] for row in cfg['before']], 'The callback must be a declared addition')


def normalized(rows):
    return [dataclasses.asdict(row) if dataclasses.is_dataclass(row) else dict(row) for row in rows]


def candidate(rows, cfg, verify=False):
    validate(cfg)
    after=[*cfg['before'],{'matching_mode':'strict','url':cfg['callback']}]
    require(normalized(rows) == (after if verify else cfg['before']), 'Existing Node-RED provider callbacks differ')
    if verify:
        return rows
    original=rows[0]
    added=dataclasses.replace(original,url=cfg['callback']) if dataclasses.is_dataclass(original) else dict(original,url=cfg['callback'])
    return [*rows,added]


def inside(cfg, verify=False):
    validate(cfg)
    os.environ.setdefault('DJANGO_SETTINGS_MODULE','authentik.root.settings')
    import django
    django.setup()
    from django.db import transaction
    from authentik.providers.oauth2.models import OAuth2Provider
    from authentik.core.models import Application
    with transaction.atomic():
        provider=OAuth2Provider.objects.select_for_update().get(pk=cfg['provider_id'])
        require(provider.client_id == cfg['client_id'] and Application.objects.filter(
            slug=cfg['slug'],provider_id=cfg['provider_id']).count() == 1, 'Existing Node-RED client or application differs')
        value=candidate(provider.redirect_uris,cfg,verify)
        if not verify:
            provider.redirect_uris=value
            provider.save(update_fields=['redirect_uris'])
            provider.refresh_from_db(fields=['redirect_uris'])
            candidate(provider.redirect_uris,cfg,True)
    return {'status':'passed','provider_id':cfg['provider_id'],'changed':not verify}


def guest(cfg, verify=False):
    validate(cfg)
    identity=json.loads(Path('/etc/homelab-application.json').read_text())
    require(os.geteuid() == 0 and not Path('/etc/pve').exists() and identity.get('kind') == 'identity'
            and identity.get('vmid') == cfg['vmid'] and identity.get('hostname') == cfg['hostname'],
            'Run only on the commissioned identity guest')
    argv=['docker','compose','-f','/opt/homelab-app/compose.yml','exec','-T','server','python','-',
          '--inside',base64.urlsafe_b64encode(json.dumps(cfg).encode()).decode()]
    if verify: argv.append('--verify')
    result=subprocess.run(argv,input=Path(__file__).read_bytes(),capture_output=True,timeout=90)
    require(result.returncode == 0,'Existing provider update failed; preserve the CD hold')
    lines=[line for line in result.stdout.decode().splitlines() if line.startswith('OIDC_RESULT=')]
    require(len(lines) == 1,'Existing provider completion differs')
    return json.loads(lines[0].split('=',1)[1])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path)
    parser.add_argument('--inside')
    parser.add_argument('--verify',action='store_true')
    args=parser.parse_args()
    try:
        if args.inside:
            require(len(args.inside) < 16384,'Oversized OIDC settings')
            result=inside(json.loads(base64.urlsafe_b64decode(args.inside)),args.verify)
            print('OIDC_RESULT='+json.dumps(result))
        else:
            require(args.config is not None,'Supply reviewed OIDC settings')
            print(json.dumps(guest(json.loads(args.config.read_text()),args.verify)))
    except Exception:
        raise SystemExit('Node-RED OIDC held; no secrets or database contents were printed') from None
