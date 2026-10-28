"""One guest job runs ordered automation deployment steps on one staged input set."""
import argparse
import fcntl
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import deploy
import foundation_cd as files

INPUTS = Path('/var/lib/homelab-inputs/automation')
SERVICES = deploy.AUTOMATION_SERVICES
HOLDS = ('HOLD.json', 'ROLLOUT-HOLD.json', 'CONTINUATION-HOLD.json', 'AUTOMATION-CD-HOLD.json')


def prepare_inputs(config, destination=INPUTS, environment=None):
    """Actual settings stay private; the one runtime token comes from GitHub Secrets."""
    value = json.loads(files.regular(config))
    files.require(isinstance(value, dict) and set(value) == {'schema', 'enabled', 'site', 'stack', 'discovery_previous_guests'}
                  and value['schema'] == 'homelab-automation-deployment-v1' and value['enabled'] is True,
                  'Use the closed automation deployment configuration')
    cfg, stack = value['site'], value['stack']
    expected = cfg['app'].get('prerequisite_packet_sha256')
    files.require(isinstance(expected,str) and len(expected) == 64
                  and all(c in '0123456789abcdef' for c in expected),
                  'Enabled automation requires the exact reviewed prerequisite digest')
    files.require(cfg['app']['kind'] == stack['kind'] == 'automation'
                  and cfg['app']['stack_config'] == str(destination / 'stack.json')
                  and set(stack['services']) == set(SERVICES),
                  'The automation stack and private path must select the same three services')
    environment = os.environ if environment is None else environment
    secret = environment.get('NODE_RED_API_TOKEN')
    files.require(isinstance(secret, str) and 0 < len(secret.encode()) <= 65536
                  and secret.strip() and not any(c in secret for c in '\r\n\x00'),
                  'Supply the existing Node-RED API token through GitHub Secrets')
    env = stack['services']['node_red'].setdefault('environment', {})
    files.require('NODE_RED_API_TOKEN' not in env, 'Do not store the Node-RED API token in Git')
    env['NODE_RED_API_TOKEN'] = secret
    payload = {'site.json': files.encoded(cfg), 'stack.json': files.encoded(stack)}
    manifest = {'schema': value['schema'], 'config_sha256': files.digest(files.regular(config)),
                'files': {key: files.digest(data) for key, data in payload.items()}}
    files.private_directory(destination.parent)
    # Guest setup creates this once. Later app steps only compare the complete
    # immutable bundle; neither can fill an interrupted preparation's gaps.
    if destination.exists() or destination.is_symlink():
        files.private_directory(destination)
        files.require({p.name for p in destination.iterdir()} == set(payload) | {'prepared.json'}
                      and files.regular(destination / 'prepared.json', private=True) == files.encoded(manifest)
                      and all(files.regular(destination / key, private=True) == data for key, data in payload.items()),
                      'Automation inputs changed or are incomplete; preserve them for review')
    else:
        files.private_directory(destination, create=True)
        for key, data in payload.items():
            files.write_new(destination / key, data)
        deploy.validate(cfg)
        files.write_new(destination / 'prepared.json', files.encoded(manifest))
    return cfg, destination / 'site.json'


def prerequisites(cfg, packet_path, oidc=None):
    """The actual guest cannot be created or started by skipping its CD prerequisites."""
    expected=cfg['app'].get('prerequisite_packet_sha256')
    files.require(isinstance(expected,str) and len(expected) == 64 and packet_path is not None
                  and deploy.sha(packet_path) == expected,
                  'Supply the exact reviewed automation prerequisite packet')
    import automation_maintenance
    packet=json.loads(files.regular(packet_path));automation_maintenance.validate(packet)
    if oidc is not None:
        selected=packet['identity']['oidc']
        files.require(selected['client_id'] == oidc['client_id'] and selected['slug'] == oidc['provider_slug']
                      and selected['callback'] == oidc['node_red_url'].rstrip('/') + '/auth/strategy/callback/',
                      'The completed OIDC prerequisite must match the selected native client and routed callback')
    # Discovery already requires each origin to select an interface on this
    # guest. Its exact addresses and ports must also match this prerequisite.
    deploy.discovery.labels(cfg)
    routes=cfg['app'].get('discovery_routes',[])
    required={(urlsplit(row['url']).hostname,urlsplit(row['url']).port or 80) for row in routes}
    admitted={(row['destination'].removesuffix('/32'),int(port))
              for row in packet['ingress']['additions'] for port in row['port'].split(',')}
    files.require(required and admitted == required,
                  'Ingress prerequisite must match this automation guest backend and service ports')
    for phase in ('ingress','identity'):
        row=packet[phase];work=Path(cfg['paths']['state_root'])/str(row['vmid'])
        receipt=work/'automation-200-prerequisite/complete.json'
        result=json.loads(files.regular(receipt,private=True))
        nas=Path(cfg['paths']['backup_directory'])/str(row['vmid'])/'automation-200-complete.json'
        files.require(result['binding'] == {'packet':row,'maintenance_source_sha256':automation_maintenance.source_hash()}
                      and result['state_sha256'] == deploy.sha(work/'terraform.tfstate')
                      and files.regular(nas,private=True) == files.regular(receipt,private=True)
                      and not any((work/name).exists() or (work/name).is_symlink() for name in files.HOLDS),
                      'The selected prerequisite is incomplete, changed or held')


def run(phase, config, destination=INPUTS, environment=None, deployment=deploy, maintenance=None):
    """A merged packet creates once; subsequent unchanged jobs only read back."""
    files.require(phase in ('guest', *SERVICES), 'Select guest setup or one automation service')
    cfg, site = prepare_inputs(config, destination, environment)
    prerequisites(cfg,maintenance)
    vmid = deployment.validate(cfg)
    work = Path(cfg['paths']['state_root']) / str(vmid)
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    if phase != 'guest':
        files.require(not any((work / name).exists() for name in HOLDS),
                      'The automation guest has an unresolved operation; no replay')
        return deployment.automation_service(site, phase)
    with (work / 'automation-cd.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        files.require(not any((work / name).exists() for name in HOLDS),
                      'The automation guest has an unresolved operation; no replay')
        if (work / 'prepare-complete.json').exists():
            deployment.automation_binding(cfg, site, work)
            return {'status': 'passed', 'vmid': vmid, 'step': 'guest', 'already_prepared': True}
        files.require(not any((work / name).exists() for name in
                              ('terraform.tfstate', 'applied.json', 'plan.json', 'guest.tfplan', 'started.json')),
                      'Existing automation state needs review; no adoption or automatic continuation')
        # Validate preserved image availability before the first guest creation.
        # The Ansible loader independently checks the uploaded bytes and image ID.
        import render
        stack = json.loads(files.regular(destination / 'stack.json', private=True))
        render.compose(stack)
        for service in stack['services'].values():
            if 'archive' in service:
                archive = Path(service['archive'])
                files.require(archive.is_file() and not archive.is_symlink()
                              and deployment.sha(archive) == service['archive_sha256'],
                              'A preserved original image archive is missing or differs')
        hold = work / 'AUTOMATION-CD-HOLD.json'
        marker = {'phase': 'guest', 'vmid': vmid, 'source_sha256': deployment.source_hash(),
                  'config_sha256': files.digest(files.regular(config)), 'automatic_retry': False}
        files.write_new(hold, files.encoded(marker))
        plan = deployment.execute('plan', site)
        deployment.check_merge_create_plan(json.loads(files.regular(work / 'guest.tfplan.json', private=True)),
                                           cfg['site']['node'], vmid)
        result = deployment.execute('prepare', site, plan['plan_sha256'])
        files.require(result.get('status') == 'passed' and result.get('vmid') == vmid
                      and json.loads(files.regular(hold, private=True)) == marker,
                      'Automation guest preparation or hold ownership differs')
        hold.unlink(); files.sync(work)
        return result


def ordinary(phase, config, maintenance, foundation=None):
    """The permanent job uses common reconciliation; migration remains separate."""
    import copy
    import tempfile
    import ordinary_cd
    value = json.loads(files.regular(config))
    files.require(set(value) == {'schema','enabled','site','stack','discovery_previous_guests'}
                  and value['schema'] == 'homelab-automation-deployment-v1' and value['enabled'] is True,
                  'Explicitly review and enable the prepared automation configuration')
    files.require(foundation is not None, 'Bind ordinary automation to its commissioned foundation configuration')
    import automation_configuration
    automation_configuration.compile_config(automation_configuration.site_config.read(foundation), value)
    cfg, stack = copy.deepcopy(value['site']), copy.deepcopy(value['stack'])
    files.require(cfg['app']['kind'] == stack['kind'] == 'automation'
                  and cfg['app'].get('exclusive_writer_confirmed') is True,
                  'Confirm the exact automation writer window')
    prerequisites(cfg, maintenance, stack.get('node_red_oidc'))
    # The selected capture remains migration provenance in the private source;
    # ordinary deployment neither reads it nor restores it.
    cfg['app'].pop('capture',None)
    identity = files.digest(files.encoded({'site':cfg,'stack':stack}))
    cfg['app']['stack_config'] = str(Path('/var/lib/homelab-inputs/ordinary/automation')/identity/'stack.json')
    packet = {'schema':'homelab-ordinary-deployment-v1','enabled':True,'kind':'automation','identity':identity,
              'files':{'site.json':files.encoded(cfg).decode(),'stack.json':files.encoded(stack).decode()}}
    with tempfile.TemporaryDirectory(prefix='automation-ordinary-') as temp:
        path=Path(temp)/'packet.json';files.write_new(path,files.encoded(packet))
        return ordinary_cd.run('infrastructure' if phase == 'guest' else phase,path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=('guest', *SERVICES))
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--maintenance',type=Path)
    parser.add_argument('--ordinary',action='store_true',help='Permanent no-restore deployment path')
    parser.add_argument('--foundation',type=Path,help='Commissioned foundation inputs for ordinary automation')
    args = parser.parse_args()
    try:
        print(json.dumps(ordinary(args.phase,args.config,args.maintenance,args.foundation) if args.ordinary else
                         run(args.phase,args.config,maintenance=args.maintenance)))
    except deploy.InputNeeded as error:
        raise SystemExit(str(error)) from None
    except (OSError, ValueError, KeyError, deploy.subprocess.CalledProcessError) as error:
        raise SystemExit(f'Automation deployment held ({type(error).__name__}); inspect private phase receipts') from None
