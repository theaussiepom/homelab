"""One operator USB attachment between stopped creation and ordinary runner CD.

Pure checks are shared by synthetic tests. Host functions run only through the
separate pinned operator connection; the runner calls only read-only API checks.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from urllib.parse import quote

RESOURCE = 'module.guest.proxmox_virtual_environment_container.guest'


def desired(cfg):
    """Return the exact provider device declaration, including its defaults."""
    return dict(path=cfg['guest']['serial_device']['path'],uid=0,gid=20,mode='0660',deny_write=False)


def stage(cfg):
    """Require the deliberate radio stage; never infer it from a failed apply."""
    selected=cfg['app'].get('usb_stage')
    if selected not in {'prepare','attached'}:
        raise ValueError('Select Zigbee usb_stage prepare or attached explicitly')
    return selected


def guest_variables(cfg):
    """Create stopped without USB; later plans retain the declared device."""
    guest=copy.deepcopy(cfg['guest'])
    if cfg['app'].get('kind')=='zigbee2mqtt' and stage(cfg)=='prepare':
        guest.update(serial_device=None,started=False,start_on_boot=False)
    return guest


def check_plan(value,cfg):
    """Never let a runner apply add, remove or alter an LXC devN field."""
    rows=[r for r in value['resource_changes'] if r['address']==RESOURCE]
    if len(rows)!=1:raise ValueError('Require one selected radio guest in the plan')
    change=rows[0]['change'];before=change.get('before');after=change.get('after') or {}
    if has_unknown(change.get('after_unknown',{}).get('device_passthrough')):
        raise ValueError('The radio plan must not contain unknown device fields')
    if stage(cfg)=='prepare':
        if (change['actions']!=['create'] or before is not None or
                after.get('device_passthrough') not in (None,[]) or
                after.get('started') is not False or after.get('start_on_boot') is not False):
            raise ValueError('USB preparation permits only a new stopped guest without devices or autostart')
    else:
        expected=[desired(cfg)]
        if (not isinstance(before,dict) or change['actions'] not in (['update'],['no-op']) or
                before.get('device_passthrough')!=expected or after.get('device_passthrough')!=expected):
            raise ValueError('The attached-device plan must preserve the exact device without a devN write')


def has_unknown(value):
    """OpenTofu can encode fully known nested blocks as lists of empty maps."""
    if isinstance(value,dict):return any(has_unknown(v) for v in value.values())
    if isinstance(value,list):return any(has_unknown(v) for v in value)
    return value is True


def parse_device(value):
    """Normalize only PVE's documented option order and omitted defaults."""
    if not isinstance(value,str):raise ValueError('Require one literal PVE device declaration')
    items={}
    for item in value.split(','):
        key,sep,val=item.partition('=')
        if not sep:key,val='path',key
        if key in items:raise ValueError('Duplicate device option')
        items[key]=val
    if set(items)-{'path','uid','gid','mode','deny-write'}:raise ValueError('Unexpected device option')
    return {'path':items.get('path'),'uid':int(items.get('uid',0)),
            'gid':int(items.get('gid',0)),'mode':items.get('mode','0660'),
            'deny_write':int(items.get('deny-write',0))!=0}


def check_guest(config,hostname):
    """Preserve the protected unprivileged guest and its default ID mapping."""
    if (config.get('hostname')!=hostname or config.get('unprivileged') not in (1,True) or
            config.get('protection') not in (1,True) or config.get('lock') or
            config.get('lxc') or any(k.startswith('lxc.') for k in config)):
        raise ValueError('Require the exact protected unprivileged guest, no lock or custom LXC overrides')


def read_live(cfg,api_get):
    """Read only the selected guest's config and runtime status with runner TLS."""
    path='/nodes/'+quote(cfg['site']['node'],safe='')+'/lxc/'+str(cfg['guest']['vmid'])
    return api_get(cfg,path+'/config'),api_get(cfg,path+'/status/current')


def verify_live(cfg,api_get):
    """Hold device/ownership drift; this does not open or qualify the USB radio."""
    config,status=read_live(cfg,api_get)
    check_guest(config,cfg['guest']['hostname'])
    devices={k:v for k,v in config.items() if re.fullmatch(r'dev\d+',k)}
    if set(devices)!={'dev0'} or parse_device(devices['dev0'])!=desired(cfg):
        raise ValueError('Read back exactly the operator-attached coordinator and its ownership before continuing')
    if status.get('status') not in {'stopped','running'}:raise ValueError('Guest runtime state is unknown')
    return {'device':desired(cfg),'status':status['status']}


def prepared_receipt(cfg,state):
    """Keep the runner's state identity across the external attachment."""
    value=json.loads(Path(state).read_text())
    if (not isinstance(value.get('lineage'),str) or not value['lineage'] or
            type(value.get('serial')) is not int or value['serial']<0):
        raise ValueError('Preserve the existing runner state lineage and serial')
    return {'node':cfg['site']['node'],'vmid':cfg['guest']['vmid'],'device':desired(cfg),
            'lineage':value['lineage'],'serial':value['serial']}


def require_prepared(cfg,work):
    """Do not adopt a guest from a workstation state copy or unrelated lineage."""
    previous=json.loads((work/'usb-prepared.json').read_text())
    current=prepared_receipt(cfg,work/'terraform.tfstate')
    if (current['serial']<previous['serial'] or
            {k:v for k,v in current.items() if k!='serial'}!={k:v for k,v in previous.items() if k!='serial'}):
        raise ValueError('The radio must retain its original runner-owned state and exact device identity')


def validate_request(request):
    """Admit one separately approved host action; never a general device grant."""
    if (set(request)!={'node','vmid','hostname','path','exclusive_writer_confirmed','native_action_approved'} or
            any(not isinstance(request[k],str) for k in ('node','hostname','path')) or
            not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]*',str(request['node'])) or
            type(request['vmid']) is not int or request['vmid']<100 or request['vmid'] in {900,4914,4915,4920} or
            not re.fullmatch(r'[a-z][a-z0-9-]{0,62}',str(request['hostname'])) or
            not re.fullmatch(r'/dev/serial/by-id/usb-[A-Za-z0-9_-]+',str(request['path'])) or
            request['native_action_approved'] is not True or type(request['exclusive_writer_confirmed']) is not bool):
        raise ValueError('Review the exact radio guest, stable USB identity and native action first')


def command(args):
    """Run one bounded host command, with no shell or credential output."""
    result=subprocess.run(args,capture_output=True,text=True,timeout=30)
    if result.returncode or len(result.stdout)>1048576:
        raise ValueError('Host USB command was not confirmed; retain the operator hold and logs')
    return result.stdout


def describe_device(path):
    """Stat the selected by-id target; never open the character device."""
    target=Path(path).resolve(strict=True);info=target.stat()
    if target.parent!=Path('/dev') or not stat.S_ISCHR(info.st_mode):
        raise ValueError('The selected USB by-id must resolve to one /dev character device')
    return {'resolved':str(target),'major':os.major(info.st_rdev),'minor':os.minor(info.st_rdev),
            'uid':info.st_uid,'gid':info.st_gid,'mode':format(stat.S_IMODE(info.st_mode),'04o')}


def host_plan(request,run=command,device=describe_device):
    """Plan only the exact attachment, binding fresh config and device metadata."""
    validate_request(request)
    path='/nodes/'+request['node']+'/lxc/'+str(request['vmid'])
    config=json.loads(run(['pvesh','get',path+'/config','--output-format','json']))
    status=json.loads(run(['pvesh','get',path+'/status/current','--output-format','json']))
    check_guest(config,request['hostname'])
    if status.get('status')!='stopped':raise ValueError('The radio guest must remain stopped during USB attachment')
    if not re.fullmatch(r'[0-9a-f]{40}',config.get('digest','')):raise ValueError('Bind the current PVE config digest')
    devices={k:v for k,v in config.items() if re.fullmatch(r'dev\d+',k)}
    expected={'path':request['path'],'uid':0,'gid':20,'mode':'0660','deny_write':False}
    if devices and (set(devices)!={'dev0'} or parse_device(devices['dev0'])!=expected):
        raise ValueError('Existing device configuration differs; no replacement or additional device')
    plan={'request':request,'config':config,'device':device(request['path']),
          'action':'already-attached' if devices else 'attach-dev0','guest_stays_stopped':True,
          'protection_changed':False}
    return dict(plan,plan_sha256=hashlib.sha256(json.dumps(plan,sort_keys=True).encode()).hexdigest())


def host_apply(request,approved,run=command,device=describe_device):
    """Attach once with PVE's config digest guard; refuse drift and preserve peers."""
    plan=host_plan(request,run,device)
    if plan['plan_sha256']!=approved:raise ValueError('The reviewed USB plan changed; no host edit was made')
    if request['exclusive_writer_confirmed'] is not True:raise ValueError('Retire the old writer in the separately approved window first')
    if plan['action']=='attach-dev0':
        binding='path='+request['path']+',uid=0,gid=20,mode=0660,deny-write=0'
        path='/nodes/'+request['node']+'/lxc/'+str(request['vmid'])+'/config'
        run(['pvesh','set',path,'--dev0',binding,'--digest',plan['config']['digest']])
    after=host_plan(request,run,device)
    if after['action']!='already-attached':raise ValueError('USB attachment readback failed')
    before_config={k:v for k,v in plan['config'].items() if k not in {'digest','dev0'}}
    after_config={k:v for k,v in after['config'].items() if k not in {'digest','dev0'}}
    if before_config!=after_config or plan['device']!=after['device']:
        raise ValueError('Other guest config or the selected physical device changed; preserve the hold')
    return {'status':'attached','vmid':request['vmid'],'node':request['node'],
            'device':request['path'],'guest_stays_stopped':True,'protection_changed':False,
            'native_radio_qualified':False,'runner_refresh_required':True}
