"""Infrastructure client for bootstrap's generic restricted NFS attachment key."""
import hashlib
import os
from pathlib import Path
from urllib.parse import urlsplit

import nfs_host_helper as helper
from commands import quiet
from private_io import private_directory, regular, require


def attach(cfg, mounts, operation, api_get):
    selected = cfg['guest']['recording_mount']
    base = '/nodes/' + cfg['site']['node'] + '/lxc/' + str(cfg['guest']['vmid'])
    current = api_get(base + '/config?current=1')
    import backup_staging
    for slot, row in enumerate(mounts[:-1]):
        backup_staging.native_row(current.get('mp'+str(slot)), row)
    request = helper.validate({'schema':helper.SCHEMA,'node':cfg['site']['node'],
        'vmid':cfg['guest']['vmid'],'hostname':cfg['guest']['hostname'],'mac':cfg['app']['mac'].lower(),
        'mount':selected,'rootfs':current['rootfs'],
        'mounts':{'mp'+str(i):current['mp'+str(i)] for i in range(selected['slot'])}})
    key, hosts = (Path(cfg['paths'][name]) for name in ('host_nfs_key','host_nfs_known_hosts'))
    for path in (key, hosts):
        private_directory(path.parent)
        regular(path, private=True)
    host = urlsplit(cfg['site']['api_endpoint']).hostname
    require(host and not host.startswith('-'), 'Use the selected host endpoint')
    argv = ['ssh','-F','/dev/null','-T','-i',str(key),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
        '-o','IdentitiesOnly=yes','-o','ControlMaster=no','-o','ClearAllForwardings=yes',
        '-o','GlobalKnownHostsFile=/dev/null','-o','VerifyHostKeyDNS=no','-o','UpdateHostKeys=no',
        '-o','UserKnownHostsFile='+str(hosts),'-o','ConnectTimeout=10','root@'+host,'attach']
    log = operation/'nfs-attachment.json'
    require(not log.exists() and not log.is_symlink(), 'Preserve prior attachment evidence; never replay')
    quiet(argv,os.environ.copy(),log,input_bytes=helper.encoded(request),timeout=180)
    result = helper.decode(regular(log,private=True,limit=4096))
    require(type(result) is dict and set(result) == {'schema','vmid','request_sha256','helper_sha256','changed'}
        and result['schema'] == helper.SCHEMA and result['vmid'] == request['vmid']
        and result['request_sha256'] == hashlib.sha256(helper.encoded(request)).hexdigest()
        and result['helper_sha256'] == helper.implementation_digest() and type(result['changed']) is bool,
        'Require the exact installed attachment implementation and request')
    return result['changed']
