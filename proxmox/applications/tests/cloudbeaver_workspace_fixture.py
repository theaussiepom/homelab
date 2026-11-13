"""Disposable Linux ownership proof; run only in the existing networkless test image."""
import importlib.util
import json
import os
from pathlib import Path
import stat

SOURCE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('workspace_under_test',SOURCE/'cloudbeaver-runtime.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
assert os.geteuid()==0 and not r.WORKSPACE.exists() and not r.CUSTODY.exists()
r.WORKSPACE.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
owner={'node':'fixture-pve','vmid':808,'hostname':'database-tools'}
r.workspace(owner)
metadata=r.WORKSPACE.stat();assert(metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))==(8978,8978,0o700)
receipt=r.CUSTODY/'workspace.json';before=receipt.read_bytes();assert(receipt.stat().st_uid,stat.S_IMODE(receipt.stat().st_mode))==(0,0o600)
r.workspace(owner);assert receipt.read_bytes()==before
r.PERMISSIONS.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
r.create(r.PERMISSIONS,{'postgresql':['user']},uid=8978,mode=0o400)
config={'workspace':str(r.WORKSPACE),'project':'homelab-db-tools',
        'connections':{'postgresql':{}}};r.templates(config)
permissions=r.WORKSPACE/'GlobalConfiguration/.dbeaver/data-sources-permissions.json'
assert(permissions.stat().st_uid,permissions.stat().st_gid,stat.S_IMODE(permissions.stat().st_mode))==(8978,8978,0o400)
value=json.loads(permissions.read_text());value['custom']=['another-user'];permissions.write_text(json.dumps(value))
before=permissions.read_bytes();r.templates(config);assert permissions.read_bytes()==before
value['postgresql']=['admin'];permissions.write_text(json.dumps(value));before=permissions.read_bytes()
try:r.templates(config)
except ValueError:pass
else:raise AssertionError('unexpected managed grants accepted')
assert permissions.read_bytes()==before
try:r.workspace(dict(owner,vmid=809))
except ValueError:pass
else:raise AssertionError('foreign workspace owner accepted')
link=r.CUSTODY/'hardlink.json';os.link(receipt,link)
try:r.private(receipt)
except ValueError:pass
else:raise AssertionError('hardlinked custody accepted')
print(json.dumps({'linux_workspace':'passed','actual_uid_gid_mode':True,'create_only_receipts':True,
                  'custom_permissions_preserved':True,'unexpected_managed_grant_refused':True,'hardlink_refused':True}))
