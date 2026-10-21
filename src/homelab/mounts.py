"""Exact observed mount identity guard; no mount/init/chown fallback."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
from .core import Refusal


def check_mount(expected: dict, observed: dict) -> dict:
    for key in ('target','source','fstype'):
        if not isinstance(expected.get(key),str) or not expected[key]:
            raise Refusal('mount contract has unresolved identity')
        if observed.get(key) != expected[key]:
            raise Refusal('exact mount identity mismatch; activation held')
    if expected.get('uuid') is not None and observed.get('uuid') != expected['uuid']:
        raise Refusal('mount UUID mismatch')
    if observed.get('is_mountpoint') is not True or observed.get('is_symlink') is not False:
        raise Refusal('missing mount or symlink; no empty-directory fallback')
    for key in ('uid','gid'):
        if type(expected.get(key)) is not int or observed.get(key) != expected[key]:
            raise Refusal('mount owner differs; no ownership repair')
    return {'mount_verified':True,'ownership_changed':False,'application_acceptance':False}


def observe_mount(expected: dict) -> dict:
    path = Path(expected['target'])
    if not path.is_absolute() or '..' in path.parts or path.is_symlink():
        raise Refusal('unsafe mount path')
    p = subprocess.run(['findmnt','--json','--mountpoint',str(path),'--output','TARGET,SOURCE,FSTYPE,UUID'],capture_output=True,text=True,timeout=10)
    if p.returncode != 0:
        raise Refusal('required mount absent or unreadable')
    rows = json.loads(p.stdout).get('filesystems',[])
    if len(rows) != 1:
        raise Refusal('ambiguous mount observation')
    st = path.stat()
    return rows[0] | {'uid':st.st_uid,'gid':st.st_gid,'is_mountpoint':True,'is_symlink':False}
