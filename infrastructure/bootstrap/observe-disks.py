#!/usr/bin/env python3
"""Read-only Linux disk/by-id observation for the separate exact-disk guard."""
import json
import os
from pathlib import Path
import subprocess

result = subprocess.run(['lsblk','--json','--bytes','--nodeps','-o','PATH,TYPE,SIZE,SERIAL,RO'],capture_output=True,text=True,check=True,timeout=10)
devices = json.loads(result.stdout)['blockdevices']
aliases = Path('/dev/disk/by-id')
observed = []
for disk in devices:
    if disk['type'] != 'disk':
        continue
    for alias in aliases.iterdir():
        if '-part' not in alias.name and os.path.realpath(alias) == disk['path']:
            observed.append({'by_id':str(alias),'serial':disk['serial'],'size_bytes':int(disk['size']),'read_only':bool(disk['ro'])})
print(json.dumps(observed,sort_keys=True))
