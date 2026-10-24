#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT=Path('/work')


def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(8*1024**2),b''):digest.update(block)
    return digest.hexdigest()


def records(path):
    result=set()
    with path.open('rb') as stream:
        for line in stream:
            if line==b'# START OF DATA - DO NOT MODIFY\n':break
            if line.startswith(b'#') or not line.strip():continue
            row=line.rstrip(b'\n')
            match=re.fullmatch(rb'(.*) R ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)',row)
            if match:row=b' '.join(match.groups()[:6]+match.groups()[7:])
            result.add(row)
    return result


with tempfile.TemporaryDirectory(prefix='homelab-metadata-') as temp:
    exported=Path(temp)/'modified.pseudo'
    image=ROOT/'build/single-usb-production/pve-installer.squashfs'
    subprocess.run(['unsquashfs','-processors','1','-pf',str(exported),str(image)],check=True,capture_output=True)
    original=records(ROOT/'build/vendor-files.pseudo');modified=records(exported)
    removed=sorted(x.decode(errors='replace') for x in original-modified)
    added=sorted(x.decode(errors='replace') for x in modified-original)
    success=len(removed)==len(added)==1 and all(x.startswith('usr/sbin/unconfigured.sh ') for x in removed+added)
    receipt={'all_other_vendor_metadata_preserved':success,'modified_squashfs_sha256':sha(image),'unchanged_records':len(original&modified),'removed':removed,'added':added,'scope':'all exported ownership/mode/timestamp/hardlink/symlink/xattr metadata; regular-file data offsets ignored'}
    (ROOT/'evidence/final-metadata-verification.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))
    if not success:raise ValueError('unexpected vendor metadata change')
