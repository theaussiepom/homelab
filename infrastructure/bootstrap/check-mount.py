#!/usr/bin/env python3
from pathlib import Path
import argparse
import json
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from homelab.core import Refusal, read_json
from homelab.mounts import check_mount, observe_mount
p=argparse.ArgumentParser();p.add_argument('--contract',type=Path,required=True);a=p.parse_args()
try:
    expected=read_json(a.contract)
    print(json.dumps(check_mount(expected,observe_mount(expected))))
except (Refusal,OSError,ValueError,KeyError,TypeError) as exc:
    print(json.dumps({'refused':True,'reason':str(exc) if isinstance(exc,Refusal) else 'invalid/missing mount metadata'}),file=sys.stderr)
    raise SystemExit(3)
