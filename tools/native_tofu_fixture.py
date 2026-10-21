#!/usr/bin/env python3
"""Local built-in terraform_data encryption fixture. Never configures PVE/S3."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--tofu', type=Path, required=True)
parser.add_argument('--work', type=Path, required=True)
args = parser.parse_args()
args.work.mkdir(parents=True, exist_ok=False, mode=0o700)
args.tofu = args.tofu.resolve()
source = Path(__file__).resolve().parents[1]
encryption = (source / 'infrastructure/proxmox/foundation/encryption.tf').read_text()
(args.work / 'main.tf').write_text(encryption + '''
terraform { required_version = "= 1.13.1" }
resource "terraform_data" "fixture" { input = "synthetic-private-marker-314159" }
output "fixture_value" { value = terraform_data.fixture.output }
''')
env = {k:v for k,v in os.environ.items() if not k.startswith(('TF_','TOFU_','AWS_','PROXMOX_'))}
key = secrets.token_urlsafe(48)
env['TF_VAR_state_passphrase'] = key
env['TF_IN_AUTOMATION'] = '1'
checks = []
def run(label, cmd, use_env=env, expect=0):
    p = subprocess.run([str(args.tofu),f'-chdir={args.work.resolve()}',*cmd],env=use_env,capture_output=True,text=True,timeout=120)
    ok = p.returncode == expect if expect == 0 else p.returncode != 0
    checks.append({'check':label,'passed':ok,'exit_code':p.returncode})
    if not ok:
        (args.work / 'failure.log').write_text(p.stdout+p.stderr)
        raise SystemExit(json.dumps({'failed':label,'private_log':str(args.work/'failure.log')}))
    return p
run('builtin-only-init',['init','-input=false','-no-color'])
run('encrypted-plan',['plan','-input=false','-no-color','-out=fixture.plan'])
show_plan=run('plan-roundtrip',['show','-json','fixture.plan'])
plan=json.loads(show_plan.stdout)
run('apply-local-builtin-fixture',['apply','-input=false','-no-color','fixture.plan'])
shown=run('state-roundtrip',['show','-json'])
state=json.loads(shown.stdout)
value = state.get('values', {}).get('outputs', {}).get('fixture_value', {}).get('value')
checks.append({'check': 'state-output-roundtrip', 'passed': value == 'synthetic-private-marker-314159'})
for name in ['terraform.tfstate','fixture.plan']:
    data=(args.work/name).read_bytes()
    checks.append({'check':name+'-no-plaintext-marker','passed':b'synthetic-private-marker-314159' not in data})
wrong=env|{'TF_VAR_state_passphrase':secrets.token_urlsafe(48)}
run('wrong-key-refused',['show','-json'],use_env=wrong,expect=1)
missing={k:v for k,v in env.items() if k!='TF_VAR_state_passphrase'}
run('missing-key-refused',['show','-json'],use_env=missing,expect=1)
result={'target':'local_builtin_fixture','checks':checks,'all_passed':all(c['passed'] for c in checks),'tofu_plan_format':plan.get('format_version'),'PVE_contacted':False,'R2_locking_or_recovery_tested':False,'production_authority':False}
(args.work/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
if not result['all_passed']:
    raise SystemExit(1)
