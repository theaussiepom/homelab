"""A fixture receipt reporting failed checks must also fail the command."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('failure', ['none', 'plaintext', 'roundtrip'])
@pytest.mark.parametrize('optimized', [False, True])
def test_native_fixture_failure_exit(tmp_path, failure, optimized):
    fake = tmp_path/'tofu'
    fake.write_text('#!' + sys.executable + '\n' + '''
import json,os,pathlib,sys
work=pathlib.Path(sys.argv[1].split('=',1)[1]);command=sys.argv[2]
key=work/'test-key'
if command=='init':key.write_text(os.environ['TF_VAR_state_passphrase'])
if command=='show' and os.environ.get('TF_VAR_state_passphrase')!=key.read_text():sys.exit(1)
marker='synthetic-private-marker-314159'
if command in ('plan','apply'):
    name='fixture.plan' if command=='plan' else 'terraform.tfstate'
    (work/name).write_text(marker if os.environ['FIXTURE_FAILURE']=='plaintext' else 'ciphertext')
if command=='show':
    value='wrong' if os.environ['FIXTURE_FAILURE']=='roundtrip' else marker
    print(json.dumps({'format_version':'1.2','values':{'outputs':{'fixture_value':{'value':value}}}}))
''')
    fake.chmod(0o700)
    work = tmp_path/'work'
    argv = [sys.executable] + (['-O'] if optimized else []) + [str(ROOT/'tools/native_tofu_fixture.py'), '--tofu', str(fake), '--work', str(work)]
    result = subprocess.run(argv, env=dict(os.environ,FIXTURE_FAILURE=failure),capture_output=True,text=True,timeout=15)
    receipt = json.loads((work/'receipt.json').read_text())
    assert receipt['all_passed'] is (failure=='none')
    assert (result.returncode==0) is (failure=='none')
