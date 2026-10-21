from pathlib import Path
import copy
import json
import os
import subprocess
import sys

import pytest
import yaml

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from homelab import core
from homelab.mounts import check_mount


def test_public_ci_cannot_choose_private_runner_or_privileged_pr_context():
    workflow=yaml.load((core.ROOT/'.github/workflows/ci.yml').read_text(),Loader=yaml.BaseLoader)
    assert 'pull_request_target' not in workflow['on']
    assert workflow['permissions']=={'contents':'read'}
    assert workflow['jobs']['validate']['runs-on']=='ubuntu-24.04'
    for step in workflow['jobs']['validate']['steps']:
        if 'uses' in step:
            assert len(step['uses'].split('@')[1])==40
        assert '${{ secrets.' not in json.dumps(step)
    assert ' bin/homelab ' in (core.ROOT/'.github/workflows/ci.yml').read_text()


def test_fleet_only_site_runs_through_the_same_executor(tmp_path):
    d=core.read_json(core.ROOT/'examples/site/catalog/site.json');d['guests']=[]
    assert core.synthetic_plan(d,tmp_path)['changes']==3
    core.synthetic_approve(d,tmp_path)
    core.synthetic_apply(d,tmp_path)
    assert core.synthetic_verify(d,tmp_path)['verified']


@pytest.mark.parametrize('field,value',[
    ('source','wrong-export'),('target','/empty-parent'),('fstype','ext4'),
    ('uuid','wrong'),('is_mountpoint',False),('is_symlink',True),('uid',999),('gid',999),
])
def test_wrong_mount_or_owner_refuses_without_fallback(field,value):
    expected={'target':'/srv/example','source':'example-pool/managed-volume','fstype':'zfs','uuid':'fixture-uuid','uid':1000,'gid':1000}
    observed=expected|{'is_mountpoint':True,'is_symlink':False};observed[field]=value
    with pytest.raises(core.Refusal):check_mount(expected,observed)


def test_exact_mount_check_grants_no_application_or_ownership_action():
    expected={'target':'/srv/example','source':'example-pool/managed-volume','fstype':'zfs','uuid':None,'uid':1000,'gid':1000}
    assert check_mount(expected,expected|{'is_mountpoint':True,'is_symlink':False})=={'mount_verified':True,'ownership_changed':False,'application_acceptance':False}


def test_ansible_prepare_defaults_hold_on_local_synthetic_host(tmp_path):
    executable=Path(sys.executable).parent/'ansible-playbook'
    if not executable.exists():pytest.skip('Ansible is not installed in this Python environment')
    inventory={'all':{'children':{'pve_guests':{'hosts':{'synthetic-local':{'ansible_connection':'local','ansible_become':False}}}}}}
    p=tmp_path/'inventory.json';p.write_text(json.dumps(inventory))
    cwd=core.ROOT/'ansible';env=os.environ.copy();env['ANSIBLE_CONFIG']=str(cwd/'ansible.cfg');env['ANSIBLE_LOCAL_TEMP']=str(tmp_path/'ansible-tmp');env['ANSIBLE_ROLES_PATH']=str(cwd/'roles')
    result=subprocess.run([str(executable),'-i',str(p),'--check','playbooks/prepare.yml'],cwd=cwd,env=env,capture_output=True,text=True,timeout=45)
    assert result.returncode!=0
    assert 'Target preparation is held' in result.stdout
    assert 'changed=0' in result.stdout


def test_ansible_verify_rejects_missing_identity_manifest(tmp_path):
    executable=Path(sys.executable).parent/'ansible-playbook'
    if not executable.exists():pytest.skip('Ansible is not installed in this Python environment')
    inventory={'all':{'children':{'pve_guests':{'hosts':{'synthetic-local':{'ansible_connection':'local','ansible_become':False}}}}}}
    p=tmp_path/'inventory.json';p.write_text(json.dumps(inventory));cwd=core.ROOT/'ansible';env=os.environ.copy();env['ANSIBLE_CONFIG']=str(cwd/'ansible.cfg');env['ANSIBLE_LOCAL_TEMP']=str(tmp_path/'ansible-tmp');env['ANSIBLE_ROLES_PATH']=str(cwd/'roles')
    result=subprocess.run([str(executable),'-i',str(p),'--check','playbooks/verify.yml'],cwd=cwd,env=env,capture_output=True,text=True,timeout=45)
    assert result.returncode!=0 and 'I08 identity manifest' in result.stdout
    assert 'changed=0' in result.stdout
