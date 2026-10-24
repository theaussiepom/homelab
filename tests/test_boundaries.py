from pathlib import Path
import copy
import json
import os
import re
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


def test_iso_ci_reuses_docker_commands_and_uploads_only_bounded_test_evidence(tmp_path):
    ci=yaml.load((core.ROOT/'.github/workflows/ci.yml').read_text(),Loader=yaml.BaseLoader)
    unit=ci['jobs']['iso-unit']
    assert unit['runs-on']=='ubuntu-24.04'
    assert unit['defaults']['run']['working-directory']=='proxmox/iso'
    assert any(step.get('run')=='make tools init unit' for step in unit['steps'])
    qualification=yaml.load((core.ROOT/'.github/workflows/proxmox-iso.yml').read_text(),Loader=yaml.BaseLoader)
    assert qualification['permissions']=={'contents':'read'}
    assert set(qualification['on'])=={'pull_request','push','workflow_dispatch'}
    for event in ('pull_request','push'):
        assert 'proxmox/iso/**' in qualification['on'][event]['paths']
        assert '.github/workflows/proxmox-iso.yml' in qualification['on'][event]['paths']
    job=qualification['jobs']['build-and-boot']
    assert job['runs-on']=='ubuntu-24.04'
    assert job['strategy']['matrix']['profile']==['fixture','integration']
    runs=[step.get('run','') for step in job['steps']]
    assert 'make fetch fixture test-boot' in runs
    assert 'make fetch build test-profile' in runs
    # Exercise the actual CI input generator in a fresh temporary checkout.
    generator=next(step['run'] for step in job['steps'] if step.get('name')=='Create invented integration inputs')
    assert generator.startswith("python3 - <<'PY'\n") and generator.endswith('\nPY\n')
    source=generator.split('\n',1)[1].rsplit('\nPY\n',1)[0]
    fixtures=tmp_path/'config';fixtures.mkdir()
    for name in ('fixture-hardware.json','fixture-site.json','fixture-ssh.pub'):
        (fixtures/name).write_bytes((core.ROOT/'proxmox/iso/config'/name).read_bytes())
    subprocess.run([sys.executable,'-c',source],cwd=tmp_path,check=True)
    local=tmp_path/'.local'
    hardware=json.loads((local/'hardware.json').read_text())
    assert all(d['disk_serial'].startswith('CI-') for d in hardware['disk_members']+hardware['protected_disks'])
    assert json.loads((local/'media-approval.json').read_text())['production_boot_or_erase_authorized'] is False
    # An existing profile must never be overwritten by a CI setup convenience.
    before={p.name:p.read_bytes() for p in local.iterdir()}
    replay=subprocess.run([sys.executable,'-c',source],cwd=tmp_path,capture_output=True)
    assert replay.returncode!=0
    assert before=={p.name:p.read_bytes() for p in local.iterdir()}
    for workflow in (ci,qualification):
        assert 'pull_request_target' not in workflow['on']
        assert '${{ secrets.' not in json.dumps(workflow)
        for candidate in workflow['jobs'].values():
            assert candidate['runs-on']=='ubuntu-24.04'
            for step in candidate['steps']:
                if 'uses' in step:assert re.fullmatch('[0-9a-f]{40}',step['uses'].split('@')[1])
                if step.get('uses','').startswith('actions/upload-artifact@'):
                    assert step['if']=='always()'
                    assert step['with']['retention-days']=='7'
                    for path in step['with']['path'].splitlines():
                        assert path.endswith(('.json','.txt','console.log'))
                        assert '.local' not in path
                        assert not path.endswith(('.iso','.raw','.squashfs'))


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
