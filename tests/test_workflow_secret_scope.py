"""Direct scalar action scope and selected-role admission with synthetic values."""
from pathlib import Path
import sys
import pytest
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'proxmox/applications'))
import component_input_secrets as inputs


def workflow():
    return yaml.load((ROOT/'.github/workflows/guest-phase.yml').read_text(),Loader=yaml.BaseLoader)


@pytest.mark.parametrize('adapter',sorted(inputs.ROLES))
def test_scoping_preserves_only_selected_values_and_missing_or_foreign_slots_refuse(adapter):
    sources={role:{'type':'environment','name':'EXAMPLE_'+role.upper()}for role in inputs.ROLES[adapter]}
    slots=inputs.slots(adapter,sources)
    values={slot:'  synthetic-$literal-'+role+'  'for role,slot in slots.items()}
    assert inputs.selected(adapter,sources,values)=={role:values[slot].encode()for role,slot in slots.items()}
    for role,slot in slots.items():
        missing=dict(values);missing.pop(slot)
        with pytest.raises(ValueError):inputs.selected(adapter,sources,missing)
        for invalid in ('',' ', 'line\nbreak'):
            with pytest.raises(ValueError):inputs.selected(adapter,sources,dict(values,**{slot:invalid}))
    foreign=dict(values);foreign[inputs.PREFIX+'UNSELECTED']='synthetic-foreign'
    with pytest.raises(ValueError):inputs.selected(adapter,sources,foreign)


def test_optional_smtp_is_required_only_when_selected_and_never_rotated_or_transformed():
    sources={role:{'type':'environment','name':'EXAMPLE_'+role.upper()}for role in('secret_key','postgresql_password')}
    values={slot:'synthetic-'+role for role,slot in inputs.slots('authentik',sources).items()}
    assert set(inputs.selected('authentik',sources,values))==set(sources)
    sources['smtp_password']={'type':'environment','name':'EXAMPLE_SMTP'}
    with pytest.raises(ValueError):inputs.selected('authentik',sources,values)
    values[inputs.PREFIX+'AUTHENTIK_SMTP_PASSWORD']='unchanged-$smtp'
    assert inputs.selected('authentik',sources,values)['smtp_password']==b'unchanged-$smtp'


def test_finite_action_slots_are_available_only_to_final_deploy_as_direct_scalars():
    steps=workflow()['jobs']['run']['steps'];deploy=steps[-1]
    declared={inputs.PREFIX+slot.upper()for roles in inputs.SLOTS.values()for slot in roles.values()}
    assert set(deploy['env'])=={'GUEST','PHASE','PBS_API_TOKEN',*declared}
    for step in steps[:-1]:assert not(set(step.get('env',{}))&{'PBS_API_TOKEN',*declared})
    assert deploy['env']['PBS_API_TOKEN']=="${{ inputs.phase == 'pbs-agent' && secrets.PBS_API_TOKEN || '' }}"
    assert 'toJSON'not in str(deploy)and'fromJSON(secrets'not in str(deploy)
    for key in declared:
        assert deploy['env'][key]=='${{ secrets.'+key.removeprefix(inputs.PREFIX).lower()+' }}'


def test_existing_admission_and_shared_credential_binding_are_preserved():
    job = workflow()['jobs']['run']
    assert job['environment'] == '${{ inputs.environment_name }}'
    assert 'github.event.repository.private == true' in job['if']
    assert "github.event_name == 'push'" in job['if']
    assert "github.ref == 'refs/heads/main'" in job['if']
    binding = next(step for step in job['steps'] if step.get('name') == 'Bind existing credentials')
    assert binding['env']['PROXMOX_APP_TOKEN'] == '${{ secrets.PROXMOX_APP_TOKEN }}'
    assert binding['env']['APPLICATION_SSH_KEY'] == '${{ secrets.APPLICATION_SSH_KEY }}'
