"""Activate one complete deployed backup group; never deploy application infrastructure."""
from contextlib import ExitStack
import fcntl
import os
from pathlib import Path

import backup_agent
import backup_api
import backup_controller
import backup_enrollment
import backup_identity
import backup_policy
import backup_client_transport
import component_ansible
import component_inputs
import component_payload
import deployment_state
from deployment_inputs import source_hash
from private_io import digest, encoded, private_directory, private_writer, read_json, regular, require, write_new


def identity(schedule, admitted):
    return {'schema':'homelab-pbs-activation-v1', 'schedule':schedule, 'source_sha256':source_hash(),
        'members':{name:{'deployment_sha256':proof, 'coverage_sha256':digest(encoded(cfg['app']['backup']))}
                   for name,(cfg,proof) in sorted(admitted.items())}}


def location(schedule, admitted):
    value = identity(schedule, admitted)
    state = min(row['state_root'] for row in schedule['group']['members'].values())
    return Path(state)/'backup-activation'/schedule['group']['name']/digest(encoded(value)), value


def verify(schedule, admitted):
    """Every backup needs the exact successful activation and unchanged private inputs."""
    root, expected = location(schedule, admitted)
    private_directory(root)
    require(not (root/'failed.json').exists() and not (root/'failed.json').is_symlink(),
            'Preserve failed backup activation')
    value = read_json(root/'complete.json', private=True)
    backup_policy.exact(value, ('identity', 'inputs'))
    require(value['identity'] == expected and set(value['inputs']) == set(admitted),
            'Activate the complete current deployed backup group before capturing data')
    for name,(cfg,_) in admitted.items():
        inputs = {key:digest(raw) for key,raw in backup_agent.inputs(cfg['app']['backup']).items()}
        require(inputs == value['inputs'][name], 'Backup private inputs changed after activation')
    return value


def activate(descriptor, token, *, admission=backup_controller.admit, api_factory=backup_api.PBS,
             fetch=backup_client_transport.fetch, deploy=component_ansible.run_phase):
    """Only the protected Backup job calls this; acquire the ordinary finite group locks."""
    backup_policy.exact(descriptor, ('schedule', 'datastore_path', 'coverage', 'enabled'))
    schedule = backup_controller.schedule(descriptor['schedule']); group = schedule['group']
    require(set(descriptor['coverage']) == set(group['members']), 'Bind every enrolled backup member')
    enabled=descriptor['enabled']
    require(isinstance(enabled,list) and enabled and len(enabled)==len(set(enabled))
            and set(enabled)<=set(group['members']), 'Activate only explicitly enabled guest members')
    deployment_state.bootstrap_closed()
    scopes = sorted({(row['state_root'],row['vmid']) for row in group['members'].values()})
    with ExitStack() as opened:
        paths = [(Path(root)/'database-network.lock',True) for root in sorted({root for root,_ in scopes})]
        paths += [(Path(root)/str(vmid)/leaf,False) for root,vmid in scopes
                  for leaf in ('workflow.lock','deployment.lock')]
        for path,shared in paths:
            stream = opened.enter_context(private_writer(path,append=True,create=False))
            fcntl.flock(stream,(fcntl.LOCK_SH if shared else fcntl.LOCK_EX)|fcntl.LOCK_NB)
        admitted = {name:admission(name,row) for name,row in group['members'].items()}
        require(all(cfg['app']['backup'] == descriptor['coverage'][name] for name,(cfg,_) in admitted.items()),
                'Deploy the exact declared backup coverage before activating the group, including disabled members')
        root, expected = location(schedule,admitted)
        for parent in (root.parent.parent, root.parent):
            private_directory(parent,create=not parent.exists())
        completed = []
        for previous in root.parent.iterdir():
            private_directory(previous)
            require((previous/'complete.json').is_file() and not (previous/'failed.json').exists(),
                    'Preserve interrupted backup activation; no automatic retry')
            completed.append(read_json(previous/'complete.json',private=True))
        for name in set(admitted)-set(enabled):
            require(any(record.get('identity',{}).get('members',{}).get(name)==expected['members'][name]
                        and record.get('inputs',{}).get(name)=={key:digest(raw) for key,raw in
                            backup_agent.inputs(admitted[name][0]['app']['backup']).items()}
                        for record in completed), 'Enable this guest for its initial or changed backup activation')
        first = next(iter(admitted.values()))[0]['app']['backup']['job']['destination']
        require(all({k:v for k,v in cfg['app']['backup']['job']['destination'].items()
                     if k not in ('auth_id','backup_id')} ==
                    {k:v for k,v in first.items() if k not in ('auth_id','backup_id')}
                    for cfg,_ in admitted.values()), 'Use one declared PBS management destination')
        api = api_factory(first,token)
        api.datastore(descriptor['datastore_path'])
        if root.exists() or root.is_symlink():
            verify(schedule,admitted)
            for name,(cfg,_) in admitted.items():
                job=cfg['app']['backup']['job']
                selected=backup_identity.binding(job['destination'],cfg['app']['backup']['owner'],group['name'],cfg['paths']['state_root'])
                backup_enrollment.provision(job,cfg['app']['backup']['owner'],cfg['paths']['state_root'],api,
                    lambda *,create:fetch(cfg,selected['identity'],create=create),allow_create=False)
            return {'status':'verified','identity':root.name,'changed':False}
        private_directory(root,create=True)
        write_new(root/'started.json',encoded(expected))
        try:
            inputs = {}
            names = sorted(admitted)
            for name in names:
                cfg,proof = admitted[name]; job=cfg['app']['backup']['job']
                selected = backup_identity.binding(job['destination'],cfg['app']['backup']['owner'],group['name'],cfg['paths']['state_root'])
                backup_enrollment.provision(job,cfg['app']['backup']['owner'],cfg['paths']['state_root'],api,
                    lambda *,create: fetch(cfg,selected['identity'],create=create),allow_create=name in enabled)
                inputs[name]={key:digest(raw) for key,raw in backup_agent.inputs(cfg['app']['backup']).items()}
            # Finish every member's remote ownership check before installing any worker or timer.
            for name in sorted(enabled):
                cfg,proof = admitted[name]
                member = root/name; private_directory(member,create=True)
                values = backup_agent.inputs(cfg['app']['backup'])
                require(inputs[name] == {key:digest(raw) for key,raw in values.items()},
                        'Private inputs changed after group ownership verification')
                payload = component_payload.prepare(member,cfg['deployment']['input_identity'],'backup-agent',
                    {'application.json':encoded(cfg['app']['backup']),**values})
                site = Path(cfg['deployment']['input_directory'])/'site.json'
                binding = component_inputs.binding(cfg,site)
                result = deploy(cfg,site,Path(cfg['paths']['state_root'])/str(cfg['guest']['vmid']),member,
                    binding,'pbs-agent',payload=payload,activate_backup=True,backup_schedule=name==sorted(enabled)[-1])
                require(result.get('status') == 'passed','Require successful backup activation')
            require(admitted == {name:admission(name,row) for name,row in group['members'].items()},
                    'A completed deployment changed during activation')
            write_new(root/'complete.json',encoded({'identity':expected,'inputs':inputs}))
            verify(schedule,admitted)
        except Exception as error:
            write_new(root/'failed.json',encoded({'error_type':type(error).__name__,'automatic_retry':False}))
            raise
    return {'status':'activated','identity':root.name,'changed':True}
