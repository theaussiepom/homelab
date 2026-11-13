"""Maintain one controller schedule early; each guest owns its own enrollment."""
from contextlib import ExitStack
import fcntl
import os
from pathlib import Path

import backup_api
import backup_client_transport
import backup_controller
import backup_enrollment
import backup_identity
import backup_policy
import backup_readiness
import backup_user
import deployment_state
from commands import quiet
from custody_records import no_markers
from deployment_inputs import source_hash
from private_io import digest, encoded, private_directory, private_writer, read_json, require, write_new

SOURCE = Path(__file__).resolve().parent


def continuity(value):
    """Read existing schedule ownership before installing or renaming protection."""
    selected = {(row['node'], row['vmid']) for row in value['group']['members'].values()}
    for state in sorted({row['state_root'] for row in value['group']['members'].values()}):
        directory = Path(state)/'backup-controller/schedules'
        if not directory.exists() and not directory.is_symlink():
            continue
        private_directory(directory.parent); private_directory(directory)
        for path in directory.glob('*.json'):
            if path.name.endswith('.owner.json'):
                continue
            previous = backup_controller.schedule(read_json(path, private=True))
            peers = {(row['node'], row['vmid']) for row in previous['group']['members'].values()}
            require(previous['group']['name'] == value['group']['name'] or not selected & peers,
                    'Retire or hand over the existing recovery group before renaming it')
            if previous['group']['name'] == value['group']['name']:
                backup_controller.continuity(previous, value)


def parameters(value):
    """Reuse the account-owned controller units and immutable source installation."""
    account = backup_user.account(os.getuid())
    state = min(row['state_root'] for row in value['group']['members'].values())
    bundle = str(Path(state)/'backup-controller/framework'/source_hash()/'proxmox')
    sources = [path for parent in (SOURCE, SOURCE.parent/'common') for path in parent.rglob('*')
        if path.is_file() and not any(part in {'.terraform', '__pycache__', '.work'} for part in path.parts)]
    files = [{'source': str(path), 'destination': str(Path(bundle)/path.relative_to(SOURCE.parent))}
             for path in sorted(sources)]
    directories = sorted({str(parent) for row in files
        for parent in [Path(row['destination']).parent, *Path(row['destination']).parent.parents]
        if parent == Path(state)/'backup-controller' or Path(state)/'backup-controller' in parent.parents},
        key=lambda path: (path.count('/'), path))
    controller = backup_controller.units(value, bundle+'/applications', account['uid'], account['home'])
    controller.update(environment=account['environment'], source_hash=source_hash(), directory=bundle+'/applications')
    return {'backup_controller': controller, 'backup_controller_files': files,
            'backup_controller_directories': directories}


def install(value, *, destination, datastore_path, token, api_factory=backup_api.PBS, execute=quiet):
    """One early job owns only the schedule; it neither enrolls nor visits guests."""
    backup_controller.schedule(value)
    require(value['schema'] == 'homelab-pbs-schedule-v2', 'Install the guest-readiness schedule')
    deployment_state.bootstrap_closed()
    backup_user.verify('homelab-backup-'+value['group']['name'])
    roots = sorted({row['state_root'] for row in value['group']['members'].values()})
    with ExitStack() as opened:
        for root in roots:
            private_directory(Path(root), create=not Path(root).exists())
            stream = opened.enter_context(private_writer(Path(root)/'database-network.lock', append=True))
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for directory in [Path(root), *Path(root).glob('database-network-cutover-*'),
                              *Path(root).glob('database-server-cutover-*')]:
                if directory.is_dir():
                    private_directory(directory); no_markers(directory)
        backup_readiness.legacy_holds(value)
        continuity(value)
        api_factory(destination, token).datastore(datastore_path)
        identity = {'schema': 'homelab-pbs-schedule-install-v1', 'schedule': value, 'source_sha256': source_hash()}
        parent = Path(roots[0])/'backup-controller'/'installations'/value['group']['name']
        for folder in (parent.parent.parent, parent.parent, parent):
            private_directory(folder, create=not folder.exists())
        operation = parent/digest(encoded(identity))
        if operation.exists() or operation.is_symlink():
            require(read_json(operation/'complete.json', private=True) == {'identity': identity},
                    'Preserve the exact completed schedule installation')
            backup_controller.installation(value)
            return {'status': 'verified', 'changed': False}
        private_directory(operation, create=True)
        write_new(operation/'started.json', encoded(identity))
        try:
            write_new(operation/'variables.json', encoded(parameters(value)))
            environment = {key: item for key, item in os.environ.items()
                           if key != 'PBS_API_TOKEN' and not key.startswith('HOMELAB_APP_SECRET_')}
            environment['ANSIBLE_CONFIG'] = str(SOURCE/'ansible/ansible.cfg')
            execute(['ansible-playbook', '-i', 'localhost,', '-c', 'local',
                     str(SOURCE/'ansible/backup-controller.yml'), '--extra-vars', '@'+str(operation/'variables.json')],
                    environment, operation/'controller.log')
            backup_controller.installation(value)
            write_new(operation/'complete.json', encoded({'identity': identity}))
        except Exception as error:
            write_new(operation/'failed.json', encoded({'error_type': type(error).__name__, 'automatic_retry': False}))
            raise
    return {'status': 'configured', 'changed': True}


def enroll(cfg, environment, *, api_factory=backup_api.PBS, fetch=backup_client_transport.fetch):
    """Called inside this guest's existing locks, before sealing its Backup payload."""
    directory = Path(cfg['deployment']['input_directory'])
    schedule = backup_controller.schedule(read_json(directory/'backup-group.json', private=True))
    require(schedule['schema'] == 'homelab-pbs-schedule-v2', 'Prepare the current guest-owned backup schedule')
    job = cfg['app']['backup']['job']
    member = job['group']['member']
    require(job['group']['name'] == schedule['group']['name']
            and schedule['coverage'].get(member) == digest(encoded(cfg['app']['backup']))
            and schedule['group']['members'][member]['state_root'] == cfg['paths']['state_root']
            and all(schedule['group']['members'][member][key] == item
                    for key, item in cfg['app']['backup']['owner'].items()),
            'Bind this guest enrollment to its declared group and exact coverage')
    backup_readiness.legacy_holds(schedule)
    backup_controller.installation(schedule)
    management = read_json(directory/'backup-management.json', private=True)
    backup_policy.exact(management, ('schema', 'credential', 'datastore_path'))
    backup_policy.exact(management['credential'], ('type', 'name'), ('workflow_secret', 'source_id'))
    require(management['schema'] == 'homelab-pbs-management-v1'
            and management['credential']['type'] == 'environment'
            and management['credential']['name'] == 'PBS_API_TOKEN'
            and management['credential'].get('workflow_secret', 'PBS_API_TOKEN') == 'PBS_API_TOKEN',
            'Bind the declared PBS management input')
    selected = backup_identity.binding(job['destination'], cfg['app']['backup']['owner'],
                                      job['group']['name'], cfg['paths']['state_root'])
    api = api_factory(job['destination'], environment.get('PBS_API_TOKEN', ''))
    api.datastore(management['datastore_path'])
    return backup_enrollment.provision(job, cfg['app']['backup']['owner'], cfg['paths']['state_root'], api,
        lambda *, create: fetch(cfg, selected['identity'], create=create))
