"""Read guest readiness from genuine completed deployments, never group activation."""
from pathlib import Path

import backup_agent
from component_guest import BACKUP_PHASE
from component_payload import AppPayload
from private_io import digest, encoded, private_directory, read_json, require, sha


def legacy_holds(schedule):
    """Retain historical activation failures as holds, without adopting old successes."""
    for state in sorted({row['state_root'] for row in schedule['group']['members'].values()}):
        for base, schema in (('backup-activation', 'homelab-pbs-activation-v1'),
                             ('backup-controller/installations', 'homelab-pbs-schedule-install-v1')):
            parent = Path(state)/base/schedule['group']['name']
            if not parent.exists() and not parent.is_symlink():
                continue
            private_directory(parent.parent); private_directory(parent)
            for operation in parent.iterdir():
                private_directory(operation)
                require(not any((operation/name).exists() or (operation/name).is_symlink()
                                for name in ('failed.json', 'FAILED.json')),
                        'Preserve failed backup setup; no automatic recovery')
                record = read_json(operation/'complete.json', private=True)
                require(isinstance(record, dict) and isinstance(record.get('identity'), dict)
                        and record['identity'].get('schema') == schema,
                        'Preserve interrupted or foreign backup setup')


def verify(schedule, admitted):
    """All desired members must have matching installed inputs in their own receipt."""
    import backup_controller
    backup_controller.schedule(schedule)
    require(schedule['schema'] == 'homelab-pbs-schedule-v2'
            and set(admitted) == set(schedule['coverage']),
            'Deploy guest-owned backup readiness for the complete declared group')
    legacy_holds(schedule)
    for name, (cfg, proof) in admitted.items():
        inventory = cfg['app']['backup']
        require(digest(encoded(inventory)) == schedule['coverage'][name],
                'Deploy the current declared backup coverage, including disabled members')
        receipt_path = Path(cfg['paths']['state_root'])/str(cfg['guest']['vmid'])/'ordinary-complete.json'
        require(sha(receipt_path) == proof, 'Preserve the admitted completed guest generation')
        receipt = read_json(receipt_path, private=True)
        selected = receipt['phase_inputs'][BACKUP_PHASE]
        payload = AppPayload.load(Path(receipt['binding']['app_inputs_directory'])/'backup-agent', selected)
        backup_agent.verify_inputs(inventory, payload)
    backup_controller.installation(schedule)
