"""One shared-file overlay through existing foundation trust, locks and custody."""
import fcntl
import json
import os
from pathlib import Path
import shlex
import time

from ingress_browser import admission, packet, require


def run(deployment, fc, cfg, site, source, selected, state_root, profile="influx"):
    import foundation_maintenance as maintenance
    require(profile in ('influx','pegaprox'), 'Use a fixed browser installation profile')
    if profile == 'pegaprox':
        from pegaprox_browser import packet as selected_packet, admission as selected_admission
    else:
        selected_packet, selected_admission = packet, admission
    settings = selected_packet(selected)
    prefix = profile + '-browser'
    playbook = 'component-pegaprox-hostname.yml' if profile == 'pegaprox' else 'component-browser.yml'
    work = state_root / str(settings['vmid'])
    require(cfg['app']['kind'] == 'ingress', 'Browser maintenance belongs to ingress')
    with (work / 'deployment.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        maintenance.expected(deployment, fc, cfg, site, work, settings)
        require(not any((work / name).exists() or (work / name).is_symlink() for name in fc.HOLDS)
                and deployment.sha(work / 'foundation-complete.json') == settings['foundation_complete_sha256']
                and deployment.sha(work / 'terraform.tfstate') == settings['state_sha256'],
                'Preserve the completed ingress state or existing failure hold')
        completion = json.loads(fc.regular(work / 'foundation-complete.json', private=True))
        public = json.loads(fc.regular(work / 'rollout-complete.json', private=True))
        plan = json.loads(fc.regular(work / 'plan.json', private=True))
        require(completion.get('status') == public.get('status') == 'passed'
                and completion.get('binding') == {'schema': fc.SCHEMA, 'guest': 'ingress', 'vmid': settings['vmid'],
                    'source_sha256': plan['source_sha256'], 'input_hashes': plan['input_hashes'],
                    'prepared_sha256': deployment.sha(site.parent / 'prepared.json')}
                and completion.get('plan_sha256') == public.get('plan_sha256') == settings['plan_sha256']
                and completion.get('public_receipt_sha256') == fc.digest(fc.encoded(public)),
                'Original completed ingress binding differs')
        prerequisites = {}
        for name in ('network_evidence', 'policy_evidence'):
            prerequisite = Path(settings[name]['path'])
            # Fixed original state root, no symlinked intermediate directories.
            require(prerequisite.is_relative_to(work), 'Prerequisite belongs to this ingress guest')
            parent = prerequisite.parent
            while parent != state_root:
                fc.private_directory(parent)
                parent = parent.parent
            raw = fc.regular(prerequisite, private=True)
            require(fc.digest(raw) == settings[name]['sha256'],
                    'Network completion or exact access/SSO review differs')
            prerequisites[name] = json.loads(raw)
        selected_admission(settings, prerequisites['network_evidence'], prerequisites['policy_evidence'])
        operation = work / (prefix + '-route')
        if not operation.exists(): operation.mkdir(mode=0o700)
        fc.private_directory(operation)
        claim, done = operation / 'claim.json', operation / 'complete.json'
        nas = Path(cfg['paths']['backup_directory']) / str(settings['vmid'])
        completed = done.exists() or done.is_symlink()
        if completed:
            require(fc.regular(claim, private=True) == fc.regular(done, private=True) == fc.encoded(settings)
                    and fc.regular(nas / (prefix + '-claim.json'), private=True) == fc.encoded(settings)
                    and fc.regular(nas / (prefix + '-complete.json'), private=True) == fc.encoded(settings)
                    and fc.digest(fc.regular(nas / (prefix + '-shared-before.json'), private=True)) == settings['shared_before_sha256'],
                    'Completed route custody differs')
        else:
            archive = nas / (prefix + '-shared-before.json')
            require(not archive.exists() and not archive.is_symlink(), 'Preserve pre-existing route original custody')
            fc.write_new(claim, fc.encoded(settings))  # Failed/interrupted claims never replay.
        marker = work / 'CONTINUATION-HOLD.json'
        fc.write_new(marker, fc.encoded(settings))
        if not completed:
            deployment.backup(cfg, work / 'terraform.tfstate', 'before-' + prefix + '-route')
            fc.write_new(nas / (prefix + '-claim.json'), fc.encoded(settings))
        evidence = operation / ('verify-' + str(time.time_ns()) if completed else 'attempt')
        evidence.mkdir(mode=0o700)
        address = deployment.application_address(cfg)
        require(address == cfg['app']['address'], 'No alternate ingress management address')
        deployment.guest_identity.pin(cfg, evidence, address, lambda path: deployment.api_get(cfg, path), deployment.write)
        fc.write_new(evidence / 'inventory.json', fc.encoded({'application': {'hosts': {cfg['app']['hostname']: {
            'ansible_host': address, 'ansible_user': 'root'}}}}))
        fc.write_new(evidence / 'variables.json', fc.encoded({'app': cfg['app'], 'browser_settings': settings,
            'browser_verify_only': completed, 'browser_archive': str(nas / (prefix + '-shared-before.json'))}))
        env = os.environ.copy()
        env.update(LC_ALL='C.UTF-8', LANG='C.UTF-8', ANSIBLE_CONFIG=str(source / 'ansible/ansible.cfg'),
            ANSIBLE_HOST_KEY_CHECKING='True', ANSIBLE_SSH_ARGS=
            '-F /dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ControlMaster=no '
            '-o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o IdentitiesOnly=yes '
            '-o UserKnownHostsFile=' + shlex.quote(cfg['paths']['known_hosts']))
        deployment.quiet(['ansible-playbook', '-i', str(evidence / 'inventory.json'), '--private-key', cfg['paths']['private_key'],
            str(source / 'ansible' / playbook), '--extra-vars', '@' + str(evidence / 'variables.json')],
            env, evidence / 'ansible.log')
        require(deployment.sha(work / 'terraform.tfstate') == settings['state_sha256']
                and fc.digest(fc.regular(nas / (prefix + '-shared-before.json'), private=True)) == settings['shared_before_sha256'],
                'Canonical state or retained watched-file original changed')
        if not completed:
            deployment.backup(cfg, work / 'terraform.tfstate', 'after-' + prefix + '-route')
            fc.write_new(done, fc.encoded(settings))
            fc.write_new(nas / (prefix + '-complete.json'), fc.encoded(settings))
        require(fc.regular(marker, private=True) == fc.encoded(settings), 'Route hold ownership changed')
        marker.unlink(); fc.sync(work)
        return {'status': 'passed', 'changed': not completed, 'browser_login_verified': False}
