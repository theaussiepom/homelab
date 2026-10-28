"""Reviewed CD maintenance without replaying a foundation guest installation.

The original guest source, inputs, state and installation receipts stay pinned.
An image-only maintenance packet owns the existing ingress runtime image. A
separate one-use packet can finish a failed read-only verification after its
dependency is repaired. Neither path stages an application or restores data.
"""
import argparse
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

STATE = Path('/var/lib/homelab-applications')
INPUTS = Path('/var/lib/homelab-inputs')


def require(value, message):
    if not value:
        raise ValueError(message)


def packet(value):
    if isinstance(value, dict) and value.get('schema') == 'homelab-ingress-browser-update-v1':
        from ingress_browser import packet as browser_packet
        return browser_packet(value)
    common = {'schema', 'revision', 'vmid', 'plan_sha256'}
    require(isinstance(value, dict), 'Supply a closed maintenance packet')
    if value.get('schema') == 'homelab-ingress-image-update-v1':
        fields = common | {'before', 'after', 'compose_sha256', 'foundation_complete_sha256'}
        require(set(value) == fields, 'Unexpected image maintenance fields')
        for key in ('before', 'after'):
            require(isinstance(value[key], str) and re.fullmatch(r'traefik@sha256:[0-9a-f]{64}', value[key]),
                    'Use immutable official Traefik images')
        require(value['before'] != value['after'], 'Select a reviewed image change')
        hashes = [value['plan_sha256'], value['compose_sha256'], value['foundation_complete_sha256']]
    elif value.get('schema') == 'homelab-ingress-acme-update-v1':
        from ingress_acme import resolvers
        fields = common | {'before','after','runtime_sha256','compose_sha256','state_sha256',
                           'foundation_complete_sha256','image'}
        require(set(value) == fields, 'Unexpected resolver maintenance fields')
        resolvers(value['before']);resolvers(value['after'])
        require(value['before'] != value['after'] and isinstance(value['image'],str)
                and re.fullmatch(r'traefik@sha256:[0-9a-f]{64}',value['image']),
                'Select the declared resolver change and unchanged immutable image')
        hashes = [value[k] for k in ('plan_sha256','runtime_sha256','compose_sha256',
                                    'state_sha256','foundation_complete_sha256')]
    elif value.get('schema') == 'homelab-ingress-acme-confirmation-v1':
        from ingress_acme import FAILURE_FILES
        require(set(value) == common | {'update','state_sha256','runtime_sha256','guest_hold_sha256','failure_hashes'},
                'Unexpected resolver confirmation fields')
        require(isinstance(value['update'],dict) and value['update'].get('schema') == 'homelab-ingress-acme-update-v1',
                'Confirmation requires the original resolver update packet')
        original = packet(value['update'])
        require(original['schema'] == 'homelab-ingress-acme-update-v1'
                and original['vmid'] == value['vmid'] and original['plan_sha256'] == value['plan_sha256']
                and isinstance(value['failure_hashes'],dict) and set(value['failure_hashes']) == set(FAILURE_FILES),
                'Bind only the original failed resolver update')
        hashes = [value[k] for k in ('plan_sha256','state_sha256','runtime_sha256','guest_hold_sha256')]
        hashes += list(value['failure_hashes'].values())
    else:
        previous = value.get('schema') == 'homelab-foundation-verify-continuation-v2'
        require(value.get('schema') in ('homelab-foundation-verify-continuation-v1',
                                       'homelab-foundation-verify-continuation-v2')
                and set(value) == common | {'verify_log', 'hashes'} | ({'previous_claim_sha256'} if previous else set())
                and isinstance(value['verify_log'], str) and re.fullmatch(r'[0-9]+-verify\.log', value['verify_log']),
                'Select only the reviewed verification continuation')
        require(isinstance(value['hashes'], dict) and set(value['hashes']) == {
            'foundation_hold', 'rollout_hold', 'plan', 'plan_file', 'plan_json', 'applied', 'started',
            'prepared', 'site', 'stack', 'trust', 'state', 'verify_log'}, 'Bind the original failed phase')
        hashes = [value['plan_sha256'], *value['hashes'].values()]
        if previous:
            hashes.append(value['previous_claim_sha256'])
    require(type(value['vmid']) is int and value['vmid'] >= 100 and value['vmid'] not in {900, 4914, 4915, 4920}
            and isinstance(value['revision'], str) and re.fullmatch('[0-9a-f]{40}', value['revision'])
            and all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in hashes),
            'Invalid maintenance identity or immutable source')
    return value


def expected(deployment, fc, cfg, site, work, selected):
    require(cfg['guest']['vmid'] == cfg['app']['vmid'] == selected['vmid']
            and cfg['paths']['state_root'] == str(STATE) and work == STATE / str(selected['vmid'])
            and cfg['app']['stack_config'] == str(site.parent / 'stack.json'), 'Wrong installed guest or input path')
    deployment.validate(cfg)
    plan = json.loads(fc.regular(work / 'plan.json', private=True))
    require(plan['plan_sha256'] == selected['plan_sha256']
            and plan['site_sha256'] == deployment.sha(site)
            and plan['source_sha256'] == deployment.source_hash()
            and plan['input_hashes'] == deployment.input_hashes(cfg)
            and json.loads(fc.regular(work / 'applied.json', private=True)) == plan
            and json.loads(fc.regular(work / 'started.json', private=True)) == plan,
            'Original applied/start/source/input bindings differ')
    deployment.guest_trust(cfg, work)
    return plan


def image_update(deployment, fc, cfg, site, source, selected):
    require(cfg['app']['kind'] == 'ingress', 'Image maintenance is only for ingress')
    work = STATE / str(selected['vmid'])
    with (work / 'deployment.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan = expected(deployment, fc, cfg, site, work, selected)
        require(not any((work / name).exists() or (work / name).is_symlink() for name in fc.HOLDS)
                and deployment.sha(work / 'foundation-complete.json') == selected['foundation_complete_sha256'],
                'Preserve the existing foundation completion or failure')
        completion = json.loads(fc.regular(work / 'foundation-complete.json', private=True))
        public = json.loads(fc.regular(work / 'rollout-complete.json', private=True))
        require(completion.get('status') == public.get('status') == 'passed'
                and completion.get('binding') == {'schema': fc.SCHEMA, 'guest': 'ingress', 'vmid': selected['vmid'],
                    'source_sha256': plan['source_sha256'], 'input_hashes': plan['input_hashes'],
                    'prepared_sha256': deployment.sha(site.parent / 'prepared.json')}
                and completion.get('plan_sha256') == public.get('plan_sha256') == selected['plan_sha256']
                and completion.get('public_receipt_sha256') == fc.digest(fc.encoded(public)),
                'Original completed ingress binding differs')
        prefix = 'image-update-' + selected['after'][-12:]
        claim, done = work / (prefix + '-claim.json'), work / (prefix + '-complete.json')
        nas = Path(cfg['paths']['backup_directory']) / str(selected['vmid'])
        completed = done.exists()
        if completed:
            require(json.loads(fc.regular(done, private=True)) == selected
                    and fc.regular(claim, private=True) == fc.encoded(selected)
                    and fc.regular(nas / done.name, private=True) == fc.regular(done, private=True)
                    and fc.regular(nas / claim.name, private=True) == fc.regular(claim, private=True),
                    'Completed maintenance custody differs')
        else:
            fc.write_new(claim, fc.encoded(selected))
            deployment.backup(cfg, work / 'terraform.tfstate', 'before-component-image-update')
            fc.write_new(nas / claim.name, fc.encoded(selected))
        evidence = work / (prefix + ('-verify-' + str(time.time_ns()) if completed else '-attempt'))
        evidence.mkdir(mode=0o700)
        address = deployment.application_address(cfg)
        require(address == cfg['app']['address'], 'No alternate component address')
        deployment.guest_identity.pin(cfg, evidence, address, lambda path: deployment.api_get(cfg, path), deployment.write)
        variables, inventory = evidence / 'variables.json', evidence / 'inventory.json'
        fc.write_new(variables, fc.encoded({'app': cfg['app'], 'component_before': selected['before'],
            'component_after': selected['after'], 'component_compose_sha256': selected['compose_sha256'],
            'component_verify_only': completed}))
        fc.write_new(inventory, fc.encoded({'application': {'hosts': {cfg['app']['hostname']: {
            'ansible_host': address, 'ansible_user': 'root'}}}}))
        env = os.environ.copy()
        env.update(LC_ALL='C.UTF-8', LANG='C.UTF-8',
            ANSIBLE_CONFIG=str(source / 'ansible/ansible.cfg'), ANSIBLE_HOST_KEY_CHECKING='True',
            ANSIBLE_SSH_ARGS='-F /dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ControlMaster=no '
            '-o GlobalKnownHostsFile=/dev/null -o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o IdentitiesOnly=yes '
            '-o UserKnownHostsFile=' + shlex.quote(cfg['paths']['known_hosts']))
        deployment.quiet(['ansible-playbook', '-i', str(inventory), '--private-key', cfg['paths']['private_key'],
            str(source / 'ansible/component-image.yml'), '--extra-vars', '@' + str(variables)], env, evidence / 'ansible.log')
        if not completed:
            deployment.backup(cfg, work / 'terraform.tfstate', 'after-component-image-update')
            fc.write_new(done, fc.encoded(selected)); fc.write_new(nas / done.name, fc.encoded(selected))
        return {'status': 'passed', 'changed': not completed}


def continue_verification(deployment, fc, cfg, site, selected, bundles):
    require(cfg['app']['kind'] == 'db-tools', 'Continuation is only for the existing database tools guest')
    work = STATE / str(selected['vmid'])
    with (work / 'foundation.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan = expected(deployment, fc, cfg, site, work, selected)
        previous = selected['schema'] == 'homelab-foundation-verify-continuation-v2'
        prefix = 'foundation-verification' + ('-v2-' + selected['previous_claim_sha256'][:12] if previous else '')
        claim = work / (prefix + '-claim.json')
        done = work / (prefix + '-complete.json')
        nas = Path(cfg['paths']['backup_directory']) / str(selected['vmid'])
        if done.exists():
            require(fc.regular(done, private=True) == fc.encoded(selected)
                    and fc.regular(claim, private=True) == fc.encoded(selected)
                    and fc.regular(nas / done.name, private=True) == fc.regular(done, private=True)
                    and fc.regular(nas / claim.name, private=True) == fc.regular(claim, private=True),
                    'Completed continuation custody differs')
            # The ordinary CD path can perform its usual read-only verification
            # on later pushes. It owns a new failure hold if that check fails.
            fcntl.flock(lock, fcntl.LOCK_UN)
            return fc.run('db-tools', deployment, bundles)
        directory = site.parent
        if previous:
            require(not claim.exists() and not claim.is_symlink(), 'This corrected verification was already claimed')
        paths = {'foundation_hold': work / 'FOUNDATION-HOLD.json', 'rollout_hold': work / 'ROLLOUT-HOLD.json',
            'plan': work / 'plan.json', 'plan_file': work / 'guest.tfplan', 'plan_json': work / 'guest.tfplan.json',
            'applied': work / 'applied.json', 'started': work / 'started.json', 'prepared': directory / 'prepared.json',
            'site': site, 'stack': directory / 'stack.json', 'trust': work / 'ssh-trust.json',
            'state': work / 'terraform.tfstate', 'verify_log': work / selected['verify_log']}
        if previous:
            for key in ('foundation_hold','rollout_hold'):
                paths[key] = work / ('foundation-verification-' + selected['plan_sha256'][:12]) / paths[key].name
            prior_claim = work / 'foundation-verification-claim.json'
            marker = work / 'CONTINUATION-HOLD.json'
            require(deployment.sha(prior_claim) == deployment.sha(marker) == selected['previous_claim_sha256'],
                    'Previous failed continuation ownership changed')
            prior = packet(json.loads(fc.regular(prior_claim,private=True)))
            require(prior['schema'] == 'homelab-foundation-verify-continuation-v1'
                    and prior['vmid'] == selected['vmid'] and prior['plan_sha256'] == selected['plan_sha256']
                    and all(prior['hashes'][k] == v for k,v in selected['hashes'].items() if k != 'verify_log')
                    and deployment.sha(work / prior['verify_log']) == prior['hashes']['verify_log'],
                    'Previous failed continuation binding differs')
        require(not any((work / name).exists() or (work / name).is_symlink()
                for name in ('HOLD.json', 'foundation-complete.json', 'rollout-complete.json',
                             *(() if previous else ('CONTINUATION-HOLD.json',)))),
                'Unexpected existing completion or other operation hold')
        for key, path in paths.items():
            require(hashlib.sha256(fc.regular(path, private=True)).hexdigest() == selected['hashes'][key],
                    'Failed evidence drifted before continuation')
        original = json.loads(fc.regular(paths['foundation_hold'], private=True))
        rollout = json.loads(fc.regular(paths['rollout_hold'], private=True))
        require(original['guest'] == 'db-tools' and original['vmid'] == selected['vmid']
                and original['plan_sha256'] == selected['plan_sha256'] and original['step'] == 'deploy'
                and original['automatic_retry'] is False and rollout['step'] == 'verify'
                and rollout['vmid'] == selected['vmid'] and rollout['plan_sha256'] == selected['plan_sha256']
                and rollout['automatic_retry'] is False, 'Unexpected failed phase ownership')
        binding = {key: original[key] for key in ('schema', 'guest', 'vmid', 'prepared_sha256', 'source_sha256', 'input_hashes')}
        require(binding['schema'] == fc.SCHEMA and binding['source_sha256'] == plan['source_sha256']
                and binding['input_hashes'] == plan['input_hashes']
                and binding['prepared_sha256'] == selected['hashes']['prepared'], 'Foundation binding changed')
        fc.write_new(claim, fc.encoded(selected))
        deployment.backup(cfg, work / 'terraform.tfstate', 'before-approved-foundation-verification')
        fc.write_new(nas / claim.name, fc.encoded(selected))
        archive = work / (prefix if previous else 'foundation-verification-' + selected['plan_sha256'][:12])
        archive.mkdir(mode=0o700)
        deployment.guest_identity.pin(cfg, archive, deployment.application_address(cfg),
                                     lambda path: deployment.api_get(cfg, path), deployment.write)
        marker = work / 'CONTINUATION-HOLD.json'
        if previous:
            require(deployment.sha(prior_claim) == deployment.sha(marker) == selected['previous_claim_sha256'],
                    'Previous continuation changed during admission')
            prior_claim.rename(archive / prior_claim.name)
            marker.rename(archive / marker.name)
        fc.write_new(marker, fc.encoded(selected))
        if not previous:
            for key in ('foundation_hold', 'rollout_hold'):
                require(deployment.sha(paths[key]) == selected['hashes'][key], 'Failed hold changed during admission')
                paths[key].rename(archive / paths[key].name)
        fc.sync(work); fc.sync(archive)
        # This is the sole target execution: no plan/apply, staging or startup.
        result = deployment.execute('verify', site)
        require(result == {'step': 'verify', 'vmid': selected['vmid'], 'status': 'passed'}, 'Verification did not pass')
        public = {'step': 'deploy', 'vmid': selected['vmid'], 'status': 'passed',
            'plan_sha256': selected['plan_sha256'], 'steps': [{'step': 'verify', 'result': result}],
            'preserved_original_phase_evidence': selected['hashes'], 'continuation': selected['schema']}
        fc.write_new(work / 'rollout-complete.json', fc.encoded(public))
        fc.write_new(work / 'foundation-complete.json', fc.encoded({'status': 'passed', 'binding': binding,
            'plan_sha256': selected['plan_sha256'], 'public_receipt_sha256': fc.digest(fc.encoded(public))}))
        fc.write_new(done, fc.encoded(selected)); fc.write_new(nas / done.name, fc.encoded(selected))
        require(fc.regular(marker, private=True) == fc.encoded(selected), 'Continuation hold ownership changed')
        marker.unlink(); fc.sync(work)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True, help='Unchanged original guest implementation')
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        selected = packet(json.loads(args.packet.read_text()))
        helper = Path(__file__).resolve().parent
        require(subprocess.check_output(['git', '-C', str(helper), 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
                == selected['revision'], 'Use the exact reviewed maintenance source')
        require(not Path('/var/lib/homelab-bootstrap/CONFIGURING').exists(), 'Bootstrap is active')
        sys.path.insert(0, str(args.source.resolve() / 'proxmox/applications'))
        deployment, fc, config = (importlib.import_module(name) for name in ('deploy', 'foundation_cd', 'site_config'))
        guest = 'ingress' if selected['schema'] in ('homelab-ingress-image-update-v1',
                                                   'homelab-ingress-acme-update-v1',
                                                   'homelab-ingress-acme-confirmation-v1',
                                                   'homelab-ingress-browser-update-v1') else 'db-tools'
        site = INPUTS / ('foundation-' + guest) / 'site.json'
        cfg = json.loads(fc.regular(site, private=True))
        with tempfile.TemporaryDirectory(prefix='homelab-foundation-maintenance-') as temp:
            bundles = Path(temp) / 'bundle'
            config.write_bundle(config.read(args.config), bundles)
            rendered, _, files, directory, work = fc.definition(guest, bundles, INPUTS, STATE)
            require(rendered == cfg and directory == site.parent and work == STATE / str(selected['vmid'])
                    and all(fc.regular(directory / name, private=True) == value for name, value in files.items()),
                    'Committed foundation configuration differs from the original private inputs')
            if selected['schema'] == 'homelab-ingress-browser-update-v1':
                import ingress_browser_maintenance
                result = ingress_browser_maintenance.run(deployment, fc, cfg, site, helper, selected, STATE)
            elif selected['schema'] == 'homelab-ingress-acme-confirmation-v1':
                import ingress_acme
                result = ingress_acme.confirm(deployment,fc,cfg,site,helper,selected,STATE)
            elif selected['schema'] == 'homelab-ingress-acme-update-v1':
                import ingress_acme
                result = ingress_acme.run(deployment,fc,cfg,site,helper,selected,STATE)
            elif guest == 'ingress':
                result = image_update(deployment, fc, cfg, site, helper, selected)
            else:
                result = continue_verification(deployment, fc, cfg, site, selected, bundles)
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Foundation maintenance held; preserve its private inputs and evidence. No automatic retry.') from None


if __name__ == '__main__':
    main()
