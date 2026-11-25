"""Resume one explicitly authorized Authentik schema transition under its guest lock."""
from pathlib import Path
import re
import tempfile

import authentik_upgrade
import component_ansible
import component_current as current
import component_generation as generation
import component_guest
import component_recovery as recovery
from component_payload import AppPayload
from private_io import private_directory, read_json, require, sha


def requested(site, guest, packet, cfg, environment, target):
    ticket = Path(site)/'authentik-forward.json'
    if not current.exists(ticket):
        return
    request = read_json(ticket)
    generation.shape(request, {'guest', 'operation', 'hold_sha256'})
    require(re.fullmatch(r'ordinary-[1-9][0-9]*-[1-9][0-9]*', request['operation'])
            and re.fullmatch('[0-9a-f]{64}', request['hold_sha256']), 'Bind the approved Authentik hold')
    if request['guest'] != guest:
        return
    repository = environment['GITHUB_REPOSITORY']
    workflow = repository+'/.github/workflows/deploy.yml'
    require(environment['GITHUB_WORKFLOW_REF'] == workflow+'@refs/heads/main'
            and recovery.enabled(), 'Use protected ordinary CD for the approved forward repair')
    with recovery.locked(cfg) as work:
        hold = work/'ORDINARY-HOLD.json'
        if not current.exists(hold):
            return
        marker = read_json(hold, private=True)
        operation = work/request['operation']
        if marker['operation'] != str(operation):
            return  # A spent approval never applies to a later operation.
        require(sha(hold) == request['hold_sha256'] and marker['workflow'] == [repository, workflow],
                'Preserve foreign or changed holds')
        state = current.read(work)
        if state and operation.name in state[0]['resolved']:
            return  # Normal pending recovery closes a verified pointer-before-release interruption.
        saved = recovery.baseline(operation, cfg)
        require(saved['marker'] == marker, 'Preserve the sealed failed deployment')
        previous_path, _, previous = recovery.owner(saved, work)
        require(sha(current.owner_path(work)) == sha(previous_path), 'Preserve the current accepted owner')
        recovery.forward_settled(operation, marker)
        held, apps = generation.sealed_inputs(marker['binding'])
        require(cfg == held and len(apps) == 1, 'Require an unchanged guest with one retained Authentik app')
        app_id, app = next(iter(apps.items()))
        phase = app['identity']['phase']
        phases = cfg['deployment']['phases']
        agents = [p for p in (component_guest.AGENT_PHASE, component_guest.BACKUP_PHASE) if p in phases]
        require(app['adapter'] == 'authentik' and app['lifecycle'] == 'retained'
                and app['image_update'] == 'release-series' and phases == ['preparation', phase, *agents],
                'Resume only the retained release-series app and its declared agents')
        limits = list(operation.glob('*-rollback-limit.json'))
        require(limits == [operation/(phase+'-schema-rollback-limit.json')]
                and current.exists(operation/'preparation-complete.json')
                and not current.exists(operation/(phase+'-complete.json')), 'Require an interrupted Authentik schema phase')
        upgrade = authentik_upgrade.plan(read_json(Path(previous['deployment']['runtime_file']), private=True),
            read_json(Path(cfg['deployment']['runtime_file']), private=True), app_id)
        require(upgrade and read_json(limits[0], private=True) == {
            'schema':'homelab-authentik-schema-transition-v1','images':upgrade['images']}, 'Preserve the sealed release chain')
        started = read_json(operation/(phase+'-started.json'), private=True)
        require(started == dict(marker, phase_inputs=started['phase_inputs']), 'Preserve the original app start receipt')
        infra = read_json(operation/'infrastructure-complete.json', private=True)
        require(infra['binding'] == marker['binding'] and generation.backend(work, {
            'vmid': cfg['guest']['vmid'], 'node': cfg['site']['node']}) == (infra['state_sha256'], infra['state_identity']),
            'Require the settled infrastructure and state identity before contacting the guest')
        folder = work/operation.name.replace('ordinary-', 'recovery-', 1)
        private_directory(folder)
        require(read_json(folder/'result.json', private=True)['status'] == 'recovery_required',
                'Require a failed protected recovery decision')
        for agent in agents:
            target(packet, work, environment, phase=agent)
        _, selected = target(packet, work, environment)
        binding = selected['binding']
        require(binding == dict(marker['binding'], source_sha256=binding['source_sha256'])
                and selected['phase_inputs'][phase] == started['phase_inputs'], 'Preserve every sealed source input and app payload')
        source = Path(cfg['deployment']['input_directory'])/'site.json'
        with tempfile.TemporaryDirectory(prefix='authentik-forward-', dir=environment['RUNNER_TEMP']) as temporary:
            for step in [phase, *agents]:
                proof = selected['phase_inputs'][step]
                payload = AppPayload.load(Path(binding['app_inputs_directory'])/proof['app'], proof)
                component_ansible.run_phase(cfg, source, work, Path(temporary), binding, step, payload=payload,
                    previously_owned=True, **({'upgrade': upgrade, 'resume': True} if step == phase else {}))
        recovery.reconcile(cfg, operation, previous_path, selected, reason='Verified the approved forward Authentik migration',
            actor_context='protected-main-reconciliation', pending_forward=True)
