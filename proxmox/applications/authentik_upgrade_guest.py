"""Run the six sealed intermediate Compose selections under the owning CD phase."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from authentik_redis_retirement import retire
from private_io import digest, encoded, private_directory, read_json, regular, require, write_new

APP_ROOT = Path('/opt/homelab-app')

# The output contains a count and hashes. No user, application, or credential values leave the worker.
PROBE = """
import hashlib, json
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from authentik.core.models import Application
from authentik.providers.oauth2.models import OAuth2Provider
ex = MigrationExecutor(connection)
apps = list(Application.objects.exclude(provider_id=None).order_by('pk').values_list('pk','slug','provider_id'))
providers = [(provider.pk, provider.client_id,
              [(entry.matching_mode, entry.url, getattr(entry, 'redirect_uri_type', 'authorization'))
               for entry in provider.redirect_uris])
             for provider in OAuth2Provider.objects.order_by('pk')]
print('AK_UPGRADE=' + json.dumps({
    'pending': len(ex.migration_plan(ex.loader.graph.leaf_nodes())),
    'applications': len(apps),
    'registration_hash': hashlib.sha256(json.dumps([apps,providers],default=str,sort_keys=True).encode()).hexdigest()}))
"""


def docker(*args, timeout=120):
    result = subprocess.run(['docker', *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout, check=True)
    return result.stdout.strip()


def active(project, service, image, expected_hash):
    ids = docker('ps', '--all', '--no-trunc', '--quiet', '--filter', 'label=com.docker.compose.project='+project,
                 '--filter', 'label=com.docker.compose.service='+service)
    require(re.fullmatch('[0-9a-f]{64}', ids), 'Expected exactly one owned Authentik container')
    fmt = '{{.Config.Image}} {{.State.Status}} {{.State.Health.Status}} {{index .Config.Labels "com.docker.compose.config-hash"}}'
    require(docker('inspect', '--type=container', '--format', fmt, ids).split() == [image, 'running', 'healthy', expected_hash],
            'The selected Authentik service did not become healthy on its pinned image')
    return ids


def check(selection, file, image):
    document = read_json(file, private=True)
    project = selection['project']
    services = docker('ps', '--all', '--filter', 'label=com.docker.compose.project='+project,
                      '--format', '{{.Label "com.docker.compose.service"}}').splitlines()
    require(sorted(services) == sorted(document['services']), 'Preserve unexpected or missing project services')
    roles = selection['roles']
    hashes = dict(line.split() for line in docker(*compose(project, file), 'config', '--hash', ','.join(roles)).splitlines())
    require(set(hashes) == set(roles) and all(re.fullmatch('[0-9a-f]{64}', value) for value in hashes.values()),
            'Verify the expected Compose service definitions')
    worker_id = None
    for role in roles:
        worker_id = active(project, role, image, hashes[role])
    text = docker('exec', worker_id, 'ak', 'shell', '-c', PROBE)
    records = [json.loads(line.removeprefix('AK_UPGRADE=')) for line in text.splitlines() if line.startswith('AK_UPGRADE=')]
    require(len(records) == 1 and records[0]['pending'] == 0, 'Outstanding migrations on this Authentik release')
    peers = {}
    for service in selection['peers']:
        container = docker('ps', '--all', '--no-trunc', '--quiet', '--filter', 'label=com.docker.compose.project='+project,
                           '--filter', 'label=com.docker.compose.service='+service)
        require(re.fullmatch('[0-9a-f]{64}', container), 'Require one container per shared project peer')
        facts = docker('inspect', '--type=container', '--format', '{{.State.StartedAt}} {{.RestartCount}}', container)
        peers[service] = digest(encoded([container, facts]))
    return dict(records[0], peers=peers)


def publish(path, value):
    if path.exists() or path.is_symlink():
        require(regular(path, private=True) == encoded(value), 'Preserve the existing immutable migration receipt')
    else:
        write_new(path, encoded(value))


def compose(project, file):
    return ['compose', '--project-directory', str(APP_ROOT), '-p', project, '-f', str(file)]


def release_image(journal, index):
    prior = read_json(journal/f'started-{index}.json', private=True)
    if prior['pulled_for_maintenance']:
        # Docker may keep a shared or already removed image. Neither case invalidates a checkpoint.
        try:
            if not docker('ps', '--all', '--quiet', '--filter', 'ancestor='+prior['image']):
                docker('image', 'rm', prior['image'])
        except subprocess.CalledProcessError:
            pass


def run(selection, canonical, *, final=False):
    root = canonical.parent
    private_directory(root)
    require(root == APP_ROOT and re.fullmatch(r'[a-z][a-z0-9_-]{0,62}\.ya?ml', canonical.name),
            'Maintain the admitted Authentik project only')
    identity = digest(encoded(selection))
    parent = root/'.authentik-upgrades'
    private_directory(parent, create=not parent.exists())
    journal = parent/identity
    private_directory(journal, create=not journal.exists())
    # Existing Compose files are private and carry no runtime secret values for this adapter.
    require(read_json(canonical, private=True) == selection['final' if final else 'initial'],
            'Installed Compose differs from the declared maintenance selection')
    project = selection['project']
    refs = selection['images']
    initial = journal/'baseline.json'
    if final:
        baseline = read_json(initial, private=True)
        last = len(selection['stages'])
        require(read_json(journal/f'completed-{last}.json', private=True) == {'image':refs[-2], 'readback':baseline},
                'Require the last intermediate release receipt before accepting the final target')
        require(check(selection, canonical, refs[-1]) == baseline, 'Final Authentik registration readback changed')
        publish(journal/'final.json', {'image':refs[-1], 'readback':baseline})
        release_image(journal, last)
        return {'completed':last + 1, 'last_release':refs[-1]}
    if not initial.exists():
        publish(initial, check(selection, canonical, refs[0]))
    baseline = read_json(initial, private=True)
    previous_file = journal/'source.yml'
    publish(previous_file, selection['initial'])
    rows = list(zip(refs[1:-1], selection['stages'], strict=True))
    completed = 0
    for index, (image, document) in enumerate(rows, 1):
        stage = journal/f'stage-{index}.yml'
        publish(stage, document)
        finished = journal/f'completed-{index}.json'
        started = journal/f'started-{index}.json'
        if finished.exists():
            receipt = read_json(finished, private=True)
            require(receipt == {'image':image, 'readback':baseline} and started.exists(),
                    'Unexpected completed Authentik checkpoint')
            completed += 1
            previous_file = stage
            continue
        require(not any((journal/f'started-{later}.json').exists() for later in range(index+1, len(rows)+1)),
                'Preserve out-of-order Authentik migration evidence')
        if started.exists():
            # A lost acknowledgement can be accepted only after native readback. Never start an older image.
            require(read_json(started, private=True)['image'] == image and check(selection, stage, image) == baseline,
                    'An interrupted migration needs operator recovery')
        else:
            require(check(selection, previous_file, refs[index-1]) == baseline, 'The previous Authentik checkpoint changed')
            argv = compose(project, stage)
            docker(*argv, 'config', '--quiet')
            cached = set(docker('image', 'ls', '--digests', '--format', '{{.Repository}}@{{.Digest}}').splitlines())
            repo_digest = image.split(':', 1)[0]+'@'+image.split('@')[1]
            docker('pull', image, timeout=600)
            publish(started, {'image':image, 'pulled_for_maintenance':repo_digest not in cached})
            docker(*compose(project,previous_file), 'stop', '--timeout', '60', *selection['roles'], timeout=150)
            if selection['redis'] not in document['services'] and selection['redis'] in read_json(previous_file, private=True)['services']:
                retire(dict(project=project, services=selection['roles'], peers=selection['peers'],
                            previously_owned=True, lifecycle='retained'), canonical)
            docker(*argv, 'up', '-d', '--wait', '--wait-timeout', '240', '--no-deps', *selection['roles'], timeout=330)
            require(check(selection, stage, image) == baseline, 'Application registration readback changed')
        publish(finished, {'image':image, 'readback':baseline})
        if index > 1:
            release_image(journal, index-1)
        previous_file = stage
    require(check(selection, previous_file, refs[-2]) == baseline, 'Final intermediate release differs from its receipt')
    return {'completed':len(rows), 'changed':completed < len(rows), 'last_release':refs[-2]}


def main():
    os.umask(0o077)
    require(len(sys.argv) == 2 or sys.argv[2:] == ['final'], 'Select a maintenance operation')
    print(json.dumps(run(json.load(sys.stdin), Path(sys.argv[1]), final=len(sys.argv) == 3)))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # The journal identifies the stage; omit raw Docker/worker output.
        sys.exit('Authentik maintenance stopped: '+(str(error) if type(error) is ValueError else type(error).__name__))
