"""Exercise the selected Traefik plugin against a stock Authentik admin API in isolation."""
import argparse
import json
import secrets
import subprocess
import tempfile
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for image in ('authentik', 'traefik', 'postgres'):
        parser.add_argument('--' + image, required=True)
    args = parser.parse_args()
    fixtures = Path(__file__).resolve().parent
    plugin = fixtures.parent / 'traefik_registrations'
    module = 'github.com/theaussiepom/homelab-registrations'
    project = 'registration-guard-' + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix=project + '-') as tmp:
        root = Path(tmp)
        root.chmod(0o755)
        credentials = secrets.token_urlsafe(32)
        environment = {
            'AUTHENTIK_POSTGRESQL__HOST': 'pg', 'AUTHENTIK_POSTGRESQL__USER': 'fixture',
            'AUTHENTIK_POSTGRESQL__PASSWORD': credentials, 'AUTHENTIK_POSTGRESQL__NAME': 'fixture',
            'AUTHENTIK_SECRET_KEY': secrets.token_urlsafe(48), 'AUTHENTIK_DISABLE_UPDATE_CHECK': 'true',
            'AUTHENTIK_ERROR_REPORTING__ENABLED': 'false',
        }
        services = {'pg': {
            'image': args.postgres, 'environment': {
                'POSTGRES_PASSWORD': credentials, 'POSTGRES_USER': 'fixture', 'POSTGRES_DB': 'fixture'},
            'healthcheck': {'test': ['CMD', 'pg_isready', '-U', 'fixture'], 'interval': '2s', 'retries': 60}}}
        for role in ('worker', 'server'):
            services[role] = {'image': args.authentik, 'environment': environment, 'command': role,
                              'depends_on': {'pg': {'condition': 'service_healthy'}}}
        static = {'entryPoints': {'web': {'address': ':8080'}},
                  'providers': {'file': {'filename': '/fixture/dynamic.yml'}},
                  'experimental': {'localPlugins': {'registrations': {'moduleName': module}}},
                  'global': {'checkNewVersion': False}}
        inventory = {'active': {'managed': 'Managed fixture'}, 'retired': {},
                     'receipts': ['homelab-forward-managed']}
        dynamic = {'http': {'routers': {'sso': {'rule': 'Host(`sso.example.invalid`)', 'service': 'sso',
                                                'entryPoints': ['web'], 'middlewares': ['guard']}},
                            'services': {'sso': {'loadBalancer': {'servers': [{'url': 'http://server:9000'}]}}},
                            'middlewares': {'guard': {'plugin': {'registrations': {
                                'inventory': json.dumps(inventory)}}}}}}
        for name, value in [('static', static), ('dynamic', dynamic)]:
            (root / (name + '.yml')).write_text(json.dumps(value))
        services['ingress'] = {'image': args.traefik, 'command': ['--configFile=/fixture/static.yml'],
                               'volumes': [f'{root}/static.yml:/fixture/static.yml:ro',
                                           f'{root}/dynamic.yml:/fixture/dynamic.yml:ro',
                                           f'{plugin}:/plugins-local/src/{module}:ro']}
        for service in services.values():
            service['platform'] = 'linux/amd64'
        file = root / 'compose.json'
        file.write_text(json.dumps({'services': services, 'networks': {'default': {'internal': True}}}))
        cli = ['docker', 'compose', '-p', project, '-f', str(file)]
        try:
            subprocess.run(cli + ['up', '-d', '--wait', '--wait-timeout', '360'], check=True, timeout=420)
            script = (fixtures / 'registration_guard_client.py').read_text()
            subprocess.run(cli + ['exec', '-T', 'worker', 'python', 'manage.py', 'shell', '-c', script],
                           check=True, timeout=180)
        finally:
            subprocess.run(cli + ['down', '-v', '--remove-orphans'], check=True, timeout=100)


if __name__ == '__main__':
    main()
