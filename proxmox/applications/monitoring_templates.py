"""Apply the explicit HTTP TLS policy to an in-memory upstream template copy."""
import argparse
import json
import sys
import yaml
import monitoring


def http_agents(value):
    if isinstance(value, dict):
        if value.get('type') == 'HTTP_AGENT':
            yield value
        for child in value.values():
            yield from http_agents(child)
    elif isinstance(value, list):
        for child in value:
            yield from http_agents(child)


def check_readback(document):
    if isinstance(document, str):
        document = json.loads(document)
    items = list(http_agents(document))
    if len(items) != 7 or any(row.get(field) != 'YES' for row in items for field in ('verify_peer', 'verify_host')):
        raise ValueError('Every pinned Proxmox HTTP item and prototype must verify its peer and hostname')


def prepared(name):
    monitoring.check_templates()
    if name not in monitoring.VERSIONS['templates']:
        raise ValueError('Select a pinned official template')
    document = yaml.safe_load((monitoring.ROOT / 'templates' / name).read_text())
    if name == 'template_app_proxmox.yaml':
        for item in http_agents(document):
            item.update(verify_peer='YES', verify_host='YES')
        check_readback(document)
    return document


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--name', choices=list(monitoring.VERSIONS['templates']))
    mode.add_argument('--check-readback', action='store_true')
    args = parser.parse_args()
    if args.check_readback:
        check_readback(json.load(sys.stdin))
        print('All seven HTTP items/prototypes require peer and hostname verification.')
    else:
        print(json.dumps(prepared(args.name)))
