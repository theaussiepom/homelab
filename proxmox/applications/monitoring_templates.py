"""Apply the explicit HTTP TLS policy to an in-memory upstream template copy."""
import argparse
import json
import sys
import hashlib
import uuid
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
    resources = [row for row in items if row.get('key') == 'proxmox.cluster.resources']
    if len(resources) != 1 or resources[0].get('history') not in ('1h', '3600'):
        raise ValueError('Retain one hour of cluster-resource values for authenticated native readback')


def prepared(name):
    monitoring.check_templates()
    if name not in monitoring.VERSIONS['templates']:
        raise ValueError('Select a pinned official template')
    document = yaml.safe_load((monitoring.ROOT / 'templates' / name).read_text())
    if name == 'template_app_docker.yaml':
        template = document['zabbix_export']['templates'][0]
        old_name, new_name = template['template'], 'HomeLab Docker by active agent 2'
        def active_copy(node):
            if isinstance(node, dict):
                for key, child in list(node.items()):
                    if key == 'uuid':
                        raw = hashlib.sha256(('homelab/docker-active/' + child).encode()).digest()[:16]
                        node[key] = uuid.UUID(bytes=raw, version=4).hex
                    elif isinstance(child, str):
                        node[key] = child.replace(old_name, new_name)
                    else:
                        active_copy(child)
                for key in ('items', 'item_prototypes', 'discovery_rules'):
                    for item in node.get(key, []):
                        if item.get('type', 'ZABBIX_PASSIVE') == 'ZABBIX_PASSIVE':
                            item['type'] = 'ZABBIX_ACTIVE'
            elif isinstance(node, list):
                for child in node:
                    active_copy(child)
        for key, child in document['zabbix_export'].items():
            if key != 'template_groups':
                active_copy(child)
    if name == 'template_app_proxmox.yaml':
        for item in http_agents(document):
            item.update(verify_peer='YES', verify_host='YES')
            if item.get('key') == 'proxmox.cluster.resources':
                # item.get lastclock/lastvalue come from stored history. The
                # upstream raw master disables it, making acceptance unreadable.
                item['history'] = '1h'
        check_readback(document)
    if name == 'template_db_influxdb_http.yaml':
        for template in document['zabbix_export']['templates']:
            template.pop('discovery_rules', None)
            template['macros'] = [m for m in template.get('macros', [])
                                  if m['macro'] != '{$INFLUXDB.API.TOKEN}']
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
