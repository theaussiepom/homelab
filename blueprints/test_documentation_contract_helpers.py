"""Test-local network/NIC pilot. Pointers connect, never redefine, the API.

Only unconditional closed-object declarations and the existing literal tagged
union are inventoried. Any other closed declaration in these owners fails with
an unclassified result. Procedural constraints still need source/test review.
"""
import ast
from dataclasses import dataclass
import re


SOURCE = 'blueprints/component_types.py'
PAGE = 'docs/reference/networks.md'
OWNERS = {'network': ('network', 'networks.<id>'),
          'interface': ('guest-nic', 'guests.<id>.interfaces.<id>')}
EVIDENCE = ('blueprints/test_component_reference_examples.py', 'ReferenceExamples',
            'test_network_nic_variants_and_exact_refusals')


@dataclass(frozen=True)
class Binding:
    control: str
    owner: str
    path: str
    variant: str
    anchor: str
    example: str
    evidence: tuple = EVIDENCE


# These are solely source, documentation and executable-evidence locators.
BINDINGS = (
    Binding('network.context', 'network', 'context', 'all', 'field-network-context', 'network-minimal'),
    Binding('network.cidr', 'network', 'cidr', 'all', 'field-network-cidr', 'network-minimal'),
    Binding('network.bridge', 'network', 'bridge', 'all', 'field-network-bridge', 'network-minimal'),
    Binding('network.vlan', 'network', 'vlan', 'all', 'field-network-vlan', 'network-minimal'),
    Binding('network.gateway', 'network', 'gateway', 'all', 'field-network-gateway', 'network-minimal'),
    Binding('guest-nic.network', 'interface', 'network', 'all', 'field-guest-nic-network', 'nic-minimal'),
    Binding('guest-nic.slot', 'interface', 'slot', 'all', 'field-guest-nic-slot', 'nic-minimal'),
    Binding('guest-nic.mac', 'interface', 'mac', 'all', 'field-guest-nic-mac', 'nic-minimal'),
    Binding('guest-nic.address', 'interface', 'address', 'all', 'field-guest-nic-address', 'nic-minimal'),
    Binding('guest-nic.default_route', 'interface', 'default_route', 'all', 'field-guest-nic-default-route', 'nic-minimal'),
    Binding('guest-nic.ipv6', 'interface', 'ipv6', 'all', 'field-guest-nic-ipv6', 'nic-minimal'),
    Binding('guest-nic.ip_filter', 'interface', 'ip_filter', 'all', 'field-guest-nic-ip-filter', 'nic-ip-filter'),
    Binding('guest-nic.address.static.mode', 'interface', 'address.mode', 'static', 'field-guest-nic-address-mode', 'nic-minimal'),
    Binding('guest-nic.address.static.value', 'interface', 'address.value', 'static', 'field-guest-nic-address-value', 'nic-minimal'),
    Binding('guest-nic.address.dhcp.mode', 'interface', 'address.mode', 'dhcp', 'field-guest-nic-address-mode', 'nic-minimal'),
    Binding('guest-nic.address.dhcp.endpoint', 'interface', 'address.endpoint', 'dhcp', 'field-guest-nic-address-endpoint', 'nic-minimal'),
    Binding('guest-nic.address.manual.mode', 'interface', 'address.mode', 'manual', 'field-guest-nic-address-mode', 'nic-minimal'),
)

# Reviewed procedural rules are separate from the extracted structural surface.
# Source symbols and executable scenarios are pointers, not inferred semantics.
RULES = (
    ('consumed-network-context', ('blueprints/component_plan.py', 'Resolver', 'guest_values'),
     'field-network-context', (EVIDENCE[0], EVIDENCE[1], 'test_unused_network_context_is_only_checked_when_consumed')),
    ('ordinary-route', (SOURCE, None, 'guest'), 'field-guest-nic-default-route', EVIDENCE),
    ('contiguous-slots', (SOURCE, None, 'guest'), 'field-guest-nic-slot', EVIDENCE),
    ('control-interface-address', (SOURCE, None, 'guest'), 'field-guest-nic-address', EVIDENCE),
    ('usable-addresses', ('blueprints/component_plan.py', 'Resolver', 'guest_values'),
     'field-guest-nic-address', EVIDENCE),
)


def fail(category, detail):
    raise AssertionError(f'{category}: {detail}')


def _control(owner, path, variant):
    prefix = OWNERS[owner][0]
    parent, _, leaf = path.rpartition('.')
    return '.'.join(part for part in (prefix, parent, variant if variant != 'all' else '', leaf) if part)


def inventory(source):
    """Recover keys and presence from their actual closed() declarations."""
    tree = ast.parse(source)
    found = {}
    for owner in OWNERS:
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == owner]
        if len(functions) != 1:
            fail('DOC_SOURCE_OWNER', f'{SOURCE}:{owner}: expected one function')
        function = functions[0]
        aliases, selectors = {'value': ''}, {}

        def unclassified(node):
            fail('DOC_UNCLASSIFIED_INVENTORY', f'{SOURCE}:{owner}:{node.lineno}: review declaration pattern')

        def path_of(node):
            if isinstance(node, ast.Name) and node.id in aliases:
                return aliases[node.id]
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                return '.'.join(filter(None, (path_of(node.value), node.slice.value)))
            unclassified(node)

        # Deliberately narrow: aliases and a literal dictionary indexed by the
        # address discriminator, not evaluation of arbitrary Python source.
        for statement in function.body:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
                continue
            name, value = statement.targets[0].id, statement.value
            if isinstance(value, ast.Subscript) and isinstance(value.value, ast.Name) and value.value.id in aliases:
                aliases[name] = path_of(value)
            elif isinstance(value, ast.Subscript) and isinstance(value.value, ast.Dict):
                try:
                    branches = ast.literal_eval(value.value)
                except (ValueError, TypeError):
                    unclassified(value)
                if not isinstance(value.slice, ast.Subscript) or not isinstance(value.slice.slice, ast.Constant):
                    unclassified(value)
                target = path_of(value.slice.value)
                discriminator = value.slice.slice.value
                if (not branches or not all(isinstance(k, str) and (v is None or isinstance(v, str)) for k, v in branches.items())
                        or not isinstance(discriminator, str)):
                    unclassified(value)
                # The literal accepted enum and selected branches must agree;
                # adding only one side cannot silently produce partial coverage.
                enums = []
                for node in ast.walk(function):
                    if (isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.In)
                            and isinstance(node.left, ast.Call) and isinstance(node.left.func, ast.Attribute)
                            and node.left.func.attr == 'get' and len(node.left.args) == 1
                            and isinstance(node.left.args[0], ast.Constant) and node.left.args[0].value == discriminator
                            and ast.dump(node.left.func.value) == ast.dump(value.slice.value)):
                        try:
                            enums.append(ast.literal_eval(node.comparators[0]))
                        except (ValueError, TypeError):
                            unclassified(node)
                if len(enums) != 1 or not isinstance(enums[0], tuple) or set(enums[0]) != set(branches):
                    unclassified(value)
                selectors[name] = (target, branches)

        calls = [n for n in ast.walk(function) if isinstance(n, ast.Call) and
                 ((isinstance(n.func, ast.Name) and n.func.id == 'closed') or
                  (isinstance(n.func, ast.Attribute) and n.func.attr == 'closed'))]
        if not calls:
            fail('DOC_EMPTY_SCOPE', f'{SOURCE}:{owner}: no closed declarations')
        direct = {id(n.value) for n in function.body if isinstance(n, ast.Expr)}
        for call in calls:
            if id(call) not in direct or not isinstance(call.func, ast.Name) or call.keywords or not 2 <= len(call.args) <= 3:
                unclassified(call)
            target = path_of(call.args[0])
            selected = [name for name in selectors if any(isinstance(n, ast.Name) and n.id == name
                        for arg in call.args[1:] for n in ast.walk(arg))]
            if len(selected) > 1:
                unclassified(call)
            if selected and selectors[selected[0]][0] != target:
                unclassified(call)
            variants = selectors[selected[0]][1] if selected else {'all': None}

            def keys(node, field):
                if isinstance(node, ast.Tuple):
                    values = []
                    for child in node.elts:
                        if isinstance(child, ast.Constant) and isinstance(child.value, str):
                            values.append(child.value)
                        elif isinstance(child, ast.Name) and selected and child.id == selected[0] and isinstance(field, str):
                            values.append(field)
                        else:
                            unclassified(child)
                    return values
                if (isinstance(node, ast.IfExp) and isinstance(node.test, ast.Compare)
                        and isinstance(node.test.left, ast.Name) and selected and node.test.left.id == selected[0]
                        and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.Is)
                        and len(node.test.comparators) == 1 and isinstance(node.test.comparators[0], ast.Constant)
                        and node.test.comparators[0].value is None):
                    return keys(node.body if field is None else node.orelse, field)
                unclassified(node)

            for variant, field in variants.items():
                for position, argument in enumerate(call.args[1:]):
                    for key in keys(argument, field):
                        path = '.'.join(filter(None, (target, key)))
                        control = _control(owner, path, variant)
                        if control in found:
                            fail('DOC_AMBIGUOUS_SOURCE', f'{SOURCE}:{owner}: {control}')
                        found[control] = {'owner': owner, 'path': path, 'variant': variant,
                                          'presence': 'Required' if position == 0 else 'Optional',
                                          'line': call.lineno}
    return found


def _cells(line):
    # GFM requires escaping literal pipes even inside inline code.
    cells, current, ticks = [], '', 0
    for token in re.findall(r'\\.|`+|[^\\`|]+|\||\\', line.strip()):
        if token.startswith('`'):
            ticks = 0 if ticks == len(token) else len(token) if not ticks else ticks
        if token == '|':
            cells.append(current.strip()); current = ''
        else:
            current += token
    cells.append(current.strip())
    if cells[0] or cells[-1] or ticks:
        fail('DOC_TABLE_SHAPE', f'{PAGE}: unsupported row {line}')
    return cells[1:-1]


def _unquote(value):
    return value[1:-1] if value.startswith('`') and value.endswith('`') else value


def documented_records(markdown):
    """Enumerate normal reader-facing field rows independently of BINDINGS."""
    text = re.sub(r'(?ms)^```[^\n]*\n.*?^```\s*$', '', markdown)
    records, header = {}, None
    for line in text.splitlines():
        if not line.startswith('|'):
            header = None
            continue
        cells = _cells(line)
        if 'Path' in cells and 'Variant' in cells:
            if not {'Path', 'Variant', 'Presence', 'Record'} <= set(cells) or len(cells) != len(set(cells)):
                fail('DOC_TABLE_SHAPE', f'{PAGE}: missing/duplicate field column')
            header = cells
            continue
        if header is None or all(re.fullmatch(r':?-+:?', cell.replace(' ', '')) for cell in cells):
            continue
        if len(cells) != len(header):
            fail('DOC_TABLE_SHAPE', f'{PAGE}: missing/extra cell')
        row = dict(zip(header, cells))
        path, variant = _unquote(row['Path']), _unquote(row['Variant'])
        owners = [owner for owner, (_, prefix) in OWNERS.items() if path.startswith(prefix + '.')]
        if len(owners) != 1:
            fail('DOC_ORPHAN_RECORD', f'{PAGE}: {path} [{variant}] has no pilot owner')
        owner = owners[0]
        control = _control(owner, path[len(OWNERS[owner][1]) + 1:], variant)
        if control in records:
            fail('DOC_AMBIGUOUS_RECORD', f'{PAGE}: duplicate {control}')
        record = re.fullmatch(r'\[[^\]]+\]\(#([a-z0-9-]+)\)', row['Record'])
        if record is None or not row['Presence']:
            fail('DOC_TABLE_SHAPE', f'{PAGE}: {control}: missing/invalid record or presence cell')
        records[control] = {'anchor': record[1], 'presence': row['Presence']}
    if not records:
        fail('DOC_EMPTY_SCOPE', f'{PAGE}: no supported-control rows')
    return records, text


def check_contract(source, markdown, bindings=BINDINGS, read_text=None):
    accepted = inventory(source)
    records, prose = documented_records(markdown)
    mapped = {row.control: row for row in bindings}
    if not mapped:
        fail('DOC_EMPTY_SCOPE', 'network/NIC mappings are empty')
    if len(mapped) != len(bindings):
        fail('DOC_AMBIGUOUS_MAPPING', 'duplicate control ID')
    for names, other, category in ((accepted, mapped, 'DOC_UNDOCUMENTED_CONTROL'),
                                    (mapped, accepted, 'DOC_STALE_MAPPING'),
                                    (records, accepted, 'DOC_ORPHAN_RECORD'),
                                    (records, mapped, 'DOC_UNMAPPED_RECORD'),
                                    (mapped, records, 'DOC_MISSING_RECORD')):
        difference = sorted(set(names) - set(other))
        if difference:
            fail(category, f'{SOURCE} -> {PAGE}: {", ".join(difference)}')
    for control, binding in mapped.items():
        actual, record = accepted[control], records[control]
        if (binding.owner, binding.path, binding.variant) != (actual['owner'], actual['path'], actual['variant']):
            fail('DOC_SOURCE_POINTER', f'{control}: {SOURCE}:{binding.owner}:{binding.path} [{binding.variant}]')
        if record['anchor'] != binding.anchor or len(re.findall(r'<a id="' + re.escape(binding.anchor) + r'"></a>', prose)) != 1:
            fail('DOC_ANCHOR', f'{control}: {PAGE}#{binding.anchor}: expected one canonical destination')
        if record['presence'] != actual['presence']:
            fail('DOC_FACT_DRIFT', f'{control}: {SOURCE}:{actual["line"]} declares {actual["presence"]}; '
                 f'{PAGE}#{binding.anchor} states {record["presence"]}')
        named_example(markdown, binding.example)
        if read_text is not None:
            resolve_symbol(binding.evidence, read_text, 'DOC_EVIDENCE_POINTER', control, test=True)
    if read_text is not None:
        for rule, source_pointer, anchor, evidence_pointer in RULES:
            resolve_symbol(source_pointer, read_text, 'DOC_SOURCE_POINTER', rule)
            resolve_symbol(evidence_pointer, read_text, 'DOC_EVIDENCE_POINTER', rule, test=True)
            if len(re.findall(r'<a id="' + re.escape(anchor) + r'"></a>', prose)) != 1:
                fail('DOC_ANCHOR', f'{rule}: {PAGE}#{anchor}')
    return len(accepted)


def resolve_symbol(pointer, read_text, category, control, *, test=False):
    filename, class_name, symbol = pointer
    try:
        nodes = ast.parse(read_text(filename)).body
    except FileNotFoundError:
        fail(category, f'{control}: missing source file {filename}')
    if class_name is not None:
        classes = [node for node in nodes if isinstance(node, ast.ClassDef) and node.name == class_name]
        nodes = classes[0].body if len(classes) == 1 else []
    matches = [node for node in nodes if isinstance(node, ast.FunctionDef) and node.name == symbol]
    if len(matches) != 1 or (test and not symbol.startswith('test_')):
        fail(category, f'{control}: {filename}:{class_name or ""}.{symbol}')


def named_example(markdown, name):
    matches = re.findall(r'<!-- example: ' + re.escape(name) + r' -->\n```yaml\n(.*?)\n```', markdown, re.S)
    if len(matches) != 1:
        fail('DOC_EXAMPLE_POINTER', f'{PAGE}/{name}: expected one named YAML fence')
    return matches[0] + '\n'


def assert_typed_equal(actual, expected, location):
    """Equality for authored values, preserving bool/int, null and omission."""
    if type(actual) is not type(expected):
        fail('DOC_FACT_DRIFT', f'{location}: different authored types')
    if isinstance(actual, dict):
        if actual.keys() != expected.keys():
            fail('DOC_FACT_DRIFT', f'{location}: different object fields')
        for key in actual:
            assert_typed_equal(actual[key], expected[key], f'{location}.{key}')
    elif isinstance(actual, list):
        if len(actual) != len(expected):
            fail('DOC_FACT_DRIFT', f'{location}: different list lengths')
        for index, (left, right) in enumerate(zip(actual, expected)):
            assert_typed_equal(left, right, f'{location}[{index}]')
    elif actual != expected:
        fail('DOC_FACT_DRIFT', f'{location}: different authored values')


def expect_component_refusal(action, code, path):
    from component_errors import ComponentError
    try:
        action()
    except ComponentError as error:
        if (error.code, error.path) != (code, path):
            fail('DOC_WRONG_REFUSAL', f'expected {code} at {".".join(path)}; received {error}')
    else:
        fail('DOC_UNEXPECTED_SUCCESS', f'expected {code} at {".".join(path)}')
