"""Mutation evidence for the bounded network/NIC documentation mechanism."""
import ast
from dataclasses import replace
from pathlib import Path
import unittest

import component_types
from test_component_reference_examples import example
from test_documentation_contract_helpers import (
    BINDINGS, PAGE, SOURCE, assert_typed_equal, check_contract,
    expect_component_refusal, inventory, named_example,
)
import authored_config

ROOT = Path(__file__).resolve().parents[1]


class DocumentationConformanceMechanism(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / SOURCE).read_text()
        self.markdown = (ROOT / PAGE).read_text()

    def check(self, source=None, markdown=None, bindings=BINDINGS):
        return check_contract(self.source if source is None else source,
                              self.markdown if markdown is None else markdown,
                              bindings, lambda path: (ROOT / path).read_text())

    def changed_owner(self, source, owner):
        # Exercise the real owner with one disposable source declaration changed;
        # do not create a fake validator or change any repository runtime source.
        node = next(node for node in ast.parse(source).body
                    if isinstance(node, ast.FunctionDef) and node.name == owner)
        namespace = dict(vars(component_types))
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<disposable-owner>', 'exec'), namespace)
        return namespace[owner]

    def test_new_accepted_optional_field_and_union_branch_require_documentation(self):
        source = self.source.replace("('gateway',))", "('gateway', 'mtu'))", 1)
        self.changed_owner(source, 'network')(dict(example('networks.md', 'network-minimal'), mtu=1500))
        with self.assertRaisesRegex(AssertionError, r'DOC_UNDOCUMENTED_CONTROL:.*network.mtu'):
            self.check(source=source)
        source = self.source.replace("('static', 'dhcp', 'manual')", "('static', 'dhcp', 'manual', 'automatic')", 1)
        source = source.replace("'manual': None}", "'manual': None, 'automatic': None}", 1)
        self.changed_owner(source, 'interface')(dict(example('networks.md', 'nic-minimal'),
                                                   address={'mode': 'automatic'}, default_route=False))
        with self.assertRaisesRegex(AssertionError, r'DOC_UNDOCUMENTED_CONTROL:.*guest-nic.address.automatic.mode'):
            self.check(source=source)

    def test_stale_mapping_and_orphan_documented_row_fail_in_reverse(self):
        source = self.source.replace("('gateway',))", "())", 1)
        with self.assertRaisesRegex(AssertionError, r'DOC_STALE_MAPPING:.*network.gateway'):
            self.check(source=source)
        row = next(line for line in self.markdown.splitlines() if '| `networks.<id>.gateway` |' in line)
        with self.assertRaisesRegex(AssertionError, r'DOC_ORPHAN_RECORD:.*network.obsolete'):
            self.check(markdown=self.markdown.replace(row, row + '\n' + row.replace('.gateway`', '.obsolete`')))

    def test_source_and_document_presence_drift_are_independent(self):
        source = self.source.replace("'bridge', 'vlan'), ('gateway',)", "'bridge', 'vlan', 'gateway'), ()", 1)
        with self.assertRaisesRegex(AssertionError, r'DOC_FACT_DRIFT:.*network.gateway'):
            self.check(source=source)
        row = next(line for line in self.markdown.splitlines() if '| `networks.<id>.gateway` |' in line)
        with self.assertRaisesRegex(AssertionError, r'DOC_FACT_DRIFT:.*network.gateway'):
            self.check(markdown=self.markdown.replace(row, row.replace('Optional', 'Required')))

    def test_missing_duplicate_record_cell_and_anchor_refuse_ambiguity(self):
        row = next(line for line in self.markdown.splitlines() if '| `networks.<id>.gateway` |' in line)
        anchor = '<a id="field-network-gateway"></a>'
        for changed, category in (
            (self.markdown.replace(row, ''), 'DOC_MISSING_RECORD'),
            (self.markdown.replace(row, row + '\n' + row), 'DOC_AMBIGUOUS_RECORD'),
            (self.markdown.replace(row, row.replace('| Optional |', '| |')), 'DOC_TABLE_SHAPE'),
            (self.markdown.replace('| Presence | Type |', '| Presence | Presence | Type |', 1), 'DOC_TABLE_SHAPE'),
            (self.markdown.replace(anchor, ''), 'DOC_ANCHOR'),
            (self.markdown.replace(anchor, anchor + '\n' + anchor), 'DOC_ANCHOR'),
        ):
            with self.subTest(category=category), self.assertRaisesRegex(AssertionError, category):
                self.check(markdown=changed)

    def test_dead_source_example_and_evidence_pointers_fail(self):
        for binding, category in (
            (replace(BINDINGS[0], path='cidr'), 'DOC_SOURCE_POINTER'),
            (replace(BINDINGS[0], example='removed-example'), 'DOC_EXAMPLE_POINTER'),
            (replace(BINDINGS[0], evidence=(BINDINGS[0].evidence[0], 'ReferenceExamples', 'test_removed')), 'DOC_EVIDENCE_POINTER'),
        ):
            with self.subTest(category=category), self.assertRaisesRegex(AssertionError, category):
                self.check(bindings=(binding, *BINDINGS[1:]))
        with self.assertRaisesRegex(AssertionError, 'DOC_AMBIGUOUS_MAPPING'):
            self.check(bindings=(*BINDINGS, BINDINGS[0]))

    def test_unclassified_branch_and_empty_scope_never_pass(self):
        source = self.source.replace("closed(value, ('context', 'cidr', 'bridge', 'vlan'), ('gateway',))",
                                     "closed(value, network_fields)", 1)
        with self.assertRaisesRegex(AssertionError, 'DOC_UNCLASSIFIED_INVENTORY'):
            self.check(source=source)
        source = self.source.replace("'manual': None}", "'manual': None, 'automatic': None}", 1)
        with self.assertRaisesRegex(AssertionError, 'DOC_UNCLASSIFIED_INVENTORY'):
            self.check(source=source)
        source = self.source.replace("closed(value, ('context', 'cidr', 'bridge', 'vlan'), ('gateway',))",
                                     "pass", 1)
        with self.assertRaisesRegex(AssertionError, 'DOC_EMPTY_SCOPE'):
            inventory(source)
        with self.assertRaisesRegex(AssertionError, 'DOC_EMPTY_SCOPE'):
            self.check(markdown='# No field records\n')
        with self.assertRaisesRegex(AssertionError, 'DOC_EMPTY_SCOPE'):
            self.check(bindings=())

    def test_stale_excerpt_and_strict_authored_value_drift_fail(self):
        original = example('networks.md', 'network-minimal')
        changed = self.markdown.replace('bridge: example0', 'bridge: stale0', 1)
        parsed = authored_config.parse(named_example(changed, 'network-minimal').encode(), '.yaml')
        component_types.network(parsed)  # Still accepted: compilation alone misses stale prose.
        with self.assertRaisesRegex(AssertionError, 'DOC_FACT_DRIFT'):
            assert_typed_equal(parsed, original, 'network excerpt -> canonical complete site')
        for actual, expected in ((True, 1), ('50', 50), ({}, {'gateway': None}), ([], None), ([1, 2], [2, 1])):
            with self.subTest(actual=actual, expected=expected), self.assertRaisesRegex(AssertionError, 'DOC_FACT_DRIFT'):
                assert_typed_equal(actual, expected, 'typed authored value')
        assert_typed_equal({'a': 1, 'b': None}, {'b': None, 'a': 1}, 'unordered object keys')

    def test_wrong_refusal_and_unexpected_success_are_not_negative_evidence(self):
        valid = example('networks.md', 'network-minimal')
        wrong = dict(valid, vlan=4095)
        expect_component_refusal(lambda: component_types.network(wrong), 'component.integer', ())
        with self.assertRaisesRegex(AssertionError, 'DOC_WRONG_REFUSAL'):
            expect_component_refusal(lambda: component_types.network(wrong), 'component.fields', ())
        with self.assertRaisesRegex(AssertionError, 'DOC_UNEXPECTED_SUCCESS'):
            expect_component_refusal(lambda: component_types.network(valid), 'component.integer', ())


if __name__ == '__main__':
    unittest.main()
