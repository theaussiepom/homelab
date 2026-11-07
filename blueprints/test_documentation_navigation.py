"""Public navigation and bounded Markdown checks, with adversarial fixtures."""
from pathlib import Path
import tempfile
import unittest

from test_documentation_navigation_helpers import check_documents, parse_markdown

ROOT = Path(__file__).resolve().parents[1]


class DocumentationNavigation(unittest.TestCase):
    def test_public_documentation_destinations_and_structure(self):
        pages = [ROOT / 'README.md', ROOT / 'AGENTS.md', *ROOT.glob('docs/**/*.md')]
        report = check_documents(ROOT, pages, entry_pages=[ROOT / 'README.md', ROOT / 'AGENTS.md'])
        self.assertGreater(report['pages'], 1)
        self.assertGreater(report['links'], 0)
        self.assertEqual(report['errors'], [], '\n'.join(report['errors']))


class NavigationMechanism(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def write(self, relative, text):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def test_supported_links_headings_anchors_and_table_forms(self):
        self.write('docs/Types (all).md', '# API `type`\n## Repeated\n## Repeated\n<a id="custom"></a>\n')
        page = self.write('README.md', r'''# Documentation
[Nested [label]](<docs/Types (all).md#api-type> "Title")
[Second](docs/Types%20%28all%29.md#repeated-1)
[Reference][types]
[types][]
[types]
![Image](image.svg)
[types]: <docs/Types (all).md#custom>
| Field | Value |
| --- | --- |
| `choice` | `a\|b` |
````md
```md
[fake](missing.md)
```
````
~~~text
[fake](missing.md)
~~~
`[not a link](missing.md)`
    [indented code](missing.md)
<!-- [comment](missing.md) -->
''')
        self.write('image.svg', '<svg/>')
        result = check_documents(self.root, [page])
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['links'], 6)

    def test_missing_wrong_case_escaped_scope_and_fragment_fail(self):
        self.write('docs/Types.md', '# Types\n')
        page = self.write('README.md', '''# Home
[missing](absent.md)
[case](docs/types.md)
[fragment](docs/Types.md#absent)
[escape](../outside.md)
[absolute](/operator/private.md)
[bad][undefined]
''')
        errors = check_documents(self.root, [page])['errors']
        self.assertEqual(len(errors), 6, errors)
        self.assertTrue(any('wrong-case' in error for error in errors))
        self.assertTrue(any('missing anchor' in error for error in errors))
        self.assertTrue(any('missing reference definition' in error for error in errors))

    def test_anchors_collisions_tables_fences_and_reference_ambiguity_fail(self):
        _, _, errors = parse_markdown('''# Same
<a id="same"></a>
<a id="custom"></a>
<a id="custom"></a>
[target]: a.md
[target]: b.md
| Field | Value |
| --- | --- |
| too | many | cells |
```yaml
missing: closing fence
''')
        self.assertEqual(len(errors), 5, errors)
        for category in ('duplicate/colliding anchor', 'duplicate reference', 'table has', 'unclosed fenced'):
            self.assertTrue(any(category in error for error in errors), errors)

    def test_selected_cross_repository_links_are_checked_without_network(self):
        dependency = self.root / 'selected'
        self.write('selected/docs/Types.md', '# Types\n')
        self.write('selected/source.py', 'first\nsecond\n')
        page = self.write('README.md', '''# Home
[type](https://github.com/example/framework/blob/abc/docs/Types.md#types)
[line](https://github.com/example/framework/blob/abc/source.py#L1-L2)
[wrong](https://github.com/example/framework/blob/abc/source.py#L9)
[unselected](https://github.com/example/framework/blob/other/docs/missing.md)
[external](https://example.invalid/missing)
''')
        result = check_documents(self.root, [page], {('example/framework', 'abc'): dependency})
        self.assertEqual(result['links'], 3)
        self.assertEqual(result['external_unverified'], 2)
        self.assertEqual(len(result['errors']), 1)
        self.assertIn('invalid source line anchor', result['errors'][0])

    def test_missing_pages_empty_scope_and_unclosed_links_fail(self):
        self.assertEqual(check_documents(self.root, [])['errors'], ['empty documentation scope'])
        self.assertIn('missing documentation page', check_documents(self.root, [self.root / 'missing.md'])['errors'][0])
        page = self.write('README.md', '# Home\n[broken](missing.md\n')
        self.assertIn('unclosed link destination', check_documents(self.root, [page])['errors'][0])

    def test_orphans_and_literal_malformed_fragments_cannot_pass(self):
        home = self.write('README.md', '# Home\n[wrong](leaf.md#`leaf`)\n')
        leaf = self.write('leaf.md', '# Leaf\n')
        orphan = self.write('orphan.md', '# Orphan\n')
        errors = check_documents(self.root, [home, leaf, orphan])['errors']
        self.assertEqual(len(errors), 2, errors)
        self.assertTrue(any('missing anchor #`leaf`' in error for error in errors))
        self.assertTrue(any('orphan.md: orphan' in error for error in errors))
        home.write_text('# Home\n[Leaf](leaf.md#leaf)\n')
        leaf.write_text('# Leaf\n[Next](orphan.md)\n')
        self.assertEqual(check_documents(self.root, [home, leaf, orphan])['errors'], [])


if __name__ == '__main__':
    unittest.main()
