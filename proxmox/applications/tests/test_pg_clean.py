"""Enforce the previously accepted clean-dump exception pair without SQL edits."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pg_clean import check_diagnostics

PAIR = '''psql:<stdin>:11: ERROR:  2BP01: cannot drop role postgres because it is required by the database system
DETAIL:  owner of database template1
LOCATION:  checkSharedDependencies, pg_shdepend.c:1234
psql:<stdin>:19: ERROR:  42710: role "postgres" already exists
LOCATION:  CreateRole, user.c:456
'''


class CleanRestoreTests(unittest.TestCase):
    def test_only_the_ordered_bootstrap_pair_is_accepted(self):
        check_diagnostics(PAIR, 0)
        check_diagnostics(PAIR.replace(':1234', ':2000'), 0)

    def test_any_extra_missing_reordered_or_fatal_diagnostic_fails(self):
        for text in ('', PAIR + 'ERROR:  42501: permission denied\n',
                     PAIR.replace('2BP01', '55006'), PAIR.replace('checkSharedDependencies', 'OtherFunction'),
                     PAIR.replace('cannot drop role postgres because it is required by the database system', 'role "postgres" cannot be dropped because some objects depend on it'),
                     PAIR.replace('ERROR:', 'FATAL:', 1), PAIR + 'ERROR: unstructured client error\n',
                     PAIR[PAIR.index('psql:<stdin>:19:'):] + PAIR[:PAIR.index('psql:<stdin>:19:')]):
            with self.subTest(text=text), self.assertRaises(ValueError): check_diagnostics(text, 0)
        with self.assertRaises(ValueError): check_diagnostics(PAIR, 1)


if __name__ == '__main__': unittest.main()
