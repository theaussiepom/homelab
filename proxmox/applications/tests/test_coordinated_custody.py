"""Durable coordinated records refuse ordinary mutation without native contact."""

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy
import test_deployment as cases


def request(vmid, schema='homelab-postgresql-cutover-v1'):
    members = {'postgresql': {'vmid': vmid}, 'identity': {'vmid': vmid + 1}, 'db-tools': {'vmid': vmid + 2}}
    if schema == 'homelab-database-server-cutover-v1':
        members = {'mariadb': {'vmid': vmid}}
    return {'schema': schema, 'operation': 'synthetic', 'members': members}


class CoordinatedCustodyTests(unittest.TestCase):
    def fixture(self):
        case = cases.LifecycleTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def records(self, case, value, *, namespace='database-network-cutover-', claim=True):
        folder = case.root / (namespace + 'synthetic')
        folder.mkdir(mode=0o700)
        raw = (json.dumps(value, indent=2) + '\n').encode()
        (folder / 'request.json').write_bytes(raw); (folder / 'request.json').chmod(0o600)
        if claim:
            (folder / 'claim.json').write_bytes(raw); (folder / 'claim.json').chmod(0o600)
        return folder, raw

    def test_matching_durable_request_and_claim_hold_before_infrastructure_without_markers(self):
        case = self.fixture()
        folder, raw = self.records(case, request(case.cfg['guest']['vmid']))
        backend = (case.work / 'terraform.tfstate').read_bytes()
        with self.assertRaisesRegex(ValueError, 'coordinated maintenance'):
            deploy.run('infrastructure', case.site)
        case.infra.assert_not_called(); case.app.assert_not_called()
        self.assertEqual((folder / 'request.json').read_bytes(), raw)
        self.assertEqual((folder / 'claim.json').read_bytes(), raw)
        self.assertEqual((case.work / 'terraform.tfstate').read_bytes(), backend)
        self.assertFalse((case.work / 'ORDINARY-HOLD.json').exists())
        self.assertFalse(any(case.work.glob('ordinary-*')))

    def test_request_alone_or_completed_record_never_releases_a_selected_member(self):
        for namespace, schema, claim, completed in [
            ('database-network-cutover-', 'homelab-postgresql-cutover-v1', False, False),
            ('database-network-cutover-', 'homelab-postgresql-cutover-v1', True, True),
            ('database-server-cutover-', 'homelab-database-server-cutover-v1', True, False),
        ]:
            case = self.fixture()
            folder, raw = self.records(case, request(case.cfg['guest']['vmid'], schema), namespace=namespace, claim=claim)
            if completed: (folder / 'complete.json').write_text('{"status":"passed"}\n')
            with self.subTest(namespace=namespace, claim=claim, completed=completed), self.assertRaisesRegex(ValueError, 'coordinated maintenance'):
                deploy.run('infrastructure', case.site)
            case.infra.assert_not_called()
            self.assertEqual((folder / 'request.json').read_bytes(), raw)

    def test_recognized_custody_for_other_members_preserves_unrelated_guest_path(self):
        case = self.fixture()
        folder, raw = self.records(case, request(880))
        deploy.run('infrastructure', case.site)
        case.infra.assert_called_once()
        self.assertEqual((folder / 'request.json').read_bytes(), raw)
        self.assertEqual((folder / 'claim.json').read_bytes(), raw)

    def test_custody_appearing_before_a_phase_preserves_existing_ordinary_marker(self):
        case = self.fixture()
        deploy.run('infrastructure', case.site)
        held = (case.work / 'ORDINARY-HOLD.json').read_bytes()
        folder, raw = self.records(case, request(case.cfg['guest']['vmid']))
        with self.assertRaisesRegex(ValueError, 'coordinated maintenance'):
            deploy.run('preparation', case.site)
        case.app.assert_not_called()
        self.assertEqual((case.work / 'ORDINARY-HOLD.json').read_bytes(), held)
        self.assertEqual((folder / 'claim.json').read_bytes(), raw)

    def test_unrecognized_changed_or_unsafe_records_fail_closed_without_mutation(self):
        variants = ['schema', 'members-type', 'roles', 'member-type', 'vmid-type', 'vmid-small', 'duplicate-vmid', 'claim-change', 'missing-request', 'duplicate-json', 'request-mode', 'request-symlink', 'claim-symlink', 'directory-mode', 'directory-symlink', 'directory-file', 'malformed-json', 'protected-vmid', 'server-many', 'server-role', 'dangling-claim', 'top-level', 'oversize']
        for variant in variants:
            case = self.fixture()
            value = request(880)
            if variant == 'top-level': value = []
            if variant == 'schema': value['schema'] = 'unknown-custody'
            if variant == 'members-type': value['members'] = []
            if variant == 'roles': value['members'].pop('db-tools')
            if variant == 'member-type': value['members']['identity'] = []
            if variant == 'vmid-type': value['members']['identity']['vmid'] = True
            if variant == 'vmid-small': value['members']['identity']['vmid'] = 2
            if variant == 'duplicate-vmid': value['members']['identity']['vmid'] = 880
            if variant == 'protected-vmid': value['members']['identity']['vmid'] = 900
            if variant == 'server-many': value['schema'] = 'homelab-database-server-cutover-v1'
            if variant == 'server-role': value = request(880, 'homelab-database-server-cutover-v1'); value['members']['unexpected'] = value['members'].pop('mariadb')
            folder, raw = self.records(case, value)
            if variant == 'dangling-claim':
                (folder / 'claim.json').unlink(); (folder / 'claim.json').symlink_to(folder / 'absent')
            if variant == 'claim-change': (folder / 'claim.json').write_bytes(raw + b' ')
            if variant == 'missing-request': (folder / 'request.json').unlink()
            if variant == 'duplicate-json': (folder / 'request.json').write_text('{"schema":"old","schema":"unknown","members":{}}')
            if variant == 'oversize': (folder / 'request.json').write_bytes(b'x' * (1024 * 1024 + 1))
            if variant == 'malformed-json': (folder / 'request.json').write_text('{')
            if variant == 'request-mode': (folder / 'request.json').chmod(0o644)
            if variant in {'request-symlink','claim-symlink'}:
                path = folder / ('request.json' if variant == 'request-symlink' else 'claim.json')
                path.rename(folder / 'retained.json'); path.symlink_to(folder / 'retained.json')
            if variant == 'directory-mode': folder.chmod(0o755)
            if variant == 'directory-symlink': folder.rename(case.root / 'retained-custody'); folder.symlink_to(case.root / 'retained-custody', target_is_directory=True)
            if variant == 'directory-file':
                folder.rename(case.root / 'retained-custody'); folder.write_text('preserve unexpected record')
            backend = (case.work / 'terraform.tfstate').read_bytes()
            with self.subTest(variant=variant), self.assertRaises((OSError, ValueError)):
                deploy.run('infrastructure', case.site)
            case.infra.assert_not_called(); case.app.assert_not_called()
            self.assertEqual((case.work / 'terraform.tfstate').read_bytes(), backend)

    def test_foreign_ordinary_hold_still_refuses_infrastructure_replay(self):
        case = self.fixture()
        held = b'{"operation":"foreign"}\n'
        (case.work / 'ORDINARY-HOLD.json').write_bytes(held)
        with self.assertRaisesRegex(ValueError, 'existing attempt requires review'):
            deploy.run('infrastructure', case.site)
        case.infra.assert_not_called()
        self.assertEqual((case.work / 'ORDINARY-HOLD.json').read_bytes(), held)
