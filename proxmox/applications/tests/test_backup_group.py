"""Closed protocol, coherent-set membership and bounded real pipe transport."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_group as group
import backup_policy as policy
import backup_worker as worker
import test_backup_worker as worker_fixture


def scope():
    return {'name': 'example', 'members': {'example-node-610': {'state_root': '/example/state',
        'node': 'example-node', 'vmid': 610, 'hostname': 'example',
        'api_address': '192.0.2.10', 'api_port': 8006}}}


def destination():
    return {'example-node-610': {'server': '192.0.2.50', 'port': 8007,
        'datastore': 'recovery', 'namespace': 'guests/example-node-610'}}


class GroupTests(unittest.TestCase):
    def test_full_membership_and_exact_completed_digests_are_required(self):
        value = scope(); group.configuration(value)
        self.assertEqual(group.member({'name': 'example', 'member': 'example-node-610'})['name'], 'example')
        digest = group.inventory_digest({'key': 'value'})
        result = group.recovery_set(value, 'a'*32, 1, {'example-node-610': digest}, destination())
        self.assertEqual(group.received_set(value, 'a'*32, 1, result), result)
        self.assertFalse(result['distributed_database_transaction'])
        for changed in [None, {}, {'name': 'example', 'members': {}},
                        {'name': 'example', 'members': {'--bad': {}}}]:
            with self.subTest(value=changed), self.assertRaises(ValueError): group.configuration(changed)
        for field, wrong in [('vmid', True), ('api_address', 'bad'), ('api_port', 0),
                             ('state_root', '/a/../b'), ('node', '--bad'), ('hostname', '')]:
            changed = copy.deepcopy(value); changed['members']['example-node-610'][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError): group.configuration(changed)
        changed = copy.deepcopy(value); changed['members']['second'] = dict(changed['members']['example-node-610'])
        with self.assertRaises(ValueError): group.configuration(changed)
        for args in [(None, 1, {'example-node-610': digest}, destination()),
                     ('a'*32, True, {'example-node-610': digest}, destination()),
                     ('a'*32, 1, {}, destination()), ('a'*32, 1, {'example-node-610': 'bad'}, destination()),
                     ('a'*32, 1, {'example-node-610': digest}, {'example-node-610': {}})]:
            with self.subTest(args=args), self.assertRaises(ValueError): group.recovery_set(value, *args)
        for field, wrong in [('server', '-bad'), ('port', True), ('datastore', 'nested/path'), ('namespace', 'bad')]:
            target = destination(); target['example-node-610'][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                group.recovery_set(value, 'a'*32, 1, {'example-node-610': digest}, target)
        for field in ('members', 'name', 'coordinated_window'):
            changed = copy.deepcopy(result); changed[field] = {} if field == 'members' else 'foreign'
            with self.subTest(field=field), self.assertRaises(ValueError): group.received_set(value, 'a'*32, 1, changed)
        with self.assertRaises(ValueError): group.member({'name': 'x', 'member': 'x', 'peers': {}})
        with self.assertRaises(ValueError): group.received_set(value, 'a'*32, 1, None)

    def test_messages_bound_bytes_duplicates_framing_and_timed_disconnects(self):
        stream = io.BytesIO(); group.send(stream, {'value': '✓'}); stream.seek(0)
        self.assertEqual(group.message(stream), {'value': '✓'})
        for raw in (b'', b'{}', b'[]\n', b'{"a":1,"a":2}\n', b'x'*(group.LIMIT+1)):
            with self.subTest(raw=raw[:50]), self.assertRaises((ValueError, json.JSONDecodeError)):
                group.message(io.BytesIO(raw))
        with self.assertRaises(ValueError): group.send(io.BytesIO(), {'oversized': 'x'*group.LIMIT})
        for raw, expected in [(b'{"ok":true}\n', {'ok': True}), (b'{}\n{}\n', None), (b'', None)]:
            read, write = os.pipe()
            with os.fdopen(read, 'rb', buffering=0) as source:
                os.write(write, raw); os.close(write)
                if expected is None:
                    with self.assertRaises(ValueError): group.message(source, timeout=1)
                else: self.assertEqual(group.message(source, timeout=1), expected)
        read, write = os.pipe()
        try:
            with os.fdopen(read, 'rb', buffering=0) as source:
                with self.assertRaises(ValueError): group.message(source, timeout=.01)
        finally: os.close(write)

    def test_worker_barriers_require_the_same_inventory_group_order_and_lease(self):
        fixture = worker_fixture.WorkerTests(); fixture.setUp()
        try:
            value = fixture.value
            begin = {'action': 'begin', 'generation': 'a'*32, 'backup_time': 1, 'group': scope(),
                'inventory_sha256': group.inventory_digest(value), 'lease_seconds': 300, 'controls': {}}
            recovery = group.recovery_set(scope(), 'a'*32, 1, {'example-node-610': 'a'*64}, destination())
            messages = [begin] + [{'action': action, 'generation': 'a'*32,
                **({'group': recovery} if action == 'upload' else {})} for _, action in group.STAGES]
            received = []
            def execute(value, **kw):
                for stage, _ in group.STAGES:
                    result = kw['barrier'](stage, {'data_manifest_sha256': 'a'*64} if stage in ('captured', 'uploaded') else {})
                    if stage == 'resumed': self.assertEqual(result, recovery)
                return 'complete'
            def receive(stream, timeout):
                received.append(timeout); return messages.pop(0)
            output = io.BytesIO()
            self.assertEqual(worker.serve(value, None, output, runner=execute, receive=receive), 'complete')
            self.assertEqual(len(output.getvalue().splitlines()), 5)
            for mutate in [lambda b: b.update(inventory_sha256='wrong'), lambda b: b.update(lease_seconds=True),
                           lambda b: b['group'].update(name='foreign')]:
                bad = copy.deepcopy(begin); mutate(bad)
                with self.subTest(begin=bad), self.assertRaises(ValueError):
                    worker.serve(value, None, io.BytesIO(), receive=lambda *a, **k: bad)
            calls = iter([begin, {'action': 'capture', 'generation': 'a'*32}])
            with self.assertRaises(ValueError):
                worker.serve(value, None, io.BytesIO(), runner=execute, receive=lambda *a, **k: next(calls))
        finally: fixture.doCleanups()
