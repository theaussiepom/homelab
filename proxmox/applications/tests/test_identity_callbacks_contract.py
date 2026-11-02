"""Sanitized contract tests for the closed existing-provider callback addition."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from uuid import UUID

SOURCE = Path(os.environ.get('IDENTITY_CALLBACKS_MODULE', Path(__file__).resolve().parents[1] / 'identity_callbacks.py'))
sys.path.insert(0, str(SOURCE.parent))
SPEC = importlib.util.spec_from_file_location('tested_identity_callbacks', SOURCE)
callbacks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(callbacks)


def identity(number):
    return str(UUID(int=number))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def fixture():
    old = [
        {'matching_mode': 'strict', 'url': 'https://old-tools.example.invalid/oauth2/authorize'},
        {'matching_mode': 'strict', 'url': 'https://tools.example.invalid/oauth2/authorize'},
    ]
    provider = {'pk': 42, 'name': 'database-tools', 'client_id_sha256': digest('public-test-client'),
        'client_type': 'confidential', 'sub_mode': 'hashed_user_id', 'issuer_mode': 'per_provider',
        'include_claims_in_id_token': True, 'authentication_flow_id': None,
        'authorization_flow_id': identity(1), 'invalidation_flow_id': identity(2),
        'signing_key_id': identity(3), '_redirect_uris': copy.deepcopy(old)}
    application = {'pk': identity(4), 'name': 'Database Tools', 'slug': 'database-tools',
        'provider_id': 42, 'policy_engine_mode': 'any', 'meta_launch_url': ''}
    policy = {
        'policy_bindings': [{'pk': identity(5), 'policy_id': None, 'group_id': identity(6),
            'order': 0, 'negate': False, 'enabled': True, 'timeout': 30, 'user_binding_present': False}],
        'bound_groups': [{'pk': identity(6), 'name': 'Database users', 'parent_id': None,
            'is_superuser': False}],
        'property_mappings': [
            {'pk': identity(9), 'name': 'Profile claims', 'scope': 'profile',
             'expression_sha256': digest('generic-profile-expression'),
             'claim_labels_present': ['preferred_username', 'groups', 'name'], 'expression_evaluated': False},
            {'pk': identity(7), 'name': 'OpenID claims', 'scope': 'openid',
             'expression_sha256': digest('generic-openid-expression'),
             'claim_labels_present': [], 'expression_evaluated': False},
            {'pk': identity(8), 'name': 'Email claims', 'scope': 'email',
             'expression_sha256': digest('generic-email-expression'),
             'claim_labels_present': ['email', 'email_verified'], 'expression_evaluated': False},
        ],
    }
    provider_metadata = {k: v for k, v in provider.items() if k != '_redirect_uris'}
    normalized = {key: sorted(value, key=lambda row: str(row['pk'])) for key, value in policy.items()}
    record = {'provider_id': 42, 'application_id': identity(4),
        'client_id_sha256': digest('public-test-client'),
        'provider_metadata_sha256': digest(provider_metadata),
        'application_metadata_sha256': digest(application), 'policy_metadata_sha256': digest(normalized),
        'existing_redirects': old, 'additions': ['https://db.example.invalid/oauth2/callback']}
    return record, provider, application, policy


class IdentityCallbackContract(unittest.TestCase):
    def test_canonical_hash_is_compact_sorted_json_including_client_string_quotes(self):
        self.assertEqual(callbacks.canonical({'z': 1, 'a': [True, None]}),
                         hashlib.sha256(b'{"a":[true,null],"z":1}').hexdigest())
        self.assertEqual(callbacks.canonical('public-test-client'), digest('public-test-client'))
        self.assertNotEqual(callbacks.canonical('public-test-client'),
                            hashlib.sha256(b'public-test-client').hexdigest())

    def test_policy_projection_sorts_only_entity_lists_without_losing_fields(self):
        _, _, _, policy = fixture()
        before = copy.deepcopy(policy)
        expected = {key: sorted(value, key=lambda row: str(row['pk'])) for key, value in policy.items()}
        self.assertEqual(callbacks.policy_projection(policy), expected)
        self.assertEqual(policy, before)

    def test_valid_closed_record_and_exact_callback_append_preserve_inputs(self):
        record, provider, application, policy = fixture()
        before = copy.deepcopy((record, provider, application, policy))
        callbacks.validate([record])
        result = callbacks.check(record, provider, application, policy)
        self.assertEqual(result, record['existing_redirects'] + [
            {'matching_mode': 'strict', 'url': record['additions'][0]}])
        self.assertEqual((record, provider, application, policy), before)

    def test_exact_already_extended_provider_is_idempotent(self):
        record, provider, application, policy = fixture()
        provider['_redirect_uris'] += [{'matching_mode': 'strict', 'url': record['additions'][0]}]
        self.assertEqual(callbacks.check(record, provider, application, policy), provider['_redirect_uris'])

    def test_policy_entity_row_reordering_keeps_exact_facts(self):
        record, provider, application, policy = fixture()
        for rows in policy.values():
            rows.reverse()
        self.assertEqual(callbacks.check(record, provider, application, policy)[-1],
                         {'matching_mode': 'strict', 'url': record['additions'][0]})

    def test_record_missing_unknown_fields_or_wrong_scalar_types_refuse(self):
        record, *_ = fixture()
        bad = []
        missing = copy.deepcopy(record); missing.pop('policy_metadata_sha256'); bad.append(missing)
        extra = copy.deepcopy(record); extra['allow_all_users'] = True; bad.append(extra)
        for key, value in [('provider_id', True), ('provider_id', 0), ('provider_id', '42'),
             ('application_id', 'not-a-uuid'), ('client_id_sha256', 'X' * 64),
             ('provider_metadata_sha256', '0' * 63), ('existing_redirects', {}), ('additions', 'https://db.example.invalid/oauth2/callback')]:
            item = copy.deepcopy(record); item[key] = value; bad.append(item)
        for item in bad:
            with self.subTest(fields=sorted(item)), self.assertRaises(ValueError):
                callbacks.validate([item])

    def test_unknown_or_widened_old_redirect_shapes_refuse(self):
        record, *_ = fixture()
        for replacement in ([{'matching_mode': 'regex', 'url': 'https://.*'}],
             [{'matching_mode': 'strict', 'url': 'https://old-tools.example.invalid/oauth2/authorize', 'extra': True}],
             [record['existing_redirects'][0], record['existing_redirects'][0]]):
            item = copy.deepcopy(record); item['existing_redirects'] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                callbacks.validate([item])

    def test_new_callbacks_require_closed_https_origin_and_exact_callback_path(self):
        record, *_ = fixture()
        for uri in ('http://db.example.invalid/oauth2/callback',
             'https://user@db.example.invalid/oauth2/callback',
             'https://db.example.invalid/not-callback',
             'https://db.example.invalid/oauth2/callback?redirect=other',
             'https://db.example.invalid/oauth2/callback#fragment'):
            item = copy.deepcopy(record); item['additions'] = [uri]
            with self.subTest(uri=uri), self.assertRaises(ValueError): callbacks.validate([item])

    def test_duplicate_provider_and_duplicate_new_callback_refuse(self):
        record, *_ = fixture()
        with self.assertRaises(ValueError): callbacks.validate([record, copy.deepcopy(record)])
        record['additions'] *= 2
        with self.assertRaises(ValueError): callbacks.validate([record])

    def test_provider_identity_client_flow_subject_or_extra_field_drift_refuses(self):
        for key, value in [('pk', 43), ('client_id_sha256', '0' * 64),
             ('authorization_flow_id', identity(100)), ('sub_mode', 'user_username'),
             ('issuer_mode', 'global'), ('include_claims_in_id_token', False), ('extra_field', 'unknown')]:
            record, provider, application, policy = fixture(); provider[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                callbacks.check(record, provider, application, policy)

    def test_application_identity_policy_engine_provider_or_launch_change_refuses(self):
        for key, value in [('pk', identity(100)), ('provider_id', 43), ('policy_engine_mode', 'all'),
             ('meta_launch_url', 'https://foreign.example.invalid/'), ('slug', 'foreign')]:
            record, provider, application, policy = fixture(); application[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                callbacks.check(record, provider, application, policy)

    def test_policy_group_and_mapping_changes_refuse(self):
        for section, key, value in [('policy_bindings', 'enabled', False),
             ('policy_bindings', 'user_binding_present', True), ('policy_bindings', 'group_id', identity(100)),
             ('policy_bindings', 'negate', True), ('bound_groups', 'parent_id', identity(100)),
             ('bound_groups', 'is_superuser', True), ('property_mappings', 'expression_sha256', '0' * 64),
             ('property_mappings', 'scope', 'foreign')]:
            record, provider, application, policy = fixture(); policy[section][0][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                callbacks.check(record, provider, application, policy)

    def test_added_or_removed_policy_binding_or_group_refuses(self):
        for section, operation in [('policy_bindings', 'add'), ('policy_bindings', 'remove'),
             ('bound_groups', 'add'), ('property_mappings', 'remove')]:
            record, provider, application, policy = fixture()
            if operation == 'add':
                extra = copy.deepcopy(policy[section][0]); extra['pk'] = identity(100); policy[section].append(extra)
            else:
                policy[section].pop()
            with self.subTest(section=section, operation=operation), self.assertRaises(ValueError):
                callbacks.check(record, provider, application, policy)

    def test_removed_reordered_regex_or_foreign_live_redirect_refuses(self):
        for operation in ('remove', 'reorder', 'regex', 'extra'):
            record, provider, application, policy = fixture()
            if operation == 'remove': provider['_redirect_uris'].pop()
            elif operation == 'reorder': provider['_redirect_uris'].reverse()
            elif operation == 'regex': provider['_redirect_uris'][0]['matching_mode'] = 'regex'
            else: provider['_redirect_uris'].append({'matching_mode': 'strict', 'url': 'https://foreign.example.invalid/oauth2/callback'})
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                callbacks.check(record, provider, application, policy)


if __name__ == '__main__': unittest.main()
