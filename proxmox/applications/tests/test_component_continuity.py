"""Finite private-role continuity units and real protected input proof reads."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import component_continuity as continuity
import component_payload
import component_private_material as material
from private_io import encoded,read_json,sha,write_new


def app(adapter='node_red',role='api_token'):
    return {'id':'selected','adapter':adapter,'lifecycle':'fresh','settings':{},
            'input_sources':{role:{'type':'environment','name':'EXISTING_INPUT','source_id':'original'}}}


def proof(selected,values):
    return continuity.document(selected,material.project(selected,values))


class PrivateContinuityUnits(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.selected=app()
        self.attempt=SimpleNamespace(receipt=self.root/'ordinary-complete.json',
            cfg={'site':{'node':'example-node'},'guest':{'vmid':610,'hostname':'example-guest'}})

    def previous(self,selected=None,values=None,*,seal=True,files=None):
        selected=self.selected if selected is None else selected
        values={'api_token':b'original-material'} if values is None else values
        previous=self.root/'previous';previous.mkdir(mode=0o700)
        payload={'application.json':encoded(selected), **(files or {})}
        if seal:payload[continuity.FILE]=encoded(proof(selected,values))
        prepared=component_payload.prepare(previous,'a'*64,selected['id'],payload)
        receipt={'operation':str(self.root/'ordinary-1-1'),'binding':{'app_inputs_directory':str(previous)},
                 'phase_inputs':{'selected-phase':prepared.check(),'preparation':None}}
        write_new(self.attempt.receipt,encoded(receipt))
        return prepared

    def test_first_fresh_selection_and_empty_retained_inputs_have_distinct_proof_floors(self):
        current=proof(self.selected,{'api_token':b'original-material'})
        continuity.verify(self.attempt,self.selected,current)
        self.selected['lifecycle']='retained'
        with self.assertRaisesRegex(ValueError,'genuine prior'):continuity.verify(self.attempt,self.selected,current)
        self.selected['input_sources']={}
        continuity.verify(self.attempt,self.selected,proof(self.selected,{}))
        self.assertFalse(self.attempt.receipt.exists())

    def test_same_material_and_source_metadata_rename_preserve_every_prior_byte(self):
        self.previous();before={p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
        self.selected['input_sources']['api_token'].update(name='RENAMED_ENV',source_id='renamed',workflow_secret='EXISTING_KEY')
        with patch.object(continuity.component_generation,'component_success',return_value=True):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))
        self.assertEqual(before,{p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()})

    def test_cloudbeaver_separation_matches_only_the_installed_recovery_password(self):
        password = b'Q' * 43 + b'=aA1!'
        previous = app('cloudbeaver', 'client_secret')
        previous.update(project_name='tools', project_file='compose.yml', authentication_resolved={'version':1},
                        identity={'runtime_id':'console', 'services':{'cloudbeaver':'server','auth_gateway':'gateway'},
                                  'networks':{'private':'tools_net'}, 'runtime_directory':'/opt/homelab-app/runtime'},
                        settings={'recovery_admin':'local-recovery'}, storage_paths={'workspace':{'source':'/data/console'}})
        auto = b'CB_ADMIN_NAME=local-recovery\nCB_ADMIN_PASSWORD=' + password + b'\n'
        payload = self.previous(previous, {'client_secret':b'old-oidc-client'}, files={'cloudbeaver.auto.conf':auto})
        current = copy.deepcopy(previous)
        current.update(lifecycle='retained', authentication_resolved={'type':'forward-auth'},
                       input_sources={'recovery_password':{'type':'environment','name':'DEDICATED'}})
        del current['identity']['services']['auth_gateway']
        with patch.object(continuity.component_generation,'component_success',return_value=True), \
             patch.object(continuity.component_generation,'previous',return_value=(None,self.attempt.cfg,None)):
            def check(material=password):
                continuity.verify(self.attempt, current, proof(current, {'recovery_password':material}))
            check()
            with self.assertRaisesRegex(ValueError,'installed recovery password'):
                check(b'new-credential')
            for field, replacement in [('lifecycle','fresh'),('project_name','another-project')]:
                with self.subTest(field=field), patch.dict(current, {field:replacement}), self.assertRaisesRegex(ValueError,'recovery owner'):
                    check()
            with patch.dict(current['settings'], recovery_admin='different'), self.assertRaisesRegex(ValueError,'recovery owner'):
                check()
            recovery = proof(current, {'recovery_password':password})['roles']['recovery_password']
            for raw in (b'', auto + auto, b'CB_ADMIN_PASSWORD=invalid\n'):
                (payload.directory / 'cloudbeaver.auto.conf').write_bytes(raw)
                with self.assertRaisesRegex(ValueError,'sealed CloudBeaver'):
                    continuity.verify_cloudbeaver_recovery(self.attempt, previous, current, payload, recovery)
                manifest = json.loads(payload.manifest)
                manifest['files']['cloudbeaver.auto.conf'] = hashlib.sha256(raw).hexdigest()
                with patch.object(payload,'manifest',json.dumps(manifest)), self.assertRaisesRegex(ValueError,'installed recovery password'):
                    continuity.verify_cloudbeaver_recovery(self.attempt, previous, current, payload, recovery)

    def test_changed_material_and_remove_then_readd_cannot_erase_previous_role(self):
        self.previous()
        for renamed in (False,True):
            if renamed:self.selected['input_sources']['api_token']['source_id']='renamed'
            with self.subTest(renamed=renamed),patch.object(continuity.component_generation,'component_success',return_value=True),self.assertRaisesRegex(ValueError,'cannot rotate'):
                continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'changed-material'}))
        removed=copy.deepcopy(self.selected);removed['input_sources']={}
        with patch.object(continuity.component_generation,'component_success',return_value=True),self.assertRaisesRegex(ValueError,'cannot remove'):
            continuity.verify(self.attempt,removed,proof(removed,{}))
        with patch.object(continuity.component_generation,'component_success',return_value=True):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))

    def test_new_role_can_be_added_and_an_unselected_new_app_has_no_peer_material_read(self):
        selected=app('authentik','secret_key');self.previous(selected,{'secret_key':b'original-material'})
        selected['input_sources']['smtp_password']={'type':'environment','name':'NEW_INPUT'}
        with patch.object(continuity.component_generation,'component_success',return_value=True):
            continuity.verify(self.attempt,selected,proof(selected,{'secret_key':b'original-material','smtp_password':b'new-capability'}))
            other=app();other['id']='new-app'
            with patch.object(continuity.component_payload.AppPayload,'load',side_effect=AssertionError('No peer material read')):
                continuity.verify(self.attempt,other,proof(other,{'api_token':b'new-material'}))

    def test_unpublished_prototype_without_material_proof_and_tampered_payload_refuse(self):
        previous=self.previous(seal=False)
        with patch.object(continuity.component_generation,'component_success',return_value=True),self.assertRaises(FileNotFoundError):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))
        (previous.directory/'application.json').write_bytes(b'{}')
        with patch.object(continuity.component_generation,'component_success',return_value=True),self.assertRaisesRegex(ValueError,'bytes changed'):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))

    def test_duplicate_phase_owners_and_malformed_material_document_refuse(self):
        self.previous();receipt=read_json(self.attempt.receipt,private=True)
        receipt['phase_inputs']['duplicate']=receipt['phase_inputs']['selected-phase']
        self.attempt.receipt.write_bytes(encoded(receipt))
        with patch.object(continuity.component_generation,'component_success',return_value=True),self.assertRaisesRegex(ValueError,'one prior'):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))
        current=proof(self.selected,{'api_token':b'original-material'})
        for mutate in (lambda p:p.update(schema='other'),lambda p:p.update(app='peer'),
                       lambda p:p.update(extra=True),lambda p:p['roles'].clear(),
                       lambda p:p['roles']['api_token'].update(material_sha256='wrong'),
                       lambda p:p['roles']['api_token']['source'].update(source_id='foreign'),
                       lambda p:p['roles']['api_token'].update(raw_value='never-accepted')):
            changed=copy.deepcopy(current);mutate(changed)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):continuity.validate(self.selected,changed)




if __name__=='__main__':unittest.main()
