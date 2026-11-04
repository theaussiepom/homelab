"""Finite private-role continuity units and real protected input proof reads."""
import copy
import os
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
from test_component_private_material import telemetry,provider


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

    def previous(self,selected=None,values=None,*,seal=True):
        selected=self.selected if selected is None else selected
        values={'api_token':b'original-material'} if values is None else values
        previous=self.root/'previous';previous.mkdir(mode=0o700)
        payload={'application.json':encoded(selected)}
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
        with patch.object(continuity.coordinated_generation,'component_success',return_value=True):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))
        self.assertEqual(before,{p:p.read_bytes()for p in self.root.rglob('*')if p.is_file()})

    def test_changed_material_and_remove_then_readd_cannot_erase_previous_role(self):
        self.previous()
        for renamed in (False,True):
            if renamed:self.selected['input_sources']['api_token']['source_id']='renamed'
            with self.subTest(renamed=renamed),patch.object(continuity.coordinated_generation,'component_success',return_value=True),self.assertRaisesRegex(ValueError,'cannot rotate'):
                continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'changed-material'}))
        removed=copy.deepcopy(self.selected);removed['input_sources']={}
        with patch.object(continuity.coordinated_generation,'component_success',return_value=True),self.assertRaisesRegex(ValueError,'cannot remove'):
            continuity.verify(self.attempt,removed,proof(removed,{}))
        with patch.object(continuity.coordinated_generation,'component_success',return_value=True):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))

    def test_new_role_can_be_added_and_an_unselected_new_app_has_no_peer_material_read(self):
        selected=app('authentik','secret_key');self.previous(selected,{'secret_key':b'original-material'})
        selected['input_sources']['smtp_password']={'type':'environment','name':'NEW_INPUT'}
        with patch.object(continuity.coordinated_generation,'component_success',return_value=True):
            continuity.verify(self.attempt,selected,proof(selected,{'secret_key':b'original-material','smtp_password':b'new-capability'}))
            other=app();other['id']='new-app'
            with patch.object(continuity.component_payload.AppPayload,'load',side_effect=AssertionError('No peer material read')):
                continuity.verify(self.attempt,other,proof(other,{'api_token':b'new-material'}))

    def test_unpublished_prototype_without_material_proof_and_tampered_payload_refuse(self):
        previous=self.previous(seal=False)
        with patch.object(continuity.coordinated_generation,'component_success',return_value=True),self.assertRaises(FileNotFoundError):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))
        (previous.directory/'application.json').write_bytes(b'{}')
        with patch.object(continuity.coordinated_generation,'component_success',return_value=True),self.assertRaisesRegex(ValueError,'bytes changed'):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))

    def test_duplicate_phase_owners_and_malformed_material_document_refuse(self):
        self.previous();receipt=read_json(self.attempt.receipt,private=True)
        receipt['phase_inputs']['duplicate']=receipt['phase_inputs']['selected-phase']
        self.attempt.receipt.write_bytes(encoded(receipt))
        with patch.object(continuity.coordinated_generation,'component_success',return_value=True),self.assertRaisesRegex(ValueError,'one prior'):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))
        current=proof(self.selected,{'api_token':b'original-material'})
        for mutate in (lambda p:p.update(schema='other'),lambda p:p.update(app='peer'),
                       lambda p:p.update(extra=True),lambda p:p['roles'].clear(),
                       lambda p:p['roles']['api_token'].update(material_sha256='wrong'),
                       lambda p:p['roles']['api_token']['source'].update(source_id='foreign'),
                       lambda p:p['roles']['api_token'].update(raw_value='never-accepted')):
            changed=copy.deepcopy(current);mutate(changed)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):continuity.validate(self.selected,changed)


class LegacyPrivateProofTests(unittest.TestCase):
    setUp = PrivateContinuityUnits.setUp
    def legacy(self,selected,values,stack,old=None):
        directory=self.root/'legacy';directory.mkdir(mode=0o700)
        hashes={}
        def bound(name,raw):
            path=directory/name;write_new(path,raw);hashes[str(path)]=sha(path);return str(path)
        old={}if old is None else copy.deepcopy(old)
        if stack is not None:
            for section,key,role in [('mqtt','credential_file','probe'),('winet','configuration_file','options')]:
                if section in stack:stack[section][key]=bound(role,values[role])
            if 'foundation'in stack:
                for role,name in {'client_secret':'oauth_client_secret','secret_key':'secret_key',
                    'postgresql_password':'postgresql_password','smtp_password':'smtp_password',
                    'cloudflare_dns_token':'cloudflare_dns_token','proxmox_token':'proxmox_token'}.items():
                    if role in values:
                        raw=values[role]
                        if role=='proxmox_token':raw=b'synthetic-token'
                        stack['foundation'].setdefault('secret_files',{})[name]=bound(role,raw)
            old['stack_config']=bound('stack.json',encoded(stack))
        for section,key,role in [('bitwarden','runtime_env_file','runtime_environment'),('pegaprox','key_source','database_key')]:
            if role in values:old[section]={key:bound(role,values[role])}
        cfg=copy.deepcopy(self.attempt.cfg);cfg['app']=old
        installed=directory/'site.json';write_new(installed,encoded(cfg))
        self.attempt.initial_selection={'installed_site':str(installed)}
        receipt={'status':'passed','binding':{'vmid':610,'site_sha256':sha(installed),
            'source_sha256':'b'*64,'blueprint_sha256':'c'*64,'input_hashes':hashes}}
        return receipt

    def test_legacy_node_embedded_scalar_and_foundation_files_keep_actual_hash_bound_bytes(self):
        receipt=self.legacy(self.selected,{'api_token':b'original-material'},
            {'services':{'node_red':{'environment':{'NODE_RED_API_TOKEN':'original-material'}}}})
        self.assertEqual(continuity.legacy(self.attempt,receipt,self.selected)['api_token']['material_sha256'],
                         proof(self.selected,{'api_token':b'original-material'})['roles']['api_token']['material_sha256'])
        del receipt['binding']['input_hashes'][next(iter(receipt['binding']['input_hashes']))]
        with self.assertRaisesRegex(ValueError,'immutable source proof'):continuity.legacy(self.attempt,receipt,self.selected)

    def test_legacy_compound_and_opaque_sources_project_only_existing_credential_material(self):
        cases=[]
        selected,record=provider();selected.update(id='selected',lifecycle='retained')
        cases.append((selected,{'proxmox_token':encoded(record)},{'foundation':{'proxmox_token_id':record['identity']}}))
        selected,options=telemetry();selected.update(id='selected',lifecycle='retained')
        cases.append((selected,{'options':encoded(options)},{'winet':copy.deepcopy(selected['settings'])}))
        cases += [(app('mqtt','probe'),{'probe':encoded({'username':'probe','password':'fixture'})},{'mqtt':{}}),
                  (app('bitwarden','runtime_environment'),{'runtime_environment':b'opaque\x00\xff'},None),
                  (app('pegaprox','database_key'),{'database_key':b'opaque key\n'},None)]
        for index,(selected,values,stack) in enumerate(cases):
            if index:(self.root/'legacy').rename(self.root/('legacy-'+str(index)))
            receipt=self.legacy(selected,values,stack)
            old=continuity.legacy(self.attempt,receipt,selected)
            self.assertEqual({role:row['material_sha256']for role,row in old.items()},
                {role:row['material_sha256']for role,row in material.project(selected,values).items()})

    def test_legacy_required_foundation_roles_optional_additions_and_changed_bound_file_refuse(self):
        for index,(adapter,values) in enumerate([('authentik',{'secret_key':b'secret','postgresql_password':b'database','smtp_password':b'smtp'}),
                ('cloudbeaver',{'client_secret':b'client'}),('traefik',{'cloudflare_dns_token':b'dns'})]):
            if index:(self.root/'legacy').rename(self.root/('legacy-'+str(index)))
            selected=app(adapter,next(iter(values)))
            selected['input_sources']={role:{'type':'environment','name':'EXISTING'}for role in values}
            receipt=self.legacy(selected,values,{'foundation':{}})
            self.assertEqual(set(continuity.legacy(self.attempt,receipt,selected)),set(values))
            path=next(path for path in receipt['binding']['input_hashes']if Path(path).name!='stack.json')
            Path(path).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'source changed'):continuity.legacy(self.attempt,receipt,selected)

    def test_missing_legacy_site_role_fingerprint_or_owner_has_no_invented_baseline(self):
        receipt=self.legacy(self.selected,{}, {'services':{}})
        with self.assertRaisesRegex(ValueError,'role-presence proof'):continuity.legacy(self.attempt,receipt,self.selected)
        for mutate in (lambda r:r['binding'].update(schema='prototype'),lambda r:r['binding'].update(site_sha256='bad'),
                       lambda r:r.update(status='failed')):
            changed=copy.deepcopy(receipt);mutate(changed)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):continuity.legacy(self.attempt,changed,self.selected)
        self.attempt.cfg['guest']['hostname']='foreign'
        with self.assertRaisesRegex(ValueError,'guest owner'):continuity.legacy(self.attempt,receipt,self.selected)

    def test_actual_legacy_verify_preserves_roles_and_cannot_drop_token_on_first_transition(self):
        receipt=self.legacy(self.selected,{'api_token':b'original-material'},
            {'services':{'node_red':{'environment':{'NODE_RED_API_TOKEN':'original-material'}}}})
        self.selected['lifecycle']='retained'
        write_new(self.attempt.receipt,encoded(receipt))
        continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'original-material'}))
        with self.assertRaisesRegex(ValueError,'cannot rotate'):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'changed-material'}))
        self.selected['input_sources']={}
        with self.assertRaisesRegex(ValueError,'cannot remove'):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{}))

    def test_hash_bound_legacy_node_environment_proves_optional_token_absence(self):
        receipt=self.legacy(self.selected,{},
            {'services':{'node_red':{'environment':{'FLOWS':'flows.json'}}}})
        self.selected.update(lifecycle='retained',input_sources={})
        write_new(self.attempt.receipt,encoded(receipt))
        continuity.verify(self.attempt,self.selected,proof(self.selected,{}))
        self.assertEqual(continuity.legacy(self.attempt,receipt,self.selected),{})
        self.selected['input_sources']={'api_token':{'type':'environment','name':'EXISTING'}}
        continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'explicit-added-role'}))
        stack=next(path for path in receipt['binding']['input_hashes']if Path(path).name=='stack.json')
        del receipt['binding']['input_hashes'][stack]
        self.attempt.receipt.write_bytes(encoded(receipt))
        with self.assertRaisesRegex(ValueError,'immutable source proof'):
            continuity.verify(self.attempt,self.selected,proof(self.selected,{'api_token':b'explicit-added-role'}))

    def test_legacy_source_path_modes_and_real_ancestor_substitution_fail_closed(self):
        for value in ('relative/file','//etc/private','/srv/../private','/srv/./private'):
            with self.subTest(path=value),self.assertRaises(ValueError):continuity._read(value)
        holder=self.root/'holder';holder.mkdir(mode=0o700)
        inside=holder/'private';inside.mkdir(mode=0o700)
        original=inside/'secret';write_new(original,b'original-private-material')
        outside=self.root/'outside';outside.mkdir(mode=0o700)
        (outside/'private').mkdir(mode=0o700)
        foreign=outside/'private/secret';write_new(foreign,b'outside-private-material')
        self.assertEqual(continuity._read(str(original)),b'original-private-material')
        real=os.open;foreign_id=(foreign.stat().st_dev,foreign.stat().st_ino)
        for timing in ('before','after'):
            triggered=[];outside_reads=[]
            def opening(path,*args,**kwargs):
                selected=str(path)=='holder'and kwargs.get('dir_fd')is not None and not triggered
                if selected and timing=='before':
                    triggered.append(True);holder.rename(self.root/'original-holder');holder.symlink_to(outside,target_is_directory=True)
                fd=real(path,*args,**kwargs)
                info=os.fstat(fd)
                if (info.st_dev,info.st_ino)==foreign_id:outside_reads.append(True)
                if selected and timing=='after':
                    triggered.append(True);holder.rename(self.root/'original-holder');holder.symlink_to(outside,target_is_directory=True)
                return fd
            with self.subTest(timing=timing),patch.object(continuity.os,'open',side_effect=opening),self.assertRaises(OSError):
                continuity._read(str(original))
            self.assertEqual(triggered,[True]);self.assertEqual(outside_reads,[])
            holder.unlink();(self.root/'original-holder').rename(holder)
        original.chmod(0o400);self.assertEqual(continuity._read(str(original)),b'original-private-material')
        original.chmod(0o644)
        with self.assertRaises(ValueError):continuity._read(str(original))

    def test_ordinary_and_coordinated_legacy_site_locators_use_only_existing_hash_bound_copies(self):
        receipt=self.legacy(self.selected,{'api_token':b'original-material'},
            {'services':{'node_red':{'environment':{'NODE_RED_API_TOKEN':'original-material'}}}})
        site=self.attempt.initial_selection['installed_site']
        self.attempt.initial_selection=None
        self.assertEqual(set(continuity.legacy(self.attempt,receipt,self.selected)),{'api_token'})
        self.attempt.cfg['app']={'kind':'identity'}
        self.attempt.custody={'members':{'identity':{'installed_site':site}}}
        self.assertEqual(set(continuity.legacy(self.attempt,receipt,self.selected)),{'api_token'})
        self.attempt.custody=None
        Path(site).write_bytes(Path(site).read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'hash-bound compiled site'):
            continuity.legacy(self.attempt,receipt,self.selected)

    def test_unknown_historical_external_password_role_has_no_fabricated_material_baseline(self):
        selected=app('mqtt_explorer','broker_password')
        receipt=self.legacy(selected,{}, {})
        with self.assertRaisesRegex(ValueError,'no genuine legacy material proof'):
            continuity.legacy(self.attempt,receipt,selected)
        selected['input_sources']={}
        self.assertEqual(continuity.legacy(self.attempt,receipt,selected),{})

    def test_existing_noncomponent_receipt_does_not_force_private_reads_for_new_empty_app(self):
        write_new(self.attempt.receipt,encoded({'status':'passed','binding':{}}))
        selected=app('unbound','unused');selected['input_sources']={}
        with patch.object(continuity,'legacy',side_effect=AssertionError('No unrelated legacy input reads')):
            continuity.verify(self.attempt,selected,proof(selected,{}))


if __name__=='__main__':unittest.main()
