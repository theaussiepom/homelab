"""Historical documents + current receiver/attempt fixtures; no legacy compiler.

Only fake app/native executors run. The three explicit Automation application
phases are receiver metadata, not an authored bundle or fixed compiler graph.
"""
import copy
from contextlib import ExitStack
import json
from pathlib import Path
import component_ansible
import component_guest
import component_inputs
import component_ownership
import component_payload
import deployment_state
import deploy
import initial_ordinary
import proxmox_guest
from unittest.mock import patch
import private_io as io
from application_contract import ADAPTERS
from custody_fixtures import save,legacy_immutable,legacy_canonical
from test_component_historical_transition import HistoricalCase


class CurrentInitialCase:
    def __init__(self,test,root,role='influxdb'):
        self.test=test
        self.h=HistoricalCase(test,root,'influxdb',phase='influxdb')
        self.cfg=self.h.cfg;self.root=root;self.work=self.h.work
        self.installed=self.h.installed;self.canonical=self.work/'ordinary-complete.json'
        selected=self.cfg['initial_ordinary']
        self.immutable=self.work/selected['receipt']['operation']/'complete.json'
        self.ca_raw=(root/'ca').read_bytes()
        self.old=io.read_json(self.immutable,private=True)
        self.old['result']={'status':'passed','rows':[1,True]}
        if role=='automation':
            self.h.role=role;self.h.adapter='homeassistant';self.h.phase='homeassistant'
            self.cfg['guest']['memory_mib']=self.cfg['app']['memory_mib']=4096
            self.cfg['app']['kind']='automation'
            installed=io.read_json(self.installed,private=True)
            installed['app']['kind']='automation'
            installed['guest']['memory_mib']=installed['app']['memory_mib']=4096
            selected.update(schema=initial_ordinary.AUTOMATION_SCHEMA,
                installed_site_sha256=save(self.installed,installed),
                incomplete_operations=['ordinary-70-1','ordinary-80-1','ordinary-90-1'])
            self.old['binding']['site_sha256']=selected['installed_site_sha256']
            self.automation_apps()
            for name in selected['incomplete_operations']:
                save(self.work/name/'failure.log',b'retained failed attempt evidence\n')
            save(self.work/'ordinary-80-1/cache/tests/HOLD.json',b'cached test fixture, not a live hold')
            save(self.work/'ordinary-80-1/cache/never-run.py',b"raise AssertionError('never execute cached controllers')")
        else:
            older=copy.deepcopy(self.old);older['binding']['source_sha256']='b'*64
            save(self.work/'ordinary-90-1/complete.json',legacy_immutable(older))
        selected['receipt']['immutable_sha256']=save(self.immutable,legacy_immutable(self.old))
        selected['receipt']['sha256']=save(self.canonical,legacy_canonical(self.old))
        self.h.publish()
        self.h.app_prepare=self.app_prepare
        self.h.app_run=self.app_run
        trust=proxmox_guest.guest_trust
        contexts=ExitStack();test.addCleanup(contexts.close);self.h.bind(contexts)
        contexts.enter_context(patch.object(proxmox_guest,'guest_trust',trust))
        self.apps=component_ansible.run_phase
        self.apps.return_value={'status':'passed','changed':False,'target_contacted':False}

    def automation_apps(self):
        cfg=self.cfg;apps={};rows={};payloads={};checks={};services={}
        for phase,app_id,adapter in [('mqtt','broker','mqtt'),('homeassistant','home','homeassistant'),('node_red','flows','node_red')]:
            names={key:'owned-'+app_id+'-'+key.replace('_','-') for key in ADAPTERS[adapter]['services']}
            apps[app_id]={'id':app_id,'adapter':adapter,'lifecycle':'retained',
                'identity':{'runtime_id':app_id,'phase':phase,'services':names,'networks':{}},
                'project_name':'retained-project','project_file':'compose.yml','storage_paths':{},'settings':{}}
            rows[phase]={'id':app_id,'adapter':adapter,'lifecycle':'retained','runtime_id':app_id,
                         'project':'retained-project','compose_file':'compose.yml','services':list(names.values())}
            services.update({name:{'image':'fixture/image:1'} for name in names.values()})
            payloads[phase]=app_id;checks[phase]=[{'name':'fake adapter','argv':['true']}]
        cfg['deployment'].update(capabilities=['linux','docker'],applications=rows,
            payload_phases=payloads,phases=['preparation',*rows])
        cfg['app'].update(service_health_checks=checks,exclusive_writer_confirmed=True)
        self.h.runtime['applications']=apps
        packet=io.read_json(self.h.packet,private=True)
        packet['files']['compose.yml']=io.encoded({'services':services}).decode()
        self.h.packet.write_bytes(io.encoded(packet))

    def publish(self):self.h.revise()

    def phase(self,phase):
        self.publish()
        return deploy.run(phase,self.h.packet,inputs=self.h.inputs,environment={})

    def all_phases(self):
        return [self.phase(phase) for phase in ['infrastructure',*component_guest.phases(self.cfg)]]

    def binding(self):
        self.publish()
        cfg,site=component_inputs.prepare(self.h.packet,self.h.inputs,create=True)
        self.test.assertEqual(cfg,self.cfg)
        return component_inputs.binding(cfg,site)

    def attempt(self,binding=None):
        return deployment_state.DeploymentAttempt(self.cfg,self.binding() if binding is None else binding,
                                                  component_guest.phases(self.cfg))

    def app_prepare(self,cfg,app_id,environment,*,attempt):
        app=self.h.runtime['applications'][app_id]
        parent=component_inputs.app_directory(cfg,create=True)
        return component_payload.prepare(parent,cfg['deployment']['input_identity'],app_id,{
            'application.json':io.encoded(app),'owned-app.json':io.encoded(component_ownership.identity(cfg,app))})

    def app_run(self,cfg,site,work,operation,binding,phase,*,payload,previously_owned):
        if phase=='preparation':self.test.assertIsNone(payload)
        else:
            started=io.read_json(operation/(phase+'-started.json'),private=True)
            self.test.assertEqual(started['phase_inputs'],payload.check())
            self.test.assertEqual(payload.app,cfg['deployment']['payload_phases'][phase])
        return {'status':'passed','changed':False,'target_contacted':False}
