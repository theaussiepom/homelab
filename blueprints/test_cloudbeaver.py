"""The explicit Community variant keeps one guest job and declared database edges."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import compile as compiler
import service_bindings
import workflows


def fixtures():
    result={}
    connections={}
    for engine,ip,port in [('postgresql','198.18.31.23',5432),('mariadb','198.18.32.24',3306)]:
        result[engine]=({'guest':{'interfaces':[{'ipv4':ip+'/24'}]},'app':{
            'service_health_checks':{engine:[{}]},'published_services':{engine:{'hostname':engine+'.database.invalid',
            'addresses':{'backend':ip},'dns_address':'backend','protocol':'tcp','port':port}}}},None,{})
        connections[engine]={'driver':engine,'name':engine,'database':''}
    result['db-tools']=({'guest':{'interfaces':[{'ipv4':'198.18.31.32/24'},{'ipv4':'198.18.32.32/24'}]},
        'app':{'service_health_checks':{'cloudbeaver':[{}]},'service_connections':{
            'cloudbeaver.'+engine:{'service':engine+'.'+engine,'address':'backend'} for engine in connections}}},
        {'kind':'db-tools','variant':'cloudbeaver','cloudbeaver':{'connections':connections}}, {})
    return result


class CloudBeaverBlueprintTests(unittest.TestCase):
    def test_each_named_connection_binds_its_engine_address_and_firewall_edge(self):
        values=fixtures();before=copy.deepcopy(values);service_bindings.bind(values)
        stack=values['db-tools'][1]
        self.assertEqual(stack['cloudbeaver']['connections']['postgresql']['host'],'198.18.31.23')
        self.assertEqual(stack['cloudbeaver']['connections']['mariadb']['port'],3306)
        edges=list(service_bindings.connections_for({key:cfg for key,(cfg,_,_) in values.items()}))
        self.assertEqual({(edge.target,edge.port)for edge in edges},{('postgresql',5432),('mariadb',3306)})
        for change in [lambda v:v['db-tools'][0]['app']['service_connections'].pop('cloudbeaver.mariadb'),
           lambda v:v['db-tools'][0]['app']['service_connections']['cloudbeaver.postgresql'].update(service='mariadb.mariadb'),
           lambda v:v['postgresql'][0]['app']['published_services']['postgresql'].update(port=3306)]:
            value=copy.deepcopy(before);change(value)
            with self.assertRaises(ValueError):service_bindings.bind(value)

    def test_variant_graph_has_plain_guest_title_and_one_application_phase(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'.github/workflows').mkdir(parents=True)
            (root/'.github/workflows/phase.yml').write_text('jobs:\n  run:\n    uses: example/framework/.github/workflows/guest-phase.yml@'+'a'*40+'\n')
            manifest={'schema':'homelab-stack-v2','routes':{},'values':{},'guests':{'db-tools':{'depends_on':[],'prerequisites':[]}}}
            (root/'stack.json').write_text(json.dumps(manifest))
            directory=root/'guests/db-tools';directory.mkdir(parents=True)
            (directory/'profile.json').write_text(json.dumps({'config':{'app':{'kind':'db-tools','variant':'cloudbeaver'}}}))
            with patch.object(workflows.compiler,'CATALOGUE',{'db-tools':compiler.CATALOGUE['db-tools']}):
                result=workflows.models(root)
            self.assertEqual(result['deploy.yml']['jobs']['db-tools']['name'],'CloudBeaver')
            job=result['guest-db-tools.yml']['jobs']['deploy']
            self.assertEqual([s['env']['PHASE']for s in job['steps']if s['name']=='Check inputs'],['infrastructure','preparation','cloudbeaver'])
            self.assertNotIn('pgadmin',json.dumps(result))


if __name__=='__main__':unittest.main()
