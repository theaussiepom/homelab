"""Provider projection units with validated Plan/app/endpoint collaborators."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'proxmox/applications'))

import component_routes as routes
from component_errors import ComponentError


def fixture():
    return SimpleNamespace(check=Mock(),resolved={'apps':{'owned':{'guest':'one'},'other':{'guest':'two'}},
        'middlewares':{'login':{'type':'forward-auth'},'other-login':{'type':'forward-auth'},
                       'security':{'type':'headers'}},'routes':{}})


def publication(**changes):
    return {'type':'http','hosts':['App.example.invalid'],
        'target':{'app':'owned','protocol':'http','address':'198.18.30.20','port':9000},**changes}


class RouteProjectionTests(unittest.TestCase):
    def test_host_alias_transport_middleware_order_and_forward_auth_are_copied(self):
        plan=fixture();value=publication(hosts=['App.example.invalid','Alias.example.invalid'],
            middlewares=['security','login'],transport='verified-backend')
        before=copy.deepcopy(value)
        selected=routes.route(plan,value)
        self.assertEqual(selected,{'host':'App.example.invalid','aliases':['Alias.example.invalid'],
            'url':'http://198.18.30.20:9000','middlewares':['security','login'],
            'transport':'verified-backend','authentik_forward_auth':'login'})
        selected['middlewares'].append('changed');selected['aliases'].append('changed')
        self.assertEqual(value,before)

    def test_internal_dashboard_has_owned_service_and_no_fabricated_socket(self):
        plan=fixture();selected=routes.route(plan,publication(
            target={'app':'ingress','internal':'dashboard'},middlewares=['login']))
        self.assertEqual(selected,{'host':'App.example.invalid','middlewares':['login'],
            'service':'api@internal','authentik_forward_auth':'login'})
        self.assertNotIn('url',selected)
        with self.assertRaisesRegex(ComponentError,'component.exposure'):
            routes.route(plan,dict(publication(),type='dns'))
        with self.assertRaisesRegex(ComponentError,'component.authentication'):
            routes.route(plan,publication(middlewares=['login','other-login']))

    def test_provider_routes_filters_ownership_and_delegates_final_protocol_validation(self):
        plan=fixture();plan.resolved['routes']={'ingress':{
            'owned':publication(),
            'other':publication(target={'app':'other','protocol':'https','address':'198.18.30.21','port':9443}),
            'external':publication(target={'protocol':'http','address':'198.18.25.8','port':80}),
            'internal':publication(target={'app':'owned','internal':'dashboard'})}}
        before=copy.deepcopy(plan.resolved)
        with patch.object(routes.discovery,'validate_routes')as validate:
            selected=routes.provider_routes(plan,'one')
        plan.check.assert_called_once_with();validate.assert_called_once_with(selected)
        self.assertEqual(selected,{'owned':{'host':'App.example.invalid','middlewares':[],
                                           'url':'http://198.18.30.20:9000'}})
        self.assertEqual(plan.resolved,before)
        plan.resolved['routes']['second']={'owned':publication()}
        with self.assertRaisesRegex(ComponentError,'component.exposure-conflict'):
            routes.provider_routes(plan,'one')

    def test_real_private_route_projection_produces_current_provider_notes(self):
        plan=fixture();plan.resolved['routes']={'ingress':{'web':publication()}}
        selected=routes.provider_routes(plan,'one')
        labels=routes.discovery.labels({'routes':selected,'guest':{'interfaces':[{'ipv4':'198.18.30.20/24'}]}})
        self.assertEqual(labels['traefik.http.routers.web.rule'],'Host(`App.example.invalid`)')
        self.assertEqual(labels['traefik.http.services.web.loadbalancer.server.url'],'http://198.18.30.20:9000')
        self.assertEqual(labels['traefik.http.routers.web.tls.certresolver'],'letsencrypt')


if __name__=='__main__':unittest.main()
