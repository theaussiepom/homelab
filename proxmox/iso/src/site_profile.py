"""Closed site-input validation and the after-install network payload."""
import ipaddress
import json
from pathlib import Path
import re
from zoneinfo import ZoneInfo
from homelab_installer import core


def validate_site(site):
    core.exact(site, {'schema','fqdn','mailto','keyboard','country','timezone','management','storage','admin_vlans','fast_vlans'}, 'site profile')
    core.require(site['schema']=='homelab-iso-site-v1','unsupported site profile')
    core.literal(site['fqdn'],'full hostname',r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?')
    core.require('.' in site['fqdn'] and all(label and len(label)<=63 and not label.startswith('-') and not label.endswith('-') for label in site['fqdn'].split('.')),'a full DNS hostname is required')
    core.literal(site['mailto'],'notification email',r'[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}')
    core.literal(site['keyboard'],'keyboard',r'[a-z0-9-]{1,32}')
    core.literal(site['country'],'country',r'[a-z]{2}')
    core.literal(site['timezone'],'timezone',r'[A-Za-z0-9_+/-]{1,80}')
    ZoneInfo(site['timezone'])
    for name,fields in [('management',{'address','gateway','dns','vlan'}),('storage',{'address','vlan'})]:
        net=core.exact(site[name],fields,name+' network')
        addr=ipaddress.IPv4Interface(net['address'])
        core.require(addr.ip not in (addr.network.network_address,addr.network.broadcast_address),'address must be a usable host address')
        core.integer(net['vlan'],1,4094,name+' VLAN')
    mgmt=ipaddress.IPv4Interface(site['management']['address']);storage=ipaddress.IPv4Interface(site['storage']['address'])
    gateway=ipaddress.IPv4Address(site['management']['gateway']);ipaddress.IPv4Address(site['management']['dns'])
    core.require(gateway in mgmt.network and gateway not in (mgmt.ip,mgmt.network.network_address,mgmt.network.broadcast_address),'gateway must be a different usable address in the management subnet')
    core.require(not mgmt.network.overlaps(storage.network),'management and storage subnets must be separate')
    for field in ('admin_vlans','fast_vlans'):
        values=site[field]
        core.require(type(values) is list and 1<=len(values)<=64,'explicit VLAN list required')
        for value in values:core.integer(value,1,4094,'VLAN')
        core.require(len(values)==len(set(values)),'duplicate VLAN')
    core.require(site['management']['vlan'] in site['admin_vlans'] and site['storage']['vlan'] in site['fast_vlans'],'host VLAN absent from its physical bridge')
    core.require(not set(site['admin_vlans'])&set(site['fast_vlans']),'physical bridge VLAN lists overlap')
    return site


def validate_production(hardware,site):
    from launch import validate_config
    validate_config(hardware);validate_site(site)
    core.require(hardware['environment']=='production','production hardware profile required')
    text=json.dumps([hardware,site]).upper()
    core.require('REPLACE' not in text and 'LAB-NEW' not in text and 'LAB-OLD' not in text,'replace example hardware values before building production media')
    core.require(not site['fqdn'].endswith(('.invalid','.example','.test')) and not site['mailto'].endswith(('.invalid','.example','.test')),'replace example hostname and email before building production media')


def first_boot_payload(hardware,site):
    validate_site(site)
    network={'expected':{name:mac for mac,name in hardware['interface_names'].items()},'management':site['management'],'storage':site['storage'],'admin_vlans':site['admin_vlans'],'fast_vlans':site['fast_vlans']}
    source=Path(__file__).with_name('first_boot.py').read_text()
    core.require(source.count('PROFILE = None')==1,'network payload placeholder changed')
    return ('#!/usr/bin/python3\n'+source.replace('PROFILE = None','PROFILE = '+repr(network))).encode()
