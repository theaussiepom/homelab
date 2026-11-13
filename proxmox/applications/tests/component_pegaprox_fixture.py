"""Synthetic resolved PegaProx descriptor for pure rendering and protocol fixtures."""
import component_runtime

IMAGE='ghcr.io/pegaprox/pegaprox:fixture@sha256:'+'1'*64


def descriptor(address='198.18.25.34',proxy='198.18.25.33/32',image=IMAGE):
    return {'id':'management','adapter':'pegaprox','lifecycle':'retained','project_name':'homelab-pegaprox',
        'identity':{'runtime_id':'management','services':{'pegaprox':'pegaprox'},
                    'networks':{'default':'default'},'runtime_directory':'/opt/homelab-app/runtime'},
        'containers':{'pegaprox':{'memory_mib':1024,'cpu_limit':1,'pids_limit':256,
            'read_only':True,'cap_drop':['ALL'],'no_new_privileges':True,
            'tmpfs':['/tmp:rw,nosuid,nodev,size=64m']}},
        'software_selection':{'images':{'pegaprox':{'image':image}}},
        'secret_bindings':{'database_key':{'type':'file','path':'/run/synthetic/retained-key'}},
        'settings':{'trusted_proxy':proxy},'role_addresses':{'web_interface':address},
        'storage_paths':{name:{'source':'/srv/homelab/data/pegaprox/'+name,'target':'/app/'+name,
                              'kind':'directory','read_only':False} for name in ('config','logs')},
        'listeners':{'web_listener':{'service':'pegaprox','namespace':'app-network','interface':'private_interface',
            'bind':'wildcard','actual_bind':'0.0.0.0','protocol':'tcp','port':5000,
            'publication_address':address,'publish':{'scope':'guest-interface','interface':'web_interface','port':5000}}}}


def guest():return {'timezone':'Etc/UTC','memory_mib':2048,'os_reserve_mib':512}


def service(address='198.18.25.34',proxy='198.18.25.33/32',image=IMAGE):
    return component_runtime._pegaprox(descriptor(address,proxy,image),guest())['pegaprox']
