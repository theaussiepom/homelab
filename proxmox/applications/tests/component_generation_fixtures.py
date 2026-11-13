"""Small current-only backend and owned JSON fixtures; no adoption constructors."""
from plan_policy import RESOURCES
from private_io import digest,encoded


def save(path,value):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    path.write_bytes(value if isinstance(value,bytes) else encoded(value))
    path.chmod(0o600)
    return digest(path.read_bytes())


def backend(vmid,serial=2):
    return {'version':4,'lineage':f'fixture-{vmid}','serial':serial,'resources':[
        {'module':address.rsplit('.',2)[0],'type':address.split('.')[-2],
         'name':address.split('.')[-1],'mode':'managed','instances':[
             {'attributes':{key:vmid,'node_name':'fixture-pve','id':f'fixture/{vmid}/{key}'}}]}
        for address,key in RESOURCES.items()]}
