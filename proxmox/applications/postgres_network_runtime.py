"""One bound PostgreSQL network change; the caller owns custody and admission.

The Ansible playbook passes this source directly to Python, so inspection and
verification install no helper or target files. Protocol results are private:
the playbook suppresses stdout and saves them only in caller-owned local custody.
No state, workflow, retries, backups, credentials or data migration are managed
here. A failed mutation remains for the caller's hold; it is never rolled back.
"""
import argparse
from contextlib import ExitStack
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time

SCHEMA = 'homelab-postgresql-network-runtime-v1'
CHANGE = 'homelab-postgresql-network-change-v1'
IDENTITY = Path('/etc/homelab-application.json')
UID_MAP = Path('/proc/self/uid_map')
PVE = Path('/etc/pve')
CLUSTERS = Path('/etc/postgresql')
DATA = Path('/var/lib/postgresql')
ROOT_UID = 0
LIMIT = 131072
SQL = """SELECT json_build_object(
 'version',current_setting('server_version'),
 'version_num',current_setting('server_version_num'),
 'config_file',current_setting('config_file'),
 'hba_file',current_setting('hba_file'),
 'data_directory',current_setting('data_directory'),
 'listen_addresses',current_setting('listen_addresses'),
 'port',current_setting('port'),
 'start_time',pg_postmaster_start_time()::text,
 'file_errors',(SELECT coalesce(json_agg(error),'[]') FROM pg_file_settings WHERE error IS NOT NULL),
 'hba',(SELECT coalesce(json_agg(json_build_object('type',type,'database',database,
   'user_name',user_name,'address',address,'netmask',netmask,'auth_method',auth_method,
   'options',options,'file_name',file_name,'error',error) ORDER BY rule_number),'[]') FROM pg_hba_file_rules)
)"""


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def command(argv, timeout=20):
    """Bounded argv-only command; never log SQL, configuration or stderr."""
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C',
                               'HOME':'/var/lib/postgresql','PGCONNECT_TIMEOUT':'3'}).stdout


def read_file(path, owners, modes=(0o600,), *, text=True):
    """Read a bounded regular file, refusing links and writable public metadata."""
    require(not any(parent.is_symlink() for parent in (path, *path.parents)), 'A cluster path is symlinked')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid in owners
                and stat.S_IMODE(info.st_mode) in modes and info.st_size <= LIMIT,
                'An installed cluster file has unsupported ownership, mode or shape')
        raw = stream.read(LIMIT + 1)
    require(len(raw) <= LIMIT and b'\x00' not in raw, 'An installed cluster file is oversized or invalid')
    result = dict(sha256=sha(raw), uid=info.st_uid, gid=info.st_gid,
                  mode=stat.S_IMODE(info.st_mode), inode=info.st_ino, device=info.st_dev)
    if text:
        result['text'] = raw.decode('utf-8')
    return result


def cluster_paths(cluster):
    require(isinstance(cluster, dict) and set(cluster) == {'major', 'name'}
            and type(cluster['major']) is int and 10 <= cluster['major'] <= 99
            and isinstance(cluster['name'], str) and re.fullmatch('[a-z][a-z0-9_]*', cluster['name']),
            'Select the exact installed PostgreSQL cluster')
    directory = CLUSTERS / str(cluster['major']) / cluster['name']
    return {'homelab.conf': directory / 'conf.d/homelab.conf', 'pg_hba.conf': directory / 'pg_hba.conf',
            'config': directory / 'postgresql.conf', 'auto': DATA / str(cluster['major']) / cluster['name'] / 'postgresql.auto.conf'}


def selected_identity(value):
    require(isinstance(value, dict) and set(value) == {'vmid', 'hostname', 'address', 'mac'}
            and type(value['vmid']) is int and value['vmid'] >= 100 and value['vmid'] not in {900,4914,4915,4920}
            and isinstance(value['hostname'], str) and re.fullmatch('[a-z][a-z0-9-]{0,62}', value['hostname'])
            and isinstance(value['address'], str) and isinstance(value['mac'], str)
            and re.fullmatch(r'02(?::[0-9a-f]{2}){5}', value['mac']), 'Select the exact existing database guest')
    ipaddress.IPv4Address(value['address'])


def guest_guard(identity):
    require(os.geteuid() == 0 and not PVE.exists(), 'Use only the selected application guest playbook')
    selected_identity(identity)
    mapping = UID_MAP.read_text()
    require(re.search(r'(?m)^\s*0\s+[1-9][0-9]*\s+[1-9][0-9]*\s*$', mapping)
            and not re.search(r'(?m)^\s*[0-9]+\s+0\s+[1-9][0-9]*\s*$', mapping), 'Refuse a privileged namespace')
    saved = json.loads(read_file(IDENTITY, {ROOT_UID})['text'])
    require(saved == {key: identity[key] for key in ('vmid','hostname','address')} | {'kind':'postgresql'},
            'The existing application identity differs')


def unit_name(cluster):
    cluster_paths(cluster)
    return 'postgresql@' + str(cluster['major']) + '-' + cluster['name'] + '.service'


def process(cluster, execute, active=True):
    output = execute(['systemctl','show',unit_name(cluster),
                      '--property=MainPID,ActiveEnterTimestampMonotonic,ActiveState']).decode().splitlines()
    result = dict(line.split('=',1) for line in output)
    require(set(result) == {'MainPID','ActiveEnterTimestampMonotonic','ActiveState'}
            and result['ActiveState'] in {'active','inactive','failed'}
            and re.fullmatch('[0-9]+',result['MainPID'])
            and re.fullmatch('[0-9]+',result['ActiveEnterTimestampMonotonic']), 'Unexpected selected cluster process state')
    if active:
        require(result['ActiveState'] == 'active' and int(result['MainPID']) > 0
                and int(result['ActiveEnterTimestampMonotonic']) > 0, 'The selected cluster is not active')
    return result


def query(execute):
    return json.loads(execute(['runuser','--user','postgres','--','/usr/bin/psql','--no-psqlrc',
        '--no-password','--host=/var/run/postgresql','--port=5432','--dbname=postgres',
        '--set=ON_ERROR_STOP=1','--tuples-only','--no-align','--command',SQL]))


def hba_rows(text, path):
    """Restrict the supported policy to preserved peer/loopback and SCRAM rows."""
    result = []
    for line in text.splitlines():
        fields = line.split('#',1)[0].split()
        if not fields:
            continue
        require(fields[0] in {'local','host'} and len(fields) == (4 if fields[0] == 'local' else 5)
                and all(re.fullmatch('[a-z_][a-z0-9_,]*', token) for token in fields[1:3]),
                'Review HBA includes, names, options or other authentication policy')
        local = fields[0] == 'local'
        require((local and fields[3] == 'peer') or (not local and fields[1:3] == ['all','all']
                and fields[4] == 'scram-sha-256'), 'Preserve peer and SCRAM authentication only')
        network = None if local else ipaddress.ip_network(fields[3], strict=True)
        result.append({'type':fields[0], 'database':fields[1].split(','), 'user_name':fields[2].split(','),
                       'address':None if local else str(network.network_address),
                       'netmask':None if local else str(network.netmask), 'auth_method':fields[-1],
                       'options':None, 'file_name':str(path), 'error':None})
    require(result, 'Require an existing explicit PostgreSQL HBA policy')
    return result


def listener(value):
    values = [part.strip() for part in value.split(',')]
    require(len(values) == len(set(values)) and all(values), 'Ambiguous PostgreSQL listener')
    return set(values)


def file_state(identity, cluster, execute):
    """Read the bound cluster files even if an approved NIC cycle stopped it."""
    guest_guard(identity)
    paths = cluster_paths(cluster); account = pwd.getpwnam('postgres')
    files = {name:read_file(paths[name], {account.pw_uid}) for name in ('homelab.conf','pg_hba.conf')}
    config = read_file(paths['config'], {ROOT_UID,account.pw_uid}, (0o600,0o640,0o644))
    includes = [line.split('#',1)[0].strip() for line in config['text'].splitlines()
                if re.match(r'\s*include',line.split('#',1)[0])]
    require(len(includes) == 1 and re.fullmatch(r"include_dir\s*=\s*'conf.d'",includes[0]),
            'Review the cluster configuration include graph')
    directory = paths['homelab.conf'].parent
    require(not directory.is_symlink() and sorted(p.name for p in directory.glob('*.conf')) == ['homelab.conf'],
            'Review extra cluster configuration files')
    require(not re.search(r'(?m)^\s*include',files['homelab.conf']['text']), 'Review includes in the managed server configuration')
    auto = read_file(paths['auto'], {account.pw_uid}, text=True)
    require(not any(line.split('#',1)[0].strip() for line in auto['text'].splitlines()),
            'Review automatic configuration overrides before changing the listener')
    binary = '/usr/lib/postgresql/'+str(cluster['major'])+'/bin/postgres'
    binary_version = execute(['runuser','--user','postgres','--',binary,'--version']).decode().strip()
    require(re.match(r'postgres \(PostgreSQL\) '+str(cluster['major'])+r'\.',binary_version),
            'The installed PostgreSQL binary version differs')
    return {'files':files, 'guards':{str(paths['config']):{k:v for k,v in config.items() if k != 'text'},
                                    str(paths['auto']):{k:v for k,v in auto.items() if k != 'text'}},
            'binary_version':binary_version}


def inspect(identity, cluster, execute=command):
    """Return private file/config/process evidence without target writes."""
    state = file_state(identity,cluster,execute); paths = cluster_paths(cluster)
    settings = query(execute)
    require(settings['config_file'] == str(paths['config']) and settings['hba_file'] == str(paths['pg_hba.conf'])
            and settings['data_directory'] == str(paths['auto'].parent) and settings['port'] == '5432'
            and int(settings['version_num']) // 10000 == cluster['major'] and settings['file_errors'] == []
            and settings['hba'] == hba_rows(state['files']['pg_hba.conf']['text'],paths['pg_hba.conf']),
            'The running cluster paths, version or parsed configuration differ')
    return {'schema':SCHEMA, 'identity':identity, 'cluster':cluster, 'unit':unit_name(cluster),
            **state,
            'settings':settings, 'process':process(cluster,execute)}


def prepare(catalogue, inspected, client_vmids, legacy_address):
    """Render an exact candidate locally with the shared server renderer."""
    import database_network_server as server
    import database_networks as networks
    require(inspected['schema'] == SCHEMA, 'Use the inspected PostgreSQL snapshot')
    selected_identity(inspected['identity'])
    net, member = networks.selected(catalogue,'postgresql',inspected['identity']['vmid'])
    require(member == net['server'] and member['hostname'] == inspected['identity']['hostname'],
            'The catalogue must select the inspected PostgreSQL server')
    result = server.render(catalogue,'postgresql',{name:row['text'] for name,row in inspected['files'].items()},
                           phase='cutover',client_vmids=client_vmids)
    packet = {'schema':CHANGE, 'before':inspected, 'old_address':legacy_address,
              'endpoint':result['endpoint'], 'clients':server.clients(catalogue,'postgresql',client_vmids),
              'candidate':{name:{'text':text,'sha256':sha(text.encode())} for name,text in result['files'].items()},
              'activation':{'action':'restart','unit':inspected['unit']}}
    validate_change(packet)
    return packet


def validate_change(packet):
    """Admit only the bounded listener/HBA delta encoded by the reviewed caller."""
    require(set(packet) == {'schema','before','old_address','endpoint','clients','candidate','activation'}
            and packet['schema'] == CHANGE, 'Use the closed PostgreSQL runtime change')
    before = packet['before']; selected_identity(before['identity']); paths = cluster_paths(before['cluster'])
    require(before['schema'] == SCHEMA and before['unit'] == unit_name(before['cluster'])
            and packet['activation'] == {'action':'restart','unit':before['unit']}
            and set(before['files']) == set(packet['candidate']) == {'homelab.conf','pg_hba.conf'}
            and set(packet['endpoint']) == {'address','port'} and packet['endpoint']['port'] == 5432,
            'Select the inspected cluster and its one restart')
    old, new = (ipaddress.IPv4Address(packet['old_address']),ipaddress.IPv4Address(packet['endpoint']['address']))
    private = [ipaddress.IPv4Network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    require(any(old in net for net in private) and any(new in net for net in private)
            and all(address not in {ipaddress.IPv4Network(str(address)+'/24',strict=False).network_address,
                                    ipaddress.IPv4Network(str(address)+'/24',strict=False).broadcast_address}
                    for address in (old,new))
            and ipaddress.IPv4Network(str(old)+'/24',strict=False) != ipaddress.IPv4Network(str(new)+'/24',strict=False),
            'Select distinct private old and new database subnets')
    clients = packet['clients']; subnet = ipaddress.IPv4Network(str(new)+'/24',strict=False)
    require(isinstance(clients,list) and 1 <= len(clients) <= 32
            and len({client['vmid'] for client in clients}) == len(clients)
            and len({client['address'] for client in clients}) == len(clients), 'Select finite distinct SQL clients')
    for client in clients:
        require(set(client) == {'vmid','hostname','address','mac'} and type(client['vmid']) is int
                and client['vmid'] >= 100 and client['vmid'] not in {900,4914,4915,4920,before['identity']['vmid']}
                and isinstance(client['address'],str) and ipaddress.IPv4Address(client['address']) in subnet
                and ipaddress.IPv4Address(client['address']) not in {subnet.network_address,subnet.broadcast_address,new},
                'A selected client differs from the new database network')
    for name in packet['candidate']:
        for value in (before['files'][name],packet['candidate'][name]):
            require(isinstance(value['text'],str) and len(value['text'].encode()) <= LIMIT
                    and sha(value['text'].encode()) == value['sha256'], 'A bound configuration digest differs')
    config = before['files']['homelab.conf']['text']
    matches = list(re.finditer(r"(?m)^([ \t]*listen_addresses[ \t]*=[ \t]*)'([^'\r\n]*)'([ \t]*(?:#[^\r\n]*)?)$",config))
    require(len(matches) == 1 and listener(matches[0][2]) == {'127.0.0.1',str(old)}
            and listener(before['settings']['listen_addresses']) == {'127.0.0.1',str(old)},
            'The old listener must match the inspected selected source')
    expected = config[:matches[0].start(2)]+'127.0.0.1,'+str(new)+config[matches[0].end(2):]
    require(packet['candidate']['homelab.conf']['text'] == expected, 'The candidate changes more than the selected listener')
    retained, remote = [], []
    hba_rows(before['files']['pg_hba.conf']['text'],paths['pg_hba.conf'])
    for line in before['files']['pg_hba.conf']['text'].splitlines():
        fields = line.split('#',1)[0].split()
        if not fields or fields[0] == 'local' or ipaddress.ip_network(fields[3],strict=True).is_loopback:
            retained.append(line)
        else:
            remote.append(ipaddress.ip_network(fields[3],strict=True))
    require(remote == [ipaddress.IPv4Network(str(old)+'/24',strict=False)],
            'Review extra remote HBA paths before replacing the selected legacy subnet')
    expected_hba = '\n'.join([*retained,*['host all all '+client['address']+'/32 scram-sha-256' for client in clients]])+'\n'
    require(packet['candidate']['pg_hba.conf']['text'] == expected_hba, 'The candidate HBA differs from only selected client access')
    hba_rows(before['files']['pg_hba.conf']['text'],paths['pg_hba.conf'])
    hba_rows(expected_hba,paths['pg_hba.conf'])


def sockets(execute):
    rows = execute(['ss','--no-header','--listening','--tcp','--numeric','sport','=',':5432']).decode().splitlines()
    addresses = set()
    for row in rows:
        fields = row.split(); require(len(fields) >= 5, 'Unexpected PostgreSQL socket output')
        address,port = fields[3].rsplit(':',1)
        require(port == '5432', 'Unexpected PostgreSQL socket port')
        addresses.add(address.strip('[]'))
    return addresses


def verify(packet, execute=command):
    """Read-only effective candidate verification; never stage files or restart."""
    validate_change(packet)
    before = packet['before']; current = inspect(before['identity'],before['cluster'],execute)
    for name,value in packet['candidate'].items():
        require(current['files'][name]['text'] == value['text'] and current['files'][name]['sha256'] == value['sha256']
                and all(current['files'][name][key] == before['files'][name][key] for key in ('uid','gid','mode','inode','device')),
                'The installed candidate content or file metadata differs')
    require(current['guards'] == before['guards'], 'An unrelated PostgreSQL configuration file changed')
    # Later maintenance verification does not own routine minor package updates.
    # Admission and activation still bind the exact inspected binary version.
    require(int(current['settings']['version_num']) // 10000 == before['cluster']['major']
            and all(current['settings'][key] == before['settings'][key] for key in
                    ('data_directory','config_file','hba_file','port')),
            'The selected cluster version or paths changed')
    expected = {'127.0.0.1',packet['endpoint']['address']}
    require(listener(current['settings']['listen_addresses']) == sockets(execute) == expected,
            'The effective PostgreSQL listeners differ from localhost and the new endpoint')
    return {'status':'passed','changed':False,'unit':before['unit'], 'endpoint':packet['endpoint'],
            'config_sha256':{name:row['sha256'] for name,row in current['files'].items()},
            'process':current['process'], 'start_time':current['settings']['start_time']}


def preflight(packet, execute=command):
    """Recheck the original healthy snapshot before caller-owned quiescence."""
    validate_change(packet)
    before = packet['before']
    require(inspect(before['identity'],before['cluster'],execute) == before,
            'The original healthy PostgreSQL runtime changed before group admission')
    return {'status':'passed','changed':False,'unit':before['unit'], 'phase':'preflight',
            'config_sha256':{name:row['sha256'] for name,row in before['files'].items()}}


def activate(packet, execute=command):
    """Write only the two bound files, validate them, restart this cluster once."""
    validate_change(packet)
    before = packet['before']; paths = cluster_paths(before['cluster'])
    require(file_state(before['identity'],before['cluster'],execute) ==
            {key:before[key] for key in ('files','guards','binary_version')},
            'The inspected cluster configuration changed before activation')
    previous_process = process(before['cluster'],execute,active=False)
    # Anchor both existing inodes before the first write. Retain ownership/mode;
    # never replace files, touch data, or hide a partial write with rollback.
    with ExitStack() as stack:
        streams = {name:stack.enter_context(os.fdopen(os.open(paths[name],os.O_RDWR|os.O_NOFOLLOW),'r+b'))
                   for name in ('homelab.conf','pg_hba.conf')}
        for name,stream in streams.items():
            info = os.fstat(stream.fileno()); bound = before['files'][name]
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)) ==
                        tuple(bound[key] for key in ('device','inode','uid','gid','mode'))
                    and stream.read() == bound['text'].encode(), 'A runtime file changed at write admission')
        for name,stream in streams.items():
            stream.seek(0); stream.write(packet['candidate'][name]['text'].encode())
            stream.truncate(); stream.flush(); os.fsync(stream.fileno())
    binary = '/usr/lib/postgresql/'+str(before['cluster']['major'])+'/bin/postgres'
    parsed = execute(['runuser','--user','postgres','--',binary,'-D',str(paths['auto'].parent),
                      '-c','config_file='+str(paths['config']),'-C','listen_addresses']).decode().strip()
    require(listener(parsed) == {'127.0.0.1',packet['endpoint']['address']}, 'PostgreSQL rejected the candidate effective listener')
    # There is no offline PostgreSQL HBA parser. The closed generated grammar
    # is validated above; use PostgreSQL's view too when the original server is
    # still running. An approved provider cycle may have left the old listener
    # down, in which case native HBA parsing is verified after the one restart.
    hba_validation = 'strict-supported-policy'
    if previous_process['ActiveState'] == 'active':
        require(query(execute)['hba'] == hba_rows(packet['candidate']['pg_hba.conf']['text'],paths['pg_hba.conf']),
                'PostgreSQL rejected the candidate HBA before restart')
        hba_validation = 'postgresql-parser'
    require(process(before['cluster'],execute,active=False) == previous_process,
            'The cluster process changed before its selected restart')
    staged = file_state(before['identity'],before['cluster'],execute)
    require(staged['guards'] == before['guards'] and staged['binary_version'] == before['binary_version']
            and all(staged['files'][name] == dict(before['files'][name],**candidate)
                    for name,candidate in packet['candidate'].items()), 'The staged candidate changed before restart')
    execute(['systemctl','restart',before['unit']],timeout=90)
    # Bounded read-only readiness attempts do not repeat mutation.
    for attempt in range(10):
        try:
            result = verify(packet,execute)
            require(result['start_time'] != before['settings']['start_time']
                    and result['process']['ActiveEnterTimestampMonotonic'] != before['process']['ActiveEnterTimestampMonotonic'],
                    'The selected restart was not observed')
            return dict(result,changed=True,hba_validation_before_restart=hba_validation)
        except (OSError,ValueError,subprocess.SubprocessError):
            if attempt == 9:
                raise
            time.sleep(1)


def run(mode, request, execute=command):
    if mode == 'inspect':
        require(set(request) == {'schema','identity','cluster'} and request['schema'] == SCHEMA,
                'Use the closed PostgreSQL inspection request')
        return inspect(request['identity'],request['cluster'],execute)
    return {'preflight':preflight,'activate':activate,'verify':verify}[mode](request,execute)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('inspect','preflight','activate','verify'))
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(1024*1024+1)
        require(len(raw) <= 1024*1024, 'Oversized private runtime request')
        print(json.dumps(run(args.mode,json.loads(raw))))
    except Exception:
        raise SystemExit('PostgreSQL runtime operation failed; preserve the caller-held private evidence. No automatic retry.') from None
