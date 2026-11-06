"""Ephemeral PostgreSQL TLS for local fixtures, never production certificates."""
from pathlib import Path
import subprocess

ENTRYPOINT = '''install -d -o postgres -g postgres -m 0700 /var/lib/postgresql/tls
install -o postgres -g postgres -m 0600 /fixture-tls/server.key /var/lib/postgresql/tls/server.key
install -o postgres -g postgres -m 0644 /fixture-tls/server.crt /var/lib/postgresql/tls/server.crt
printf 'local all all trust\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostnossl all all 0.0.0.0/0 reject\n' > /var/lib/postgresql/tls/pg_hba.conf
chown postgres:postgres /var/lib/postgresql/tls/pg_hba.conf
chmod 0600 /var/lib/postgresql/tls/pg_hba.conf
exec /usr/local/bin/docker-entrypoint.sh postgres -c hba_file=/var/lib/postgresql/tls/pg_hba.conf -c ssl=on -c ssl_cert_file=/var/lib/postgresql/tls/server.crt -c ssl_key_file=/var/lib/postgresql/tls/server.key
'''


def prepare(root):
    directory=root/'postgres-tls';directory.mkdir(mode=0o700)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1',
                    '-subj','/CN=postgres','-addext','subjectAltName=DNS:postgres',
                    '-keyout',str(directory/'server.key'),'-out',str(directory/'server.crt')],
                    check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (directory/'server.key').chmod(0o600)
    return directory


def apply(service, directory):
    service['entrypoint']=['sh','-eu','-c',ENTRYPOINT]
    service.setdefault('volumes',[]).append(str(directory)+':/fixture-tls:ro')
