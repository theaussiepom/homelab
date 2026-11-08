"""Finite PBS management API; authenticate only after exact TLS pin verification."""
import hashlib
import http.client
import re
import ssl
from urllib.parse import urlencode

from private_io import decode_json, require

LIMIT = 1024 * 1024
USER = r'hl-[0-9a-f]{32}@pbs'


class PBS:
    def __init__(self, destination, token, *, connect=http.client.HTTPSConnection):
        require(isinstance(destination.get('server'), str)
                and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', destination['server'])
                and type(destination.get('port')) is int and 1 <= destination['port'] <= 65535
                and isinstance(destination.get('datastore'), str)
                and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9._-]{2,31}', destination['datastore'])
                and isinstance(destination.get('fingerprint'), str)
                and re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){31}', destination['fingerprint']),
                'Use the validated PBS management destination')
        require(isinstance(token, str) and re.fullmatch(
            r'[A-Za-z0-9_.-]+@pbs![A-Za-z0-9_.-]+:[A-Za-z0-9_.-]{16,512}', token),
            'Use the protected PBS management token')
        self.destination, self.token, self.connect = dict(destination), token, connect
        self.store = destination['datastore']

    def request(self, method, path, fields=None):
        """No redirects, retries, response logging, datastore writes or arbitrary API."""
        allowed = {
            'GET': (r'/config/datastore/' + re.escape(self.store),
                    r'/admin/datastore/' + re.escape(self.store) + '/namespace',
                    r'/access/(?:users|acl|permissions)'),
            'POST': (r'/admin/datastore/' + re.escape(self.store) + '/namespace',
                     r'/access/users', r'/access/users/' + USER + '/token/backup'),
            'PUT': (r'/access/acl',)}
        require(method in allowed and isinstance(path, str)
                and any(re.fullmatch(pattern, path) for pattern in allowed[method]),
                'Refuse an undeclared PBS API operation')
        require(fields is None or isinstance(fields, dict)
                and all(isinstance(k, str) and isinstance(v, (str, int))
                    and not isinstance(v, bool) for k, v in fields.items()),
                'Use finite PBS API form fields')
        form = urlencode(fields or {})
        require(len(form) <= 8192, 'Bound PBS management requests')
        # PBS bootstrap uses its explicitly verified self-signed certificate.
        # The pin is checked on the connected socket BEFORE any HTTP credential.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = self.connect(self.destination['server'], self.destination['port'],
                                  timeout=30, context=context)
        try:
            connection.connect()
            connection.auto_open = 0  # A later HTTP write must never reconnect without rechecking the pin.
            peer = connection.sock.getpeercert(binary_form=True)
            require(hashlib.sha256(peer).hexdigest() == self.destination['fingerprint'].replace(':', ''),
                    'PBS certificate identity changed; no credential was sent')
            target = '/api2/json' + path + ('?' + form if method == 'GET' and form else '')
            connection.request(method, target, body=None if method == 'GET' else form,
                headers={'Authorization': 'PBSAPIToken=' + self.token,
                         'Content-Type': 'application/x-www-form-urlencoded'})
            response = connection.getresponse()
            require(200 <= response.status < 300, 'PBS refused a management request; no retry')
            raw = response.read(LIMIT + 1)
            require(len(raw) <= LIMIT, 'Oversized PBS management response')
            value = decode_json(raw)
            require(isinstance(value, dict) and 'data' in value, 'Invalid PBS management response')
            return value
        except (OSError, http.client.HTTPException):
            raise ValueError('PBS management transport failed; preserve any pending operation') from None
        finally:
            connection.close()

    def datastore(self, expected_path):
        value = self.request('GET', '/config/datastore/' + self.store)['data']
        require(isinstance(value, dict) and value.get('name') == self.store
                and value.get('path') == expected_path,
                'Prepare the declared datastore and mount before CD; never create a replacement')

    def users(self):
        value = self.request('GET', '/access/users', {'include_tokens': 1})['data']
        require(isinstance(value, list) and all(isinstance(row, dict) and 'userid' in row for row in value),
                'Invalid PBS user inventory')
        return value

    def namespaces(self):
        value = self.request('GET', '/admin/datastore/' + self.store + '/namespace', {'max-depth': 7})['data']
        require(isinstance(value, list) and all(isinstance(row, dict) and isinstance(row.get('ns'), str) for row in value),
                'Invalid PBS namespace inventory')
        return {row['ns'] for row in value}

    def permission(self, auth_id):
        value = self.request('GET', '/access/permissions', {'auth-id': auth_id})['data']
        require(isinstance(value, dict) and all(isinstance(path, str) and isinstance(row, dict)
                and all(isinstance(key, str) and type(flag) is bool for key, flag in row.items())
                for path, row in value.items()), 'Invalid PBS permission inventory')
        return value
