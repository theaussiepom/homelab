"""Real fixture files; only numeric ownership/chown and Docker boundaries mocked."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

CODE = Path(os.environ.get('MQTT_EXPLORER_RUNTIME', Path(__file__).resolve().parents[1] / 'mqtt-explorer-runtime.py'))

class Patches:
    def __init__(self, case): self.case = case
    def setattr(self, obj, name, value):
        item = patch.object(obj, name, value)
        item.start()
        self.case.addCleanup(item.stop)

def fixture(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('mqtt_explorer_runtime_fixture', CODE)
    m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    base = tmp_path.resolve();data = base / 'data' / 'mqtt-explorer';data.parent.mkdir()
    custody = base / 'custody';runtime = base / 'runtime';runtime.mkdir()
    monkeypatch.setattr(m, 'DATA', data);monkeypatch.setattr(m, 'CUSTODY', custody);monkeypatch.setattr(m, 'RUNTIME', runtime)
    owners, calls = {}, []
    original_lstat, original_fstat, original_open = Path.lstat, os.fstat, os.open

    def local(path):
        return isinstance(path, (str, bytes, Path)) and str(Path(path).absolute()).startswith(str(base) + '/')

    def key(info):
        return info.st_dev, info.st_ino

    def overlay(info, default=False):
        ids = owners.get(key(info), (0, 0) if default else None)
        if ids is None:
            return info
        return SimpleNamespace(**{name: ids[0] if name == 'st_uid' else ids[1] if name == 'st_gid' else getattr(info, name)
                                  for name in dir(info) if name.startswith('st_')})

    def lstat(path, *args, **kwargs):
        return overlay(original_lstat(path, *args, **kwargs), local(path))

    def opened(path, flags, mode=0o600, **kwargs):
        fd = original_open(path, flags, mode, **kwargs)
        if local(path):
            owners.setdefault(key(original_fstat(fd)), (0, 0))
        return fd

    def chown(path, uid, gid, **kwargs):
        assert local(path)
        owners[key(original_lstat(Path(path)))] = uid, gid
        calls.append((Path(path), uid, gid))

    def own(path, uid, gid):
        owners[key(original_lstat(Path(path)))] = uid, gid

    monkeypatch.setattr(Path, 'lstat', lstat)
    monkeypatch.setattr(m.os, 'fstat', lambda fd: overlay(original_fstat(fd)))
    monkeypatch.setattr(m.os, 'open', opened)
    monkeypatch.setattr(m.os, 'chown', chown)
    monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    return SimpleNamespace(m=m, data=data, custody=custody, runtime=runtime, own=own, calls=calls,
                           owner={'node': 'fixture-node', 'vmid': 123, 'hostname': 'fixture-guest'})

def healthy(f, monkeypatch):
    m = f.m;m.workspace(f.owner)
    ids = {'mqtt_explorer': 'a' * 64, 'explorer_gateway': 'b' * 64}
    config = {'data_path': str(f.data), 'bind_address': '198.18.0.2',
              'images': {name: 'registry.invalid/' + name + '@sha256:' + 'c' * 64 for name in ids}, 'runtime_sha256': {}}
    for name in ('explorer-traefik.json', 'explorer-routes.yml'):
        path = f.runtime / name;path.write_bytes(('public fixture ' + name).encode());path.chmod(0o400);f.own(path, 65532, 65532)
        config['runtime_sha256'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
    rows = {}
    for name in ids:
        rows[name] = {'Id': ids[name], 'Config': {'Labels': {'com.docker.compose.project': 'homelab-mqtt',
                       'com.docker.compose.service': name}, 'Image': config['images'][name],
                       'User': '1001:1001' if name == 'mqtt_explorer' else '65532:65532',
                       'Cmd': ['node', '-e', "process.umask(0o077);for(const level of ['log','info','debug','dir','table','trace'])console[level]=()=>{};console.warn=()=>process.stderr.write('MQTT Explorer warning\\n');console.error=()=>process.stderr.write('MQTT Explorer error\\n');require('./dist/src/server.js')"],
                       'Env': ['MQTT_EXPLORER_SKIP_AUTH=true']},
                      'State': {'Running': True, 'Health': {'Status': 'healthy'}},
                      'HostConfig': {'ReadonlyRootfs': True, 'NetworkMode': 'fixture-managed-network',
                                     'PortBindings': {} if name == 'mqtt_explorer' else {'4180/tcp': [{'HostIp': config['bind_address'], 'HostPort': '80'}]}},
                      'NetworkSettings': {'Networks': {'fixture-managed-network': {}}},
                      'Mounts': [{'Source': str(f.data), 'Destination': '/app/data', 'Type': 'bind', 'RW': True}] if name == 'mqtt_explorer' else []}

    def docker(args):
        if args[0] == 'ps':
            return ids[args[-1].rsplit('=', 1)[-1]] + '\n'
        assert args[0] == 'inspect'
        return json.dumps([rows[next(name for name, identifier in ids.items() if identifier == args[1])]])

    monkeypatch.setattr(m, 'docker', docker)
    return config, rows, docker

class MqttExplorerRuntimeTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.patches = Patches(self)
        self.fixture = fixture(Path(temporary.name), self.patches)
    def test_workspace_create_once_preserves_real_bytes_modes_and_owned_rerun(self):
        fixture = self.fixture
        monkeypatch = self.patches
        f = fixture;m = f.m
        assert m.workspace(f.owner) == {'workspace': 'owned'}
        receipt = f.custody / 'workspace.json';before = receipt.read_bytes()
        assert json.loads(before) == f.owner and receipt.stat().st_mode & 0o777 == 0o600
        assert f.data.stat().st_mode & 0o777 == 0o700
        assert f.calls == [(f.data, 1001, 1001)]
        content = f.data / 'retained-profile.json';content.write_bytes(b'public retained profile')
        assert m.workspace(f.owner) == {'workspace': 'owned'}
        assert receipt.read_bytes() == before and content.read_bytes() == b'public retained profile'
        assert len(f.calls) == 1

    def test_existing_unowned_nonempty_directory_refuses_without_chown(self):
        fixture = self.fixture
        monkeypatch = self.patches
        f = fixture;f.data.mkdir(mode=0o700);(f.data / 'existing').write_bytes(b'preserve')
        with self.assertRaises(ValueError):f.m.workspace(f.owner)
        assert f.calls == [] and (f.data / 'existing').read_bytes() == b'preserve'
        assert not (f.custody / 'workspace.json').exists()

    def test_foreign_receipt_or_data_identity_refuses_without_recommissioning(self):
        fixture = self.fixture
        monkeypatch = self.patches
        f = fixture;f.m.workspace(f.owner);before = (f.custody / 'workspace.json').read_bytes()
        with self.assertRaises(ValueError):f.m.workspace(dict(f.owner, hostname='other'))
        f.own(f.data, 55, 55)
        with self.assertRaises(ValueError):f.m.workspace(f.owner)
        assert (f.custody / 'workspace.json').read_bytes() == before and len(f.calls) == 1

    def test_real_private_read_refuses_mode_link_and_identity_drift(self):
        fixture = self.fixture
        monkeypatch = self.patches
        f = fixture;path = f.runtime / 'input';path.write_bytes(b'public fixture');path.chmod(0o600)
        assert f.m.read(path) == b'public fixture'
        path.chmod(0o644)
        with self.assertRaises(ValueError):f.m.read(path)
        path.chmod(0o600);link = path.with_name('link');os.link(path, link)
        with self.assertRaises(ValueError):f.m.read(path)
        link.unlink();link.symlink_to(path)
        with self.assertRaises((ValueError, OSError)):f.m.read(link)
        f.own(path, 77, 77)
        with self.assertRaises(ValueError):f.m.read(path)

    def test_health_checks_real_runtime_files_with_closed_docker_boundary(self):
        fixture = self.fixture
        monkeypatch = self.patches
        config, _, _ = healthy(fixture, monkeypatch)
        assert fixture.m.health(config) == {'mqtt_explorer': 'passed', 'gateway_only_listener': True,
                                          'sign_in': 'identity_provider_required'}
        (fixture.runtime / 'explorer-routes.yml').chmod(0o600)
        (fixture.runtime / 'explorer-routes.yml').write_bytes(b'tampered public fixture')
        with self.assertRaises(ValueError):fixture.m.health(config)

    def _health_drift(self, change):
        fixture = self.fixture
        monkeypatch = self.patches
        config, rows, _ = healthy(fixture, monkeypatch);app=rows['mqtt_explorer'];gateway=rows['explorer_gateway']
        if change == 'image':app['Config']['Image'] = 'foreign'
        elif change == 'label':app['Config']['Labels']['com.docker.compose.project'] = 'foreign'
        elif change == 'stopped':app['State']['Running'] = False
        elif change == 'unhealthy':gateway['State']['Health']['Status'] = 'unhealthy'
        elif change == 'writable':app['HostConfig']['ReadonlyRootfs'] = False
        elif change == 'hostnet':gateway['HostConfig']['NetworkMode'] = 'host'
        elif change == 'networks':gateway['NetworkSettings']['Networks'] = {'foreign': {}}
        elif change == 'user':app['Config']['User'] = '0:0'
        elif change == 'appport':app['HostConfig']['PortBindings'] = {'4000/tcp': [{'HostPort': '4000'}]}
        elif change == 'gatewayport':gateway['HostConfig']['PortBindings']['4180/tcp'][0]['HostIp'] = '0.0.0.0'
        elif change == 'command':app['Config']['Cmd'] = ['node', 'foreign.js']
        elif change == 'mount':app['Mounts'] = []
        elif change == 'mountreadonly':app['Mounts'][0]['RW'] = False
        elif change == 'llm':app['Config']['Env'].append('OPENAI_KEY=fixture')
        elif change == 'skipauth':app['Config']['Env'] = []
        with self.assertRaises(ValueError):fixture.m.health(config)

    def _inspect_boundary(self, payload):
        fixture = self.fixture
        monkeypatch = self.patches
        config, _, docker = healthy(fixture, monkeypatch)
        monkeypatch.setattr(fixture.m, 'docker', lambda args: payload if args[0] == 'inspect' else docker(args))
        with self.assertRaises((ValueError, KeyError, TypeError)):fixture.m.health(config)

    def test_health_refuses_nested_workspace_shadow(self):
        fixture = self.fixture
        monkeypatch = self.patches
        config, rows, _ = healthy(fixture, monkeypatch)
        rows['mqtt_explorer']['Mounts'].append({'Source': '/unexpected/fixture', 'Destination': '/app/data/profiles',
                                              'Type': 'bind', 'RW': True})
        with self.assertRaises(ValueError):fixture.m.health(config)

    def test_health_drift_image(self):
        self._health_drift('image')

    def test_health_drift_label(self):
        self._health_drift('label')

    def test_health_drift_stopped(self):
        self._health_drift('stopped')

    def test_health_drift_unhealthy(self):
        self._health_drift('unhealthy')

    def test_health_drift_writable(self):
        self._health_drift('writable')

    def test_health_drift_hostnet(self):
        self._health_drift('hostnet')

    def test_health_drift_networks(self):
        self._health_drift('networks')

    def test_health_drift_user(self):
        self._health_drift('user')

    def test_health_drift_appport(self):
        self._health_drift('appport')

    def test_health_drift_gatewayport(self):
        self._health_drift('gatewayport')

    def test_health_drift_command(self):
        self._health_drift('command')

    def test_health_drift_mount(self):
        self._health_drift('mount')

    def test_health_drift_mountreadonly(self):
        self._health_drift('mountreadonly')

    def test_health_drift_llm(self):
        self._health_drift('llm')

    def test_health_drift_skipauth(self):
        self._health_drift('skipauth')

    def test_inspect_boundary_0(self):
        self._inspect_boundary('[]')

    def test_inspect_boundary_1(self):
        self._inspect_boundary('{}')

    def test_inspect_boundary_2(self):
        self._inspect_boundary('[{},{}]')

    def test_inspect_boundary_3(self):
        self._inspect_boundary('not-json')


if __name__ == '__main__':
    unittest.main()
