'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const test = require('node:test');

test('the exact generated startup hides RPC payloads and retains fixed errors and exit status', () => {
  const root = path.resolve(__dirname, '../../..');
  const rendered = spawnSync('python3', ['-c',
    "import sys,json;sys.path.insert(0,'proxmox/applications/tests');" +
    'from test_component_proxies import descriptor,guest;import component_runtime as runtime;' +
    "app=descriptor('mqtt_explorer');" +
    "cfg={'schema':runtime.SCHEMA,'guest':guest('mqtt_explorer'),'applications':{'selected':app}};" +
    "print(json.dumps(runtime.compositions(cfg)[app['project_name']]['services']['mqtt_explorer']['command']))"],
  {cwd: root, encoding: 'utf8', timeout: 15000});
  assert.equal(rendered.status, 0, rendered.stderr);
  const command = JSON.parse(rendered.stdout);
  assert.deepEqual(command.slice(0, 2), ['node', '-e']);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mqtt-console-fixture-'));
  try {
    const source = "const secret='synthetic-private-broker-password';" +
      "for(const level of ['log','info','debug','dir','table','trace'])console[level]({password:secret},new Error(secret));" +
      'console.warn(new Error(secret));console.error({password:secret});' +
      'if(process.umask()!==0o077)process.exit(8);';
    fs.mkdirSync(path.join(directory, 'dist/src'), {recursive: true});
    for (const exitCode of [0, 7]) {
      fs.writeFileSync(path.join(directory, 'dist/src/server.js'), source+'process.exitCode='+exitCode+';');
      const result = spawnSync(process.execPath, command.slice(1), {cwd: directory, encoding: 'utf8', timeout: 15000});
      assert.equal(result.status, exitCode);
      assert.equal(result.stdout, '');
      assert.equal(result.stderr, 'MQTT Explorer warning\nMQTT Explorer error\n');
      assert.ok(!(result.stdout+result.stderr).includes('synthetic-private-broker-password'));
    }
  } finally {
    fs.rmSync(directory, {recursive: true});
  }
});
