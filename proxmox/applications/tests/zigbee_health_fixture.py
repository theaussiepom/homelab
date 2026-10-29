#!/usr/bin/env python3
"""Run the generated health command in the pinned Zigbee image, without USB access."""

import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_render import fixture
import render

IMAGE = "koenkk/zigbee2mqtt@sha256:fef0de769dcd04c27b3a6d277b61046eb96284bdd4198dcb1687c3a01b3020f3"
CHECK = r"""
const http = require('http');
const {execFile} = require('child_process');
const health = JSON.parse(process.argv[1]);
let mode = 200;
const server = http.createServer((req, res) => {
  if (mode === 'stall') return;
  res.writeHead(mode); res.end('fixture');
});
function run() {
  return new Promise((resolve, reject) => execFile(health[0], health.slice(1), {timeout: 6000}, error => {
    if (error && error.code !== 1) reject(error);
    else resolve(error ? error.code : 0);
  }));
}
server.listen(8099, '127.0.0.1', async () => {
  try {
    const results = [await run()];
    mode = 503; results.push(await run());
    mode = 'stall'; results.push(await run());
    await new Promise(resolve => server.close(resolve));
    results.push(await run());
    if (JSON.stringify(results) !== '[0,1,1,1]') throw new Error('Unexpected health results');
    console.log(JSON.stringify({passed: true, http_200: true, http_503: false, timeout: false, refused: false, radio_opened: false}));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
  finally { server.close(); }
});
"""

if __name__ == "__main__":
    health = render.compose(fixture("zigbee2mqtt"))["services"]["zigbee2mqtt"][
        "healthcheck"
    ]["test"]
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=64m",
            "--entrypoint",
            "node",
            IMAGE,
            "-e",
            CHECK,
            json.dumps(health[1:]),
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode:
        raise SystemExit("Isolated Zigbee health fixture failed: " + result.stderr)
    print(result.stdout.strip())
