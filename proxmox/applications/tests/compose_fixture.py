"""Render synthetic current app stacks for Docker Compose structural validation."""

import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_render import fixture
from test_foundation import fixture as foundation_fixture
from render import compose

root = Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory() as td:
    directory = Path(td)
    for kind in ["dns", "identity", "ingress", "automation", "db-tools", "zigbee2mqtt"]:
        cfg = (
            foundation_fixture(directory, kind)
            if kind in ["identity", "ingress", "db-tools"]
            else fixture(kind)
        )
        (root / (kind + ".json")).write_text(json.dumps(compose(cfg)))
