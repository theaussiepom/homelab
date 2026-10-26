"""Write synthetic Compose documents for Docker Compose's real parser."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_render import fixture
from render import compose, ingress
from test_pgadmin import fixture as pgadmin_fixture

output = Path(sys.argv[1]); output.mkdir(parents=True, exist_ok=True)
for kind in ('dns', 'identity', 'ingress', 'automation'):
    (output / f'{kind}.json').write_text(json.dumps(compose(fixture(kind))))
(output / 'routes.json').write_text(json.dumps(ingress(fixture('ingress'))))
(output / 'db-tools.json').write_text(json.dumps(compose(pgadmin_fixture())))
