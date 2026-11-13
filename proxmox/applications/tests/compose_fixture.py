"""Render independent synthetic apps/projects for Compose structural validation."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import protocol_component_fixtures as component_fixtures


def main(output):
    root = Path(output)
    root.mkdir(parents=True, exist_ok=True)
    for project, document in component_fixtures.structural_documents().items():
        (root / (project + ".json")).write_text(json.dumps(document))


if __name__ == "__main__":
    main(sys.argv[1])
