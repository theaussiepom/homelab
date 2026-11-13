"""Shared immutable deployment source binding, independent of authored layouts."""
import hashlib
from pathlib import Path
from private_io import sha

SOURCE=Path(__file__).resolve().parent


def binding(cfg,site):
    from component_inputs import binding as selected
    return selected(cfg,site)


def source_hash():
    result = hashlib.sha256()
    for path in sorted([*SOURCE.rglob("*"), *(SOURCE.parent / "common").rglob("*")]):
        if path.is_file() and not any(
            p in {".terraform", "__pycache__", ".work"} for p in path.parts
        ):
            result.update(str(path.relative_to(SOURCE.parent)).encode())
            result.update(bytes.fromhex(sha(path)))
    return result.hexdigest()
