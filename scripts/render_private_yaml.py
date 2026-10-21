#!/usr/bin/env python3
"""Render YAML !env scalar references from private environment values.

No shell execution, template evaluation, recursive expansion or deployment.
Requires PyYAML. Output is a new mode-0600 file; existing paths are refused.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import yaml

KEY = re.compile(r"HOMELAB_[A-Z0-9_]+")
LIMIT = 8 * 1024 * 1024


def read_regular(path, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size > LIMIT:
            raise ValueError("invalid_input_file")
        if private and s.st_mode & 0o077:
            raise ValueError("private_env_permissions")
        with os.fdopen(os.dup(fd), "rb") as f:
            data = f.read(LIMIT+1)
        after = os.fstat(fd)
        if len(data) > LIMIT or (s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("input_changed")
        return data.decode("utf-8")
    finally:
        os.close(fd)


def dotenv(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not separator or not KEY.fullmatch(name) or name in values:
            raise ValueError("invalid_or_duplicate_env_key")
        if value.startswith('"'):
            try:
                value = json.loads(value)
            except ValueError:
                raise ValueError("invalid_quoted_env_value") from None
            if not isinstance(value, str):
                raise ValueError("env_value_not_string")
        elif value.startswith("'"):
            if not value.endswith("'") or len(value) < 2:
                raise ValueError("invalid_quoted_env_value")
            value = value[1:-1]
        elif any(c.isspace() for c in value):
            raise ValueError("quote_env_whitespace")
        values[name] = value
    return values


def render(text, values):
    class Loader(yaml.SafeLoader):
        pass
    def env(loader, node):
        name = loader.construct_scalar(node)
        if not KEY.fullmatch(name):
            raise ValueError("invalid_env_reference")
        value = values.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError("missing_required_private_value")
        return value
    Loader.add_constructor("!env", env)
    try:
        obj = yaml.load(text, Loader=Loader)
    except yaml.YAMLError:
        raise ValueError("invalid_yaml_template") from None
    return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True)


def write_new(path, content):
    path = Path(path)
    parent = path.absolute().parent
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parent.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        out = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=fd)
        with os.fdopen(out, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", required=True)
    parser.add_argument("--env-file")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        values = dotenv(read_regular(args.env_file, private=True)) if args.env_file else {}
        values.update({k: v for k, v in os.environ.items() if KEY.fullmatch(k)})
        output = render(read_regular(args.template), values)
        write_new(args.output, output)
    except (OSError, ValueError):
        print(json.dumps({"status": "render_refused", "values_emitted": False}), file=sys.stderr)
        return 1
    print(json.dumps({"status": "private_config_rendered", "mode": "0600",
                      "service_actions": 0, "values_emitted": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
