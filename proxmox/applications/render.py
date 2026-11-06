#!/usr/bin/env python3
"""Render explicit component runtime projects without private input materialization."""
import argparse
from pathlib import Path
import component_runtime
from private_io import private_directory,read_json,regular,require,write_bytes


def compositions(cfg):
    return component_runtime.compositions(cfg)


def compose(cfg):
    """Convenience API only for a single explicit component project."""
    documents=compositions(cfg)
    require(len(documents)==1,'Use compositions for multiple or native-only projects')
    return next(iter(documents.values()))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    artifacts=component_runtime.artifacts(read_json(args.config))
    private_directory(args.output,create=not args.output.exists())
    for name in artifacts:
        path=args.output/name
        if path.exists() or path.is_symlink():
            regular(path,private=True)
    for name,raw in artifacts.items():
        write_bytes(args.output/name,raw)


if __name__=='__main__':main()
