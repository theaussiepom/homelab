"""Extract the finite hash-locked compiler dependencies; never resolve floating packages."""
from pathlib import Path
import os
import re
import stat
import sys

PACKAGES = ('pyyaml', 'cryptography', 'cffi', 'pycparser')
MARKERS = {'pyyaml':'', 'cryptography':'', 'cffi':" ; platform_python_implementation != 'PyPy'",
           'pycparser':" ; implementation_name != 'PyPy' and platform_python_implementation != 'PyPy'"}


def selected(lock):
    error = 'Use the selected bounded framework dependency lock'
    try:
        fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024*1024:
                raise ValueError(error)
            raw = stream.read(1024*1024+1)
        if len(raw) > 1024*1024:
            raise ValueError(error)
        lines = raw.decode('utf-8').splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(error) from exc
    blocks = []
    for package in PACKAGES:
        starts = [i for i,line in enumerate(lines) if line.startswith(package+'==')]
        if len(starts) != 1:
            raise ValueError('Use one exact hash-locked compiler dependency')
        first = starts[0]; block = [lines[first]]
        for line in lines[first+1:]:
            if not line.startswith('    --hash='):
                break
            block.append(line)
        pattern = re.escape(package)+r'==[0-9]+(?:\.[0-9]+)+'+re.escape(MARKERS[package])+r' \\'
        if (not re.fullmatch(pattern,block[0]) or len(block)<2
            or any(not re.fullmatch(r'    --hash=sha256:[0-9a-f]{64} \\',line) for line in block[1:-1])
            or not re.fullmatch(r'    --hash=sha256:[0-9a-f]{64}',block[-1])):
            raise ValueError('Use complete reviewed compiler package hashes and markers')
        blocks.extend(block)
    return '\n'.join(blocks)+'\n'


def main():
    if len(sys.argv) != 2:
        raise ValueError('Supply one new dependency-lock output')
    raw = selected(Path(__file__).resolve().parents[1]/'requirements.lock.txt')
    with Path(sys.argv[1]).open('x') as stream:
        stream.write(raw)


if __name__=='__main__':main()
