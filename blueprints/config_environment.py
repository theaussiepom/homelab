"""Extract the finite hash-locked compiler dependencies; never resolve floating packages."""
from pathlib import Path
import re
import sys

PACKAGES = ('pyyaml', 'cryptography', 'cffi', 'pycparser')
MARKERS = {'pyyaml':'', 'cryptography':'', 'cffi':" ; platform_python_implementation != 'PyPy'",
           'pycparser':" ; implementation_name != 'PyPy' and platform_python_implementation != 'PyPy'"}


def selected(lock):
    if lock.is_symlink() or not lock.is_file() or lock.stat().st_size > 1024*1024:
        raise ValueError('Use the selected bounded framework dependency lock')
    lines = lock.read_text().splitlines(); blocks = []
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
