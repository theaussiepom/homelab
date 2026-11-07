"""Linux/GNU-tar integration: literal exclusions must not hide required siblings."""
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_capture


def main():
    version = subprocess.check_output(['tar', '--version'], text=True, timeout=10)
    assert 'GNU tar' in version, 'This native fixture requires GNU tar, as on the Debian guest'
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve(); selected = root/'source'; selected.mkdir()
        excluded = selected/'omit[1]'; excluded.mkdir(); (excluded/'private').write_text('excluded fixture')
        wildcard = selected/'omit1'; wildcard.mkdir(); (wildcard/'required').write_text('retain this sibling')
        nested = selected/'nested'/str(excluded).lstrip('/')
        nested.mkdir(parents=True); (nested/'required').write_text('retain the same component sequence elsewhere')
        output = root/'recovery.tar'
        value = {'include': [{'path': str(selected)}], 'exclude': [str(excluded)]}
        subprocess.run(backup_capture.archive(value, output), check=True, timeout=20, capture_output=True)
        with tarfile.open(output) as archive:
            names = archive.getnames()
            assert str(wildcard/'required').lstrip('/') in names
            assert str(nested/'required').lstrip('/') in names
            assert not any(name == str(excluded).lstrip('/') or name.startswith(str(excluded).lstrip('/')+'/') for name in names)
            assert archive.getmember(str(wildcard/'required').lstrip('/')).uid == os.getuid()
    print('GNU tar: literal root exclusions omit only their exact subtree; required peers and numeric ownership remain.')


if __name__ == '__main__': main()
