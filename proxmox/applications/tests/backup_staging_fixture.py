"""Linux fdinfo/preimage integration inside the existing disposable tools image."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_staging


def main():
    assert Path('/.dockerenv').is_file() and os.geteuid() == 0
    Path('/srv').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir='/srv') as temporary:
        root = Path(temporary); empty = root/'stage'; empty.mkdir(mode=0o700)
        for path, expected in [(empty, 0), (root/'absent', 0), (Path('/proc'), 1)]:
            result = subprocess.run([sys.executable, '-', str(path)], input=backup_staging.SCRIPT,
                capture_output=True, timeout=10)
            assert (result.returncode == 0) == (expected == 0), result.stderr.decode()[-800:]
        (empty/'existing').write_text('synthetic existing material')
        result = subprocess.run([sys.executable, '-', str(empty)], input=backup_staging.SCRIPT,
            capture_output=True, timeout=10)
        assert result.returncode != 0 and (empty/'existing').read_text() == 'synthetic existing material'
    print('Linux fdinfo: empty/absent targets pass; foreign mount and existing contents refuse without changes.')


if __name__ == '__main__': main()
