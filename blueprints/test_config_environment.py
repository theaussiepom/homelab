"""Dependency extraction preserves finite package pins, hashes, and isolated install inputs."""
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch
import config_environment as subject

class CompilerEnvironmentTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
    def test_cli_creates_once_and_refuses_replacement(self):
        output=self.root/'new.lock'
        with patch.object(sys,'argv',['config',str(output)]):
            subject.main()
            self.assertIn('cryptography==',output.read_text())
            with self.assertRaises(FileExistsError):subject.main()
        with patch.object(sys,'argv',['config']),self.assertRaises(ValueError):subject.main()
        with patch.object(sys,'argv',['config',str(self.root/'entry.lock')]):runpy.run_path(subject.__file__,run_name='__main__')
    def test_complete_final_hash_and_invalid_marker_or_version(self):
        blocks=[name+'==1.2.3'+subject.MARKERS[name]+' '+chr(92)+'\n    --hash=sha256:'+'a'*64 for name in subject.PACKAGES]
        raw='\n'.join(blocks)+'\n';lock=self.root/'requirements.lock.txt';lock.write_text(raw)
        self.assertEqual(subject.selected(lock),raw)
        for changed in (raw.replace('cffi==1.2.3','cffi==next'),raw.replace("!= 'PyPy'","== 'PyPy'"),raw.replace('a'*64,'b'*63)):
            lock.write_text(changed)
            with self.assertRaises(ValueError):subject.selected(lock)

if __name__=='__main__':unittest.main()
