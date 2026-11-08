"""Dependency extraction preserves finite package pins, hashes, and isolated install inputs."""
from pathlib import Path
import runpy
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
import config_environment as subject

class CompilerEnvironmentTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.raw='\n'.join(name+'==1.2.3'+subject.MARKERS[name]+' '+chr(92)+'\n    --hash=sha256:'+'a'*64 for name in subject.PACKAGES)+'\n'
        self.lock=self.root/'requirements.lock.txt';self.lock.write_text(self.raw)
    def test_cli_creates_once_and_refuses_replacement(self):
        output=self.root/'new.lock'
        with patch.object(sys,'argv',['config',str(output)]),patch.object(subject,'__file__',str(self.root/'blueprints/config_environment.py')):
            subject.main()
            self.assertIn('cryptography==',output.read_text())
            with self.assertRaises(FileExistsError):subject.main()
        with patch.object(sys,'argv',['config']),self.assertRaises(ValueError):subject.main()
        script=self.root/'blueprints/config_environment.py';script.parent.mkdir();script.write_text(Path(subject.__file__).read_text())
        with patch.object(sys,'argv',['config',str(self.root/'entry.lock')]):runpy.run_path(str(script),run_name='__main__')
    def test_opened_file_refuses_links_nonregular_large_and_invalid_utf8(self):
        link=self.root/'link';link.symlink_to(self.lock)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        for path in (link,fifo,self.root,self.root/'missing'):
            with self.subTest(path=path.name),self.assertRaises(ValueError):subject.selected(path)
        for raw in (b'x'*(1024*1024+1),b'\xff'):
            self.lock.write_bytes(raw)
            with self.assertRaises(ValueError):subject.selected(self.lock)
    def test_growth_after_stat_is_bounded_and_open_inode_survives_path_swap(self):
        self.lock.write_bytes(b'x'*(1024*1024+1))
        metadata=self.lock.stat()
        with patch.object(subject.os,'fstat',return_value=type('Stat',(),{'st_mode':metadata.st_mode,'st_size':1})()),self.assertRaises(ValueError):
            subject.selected(self.lock)
        self.lock.write_text(self.raw);original_open=os.open
        def swapped(path,flags):
            fd=original_open(path,flags)
            self.lock.rename(self.root/'original');self.lock.symlink_to(self.root/'missing')
            return fd
        with patch.object(subject.os,'open',side_effect=swapped):self.assertEqual(subject.selected(self.lock),self.raw)

    def test_complete_final_hash_and_invalid_marker_or_version(self):
        blocks=[name+'==1.2.3'+subject.MARKERS[name]+' '+chr(92)+'\n    --hash=sha256:'+'a'*64 for name in subject.PACKAGES]
        raw='\n'.join(blocks)+'\n';lock=self.root/'requirements.lock.txt';lock.write_text(raw)
        self.assertEqual(subject.selected(lock),raw)
        for changed in (raw.replace('cffi==1.2.3','cffi==next'),raw.replace("!= 'PyPy'","== 'PyPy'"),raw.replace('a'*64,'b'*63)):
            lock.write_text(changed)
            with self.assertRaises(ValueError):subject.selected(lock)

if __name__=='__main__':unittest.main()
