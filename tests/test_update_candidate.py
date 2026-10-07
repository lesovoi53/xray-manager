"""Execute actual update entrypoint with isolated synthetic distributions."""
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class CandidateUpdate(unittest.TestCase):
    def run_archive(self, entries, checksum=None):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); archive=root/'candidate.tar.gz'; marker=root/'installed'
            with tarfile.open(archive,'w:gz') as tar:
                for name,kind in entries:
                    data=(('#!/bin/bash\nset -eu\n[ "$1" = --update ]\nprintf installed > '+str(marker)+'\n').encode())
                    entry=tarfile.TarInfo(name);entry.size=len(data)
                    if kind=='symlink':entry.type=tarfile.SYMTYPE;entry.linkname='/tmp/escape';entry.size=0
                    tar.addfile(entry,io.BytesIO(data) if kind!='symlink' else None)
            sha=checksum or hashlib.sha256(archive.read_bytes()).hexdigest()
            result=subprocess.run(['bash',str(ROOT/'scripts/update-release.sh'),'--archive',str(archive),'--sha256',sha],text=True,capture_output=True,timeout=15)
            return result,marker.exists()

    def test_verified_candidate_reaches_real_update_entrypoint(self):
        result,installed=self.run_archive([('install.sh','file')])
        self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(installed)

    def test_corrupted_checksum_never_runs_installer(self):
        result,installed=self.run_archive([('install.sh','file')],'0'*64)
        self.assertNotEqual(result.returncode,0);self.assertFalse(installed)
        self.assertIn('SHA-256 mismatch',result.stderr)

    def test_path_traversal_and_symlinks_rejected(self):
        for entry in [('../escape','file'),('/tmp/escape','file'),('escape','symlink')]:
            with self.subTest(entry=entry):
                result,installed=self.run_archive([('install.sh','file'),entry])
                self.assertNotEqual(result.returncode,0);self.assertFalse(installed)
                self.assertIn('Unsafe release archive',result.stderr)

    def test_incomplete_distribution_rejected(self):
        result,installed=self.run_archive([('README','file')])
        self.assertNotEqual(result.returncode,0);self.assertFalse(installed)

if __name__=='__main__':unittest.main()
