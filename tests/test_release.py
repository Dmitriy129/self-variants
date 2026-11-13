"""Publication must not pick up private files or depend on file timestamps."""
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from tools.build_release import FILES, build


class ReleaseTests(unittest.TestCase):
    def fixture(self, root):
        for name in FILES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('["personal"]\n' if name == 'users.example.json' else f'fixture: {name}\n')

    def test_public_archive_is_deterministic_and_excludes_private_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.fixture(root)
            (root / 'users.json').write_text('["PRIVATE-FAMILY-NAME"]')
            (root / 'instance.json').write_text('{"secret":"PRIVATE-INSTANCE-SECRET"}')
            archive = root / 'dist/vpn-installer.tar.gz'
            first = build(root, archive)
            encoded = archive.read_bytes()
            (root / 'users.json').write_text('CHANGED-LOCAL-CONFIG')
            self.assertEqual(build(root, archive), first)
            self.assertEqual(archive.read_bytes(), encoded)
            self.assertEqual(first, hashlib.sha256(encoded).hexdigest())
            self.assertEqual(archive.with_name(archive.name + '.sha256').read_text(),
                             f'{first}  vpn-installer.tar.gz\n')
            with tarfile.open(fileobj=io.BytesIO(encoded), mode='r:gz') as package:
                self.assertEqual(set(package.getnames()),
                                 {'vpn-installer/' + name for name in (*FILES, 'users.json')})
                self.assertEqual(package.extractfile('vpn-installer/users.json').read(), b'["personal"]\n')
                for member in package.getmembers():
                    self.assertTrue(member.isfile())
                    self.assertEqual(member.uid, 0)
                    self.assertEqual(member.gid, 0)
                    self.assertEqual(member.mtime, 0)
                    self.assertNotIn(b'PRIVATE-', package.extractfile(member).read())

    def test_symlinked_source_cannot_enter_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.fixture(root)
            example = root / 'users.example.json'
            example.unlink()
            (root / 'users.json').write_text('["private"]')
            example.symlink_to(root / 'users.json')
            with self.assertRaisesRegex(ValueError, 'regular release file'):
                build(root, root / 'dist/vpn-installer.tar.gz')


if __name__ == '__main__':
    unittest.main()
