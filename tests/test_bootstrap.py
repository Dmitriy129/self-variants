"""Run a fixture copy of the shell bootstrap with fake OS/network/package tools.

Only path constants in that temporary copy change. The production script has
no environment switch that bypasses its host checks or redirects installation.
"""
import hashlib
import fcntl
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest


BOOTSTRAP = Path(__file__).resolve().parents[1] / 'bootstrap.sh'


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.bin = self.root / 'fake-bin'
        self.bin.mkdir()
        self.install_root = self.root / 'opt/vpn-installer'
        self.install_root.parent.mkdir()
        self.lock = self.root / 'run/lock/bootstrap.lock'
        self.lock.parent.mkdir(parents=True)
        self.systemd = self.root / 'run/systemd/system'
        self.systemd.mkdir(parents=True)
        self.os_release = self.root / 'os-release'
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        self.ca = self.root / 'ca.pem'
        self.ca.write_text('test fixture CA presence marker\n')
        self.archive = self.root / 'release.tar.gz'
        self.events = self.root / 'tool-events.jsonl'
        self.installs = self.root / 'installer-args.jsonl'
        self.script = self.root / 'bootstrap-fixture.sh'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + '/usr/bin:/bin',
                        TEST_ARCHIVE=str(self.archive), TEST_EVENTS=str(self.events),
                        TEST_INSTALLS=str(self.installs), TEST_CA=str(self.ca),
                        TEST_PYTHON=sys.executable, TEST_UID='0', TEST_SYSTEM='Linux', TEST_MACHINE='x86_64')
        self.tool('id', "import os\nprint(os.environ['TEST_UID'])\n")
        self.tool('uname', "import os, sys\nprint(os.environ['TEST_SYSTEM' if sys.argv[1] == '-s' else 'TEST_MACHINE'])\n")
        self.tool('flock', "import fcntl, sys\ntry:\n fcntl.flock(int(sys.argv[-1]), fcntl.LOCK_EX | fcntl.LOCK_NB)\nexcept BlockingIOError:\n sys.exit(1)\n")
        self.tool('curl', """import json, os, shutil, sys
with open(os.environ['TEST_EVENTS'], 'a') as out:
    out.write(json.dumps({'command': 'curl', 'args': sys.argv[1:]}) + '\\n')
shutil.copyfile(os.environ['TEST_ARCHIVE'], sys.argv[sys.argv.index('--output') + 1])
""")
        self.tool('apt-get', """import json, os, pathlib, sys
with open(os.environ['TEST_EVENTS'], 'a') as out:
    out.write(json.dumps({'command': 'apt-get', 'args': sys.argv[1:],
                         'frontend': os.environ.get('DEBIAN_FRONTEND'),
                         'restart': os.environ.get('NEEDRESTART_MODE')}) + '\\n')
pathlib.Path(os.environ['TEST_CA']).write_text('installed fixture CA')
""")
        for command in ('openssl', 'ip', 'tar'):
            self.tool(command, 'raise SystemExit(0)\n')
        (self.bin / 'python3').symlink_to(sys.executable)
        self.build_archive()
        self.write_script()

    def tool(self, name, body):
        path = self.bin / name
        path.write_text('#!' + sys.executable + '\n' + body)
        path.chmod(0o700)

    def build_archive(self, extra=None, omit=None):
        installer = b'''#!/usr/bin/env bash
exec "$TEST_PYTHON" - "$@" <<'PY'
import json, os, sys
with open(os.environ['TEST_INSTALLS'], 'a') as output:
    output.write(json.dumps(sys.argv[1:]) + '\\n')
PY
'''
        entries = {'vpn-installer/install.sh': installer,
                   'vpn-installer/versions.json': b'{}',
                   'vpn-installer/vpn_installer/__init__.py': b'',
                   'vpn-installer/vpn_installer/cli.py': b'# fixture'}
        if omit:
            entries.pop(omit)
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, payload in entries.items():
                member = tarfile.TarInfo(name)
                member.mode = 0o755 if name.endswith('install.sh') else 0o644
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            if extra:
                member, payload = extra
                archive.addfile(member, io.BytesIO(payload) if payload is not None else None)

    def write_script(self):
        contents = BOOTSTRAP.read_text()
        replacements = {
            'INSTALL_ROOT': self.install_root,
            'OS_RELEASE': self.os_release,
            'SYSTEMD_ROOT': self.systemd,
            'LOCK_FILE': self.lock,
            'CA_BUNDLE': self.ca,
        }
        lines = contents.splitlines()
        for index, line in enumerate(lines):
            for name, path in replacements.items():
                if line.startswith(name + '='):
                    lines[index] = name + '=' + shlex.quote(str(path))
            if line.startswith('ARCHIVE_SHA256='):
                lines[index] = "ARCHIVE_SHA256='" + hashlib.sha256(self.archive.read_bytes()).hexdigest() + "'"
        self.script.write_text('\n'.join(lines) + '\n')

    def run_bootstrap(self, *args, pipe=False):
        if pipe:
            return subprocess.run(['bash', '-s', '--', *args], input=self.script.read_text(),
                                  env=self.env, text=True, capture_output=True, timeout=20)
        return subprocess.run(['bash', str(self.script), *args], env=self.env,
                              text=True, capture_output=True, timeout=20)

    def records(self, path):
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_not_installed(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.installs.exists())
        self.assertFalse((self.install_root / 'releases/v0.1.4').exists())

    def test_success_and_piped_stdin_preserve_every_argument_without_logging_values(self):
        args = ['--profile', 'reality', '--email', 'owner@example.com', '--users-file',
                'family names "quoted" $(must-not-run) $HOME\nfile.json', '--domain', 'panel.example.com']
        result = self.run_bootstrap(*args, pipe=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.records(self.installs), [args])
        self.assertNotIn(args[5], result.stdout + result.stderr)
        release = self.install_root / 'releases/v0.1.4'
        self.assertEqual((self.install_root / 'current').resolve(), release)
        self.assertEqual((release / '.archive.sha256').read_text().strip(), hashlib.sha256(self.archive.read_bytes()).hexdigest())
        events = self.records(self.events)
        self.assertEqual([event['command'] for event in events], ['curl'])
        command = events[0]['args']
        self.assertIn('https://github.com/Dmitriy129/self-variants/releases/download/v0.1.4/vpn-installer.tar.gz', command)
        self.assertEqual(command[command.index('--proto') + 1], '=https')
        self.assertEqual(command[command.index('--proto-redir') + 1], '=https')
        self.assertIn('--retry', command)
        self.assertIn('--max-time', command)
        self.assertFalse(list(self.install_root.glob('.download.*')))
        self.assertFalse(list((self.install_root / 'releases').glob('.v0.1.4.*')))

    def test_repeat_uses_owned_verified_release_and_passes_new_args(self):
        self.assertEqual(self.run_bootstrap('--first').returncode, 0)
        release = self.install_root / 'releases/v0.1.4/install.sh'
        before = release.stat().st_mtime_ns
        self.archive.unlink()  # A cached run must not need the remote asset.
        result = self.run_bootstrap('--second', 'literal value')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.records(self.installs), [['--first'], ['--second', 'literal value']])
        self.assertEqual(len(self.records(self.events)), 1)
        self.assertEqual(release.stat().st_mtime_ns, before)

    def test_new_release_replaces_current_link_when_previous_version_is_cached(self):
        self.assertEqual(self.run_bootstrap('--previous').returncode, 0)
        current = self.install_root / 'current'
        release = self.install_root / 'releases/v0.1.4'
        previous = self.install_root / 'releases/v0.1.3'
        release.rename(previous)
        (previous / '.archive.sha256').write_text('0' * 64 + '\n')
        original = (previous / 'install.sh').read_bytes()
        current.unlink()
        current.symlink_to(previous)
        result = self.run_bootstrap('--profile', 'reality')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(current.resolve(), release)
        self.assertEqual((previous / 'install.sh').read_bytes(), original)
        self.assertEqual((release / '.archive.sha256').read_text().strip(),
                         hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(len(self.records(self.events)), 2)
        self.assertEqual(self.records(self.installs)[-1], ['--profile', 'reality'])

    def test_tampered_download_cannot_extract_or_execute(self):
        self.archive.write_bytes(b'not the archive matching the embedded hash')
        result = self.run_bootstrap('--secret', 'not-printed')
        self.assert_not_installed(result)
        self.assertIn('контрольная сумма', result.stderr)
        self.assertNotIn('not-printed', result.stderr + result.stdout)
        self.assertFalse(list(self.install_root.glob('.download.*')))

    def test_checksum_verified_archive_still_refuses_traversal_links_and_wrong_prefix(self):
        variants = []
        traversal = tarfile.TarInfo('vpn-installer/../../escaped')
        traversal.size = 4
        variants.append((traversal, b'bad!'))
        wrong = tarfile.TarInfo('other-root/file')
        wrong.size = 4
        variants.append((wrong, b'bad!'))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            link = tarfile.TarInfo('vpn-installer/link')
            link.type = kind
            link.linkname = str(self.root / 'escaped')
            variants.append((link, None))
        for extra in variants:
            with self.subTest(name=extra[0].name, kind=extra[0].type):
                self.build_archive(extra)
                self.write_script()
                result = self.run_bootstrap()
                self.assert_not_installed(result)
                self.assertFalse((self.root / 'escaped').exists())
                self.assertFalse(list((self.install_root / 'releases').glob('.v0.1.4.*')))

    def test_incomplete_archive_cannot_execute_its_install_script(self):
        self.build_archive(omit='vpn-installer/vpn_installer/cli.py')
        self.write_script()
        self.assert_not_installed(self.run_bootstrap())

    def test_unmanaged_install_root_is_refused_before_packages_or_downloads(self):
        self.install_root.mkdir()
        sentinel = self.install_root / 'existing-data'
        sentinel.write_text('keep')
        self.ca.unlink()
        self.assert_not_installed(self.run_bootstrap())
        self.assertEqual(sentinel.read_text(), 'keep')
        self.assertEqual(self.records(self.events), [])

    def test_unmanaged_current_is_not_replaced(self):
        self.install_root.mkdir()
        (self.install_root / '.bootstrap-owner').write_text('vpn-installer-bootstrap:v1:Dmitriy129/self-variants\n')
        current = self.install_root / 'current'
        current.write_text('unrelated')
        self.assert_not_installed(self.run_bootstrap())
        self.assertEqual(current.read_text(), 'unrelated')
        self.assertEqual(self.records(self.events), [])

    def test_cached_release_with_wrong_marker_is_refused_without_download(self):
        self.assertEqual(self.run_bootstrap().returncode, 0)
        release = self.install_root / 'releases/v0.1.4'
        (release / '.archive.sha256').write_text('0' * 64 + '\n')
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.records(self.installs)), 1)
        self.assertEqual(len(self.records(self.events)), 1)

    def test_bootstrap_dependencies_are_installed_noninteractively_only_when_needed(self):
        self.ca.unlink()
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.records(self.events)
        self.assertEqual([item['command'] for item in events], ['apt-get', 'apt-get', 'curl'])
        self.assertEqual(events[0]['args'], ['update', '-qq'])
        self.assertEqual(events[1]['frontend'], 'noninteractive')
        self.assertEqual(events[1]['restart'], 'a')
        for package in ('python3', 'openssl', 'iproute2', 'ca-certificates', 'curl', 'tar'):
            self.assertIn(package, events[1]['args'])

    def test_unsupported_os_arch_root_and_systemd_fail_before_any_writes(self):
        for name, value in (('TEST_UID', '501'), ('TEST_SYSTEM', 'Darwin'), ('TEST_MACHINE', 'aarch64')):
            old = self.env[name]
            self.env[name] = value
            with self.subTest(name=name):
                self.assert_not_installed(self.run_bootstrap())
                self.assertFalse(self.install_root.exists())
                self.assertFalse(self.lock.exists())
                self.assertEqual(self.records(self.events), [])
            self.env[name] = old
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
        self.assert_not_installed(self.run_bootstrap())
        self.assertFalse(self.lock.exists())
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        self.systemd.rmdir()
        self.assert_not_installed(self.run_bootstrap())
        self.assertFalse(self.lock.exists())
        self.assertFalse(self.install_root.exists())

    def test_help_works_without_root_or_network_and_does_not_write(self):
        self.env.update(TEST_SYSTEM='Darwin', TEST_UID='501')
        result = self.run_bootstrap('--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn('Ubuntu 24.04', result.stdout)
        self.assertFalse(self.install_root.exists())
        self.assertFalse(self.lock.exists())
        self.assertEqual(self.records(self.events), [])

    def test_parallel_bootstrap_is_refused_before_packages_or_installation(self):
        self.ca.unlink()
        with self.lock.open('w') as owner:
            fcntl.flock(owner.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_bootstrap()
        self.assert_not_installed(result)
        self.assertIn('Другой загрузчик', result.stderr)
        self.assertFalse(self.install_root.exists())
        self.assertEqual(self.records(self.events), [])


if __name__ == '__main__':
    unittest.main()
