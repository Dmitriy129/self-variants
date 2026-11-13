#!/usr/bin/env python3
"""Build the public, reproducible runtime archive without local configuration."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile


ROOT = Path(__file__).resolve().parents[1]
# Deliberately explicit: a new local file must never silently enter a release.
# bootstrap.sh embeds the archive hash, so neither it nor its tests are bundled.
FILES = (
    'install.sh', 'README.md', 'versions.json', 'users.example.json',
    'vpn_installer/__init__.py', 'vpn_installer/cli.py', 'vpn_installer/config.py',
    'vpn_installer/network.py', 'vpn_installer/panel.py', 'vpn_installer/system.py',
    'vpn_installer/monitoring.py',
    'sites/README.md', 'sites/field-notes/index.html', 'sites/ceramic-studio/index.html',
    'sites/trail-journal/index.html', 'sites/reading-room/index.html',
    'tests/test_cli.py', 'tests/test_config.py', 'tests/test_network.py',
    'tests/test_panel.py', 'tests/test_system.py', 'tests/test_monitoring.py',
    'tests/integration.py', 'tests/run-integration.sh',
)


def build(root: Path, destination: Path) -> str:
    """Only read allowlisted regular files; local users.json is never opened."""
    payloads = {}
    for name in FILES:
        source = root / name
        if source.is_symlink() or not source.is_file() or source.resolve() != source.absolute():
            raise ValueError(f'Expected a regular release file: {name}')
        payloads[name] = source.read_bytes()
    example = json.loads(payloads['users.example.json'])
    if not isinstance(example, list) or not example or not all(isinstance(x, str) and x for x in example):
        raise ValueError('users.example.json must contain public example names')
    payloads['users.json'] = payloads['users.example.json']
    buffer = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buffer, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(payloads.items()):
                member = tarfile.TarInfo('vpn-installer/' + name)
                member.mode = 0o755 if name.endswith('.sh') else 0o644
                member.size = len(data)
                member.mtime = member.uid = member.gid = 0
                member.uname = member.gname = ''
                archive.addfile(member, io.BytesIO(data))
    encoded = buffer.getvalue()
    digest = hashlib.sha256(encoded).hexdigest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encoded)
    destination.with_name(destination.name + '.sha256').write_text(
        f'{digest}  {destination.name}\n', encoding='ascii')
    return digest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--update-bootstrap', action='store_true',
                        help='Pin this archive SHA-256 in bootstrap.sh after building')
    args = parser.parse_args()
    archive = ROOT / 'dist/vpn-installer.tar.gz'
    digest = build(ROOT, archive)
    if args.update_bootstrap:
        script = ROOT / 'bootstrap.sh'
        updated, count = re.subn(r"^ARCHIVE_SHA256='[^']*'$", f"ARCHIVE_SHA256='{digest}'",
                                 script.read_text(), flags=re.MULTILINE)
        if count != 1:
            raise ValueError('Expected exactly one ARCHIVE_SHA256 in bootstrap.sh')
        script.write_text(updated)
    print(f'{archive}\nSHA-256: {digest}')


if __name__ == '__main__':
    main()
