"""Best-effort private access-log history, independent of 3x-ui truncation.

The upstream panel may truncate access.log between polls; those lost bytes
cannot be recovered. Copy/truncate also has the usual concurrent-writer race.
Retention and the source-plus-history budget are enforced at collection time,
not as a real-time quota. UTC calendar-day expiry may remove records early.
Basic mode keeps cleanup running but never copies new destination records.

This module deliberately has no package-relative imports: configure() installs
the same file as a standalone systemd helper.
"""
from __future__ import annotations

import argparse
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile


SOURCE = Path('/var/log/x-ui/access.log')
LOG_ROOT = Path('/var/log/vpn-installer')
HISTORY = LOG_ROOT / 'history'
CURSOR = LOG_ROOT / 'cursor.json'
LOCK = LOG_ROOT / 'collector.lock'
SETTINGS = Path('/etc/vpn-installer/monitoring.json')
HELPER = Path('/usr/local/lib/vpn-installer/monitoring.py')
SERVICE_PATH = Path('/etc/systemd/system/vpn-installer-monitoring.service')
TIMER_PATH = Path('/etc/systemd/system/vpn-installer-monitoring.timer')
MIB = 1024 * 1024
READ_SIZE = 8 * MIB
_ARCHIVE_NAME = re.compile(r'\d{4}-\d{2}-\d{2}\.log\Z')

SERVICE = '''[Unit]
Description=Private VPN access history collection and expiry

[Service]
Type=oneshot
User=root
UMask=0077
ExecStart=/usr/bin/python3 /usr/local/lib/vpn-installer/monitoring.py collect --config /etc/vpn-installer/monitoring.json
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/vpn-installer /var/log/x-ui
'''

TIMER = '''[Unit]
Description=Collect or expire private VPN history every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=1s
Unit=vpn-installer-monitoring.service

[Install]
WantedBy=timers.target
'''


def _settings(value):
    if not isinstance(value, dict) or set(value) != {'mode', 'retention_days', 'max_log_mb'}:
        raise ValueError('monitoring requires mode, retention_days and max_log_mb')
    if value['mode'] not in ('basic', 'destinations'):
        raise ValueError('monitoring.mode must be basic or destinations')
    for name, low, high in (('retention_days', 1, 30), ('max_log_mb', 16, 1024)):
        if type(value[name]) is not int or not low <= value[name] <= high:
            raise ValueError(f'monitoring.{name} must be an integer from {low} to {high}')
    return dict(value)


def _path(root, absolute):
    base = Path(root).resolve()
    target = base / absolute.relative_to('/')
    current = base
    for part in target.relative_to(base).parts:
        current /= part
        if current.is_symlink():
            raise ValueError('monitoring paths must not contain symlinks')
    return target


def _private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    if os.geteuid() == 0:
        os.chown(path, 0, 0)


def _open(path, flags, mode=0o600, private=True):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('monitoring files must be regular files with one link')
        if private:
            os.fchmod(fd, 0o600)
            if os.geteuid() == 0:
                os.fchown(fd, 0, 0)
        return fd
    except Exception:
        os.close(fd)
        raise


def _atomic(path, content):
    if path.is_symlink():
        raise ValueError('refusing a monitoring file symlink')
    fd, temporary = tempfile.mkstemp(prefix='.monitoring-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _json_write(path, data):
    _atomic(path, (json.dumps(data, sort_keys=True) + '\n').encode())


def _load_json(path, private=False):
    fd = _open(path, os.O_RDONLY, private=private)
    with os.fdopen(fd, 'rb') as stream:
        content = stream.read(65537)
    if len(content) > 65536:
        raise ValueError('monitoring settings or cursor exceeds its size limit')
    return json.loads(content)


@contextmanager
def _locked(root, readonly=False):
    path = _path(root, LOCK)
    if readonly and not path.exists():
        yield
        return
    fd = _open(path, os.O_RDONLY if readonly else os.O_RDWR | os.O_CREAT, private=not readonly)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH if readonly else fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _prepare(root):
    # Reject all managed symlinks before creating directories or files.
    for path in (SOURCE, LOG_ROOT, HISTORY, CURSOR, LOCK):
        _path(root, path)
    for path in (SOURCE.parent, LOG_ROOT, HISTORY):
        _private_dir(_path(root, path))


def _source_state(fd, offset, day=None):
    info = os.fstat(fd)
    anchor = os.pread(fd, min(offset, 256), max(0, offset - 256))
    value = {'device': info.st_dev, 'inode': info.st_ino, 'offset': offset,
             'anchor': hashlib.sha256(anchor).hexdigest()}
    if day is not None:
        value['day'] = day
    return value


def _valid_source(value):
    return (isinstance(value, dict) and set(value) in ({'device', 'inode', 'offset', 'anchor'},
                                                    {'device', 'inode', 'offset', 'anchor', 'day'})
            and all(type(value[key]) is int and value[key] >= 0 for key in ('device', 'inode', 'offset'))
            and isinstance(value['anchor'], str) and re.fullmatch(r'[0-9a-f]{64}', value['anchor'])
            and ('day' not in value or isinstance(value['day'], str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}', value['day'])))


def _cursor(root):
    path = _path(root, CURSOR)
    if not path.exists():
        return {'version': 1, 'source': None}
    state = _load_json(path, private=True)
    if (not isinstance(state, dict) or state.get('version') != 1
            or set(state) - {'version', 'source', 'pending'}
            or (state.get('source') is not None and not _valid_source(state['source']))):
        raise ValueError('invalid monitoring cursor')
    pending = state.get('pending')
    if pending is not None:
        if (not isinstance(pending, dict) or set(pending) != {'archive', 'start', 'length', 'sha256', 'next_source'}
                or not isinstance(pending['archive'], str) or not _ARCHIVE_NAME.fullmatch(pending['archive'])
                or any(type(pending[key]) is not int or pending[key] < 0 for key in ('start', 'length'))
                or pending['length'] > READ_SIZE or not _valid_source(pending['next_source'])
                or not isinstance(pending['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', pending['sha256'])):
            raise ValueError('invalid pending monitoring append')
    return state


def _recover(root, state):
    """Finish a committed append, or discard its incomplete bytes before retry."""
    pending = state.get('pending')
    if pending is None:
        return state
    archive = _path(root, HISTORY / pending['archive'])
    complete = False
    if archive.exists():
        fd = _open(archive, os.O_RDWR)
        try:
            content = os.pread(fd, pending['length'], pending['start'])
            complete = len(content) == pending['length'] and hashlib.sha256(content).hexdigest() == pending['sha256']
            if not complete:
                os.ftruncate(fd, min(pending['start'], os.fstat(fd).st_size))
                os.fsync(fd)
        finally:
            os.close(fd)
    recovered = {'version': 1, 'source': pending['next_source'] if complete else state.get('source')}
    _json_write(_path(root, CURSOR), recovered)
    return recovered


def _append_bytes(path, content):
    fd = _open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
    with os.fdopen(fd, 'ab') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _append(root, state, archive_name, content, next_source):
    archive = _path(root, HISTORY / archive_name)
    if archive.exists():
        fd = _open(archive, os.O_RDONLY)
        try:
            start = os.fstat(fd).st_size
        finally:
            os.close(fd)
    else:
        start = 0
    pending = dict(state, pending={'archive': archive_name, 'start': start, 'length': len(content),
                                  'sha256': hashlib.sha256(content).hexdigest(), 'next_source': next_source})
    _json_write(_path(root, CURSOR), pending)
    _append_bytes(archive, content)
    state = {'version': 1, 'source': next_source}
    _json_write(_path(root, CURSOR), state)
    return state


def _archives(root):
    folder = _path(root, HISTORY)
    if not folder.exists():
        return []
    result = []
    for item in folder.iterdir():
        if item.is_symlink():
            raise ValueError('monitoring archives must not be symlinks')
        if _ARCHIVE_NAME.fullmatch(item.name):
            datetime.strptime(item.stem, '%Y-%m-%d')
            if not item.is_file() or item.stat().st_nlink != 1:
                raise ValueError('monitoring archives must be regular files with one link')
            result.append(item)
    return sorted(result)


def _trim_oldest_bytes(path, keep):
    """Keep a suffix of complete lines without loading the archive into RAM."""
    fd = _open(path, os.O_RDONLY)
    temporary_fd, temporary = tempfile.mkstemp(prefix='.history-', dir=path.parent)
    try:
        with os.fdopen(fd, 'rb') as source, os.fdopen(temporary_fd, 'wb') as dest:
            os.fchmod(dest.fileno(), 0o600)
            source.seek(max(0, os.fstat(source.fileno()).st_size - keep))
            # A cut inside a record discards that record. Bounded readline
            # chunks also handle unexpectedly large or incomplete records.
            if source.tell():
                while True:
                    discarded = source.readline(65536)
                    if not discarded or discarded.endswith(b'\n'):
                        break
            shutil.copyfileobj(source, dest, 65536)
            dest.flush()
            os.fsync(dest.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _prune(root, settings, now, source_bytes):
    cutoff = (now.date() - timedelta(days=settings['retention_days'] - 1)).isoformat()
    paths = _archives(root)
    removed = 0
    for path in paths:
        path.chmod(0o600)
        if os.geteuid() == 0:
            os.chown(path, 0, 0)
        if path.stem < cutoff:
            path.unlink()
            removed += 1
    paths = [path for path in paths if path.exists()]
    budget = max(0, settings['max_log_mb'] * MIB - source_bytes)
    total = sum(path.stat().st_size for path in paths)
    for path in paths:
        if total <= budget:
            break
        size = path.stat().st_size
        excess = total - budget
        if size <= excess:
            path.unlink()
            total -= size
            removed += 1
        else:
            _trim_oldest_bytes(path, size - excess)
            total = total - size + path.stat().st_size
    return {'history_bytes': total, 'source_bytes': source_bytes, 'removed_archives': removed}


def collect(settings, root=Path('/'), now=None):
    """Collect complete lines and prune. A temporary root is safe for tests."""
    settings = _settings(settings)
    if Path(root).resolve() == Path('/') and os.geteuid() != 0:
        raise PermissionError('monitoring collection requires root')
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('monitoring timestamps must have a timezone')
    now = now.astimezone(timezone.utc)
    _prepare(root)
    result = {'copied_bytes': 0, 'copied_lines': 0, 'source_rotated': False,
              'source_expired': False, 'dropped_partial_bytes': 0}
    with _locked(root):
        state = _recover(root, _cursor(root))
        source = _path(root, SOURCE)
        source_bytes = 0
        if source.exists():
            fd = _open(source, os.O_RDWR)
            try:
                info = os.fstat(fd)
                cutoff = now.date() - timedelta(days=settings['retention_days'] - 1)
                expired = datetime.fromtimestamp(info.st_mtime, timezone.utc).date() < cutoff
                if settings['mode'] == 'basic' or expired:
                    # Do not read or archive any destination bytes in basic mode.
                    # Likewise, expired source bytes must not receive a new
                    # retention period merely because collection was stopped.
                    os.ftruncate(fd, 0)
                    os.fsync(fd)
                    result['source_expired'] = expired
                    _json_write(_path(root, CURSOR), {'version': 1, 'source': None})
                else:
                    previous = state.get('source')
                    offset = 0
                    source_day = now.date().isoformat()
                    if (previous and previous['device'] == info.st_dev and previous['inode'] == info.st_ino
                            and info.st_size >= previous['offset']
                            and _source_state(fd, previous['offset'])['anchor'] == previous['anchor']):
                        offset = previous['offset']
                        source_day = previous.get('day', source_day)
                    while offset < info.st_size:
                        chunk = os.pread(fd, min(READ_SIZE, info.st_size - offset), offset)
                        complete = chunk.rfind(b'\n') + 1
                        if not complete:
                            break
                        chunk = chunk[:complete]
                        offset += complete
                        state = _append(root, state, now.date().isoformat() + '.log', chunk,
                                        _source_state(fd, offset, source_day))
                        result['copied_bytes'] += len(chunk)
                        result['copied_lines'] += chunk.count(b'\n')
                    current = os.fstat(fd)
                    source_limit = min(16 * MIB, settings['max_log_mb'] * MIB // 4)
                    daily_rotation = source_day < now.date().isoformat()
                    checkpoint = _source_state(fd, offset, source_day)
                    if state.get('source') != checkpoint:
                        _json_write(_path(root, CURSOR), {'version': 1, 'source': checkpoint})
                    if (current.st_size > source_limit or daily_rotation) and current.st_size >= offset:
                        tail_length = current.st_size - offset
                        tail = os.pread(fd, tail_length, offset) if not daily_rotation and tail_length <= READ_SIZE else b''
                        after = os.fstat(fd)
                        # Do not discard bytes observed arriving during this
                        # copy. A writer racing the final truncate can still
                        # lose bytes, as with any copytruncate mechanism.
                        if (after.st_size, after.st_mtime_ns) == (current.st_size, current.st_mtime_ns):
                            os.ftruncate(fd, 0)
                            if tail:
                                os.pwrite(fd, tail, 0)
                            os.fsync(fd)
                            result['source_rotated'] = True
                            if daily_rotation or tail_length > READ_SIZE:
                                result['dropped_partial_bytes'] = tail_length
                            _json_write(_path(root, CURSOR), {'version': 1,
                                        'source': _source_state(fd, 0, now.date().isoformat())})
                    source_bytes = os.fstat(fd).st_size
            finally:
                os.close(fd)
        result.update(_prune(root, settings, now, source_bytes))
    return result


def configure(instance, runner=subprocess.run, root=Path('/')):
    """Install the private standalone helper; no monitoring field is a no-op."""
    if 'monitoring' not in instance:
        return
    settings = _settings(instance['monitoring'])
    if Path(root).resolve() != Path('/') and runner is subprocess.run:
        raise ValueError('a non-system root requires an injected service runner')
    if Path(root).resolve() == Path('/') and os.geteuid() != 0:
        raise PermissionError('monitoring configuration requires root')
    for path in (SETTINGS, HELPER, SERVICE_PATH, TIMER_PATH):
        _path(root, path)
    _prepare(root)
    for path in (SETTINGS.parent, HELPER.parent):
        _private_dir(_path(root, path))
    _path(root, SERVICE_PATH.parent).mkdir(parents=True, exist_ok=True)
    with _locked(root):
        fd = _open(_path(root, SOURCE), os.O_RDWR | os.O_CREAT)
        os.close(fd)
        _json_write(_path(root, SETTINGS), settings)
        _atomic(_path(root, HELPER), Path(__file__).read_bytes())
        _atomic(_path(root, SERVICE_PATH), SERVICE.encode())
        _atomic(_path(root, TIMER_PATH), TIMER.encode())
    runner(['systemctl', 'daemon-reload'], check=True)
    # Basic retains the timer for cleanup; old history therefore still expires.
    runner(['systemctl', 'enable', '--now', 'vpn-installer-monitoring.timer'], check=True)


def history_lines(settings, root=Path('/'), user=None, now=None):
    """Read retained archives chronologically; user matches the exact email field."""
    settings = _settings(settings)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('monitoring timestamps must have a timezone')
    cutoff = (now.astimezone(timezone.utc).date() - timedelta(days=settings['retention_days'] - 1)).isoformat()
    match = re.compile(r'(?:^|\s)email:\s*' + re.escape(user) + r'(?=$|[\s\]])') if user is not None else None
    with _locked(root, readonly=True):
        for path in _archives(root):
            if path.stem < cutoff:
                continue
            fd = _open(path, os.O_RDONLY, private=False)
            with os.fdopen(fd, 'r', encoding='utf-8', errors='replace') as source:
                for line in source:
                    if match is None or match.search(line):
                        yield line.rstrip('\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('collect', 'history'))
    parser.add_argument('--config', type=Path, default=SETTINGS)
    parser.add_argument('--user', help='exact Xray email/user identifier for history')
    parser.add_argument('--limit', type=int, default=1000, help='maximum number of newest history lines')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error('run this helper as root')
    if not 1 <= args.limit <= 100000:
        parser.error('--limit must be between 1 and 100000')
    settings = _settings(_load_json(args.config))
    if args.action == 'collect':
        collect(settings)
    else:
        for line in deque(history_lines(settings, user=args.user), maxlen=args.limit):
            print(''.join(char if char.isprintable() else '?' for char in line))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
