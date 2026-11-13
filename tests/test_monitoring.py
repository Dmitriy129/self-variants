"""Collector recovery, expiry and private deployment using temporary files only."""
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from vpn_installer import monitoring


class MonitoringTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.settings = {'mode': 'destinations', 'retention_days': 7, 'max_log_mb': 128}
        self.now = datetime.now(timezone.utc).replace(hour=12, minute=0, second=0, microsecond=0)
        self.source = self.at(monitoring.SOURCE)
        self.source.parent.mkdir(parents=True)
        self.history = self.at(monitoring.HISTORY)

    def at(self, path):
        return self.root / path.relative_to('/')

    def collect(self, **kwargs):
        return monitoring.collect(self.settings, root=self.root, now=self.now, **kwargs)

    def lines(self, user=None):
        return list(monitoring.history_lines(self.settings, root=self.root, user=user, now=self.now))

    def archive(self, days_ago=0):
        return self.history / ((self.now.date() - timedelta(days=days_ago)).isoformat() + '.log')

    def test_complete_lines_only_and_persisted_cursor_prevent_normal_duplicates(self):
        self.source.write_bytes(b'one email: dad\ntwo email: mom\npartial')
        result = self.collect()
        self.assertEqual(result['copied_lines'], 2)
        self.assertEqual(self.lines(), ['one email: dad', 'two email: mom'])
        self.assertEqual(self.collect()['copied_bytes'], 0)
        with self.source.open('ab') as output:
            output.write(b' finished email: dad\n')
        self.assertEqual(self.collect()['copied_lines'], 1)
        self.assertEqual(self.lines(), ['one email: dad', 'two email: mom', 'partial finished email: dad'])
        self.assertEqual(self.collect()['copied_bytes'], 0)

    def test_parallel_collectors_serialize_the_cursor_and_archive(self):
        self.source.write_bytes(b'one\ntwo\nthree\n')
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: self.collect(), range(2)))
        self.assertEqual(sum(result['copied_lines'] for result in results), 3)
        self.assertEqual(self.lines(), ['one', 'two', 'three'])

    def test_same_inode_truncation_and_regrowth_are_detected(self):
        self.source.write_bytes(b'old entry\n')
        self.collect()
        inode = self.source.stat().st_ino
        self.source.write_bytes(b'new entry after upstream truncate and regrowth\n')
        self.assertEqual(self.source.stat().st_ino, inode)
        self.collect()
        self.source.write_bytes(b'x\n')
        self.collect()
        self.assertEqual(self.lines(), ['old entry', 'new entry after upstream truncate and regrowth', 'x'])

    def test_recreated_source_is_read_from_its_start(self):
        self.source.write_bytes(b'first\n')
        self.collect()
        self.source.rename(self.source.with_name('old.log'))
        self.source.write_bytes(b'replacement\n')
        self.collect()
        self.assertEqual(self.lines(), ['first', 'replacement'])

    def test_crash_after_append_before_cursor_commit_does_not_duplicate_lines(self):
        self.source.write_bytes(b'complete transaction\n')
        original = monitoring._json_write
        writes = 0
        def fail_commit(path, data):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError('simulated interruption before cursor commit')
            return original(path, data)
        with mock.patch.object(monitoring, '_json_write', side_effect=fail_commit), self.assertRaises(OSError):
            self.collect()
        self.assertIn('pending', json.loads(self.at(monitoring.CURSOR).read_text()))
        self.assertEqual(self.collect()['copied_bytes'], 0)
        self.assertEqual(self.lines(), ['complete transaction'])
        self.assertNotIn('pending', json.loads(self.at(monitoring.CURSOR).read_text()))

    def test_crash_during_append_discards_partial_archive_bytes_and_retries(self):
        self.source.write_bytes(b'previous\n')
        self.collect()
        with self.source.open('ab') as output:
            output.write(b'new complete record\n')
        def partial_append(path, data):
            with path.open('ab') as output:
                output.write(data[:5])
            raise OSError('simulated interrupted write')
        with mock.patch.object(monitoring, '_append_bytes', side_effect=partial_append), self.assertRaises(OSError):
            self.collect()
        self.collect()
        self.assertEqual(self.lines(), ['previous', 'new complete record'])

    def test_retention_expires_by_utc_day_and_basic_keeps_cleanup_running(self):
        self.history.mkdir(parents=True)
        expired = self.archive(7)
        kept = self.archive(6)
        expired.write_text('old private destination\n')
        kept.write_text('within retained calendar days\n')
        self.source.write_bytes(b'must not be archived in basic mode\n')
        self.settings['mode'] = 'basic'
        result = self.collect()
        self.assertFalse(expired.exists())
        self.assertEqual(kept.read_text(), 'within retained calendar days\n')
        self.assertEqual(self.source.read_bytes(), b'')
        self.assertEqual(result['copied_lines'], 0)
        self.assertEqual(self.lines(), ['within retained calendar days'])
        self.now += timedelta(days=1)
        self.collect()
        self.assertFalse(kept.exists())

    def test_basic_does_not_read_new_source_content(self):
        self.source.write_bytes(b'private destination\n')
        self.settings['mode'] = 'basic'
        with mock.patch.object(monitoring.os, 'pread', side_effect=AssertionError('basic must not read source bytes')):
            self.collect()
        self.assertEqual(self.source.stat().st_size, 0)
        self.assertEqual(self.lines(), [])

    def test_source_copytruncate_preserves_partial_line_for_the_next_tick(self):
        self.settings['max_log_mb'] = 16
        complete = (b'a' * 1023 + b'\n') * (4 * 1024 + 1)
        self.source.write_bytes(complete + b'partial')
        result = self.collect()
        self.assertTrue(result['source_rotated'])
        self.assertEqual(self.source.read_bytes(), b'partial')
        self.assertEqual(result['copied_lines'], 4 * 1024 + 1)
        with self.source.open('ab') as output:
            output.write(b' completed\n')
        self.collect()
        self.assertEqual(self.lines()[-1], 'partial completed')
        self.assertEqual(len(self.lines()), 4 * 1024 + 2)

    def test_budget_includes_source_and_deletes_oldest_history_first(self):
        self.settings['max_log_mb'] = 16
        self.history.mkdir(parents=True)
        old = self.archive(2)
        recent = self.archive(1)
        line = b'x' * 1023 + b'\n'
        old.write_bytes(line * (14 * 1024))
        recent.write_bytes(line * (4 * 1024))
        self.source.write_bytes(b'newest record\n')
        result = self.collect()
        self.assertLessEqual(result['history_bytes'] + result['source_bytes'], 16 * monitoring.MIB)
        self.assertEqual(recent.stat().st_size, 4 * monitoring.MIB)
        self.assertLess(old.stat().st_size, 14 * monitoring.MIB)
        self.assertEqual(self.lines()[-1], 'newest record')
        self.assertTrue(old.read_bytes().endswith(b'\n'))

    def test_budget_can_remove_whole_old_archive(self):
        self.settings['max_log_mb'] = 16
        self.history.mkdir(parents=True)
        old = self.archive(2)
        recent = self.archive(1)
        old.write_bytes(b'old\n')
        recent.write_bytes((b'x' * 1023 + b'\n') * (17 * 1024))
        self.collect()
        self.assertFalse(old.exists())
        self.assertLessEqual(recent.stat().st_size, 16 * monitoring.MIB)

    def test_private_permissions_and_readonly_history_exact_user_filter(self):
        self.source.write_bytes(b'one email: dad\ntwo email: daddy\nthree email: mom\n')
        self.source.chmod(0o644)
        self.collect()
        self.assertEqual(self.lines(user='dad'), ['one email: dad'])
        paths = [self.source, self.at(monitoring.CURSOR), self.at(monitoring.LOCK), *self.history.iterdir()]
        for path in paths:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for path in (self.source.parent, self.history, self.at(monitoring.LOG_ROOT)):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}
        self.lines()
        self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths})

    def test_source_rotates_at_next_utc_day_even_when_small_and_recently_appended(self):
        self.source.write_bytes(b'first day\n')
        self.collect()
        self.now += timedelta(days=1)
        with self.source.open('ab') as output:
            output.write(b'new day\nincomplete')
        result = self.collect()
        self.assertTrue(result['source_rotated'])
        self.assertEqual(self.source.read_bytes(), b'')
        self.assertEqual(result['dropped_partial_bytes'], len(b'incomplete'))
        self.assertEqual(self.lines(), ['first day', 'new day'])

    def test_expired_source_is_cleared_without_renewing_records_in_new_archive(self):
        self.source.write_bytes(b'old destination must expire\n')
        stamp = (self.now - timedelta(days=7)).timestamp()
        os.utime(self.source, (stamp, stamp))
        result = self.collect()
        self.assertTrue(result['source_expired'])
        self.assertEqual(self.source.read_bytes(), b'')
        self.assertEqual(result['copied_bytes'], 0)
        self.assertEqual(self.lines(), [])

    def test_history_with_no_files_is_readonly(self):
        self.assertEqual(self.lines(), [])
        self.assertFalse(self.at(monitoring.LOG_ROOT).exists())

    def test_collector_refuses_source_cursor_and_archive_symlinks(self):
        outside = self.root / 'unrelated'
        outside.write_bytes(b'preserve')
        for absolute in (monitoring.SOURCE, monitoring.CURSOR, monitoring.HISTORY / '2026-11-17.log'):
            path = self.at(absolute)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(outside)
            with self.subTest(path=absolute), self.assertRaises((ValueError, OSError)):
                self.collect()
            path.unlink()
        self.assertEqual(outside.read_bytes(), b'preserve')

    def test_collector_refuses_linked_directory_and_hardlinked_source(self):
        self.at(monitoring.LOG_ROOT).parent.mkdir(parents=True, exist_ok=True)
        outside = self.root / 'outside'
        outside.mkdir()
        self.at(monitoring.LOG_ROOT).symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.collect()
        self.at(monitoring.LOG_ROOT).unlink()
        file = self.root / 'unrelated'
        file.write_bytes(b'preserve')
        os.link(file, self.source)
        with self.assertRaises(ValueError):
            self.collect()
        self.assertEqual(file.read_bytes(), b'preserve')

    def test_configure_installs_standalone_helper_and_timer_for_both_modes(self):
        for mode in ('destinations', 'basic'):
            self.settings['mode'] = mode
            runner = mock.Mock()
            self.source.write_bytes(b'existing records are not destroyed by configure\n')
            monitoring.configure({'monitoring': self.settings}, runner=runner, root=self.root)
            self.assertIn(b'existing records', self.source.read_bytes())
            self.assertEqual(json.loads(self.at(monitoring.SETTINGS).read_text()), self.settings)
            self.assertEqual(self.at(monitoring.HELPER).read_bytes(), Path(monitoring.__file__).read_bytes())
            self.assertEqual(runner.call_args_list, [
                mock.call(['systemctl', 'daemon-reload'], check=True),
                mock.call(['systemctl', 'enable', '--now', 'vpn-installer-monitoring.timer'], check=True),
            ])
            for absolute in (monitoring.HELPER, monitoring.SETTINGS, monitoring.SERVICE_PATH, monitoring.TIMER_PATH):
                self.assertEqual(self.at(absolute).stat().st_mode & 0o777, 0o600)
            self.assertIn('OnUnitActiveSec=1min', self.at(monitoring.TIMER_PATH).read_text())
            self.assertIn('ReadWritePaths=/var/log/vpn-installer /var/log/x-ui', self.at(monitoring.SERVICE_PATH).read_text())

    def test_absent_monitoring_is_noop_and_test_root_needs_fake_runner(self):
        runner = mock.Mock()
        monitoring.configure({}, runner=runner, root=self.root)
        runner.assert_not_called()
        self.assertFalse(self.at(monitoring.LOG_ROOT).exists())
        with self.assertRaises(ValueError):
            monitoring.configure({'monitoring': self.settings}, root=self.root)
        self.assertFalse(self.at(monitoring.LOG_ROOT).exists())

    def test_configuration_rejects_symlink_before_service_calls(self):
        target = self.at(monitoring.SETTINGS)
        target.parent.mkdir(parents=True)
        outside = self.root / 'other-settings'
        outside.write_text('preserve')
        target.symlink_to(outside)
        runner = mock.Mock()
        with self.assertRaises(ValueError):
            monitoring.configure({'monitoring': self.settings}, runner=runner, root=self.root)
        runner.assert_not_called()
        self.assertEqual(outside.read_text(), 'preserve')

    def test_invalid_settings_are_refused_without_files_or_commands(self):
        for field, value in (('mode', 'domains'), ('retention_days', 0), ('retention_days', 31),
                             ('retention_days', True), ('max_log_mb', 15), ('max_log_mb', 1025)):
            settings = dict(self.settings, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                monitoring.collect(settings, root=self.root, now=self.now)
        self.assertFalse(self.at(monitoring.LOG_ROOT).exists())


if __name__ == '__main__':
    unittest.main()
