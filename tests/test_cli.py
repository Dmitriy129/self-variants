"""User-data preservation and failure ordering, with all host actions mocked."""

import contextlib
import copy
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

from vpn_installer import cli, system
from vpn_installer.config import save_instance


def manifest():
    return {
        "schema_version": 1, "profile": "hysteria2", "domain": "vpn.example.com",
        "email": "owner@example.com", "https_port": 8443,
        "panel": {"path": "/preserve-panel/", "username": "admin", "password": "AdminPassword123!"},
        "subscription": {"path": "/preserve-sub/"},
        "users": [{"email": "alice@example.com", "sub_id": "preserve-token-123", "password": "UserPassword123!",
                   "enable": True, "expiry_time": 0, "total_gb": 0, "limit_ip": 0}],
    }


class MainBoundaryTests(unittest.TestCase):
    def test_running_panel_with_failed_xray_is_not_reported_healthy(self):
        panel = mock.Mock()
        panel.xray_running.return_value = False
        with mock.patch.object(cli.system, 'run'), \
                mock.patch.object(cli, 'connected_panel', return_value=panel), \
                mock.patch.object(cli.time, 'sleep'), \
                self.assertRaises(cli.system.InstallError):
            cli.verify_services({})

    def test_invalid_restore_is_refused_before_host_checks_locks_or_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text('{"schema_version":1}')
            with mock.patch.object(cli.os, "umask"), \
                    mock.patch.object(system, "require_host") as host, \
                    mock.patch("vpn_installer.cli.open", create=True) as lock_open, \
                    mock.patch.object(cli, "deploy") as deploy, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["--config", str(path)]), 1)
            host.assert_not_called()
            lock_open.assert_not_called()
            deploy.assert_not_called()

    def test_check_config_is_read_only_and_does_not_require_root(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instance.json"
            save_instance(path, manifest())
            before = path.read_bytes()
            output = io.StringIO()
            with mock.patch.object(cli.os, "umask"), \
                    mock.patch.object(system, "require_host") as host, \
                    mock.patch("vpn_installer.cli.open", create=True) as lock_open, \
                    contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(["--check-config", str(path)]), 0)
            self.assertEqual(path.read_bytes(), before)
            host.assert_not_called()
            lock_open.assert_not_called()
            for secret in (manifest()["panel"]["password"], manifest()["users"][0]["password"], manifest()["users"][0]["sub_id"]):
                self.assertNotIn(secret, output.getvalue())

    def test_external_command_failure_does_not_log_credentials(self):
        secret = "NeverPrintThisPassword123"
        error = subprocess.CalledProcessError(1, ["x-ui", "-password", secret], output=secret, stderr=secret)
        stderr = io.StringIO()
        with mock.patch.object(cli.os, "umask"), \
                mock.patch.object(system, "require_host", side_effect=error), \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(cli.main(["--status"]), 1)
        self.assertNotIn(secret, stderr.getvalue())
        self.assertIn("x-ui", stderr.getvalue())

    def test_orphaned_manifest_is_not_treated_as_clean_install(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "instance.json").write_text("{}")
            with self.assertRaises(system.InstallError):
                cli.read_state(directory)


class DeployTests(unittest.TestCase):
    def test_completed_rerun_exports_live_users_never_replays_old_manifest(self):
        saved = manifest()
        supplied = copy.deepcopy(saved)
        live = copy.deepcopy(saved)
        live["users"][0]["enable"] = False
        live["users"].append(dict(live["users"][0], email="bob@example.com", sub_id="new-live-token-456", password="NewPassword123!"))
        state = {"owner": "vpn-installer", "schema": 1, "phase": "complete"}
        args = cli.parser().parse_args(["--config", "/unused.json"])
        with mock.patch.object(cli, "read_state", return_value=state), \
                mock.patch.object(cli, "load_instance", return_value=saved), \
                mock.patch.object(cli, "export_live", return_value=live) as export, \
                mock.patch.object(cli, "verify_services") as verify, \
                mock.patch.object(cli, "show_result") as result, \
                mock.patch.object(cli, "configure_instance") as configure, \
                mock.patch.object(system, "install_binaries") as install, \
                mock.patch.object(system, "download_artifacts") as download, \
                contextlib.redirect_stdout(io.StringIO()):
            cli.deploy(args, supplied)
        export.assert_called_once()
        verify.assert_called_once_with(live)
        result.assert_called_once_with(live)
        configure.assert_not_called()
        install.assert_not_called()
        download.assert_not_called()
        self.assertEqual(supplied, saved)

    def test_managed_restore_refuses_namespace_changes_without_contacting_panel(self):
        for field in ("domain", "profile", "panel", "subscription"):
            original = manifest()
            supplied = copy.deepcopy(original)
            if field == "domain":
                supplied[field] = "other.example.com"
            elif field == "profile":
                supplied[field] = "reality"
            else:
                supplied[field]["path"] = "/different/"
            args = cli.parser().parse_args(["--config", "/unused.json"])
            with self.subTest(field=field), \
                    mock.patch.object(cli, "read_state", return_value={"phase": "complete"}), \
                    mock.patch.object(cli, "load_instance", return_value=original), \
                    mock.patch.object(cli, "export_live") as export, \
                    mock.patch.object(system, "run") as runner, \
                    self.assertRaises(system.InstallError):
                cli.deploy(args, supplied)
            export.assert_not_called()
            runner.assert_not_called()

    def test_dirty_host_rejected_before_download_packages_firewall_or_state(self):
        args = cli.parser().parse_args(["--config", "/unused.json"])
        with mock.patch.object(cli, "read_state", return_value=None), \
                mock.patch.object(system, "check_clean_host", side_effect=system.InstallError("dirty")), \
                mock.patch.object(system, "download_artifacts") as download, \
                mock.patch.object(system, "install_dependencies") as dependencies, \
                mock.patch.object(cli.network, "configure_firewall") as firewall, \
                mock.patch.object(cli, "write_state") as state, \
                self.assertRaises(system.InstallError):
            cli.deploy(args, manifest())
        for action in (download, dependencies, firewall, state):
            action.assert_not_called()


class UpdateRollbackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = self.root / "x-ui"
        self.app.mkdir()
        (self.app / "x-ui").write_bytes(b"old executable")
        self.database = self.root / "db"
        self.database.mkdir()
        with contextlib.closing(sqlite3.connect(self.database / "x-ui.db")) as connection, connection:
            connection.execute("CREATE TABLE users (sub_id TEXT)")
            connection.execute("INSERT INTO users VALUES ('stable-link-123')")
        self.instance = manifest()
        self.state = {"owner": "vpn-installer", "schema": 1, "phase": "complete", "versions": {"old": "version"}}
        self.args = cli.parser().parse_args(["--update"])
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(system, "APP_DIR", self.app))
        self.stack.enter_context(mock.patch.object(system, "DB_DIR", self.database))
        self.stack.enter_context(mock.patch.object(cli, "load_instance", return_value=self.instance))
        self.backup = self.stack.enter_context(mock.patch.object(cli, "export_and_backup", return_value=self.instance))
        self.stack.enter_context(mock.patch.object(system, "read_versions", return_value={"new": "version"}))
        self.stack.enter_context(mock.patch.object(system, "download_artifacts", return_value={}))
        self.runner = self.stack.enter_context(mock.patch.object(system, "run", return_value=subprocess.CompletedProcess([], 0)))
        self.connect = self.stack.enter_context(mock.patch.object(cli, "connected_panel"))
        self.verify = self.stack.enter_context(mock.patch.object(cli, "verify_services"))
        self.write_state = self.stack.enter_context(mock.patch.object(cli, "write_state"))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def test_failed_health_restores_binaries_and_pre_migration_database(self):
        def install(_):
            (self.app / "x-ui").write_bytes(b"new executable")
        def check(_):
            with contextlib.closing(sqlite3.connect(self.database / "x-ui.db")) as connection, connection:
                connection.execute("DROP TABLE users")
                connection.execute("CREATE TABLE incompatible_schema (changed TEXT)")
            raise system.InstallError("new release failed health check")
        self.verify.side_effect = check
        with mock.patch.object(system, "install_binaries", side_effect=install), self.assertRaises(system.InstallError):
            cli.maintain(self.args, self.state)
        self.assertEqual((self.app / "x-ui").read_bytes(), b"old executable")
        with contextlib.closing(sqlite3.connect(self.database / "x-ui.db")) as connection:
            self.assertEqual(connection.execute("SELECT sub_id FROM users").fetchall(), [("stable-link-123",)])
        self.assertEqual(self.state["versions"], {"old": "version"})
        self.write_state.assert_not_called()
        self.assertEqual(self.runner.call_args_list[-1].args[0], ["systemctl", "start", "x-ui"])

    def test_snapshot_copy_failure_leaves_old_service_running(self):
        def fail_copy(source, destination):
            Path(destination).mkdir()
            (Path(destination) / "partial").write_bytes(b"partial copy")
            raise OSError("disk full")
        with mock.patch("shutil.copytree", side_effect=fail_copy), \
                mock.patch.object(system, "install_binaries") as install, self.assertRaises(OSError):
            cli.maintain(self.args, self.state)
        self.assertEqual((self.app / "x-ui").read_bytes(), b"old executable")
        install.assert_not_called()
        commands = [call.args[0] for call in self.runner.call_args_list]
        # If the old service was stopped at all, the error path must restart it.
        if ["systemctl", "stop", "x-ui"] in commands:
            self.assertEqual(commands[-1], ["systemctl", "start", "x-ui"])

    def test_failed_initial_stop_never_restores_stale_snapshot_over_live_users(self):
        stops = 0
        def command(argv, **kwargs):
            nonlocal stops
            if argv == ["systemctl", "stop", "x-ui"]:
                stops += 1
                if stops == 1:
                    with contextlib.closing(sqlite3.connect(self.database / "x-ui.db")) as connection, connection:
                        connection.execute("INSERT INTO users VALUES ('created-during-backup')")
                if kwargs.get("check", True):
                    raise subprocess.CalledProcessError(1, argv)
                return subprocess.CompletedProcess(argv, 1)
            return subprocess.CompletedProcess(argv, 0)
        self.runner.side_effect = command
        with mock.patch.object(system, "install_binaries") as install, self.assertRaises(Exception):
            cli.maintain(self.args, self.state)
        install.assert_not_called()
        with contextlib.closing(sqlite3.connect(self.database / "x-ui.db")) as connection:
            rows = connection.execute("SELECT sub_id FROM users ORDER BY sub_id").fetchall()
        self.assertEqual(rows, [("created-during-backup",), ("stable-link-123",)])
        self.assertEqual((self.app / "x-ui").read_bytes(), b"old executable")

    def test_failed_rollback_stop_keeps_recovery_copy_and_does_not_replace_live_files(self):
        stops = 0
        def command(argv, **kwargs):
            nonlocal stops
            if argv == ["systemctl", "stop", "x-ui"]:
                stops += 1
                if stops > 1:
                    if kwargs.get("check", True):
                        raise subprocess.CalledProcessError(1, argv)
                    return subprocess.CompletedProcess(argv, 1)
            return subprocess.CompletedProcess(argv, 0)
        self.runner.side_effect = command
        self.verify.side_effect = system.InstallError("new release failed health check")
        def install(_):
            (self.app / "x-ui").write_bytes(b"new executable still running")
        with mock.patch.object(system, "install_binaries", side_effect=install), self.assertRaises(Exception):
            cli.maintain(self.args, self.state)
        self.assertEqual((self.app / "x-ui").read_bytes(), b"new executable still running")
        self.assertTrue(self.app.with_name("x-ui.vpn-installer-rollback").exists())
        self.write_state.assert_not_called()

    def test_successful_update_preserves_users_and_records_new_versions(self):
        def install(_):
            (self.app / "x-ui").write_bytes(b"new executable")
        with mock.patch.object(system, "install_binaries", side_effect=install):
            cli.maintain(self.args, self.state)
        self.assertEqual((self.app / "x-ui").read_bytes(), b"new executable")
        with contextlib.closing(sqlite3.connect(self.database / "x-ui.db")) as connection:
            self.assertEqual(connection.execute("SELECT sub_id FROM users").fetchall(), [("stable-link-123",)])
        self.assertEqual(self.state["versions"], {"new": "version"})
        self.write_state.assert_called_once()
        self.assertFalse(self.app.with_name("x-ui.vpn-installer-rollback").exists())
        self.backup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
