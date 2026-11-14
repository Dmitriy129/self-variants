"""User-data preservation and failure ordering, with all host actions mocked."""

import contextlib
import base64
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
from vpn_installer.config import ConfigError, load_instance, save_instance, subscription_urls


def manifest(profile="hysteria2", version=1):
    data = {
        "schema_version": 1, "profile": "hysteria2", "domain": "vpn.example.com",
        "email": "owner@example.com", "https_port": 8443,
        "panel": {"path": "/preserve-panel/", "username": "admin", "password": "AdminPassword123!"},
        "subscription": {"path": "/preserve-sub/"},
        "users": [{"email": "alice@example.com", "sub_id": "preserve-token-123", "password": "UserPassword123!",
                   "enable": True, "expiry_time": 0, "total_gb": 0, "limit_ip": 0}],
    }
    data["profile"] = profile
    if profile == "reality":
        encode = lambda value: base64.urlsafe_b64encode(bytes.fromhex(value)).decode().rstrip("=")
        data["reality"] = {
            "target": "www.example.org:443", "server_name": "www.example.org",
            "private_key": encode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            "public_key": encode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            "short_id": "aabbccddeeff0011",
        }
        data["users"][0].pop("password")
        data["users"][0]["uuid"] = "f26544bf-882a-4cc0-a336-927bc2e938b5"
    if version == 2:
        data.update(schema_version=2, https_port=443)
        if profile == "reality":
            data["site"] = {"domain": "journal.example.org", "template": "field-notes"}
            data["reality"].update(target="127.0.0.1:9443", server_name="journal.example.org")
    return data


def monitored_manifest(mode="basic", profile="hysteria2", version=2):
    data = manifest(profile, version)
    data["monitoring"] = {"mode": mode, "retention_days": 7, "max_log_mb": 128}
    return data


class MainBoundaryTests(unittest.TestCase):
    def test_live_export_saves_names_marker_and_preserves_renamed_user_url(self):
        baseline = manifest("hysteria2", 2)
        baseline["subscription"] = {"path": "/app/", "id_mode": "names"}
        baseline["users"][0].update(email="fix", sub_id="fix")
        live = copy.deepcopy(baseline)
        live["users"][0].update(email="renamed-user", enable=False)
        client = mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.json"
            with mock.patch.object(cli, "connected_panel", return_value=client), \
                    mock.patch.object(cli, "export_instance", return_value=live) as export:
                self.assertEqual(cli.export_live(baseline, path), live)
            export.assert_called_once_with(client, baseline)
            restored = load_instance(path)
            self.assertEqual(restored, live)
            self.assertEqual(subscription_urls(restored), {"renamed-user": "https://vpn.example.com/app/fix"})

    def test_cli_names_and_users_file_are_mutually_exclusive(self):
        for options in (["--users", "owner,family", "--users-file", "/unused.json"],
                        ["--users-file", "/unused.json", "--users", "owner,family"]):
            with self.subTest(options=options), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as failure:
                cli.parser().parse_args(["--profile", "hysteria2", *options])
            self.assertEqual(failure.exception.code, 2)

    def test_running_core_with_monitoring_drift_is_not_reported_healthy(self):
        panel = mock.Mock()
        panel.xray_running.return_value = True
        instance = monitored_manifest()
        with mock.patch.object(system, "run"), \
                mock.patch.object(cli, "connected_panel", return_value=panel), \
                mock.patch.object(cli, "validate_monitoring", side_effect=RuntimeError("counter disabled")) as validate, \
                self.assertRaises(RuntimeError):
            cli.verify_services(instance)
        validate.assert_called_once_with(panel, instance)

    def test_monitoring_and_log_arguments_are_checked_before_host_changes(self):
        for argv in (["--status", "--monitoring", "destinations"],
                     ["--status", "--fingerprint", "firefox"],
                     ["--profile", "hysteria2", "--fingerprint", "firefox"],
                     ["--set-fingerprint", "Firefox\n"],
                     ["--set-fingerprint", ""],
                     ["--show-logs", "--log-lines", "0"],
                     ["--show-logs", "--log-lines", "10001"],
                     ["--status", "--log-user", "alice"]):
            with self.subTest(argv=argv), mock.patch.object(cli.os, "umask"), \
                    mock.patch.object(system, "require_host") as host, \
                    mock.patch("vpn_installer.cli.open", create=True) as lock_open, \
                    mock.patch.object(cli, "maintain") as maintain, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(argv), 1)
            host.assert_not_called()
            lock_open.assert_not_called()
            maintain.assert_not_called()

    def test_running_core_with_unavailable_local_site_is_not_reported_healthy(self):
        panel = mock.Mock()
        panel.xray_running.return_value = True
        saved = manifest('reality', 2)
        with mock.patch.object(system, 'run'), \
                mock.patch.object(cli, 'connected_panel', return_value=panel), \
                mock.patch.object(system, 'check_reality_target', side_effect=system.InstallError('site unavailable')) as probe, \
                self.assertRaises(system.InstallError):
            cli.verify_services(saved)
        probe.assert_called_once_with(saved)

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


class DeploySequenceTests(unittest.TestCase):
    """Exercise the real orchestration while every host operation is replaced."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(cli, "STATE_DIR", self.root / "state"))
        self.startup_users = self.root / "package-users.json"
        self.startup_users.write_text(json.dumps(["starter"]))
        self.stack.enter_context(mock.patch.object(cli, "DEFAULT_USERS_FILE", self.startup_users))
        self.example_users = self.root / "users.example.json"
        self.example_users.write_text(json.dumps(["personal"]))
        self.stack.enter_context(mock.patch.object(cli, "EXAMPLE_USERS_FILE", self.example_users))
        self.stack.enter_context(mock.patch.object(Path, "is_symlink", return_value=False))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.actions = mock.Mock()
        self.mocks = {}
        self.state = None
        for module, names in (
            (cli, ("read_state", "write_state", "save_instance", "load_instance", "connected_panel",
                   "configure_instance", "verify_services", "export_live", "show_result")),
            (system, ("check_clean_host", "check_dns", "check_reality_target", "detect_ssh_ports",
                      "read_versions", "download_artifacts", "install_dependencies", "install_binaries",
                      "bootstrap_panel", "run")),
            (cli.network, ("configure_firewall", "configure_http", "issue_certificate", "install_static_site",
                           "configure_https")),
        ):
            for name in names:
                patched = self.stack.enter_context(mock.patch.object(module, name))
                self.actions.attach_mock(patched, name)
                self.mocks[name] = patched
        self.mocks["read_state"].return_value = None
        self.mocks["detect_ssh_ports"].return_value = [22]
        self.mocks["read_versions"].return_value = {"version": "fixture"}
        self.mocks["download_artifacts"].return_value = {}
        self.mocks["run"].return_value = subprocess.CompletedProcess([], 0)
        self.mocks["export_live"].side_effect = lambda data, destination: data
        monitoring_configure = self.stack.enter_context(mock.patch.object(cli.monitoring, "configure"))
        self.actions.attach_mock(monitoring_configure, "monitoring_configure")
        self.mocks["monitoring_configure"] = monitoring_configure

    def deploy(self, data, prepare=False):
        args = cli.parser().parse_args(["--config", "/unused.json"] + (["--prepare"] if prepare else []))
        cli.deploy(args, data)

    def order(self, *names):
        calls = [call[0] for call in self.actions.mock_calls]
        positions = [calls.index(name) for name in names]
        self.assertEqual(positions, sorted(positions), calls)

    def new_args(self, *options):
        return cli.parser().parse_args([
            "--profile", "hysteria2", "--domain", "vpn.example.com",
            "--email", "owner@example.com", *options])

    def test_fresh_names_and_public_path_flags_reach_generator(self):
        with mock.patch.object(cli, "new_instance", wraps=cli.new_instance) as create:
            cli.deploy(self.new_args("--users", "fix,ee,fix-vps", "--subscription-ids", "names",
                                     "--subscription-path", "app", "--panel-path", "control"))
        self.assertEqual(create.call_args.kwargs["subscription_ids"], "names")
        self.assertEqual(create.call_args.kwargs["subscription_path"], "app")
        self.assertEqual(create.call_args.kwargs["panel_path"], "control")
        saved = self.mocks["save_instance"].call_args.args[1]
        self.assertEqual(saved["subscription"], {"path": "/app/", "id_mode": "names"})
        self.assertEqual(saved["panel"]["path"], "/control/")
        self.assertEqual([user["sub_id"] for user in saved["users"]], ["fix", "ee", "fix-vps"])

    def test_fingerprint_flag_applies_only_to_fresh_reality(self):
        args = cli.parser().parse_args(['--profile', 'reality', '--domain', 'vpn.example.com',
            '--email', 'owner@example.com', '--site-domain', 'site.example.com',
            '--users', 'owner', '--fingerprint', 'hellochrome_155'])
        cli.deploy(args)
        saved = self.mocks['save_instance'].call_args.args[1]
        self.assertEqual(saved['reality']['fingerprint'], 'hellochrome_155')
        self.mocks['read_state'].return_value = {'phase': 'complete'}
        self.mocks['load_instance'].return_value = saved
        args.fingerprint = 'firefox'
        with mock.patch.object(cli, 'new_instance', side_effect=AssertionError('must not replace live state')):
            cli.deploy(args)
        self.assertEqual(self.mocks['export_live'].call_args.args[0]['reality']['fingerprint'], 'hellochrome_155')

    def test_same_named_subscription_command_on_two_clean_states_recreates_urls(self):
        args = self.new_args("--users", "fix,ee,fix-vps", "--subscription-ids", "names",
                             "--subscription-path", "app", "--panel-path", "control")
        instances = []
        for number in (1, 2):
            with mock.patch.object(cli, "STATE_DIR", self.root / f"clean-state-{number}"):
                cli.deploy(args)
            instances.append(copy.deepcopy(self.mocks["save_instance"].call_args.args[1]))
        expected = {name: f"https://vpn.example.com/app/{name}" for name in ("fix", "ee", "fix-vps")}
        self.assertEqual(subscription_urls(instances[0]), expected)
        self.assertEqual(subscription_urls(instances[1]), expected)
        for before, after in zip(instances[0]["users"], instances[1]["users"]):
            self.assertNotEqual(before["password"], after["password"])

    def test_invalid_named_subscription_input_refuses_fresh_install_before_host_actions(self):
        for options in (("--users", "fix,мама"), ("--users", "fix", "--subscription-path", "bad//path"),
                        ("--users", "fix", "--subscription-path", "app", "--panel-path", "app/child")):
            with self.subTest(options=options), \
                    mock.patch("vpn_installer.config.secrets.token_urlsafe", side_effect=AssertionError("validate before generation")), \
                    self.assertRaises(ConfigError):
                cli.deploy(self.new_args("--subscription-ids", "names", *options))
        for name in ("check_clean_host", "check_dns", "detect_ssh_ports", "download_artifacts",
                     "write_state", "save_instance", "install_dependencies", "configure_firewall",
                     "install_binaries", "bootstrap_panel", "configure_http", "run"):
            self.mocks[name].assert_not_called()
        self.assertFalse((self.root / "state").exists())

    def test_inline_names_bypass_both_files_and_preserve_the_requested_users(self):
        self.startup_users.write_text("invalid local file must not be read")
        self.example_users.unlink()
        with mock.patch.object(cli, "load_user_names", side_effect=AssertionError("--users must bypass files")) as load:
            cli.deploy(self.new_args("--users", " owner , мама,family-phone "))
        load.assert_not_called()
        saved = self.mocks["save_instance"].call_args.args[1]
        self.assertEqual([user["email"] for user in saved["users"]], ["owner", "мама", "family-phone"])
        self.assertEqual(self.mocks["configure_instance"].call_args.args[1]["users"], saved["users"])

    def test_inline_invalid_names_fail_before_generation_or_host_mutation(self):
        for value in ("", "owner,", "owner,OWNER", "Мама,мама", "owner,two names", "owner,bad\nname"):
            with self.subTest(value=value), \
                    mock.patch.object(cli, "new_instance", side_effect=AssertionError("validate names first")) as create, \
                    mock.patch.object(cli, "load_user_names", side_effect=AssertionError("inline names bypass files")) as load, \
                    self.assertRaises(ConfigError):
                cli.deploy(self.new_args("--users", value))
            create.assert_not_called()
            load.assert_not_called()
        for name in ("check_clean_host", "check_dns", "detect_ssh_ports", "download_artifacts",
                     "write_state", "save_instance", "install_dependencies", "configure_firewall",
                     "install_binaries", "bootstrap_panel", "configure_http", "monitoring_configure", "run"):
            self.mocks[name].assert_not_called()

    def test_missing_local_user_list_uses_public_example(self):
        self.startup_users.unlink()
        with mock.patch.object(cli, "load_user_names", wraps=cli.load_user_names) as load:
            cli.deploy(self.new_args())
        load.assert_called_once_with(self.example_users)
        saved = self.mocks["save_instance"].call_args.args[1]
        self.assertEqual([user["email"] for user in saved["users"]], ["personal"])

    def test_present_invalid_local_user_list_does_not_silently_use_example(self):
        self.startup_users.write_text("invalid local JSON")
        with mock.patch.object(cli, "load_user_names", wraps=cli.load_user_names) as load, \
                self.assertRaises(ConfigError):
            cli.deploy(self.new_args())
        load.assert_called_once_with(self.startup_users)
        self.mocks["save_instance"].assert_not_called()
        self.mocks["check_clean_host"].assert_not_called()

    def test_new_install_monitoring_default_and_explicit_mode_are_persisted(self):
        for options, expected_mode in (((), "basic"), (("--monitoring", "destinations"), "destinations")):
            with self.subTest(mode=expected_mode):
                self.actions.reset_mock()
                cli.deploy(self.new_args(*options))
                saved = self.mocks["save_instance"].call_args.args[1]
                self.assertEqual(saved["monitoring"], {
                    "mode": expected_mode, "retention_days": 7, "max_log_mb": 128})
                self.mocks["monitoring_configure"].assert_called_once_with(saved, runner=system.run)
                self.order("bootstrap_panel", "monitoring_configure", "configure_http", "configure_instance")

    def test_monitoring_restore_and_prepare_preserve_mode_without_reading_startup_users(self):
        data = monitored_manifest("destinations")
        original = copy.deepcopy(data)
        self.startup_users.write_text("this file must not be parsed during restore")
        self.deploy(data, prepare=True)
        self.mocks["monitoring_configure"].assert_called_once_with(data, runner=system.run)
        self.mocks["configure_instance"].assert_not_called()
        self.assertEqual(self.mocks["save_instance"].call_args.args[1], original)
        self.assertEqual(data, original)

    def test_legacy_restore_does_not_create_monitoring_files_or_services(self):
        self.deploy(manifest("hysteria2", 1))
        self.mocks["monitoring_configure"].assert_not_called()
        saved = self.mocks["save_instance"].call_args.args[1]
        self.assertNotIn("monitoring", saved)

    def test_new_install_reads_default_family_list_once_and_saves_each_name(self):
        names = ["dad", "mom", "child-one"]
        self.startup_users.write_text(json.dumps(names))
        with mock.patch.object(cli, "load_user_names", wraps=cli.load_user_names) as load:
            cli.deploy(self.new_args())
        load.assert_called_once_with(self.startup_users)
        saved = self.mocks["save_instance"].call_args.args[1]
        self.assertEqual([user["email"] for user in saved["users"]], names)
        configured = self.mocks["configure_instance"].call_args.args[1]
        self.assertEqual(configured["users"], saved["users"])

    def test_explicit_family_file_overrides_default_file_without_reading_it(self):
        self.startup_users.write_text("malformed default must not be read")
        custom = self.root / "custom-users.json"
        custom.write_text(json.dumps(["grandparent", "guest"]))
        with mock.patch.object(cli, "load_user_names", wraps=cli.load_user_names) as load:
            cli.deploy(self.new_args("--users-file", str(custom)))
        load.assert_called_once_with(custom)
        saved = self.mocks["save_instance"].call_args.args[1]
        self.assertEqual([user["email"] for user in saved["users"]], ["grandparent", "guest"])

    def test_invalid_startup_list_is_refused_before_host_checks_or_mutations(self):
        self.startup_users.write_text(json.dumps(["Dad", "dad"]))
        for options in ((), ("--users-file", str(self.startup_users))):
            with self.subTest(options=options), \
                    mock.patch.object(cli, "new_instance") as create, \
                    self.assertRaises(ConfigError):
                cli.deploy(self.new_args(*options))
            create.assert_not_called()
        for name in ("check_clean_host", "check_dns", "detect_ssh_ports", "download_artifacts",
                     "write_state", "save_instance", "install_dependencies", "configure_firewall",
                     "install_binaries", "bootstrap_panel", "configure_http", "run"):
            self.mocks[name].assert_not_called()
        self.assertFalse((self.root / "state").exists())

    def test_completed_rerun_never_reads_changed_or_missing_startup_list(self):
        saved = manifest("hysteria2", 2)
        live = copy.deepcopy(saved)
        live["users"][0]["enable"] = False
        self.startup_users.write_text(json.dumps(["replacement-family"]))
        self.mocks["read_state"].return_value = {"phase": "complete"}
        self.mocks["load_instance"].return_value = saved
        self.mocks["export_live"].side_effect = None
        self.mocks["export_live"].return_value = live
        for options in ((), ("--users-file", str(self.root / "missing.json")),
                        ("--users", "replacement,REPLACEMENT"),
                        ("--subscription-ids", "names", "--subscription-path", "changed//invalid", "--panel-path", "new-control")):
            with self.subTest(options=options), \
                    mock.patch.object(cli, "load_user_names", side_effect=AssertionError("must not read startup users")) as load, \
                    mock.patch.object(cli, "parse_user_names", side_effect=AssertionError("must not parse replacement users")) as parse, \
                    mock.patch.object(cli, "new_instance", side_effect=AssertionError("must not recreate users")) as create:
                cli.deploy(self.new_args(*options))
            load.assert_not_called()
            parse.assert_not_called()
            create.assert_not_called()
        self.mocks["show_result"].assert_called_with(live)
        self.mocks["configure_instance"].assert_not_called()
        self.mocks["install_binaries"].assert_not_called()
        self.mocks["save_instance"].assert_not_called()

    def test_prepared_resume_never_replaces_saved_users_from_startup_list(self):
        saved = manifest("hysteria2", 2)
        saved["users"][0]["enable"] = False
        self.mocks["read_state"].return_value = {"phase": "prepared", "ssh_ports": [2222]}
        self.mocks["load_instance"].return_value = saved
        self.startup_users.write_text(json.dumps(["replacement-family"]))
        for options in ((), ("--users-file", str(self.root / "missing.json")),
                        ("--users", "replacement,REPLACEMENT"),
                        ("--subscription-ids", "names", "--subscription-path", "changed//invalid", "--panel-path", "new-control")):
            self.mocks["read_state"].return_value = {"phase": "prepared", "ssh_ports": [2222]}
            with self.subTest(options=options), \
                    mock.patch.object(cli, "load_user_names", side_effect=AssertionError("must not read startup users")) as load, \
                    mock.patch.object(cli, "parse_user_names", side_effect=AssertionError("must not parse replacement users")) as parse, \
                    mock.patch.object(cli, "new_instance", side_effect=AssertionError("must not recreate users")) as create:
                cli.deploy(self.new_args(*options))
            load.assert_not_called()
            parse.assert_not_called()
            create.assert_not_called()
            self.assertEqual(self.mocks["configure_instance"].call_args.args[1]["users"], saved["users"])
        self.mocks["save_instance"].assert_not_called()

    def test_portable_restore_ignores_startup_list_even_when_explicitly_passed(self):
        self.startup_users.write_text(json.dumps(["replacement-family"]))
        for profile, version in (("reality", 1), ("reality", 2), ("hysteria2", 2)):
            supplied = manifest(profile, version)
            supplied["users"][0]["enable"] = False
            before = copy.deepcopy(supplied)
            for options in (("--users-file", str(self.root / "missing.json")),
                            ("--users", "replacement,REPLACEMENT"),
                            ("--subscription-ids", "names", "--subscription-path", "changed//invalid", "--panel-path", "new-control")):
                args = cli.parser().parse_args(["--config", "/unused.json", *options])
                with self.subTest(profile=profile, version=version, options=options), \
                        mock.patch.object(cli, "load_user_names", side_effect=AssertionError("restore must not read startup users")) as load, \
                        mock.patch.object(cli, "parse_user_names", side_effect=AssertionError("restore must not parse replacement users")) as parse, \
                        mock.patch.object(cli, "new_instance", side_effect=AssertionError("restore must not generate identities")) as create:
                    cli.deploy(args, supplied)
                load.assert_not_called()
                parse.assert_not_called()
                create.assert_not_called()
                self.assertEqual(self.mocks["save_instance"].call_args.args[1], before)
                self.assertEqual(self.mocks["configure_instance"].call_args.args[1], before)
                self.assertEqual(supplied, before)

    def test_new_install_chooses_random_template_without_prompt_even_in_terminal(self):
        for option in ([], ['--site-template', 'random']):
            args = cli.parser().parse_args([
                '--profile', 'reality', '--domain', 'panel.example.com',
                '--site-domain', 'site.example.com', '--email', 'owner@example.com', *option])
            with self.subTest(option=option), \
                    mock.patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                    mock.patch('builtins.input', side_effect=AssertionError('unexpected prompt')), \
                    mock.patch('vpn_installer.config.secrets.choice', return_value='reading-room') as choice:
                cli.deploy(args)
            choice.assert_called_once_with(cli.SITE_TEMPLATES)
            saved = self.mocks['save_instance'].call_args.args[1]
            self.assertEqual(saved['site']['template'], 'reading-room')
            self.assertEqual(self.mocks['install_static_site'].call_args.args[0]['site'], saved['site'])

    def test_v2_checks_both_dns_then_installs_site_before_local_tls_probe(self):
        data = manifest("reality", 2)
        original = copy.deepcopy(data)
        self.deploy(data)
        self.assertEqual(self.mocks["check_dns"].call_args_list,
                         [mock.call("vpn.example.com"), mock.call("journal.example.org")])
        self.order("check_clean_host", "check_dns", "download_artifacts", "install_dependencies",
                   "configure_http", "issue_certificate", "install_static_site", "configure_https",
                   "check_reality_target", "connected_panel", "configure_instance", "verify_services")
        self.mocks["check_reality_target"].assert_called_once_with(data)
        self.mocks["install_static_site"].assert_called_once_with(data)
        self.mocks["configure_https"].assert_called_once_with(data, runner=system.run)
        self.assertEqual(data, original)
        self.assertEqual(self.mocks["write_state"].call_args.args[0]["phase"], "complete")

    def test_wrong_site_dns_stops_before_download_or_any_installation_write(self):
        self.mocks["check_dns"].side_effect = [None, system.InstallError("foreign site DNS")]
        with self.assertRaises(system.InstallError):
            self.deploy(manifest("reality", 2))
        for name in ("download_artifacts", "write_state", "save_instance", "install_dependencies",
                     "configure_firewall", "configure_http", "issue_certificate"):
            self.mocks[name].assert_not_called()
        self.assertFalse((self.root / "state").exists())

    def test_v2_prepare_needs_neither_dns_nor_local_target_and_stops_before_tls(self):
        self.deploy(manifest("reality", 2), prepare=True)
        for name in ("check_dns", "check_reality_target", "issue_certificate", "install_static_site",
                     "configure_https", "connected_panel", "configure_instance"):
            self.mocks[name].assert_not_called()
        self.mocks["configure_http"].assert_called_once()
        self.assertEqual(self.mocks["write_state"].call_args.args[0]["phase"], "prepared")

    def test_failed_local_tls_probe_cannot_start_or_configure_panel(self):
        self.mocks["check_reality_target"].side_effect = system.InstallError("local TLS failed")
        with self.assertRaises(system.InstallError):
            self.deploy(manifest("reality", 2))
        self.mocks["configure_https"].assert_called_once()
        self.mocks["configure_instance"].assert_not_called()
        self.mocks["connected_panel"].assert_not_called()
        self.mocks["run"].assert_not_called()
        self.assertEqual(self.mocks["write_state"].call_args.args[0]["phase"], "prepared")

    def test_legacy_restore_preserves_8443_and_checks_external_target_before_install(self):
        data = manifest("reality", 1)
        original = copy.deepcopy(data)
        self.deploy(data)
        self.mocks["check_dns"].assert_called_once_with("vpn.example.com")
        self.order("check_dns", "check_reality_target", "download_artifacts", "configure_http", "configure_https")
        self.mocks["install_static_site"].assert_not_called()
        self.assertEqual(self.mocks["configure_https"].call_args.args[0]["https_port"], 8443)
        self.assertEqual(self.mocks["configure_instance"].call_args.args[1], original)
        self.assertEqual(data, original)

    def test_hysteria_uses_only_management_domain_without_site(self):
        data = manifest("hysteria2", 2)
        self.deploy(data)
        self.mocks["check_dns"].assert_called_once_with(data["domain"])
        self.mocks["install_static_site"].assert_not_called()
        self.assertEqual(self.mocks["configure_https"].call_args.args[0]["https_port"], 443)

    def test_prepared_resume_reuses_saved_site_and_preserves_prior_ssh_port(self):
        data = manifest("reality", 2)
        data["site"]["template"] = "reading-room"
        self.mocks["read_state"].return_value = {
            "owner": "vpn-installer", "schema": 1, "phase": "prepared", "ssh_ports": [2222]}
        self.mocks["load_instance"].return_value = data
        args = cli.parser().parse_args(["--profile", "reality"])
        with mock.patch.object(cli, "new_instance", side_effect=AssertionError("resume must not generate identities")):
            cli.deploy(args)
        self.mocks["check_clean_host"].assert_not_called()
        self.mocks["configure_firewall"].assert_called_once_with(data, [22, 2222], runner=system.run)
        self.mocks["install_static_site"].assert_called_once_with(data)
        self.order("configure_https", "check_reality_target", "configure_instance")

    def test_managed_deployment_rejects_site_domain_schema_or_public_port_changes(self):
        original = manifest("reality", 2)
        self.mocks["read_state"].return_value = {"phase": "complete"}
        self.mocks["load_instance"].return_value = original
        for field in ("site", "schema_version", "https_port"):
            data = copy.deepcopy(original)
            if field == "site":
                data["site"]["domain"] = "changed.example.com"
            elif field == "schema_version":
                data[field] = 1
            else:
                data[field] = 8443
            with self.subTest(field=field), self.assertRaises(system.InstallError):
                self.deploy(data)
        self.mocks["export_live"].assert_not_called()
        self.mocks["run"].assert_not_called()


class FingerprintMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(mock.patch.object(cli, 'STATE_DIR', self.root))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.path = self.root / 'instance.json'
        self.saved = manifest('reality', 2)
        save_instance(self.path, self.saved)
        self.live = copy.deepcopy(self.saved)
        self.live['users'][0]['enable'] = False
        self.live['reality']['host_fingerprint'] = 'chrome'
        self.state = {'phase': 'complete'}
        self.args = cli.parser().parse_args(['--set-fingerprint', 'firefox'])
        self.calls = mock.Mock()
        self.mocks = {}
        for name in ('connected_panel', 'export_and_backup', 'apply_fingerprint', 'verify_services', 'export_instance'):
            self.mocks[name] = self.stack.enter_context(mock.patch.object(cli, name))
            self.calls.attach_mock(self.mocks[name], name)
        self.mocks['export_and_backup'].return_value = self.live
        self.mocks['export_instance'].side_effect = lambda client, expected: copy.deepcopy(expected)
        self.runner = self.stack.enter_context(mock.patch.object(system, 'run'))
        self.calls.attach_mock(self.runner, 'run')

    def test_change_uses_live_users_and_backups_before_api_update(self):
        cli.maintain(self.args, self.state)
        expected = copy.deepcopy(self.live)
        expected['reality'].update(fingerprint='firefox', host_fingerprint='firefox')
        self.assertEqual(load_instance(self.path), expected)
        self.mocks['apply_fingerprint'].assert_called_once_with(self.mocks['connected_panel'].return_value, expected)
        self.runner.assert_called_once_with(['systemctl', 'restart', 'x-ui'])
        calls = [call[0] for call in self.calls.mock_calls]
        self.assertLess(calls.index('export_and_backup'), calls.index('apply_fingerprint'))

    def test_failed_api_or_health_rolls_back_only_fingerprints(self):
        for failure in ('apply_fingerprint', 'verify_services'):
            with self.subTest(failure=failure):
                for mocked in self.mocks.values():
                    mocked.reset_mock()
                self.mocks[failure].side_effect = [RuntimeError('failure'), None]
                with self.assertRaisesRegex(RuntimeError, 'failure'):
                    cli.maintain(self.args, self.state)
                self.assertEqual(load_instance(self.path), self.live)
                self.assertEqual(self.mocks['apply_fingerprint'].call_args.args[1], self.live)
                self.mocks[failure].side_effect = None

    def test_failed_rollback_reports_backup_location(self):
        self.mocks['apply_fingerprint'].side_effect = RuntimeError('unreachable')
        with self.assertRaisesRegex(system.InstallError, 'откат не подтверждён'):
            cli.maintain(self.args, self.state)
        self.assertEqual(load_instance(self.path), self.saved)

    def test_failed_backup_or_wrong_profile_never_changes_panel(self):
        self.mocks['export_and_backup'].side_effect = RuntimeError('backup failed')
        with self.assertRaisesRegex(RuntimeError, 'backup failed'):
            cli.maintain(self.args, self.state)
        self.mocks['apply_fingerprint'].assert_not_called()
        save_instance(self.path, manifest('hysteria2', 2))
        self.mocks['export_and_backup'].reset_mock()
        with self.assertRaisesRegex(system.InstallError, 'только для REALITY'):
            cli.maintain(self.args, self.state)
        self.mocks['export_and_backup'].assert_not_called()
        self.runner.assert_not_called()


class MonitoringMaintenanceTests(unittest.TestCase):
    """Mode changes own only monitoring; the panel remains the user source."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "instance.json"
        self.saved = monitored_manifest()
        save_instance(self.path, self.saved)
        self.live = copy.deepcopy(self.saved)
        self.live["users"][0]["enable"] = False
        self.live["users"].append(dict(self.live["users"][0], email="new-family-member",
                                       sub_id="new-family-token-456", password="NewFamilyPassword123!"))
        self.state = {"owner": "vpn-installer", "schema": 1, "phase": "complete"}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(cli, "STATE_DIR", self.root))
        self.output = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        self.calls = mock.Mock()
        self.client = mock.Mock()
        self.previous_template = {"log": {"access": "none"}, "routing": {"rules": [{"tag": "preserve"}]}}
        self.client.get_xray_settings.return_value = copy.deepcopy(self.previous_template)
        self.mocks = {}
        for name in ("connected_panel", "export_and_backup", "apply_monitoring", "validate_monitoring",
                     "verify_services", "configure_instance", "new_instance"):
            replacement = self.stack.enter_context(mock.patch.object(cli, name))
            self.calls.attach_mock(replacement, name)
            self.mocks[name] = replacement
        self.mocks["connected_panel"].return_value = self.client
        self.mocks["export_and_backup"].side_effect = self.refresh_live_backup
        # verify_services performs monitoring validation after process health.
        # Keep that final check live in this orchestration test while replacing
        # the external commands and readiness loop.
        self.mocks["verify_services"].side_effect = lambda instance: cli.validate_monitoring(self.client, instance)
        self.configure = self.stack.enter_context(mock.patch.object(cli.monitoring, "configure"))
        self.calls.attach_mock(self.configure, "collector_configure")
        self.history = self.stack.enter_context(mock.patch.object(cli.monitoring, "history_lines"))
        self.runner = self.stack.enter_context(mock.patch.object(system, "run"))
        self.calls.attach_mock(self.runner, "run")
        self.runner.return_value = subprocess.CompletedProcess([], 0)
        self.save = self.stack.enter_context(mock.patch.object(cli, "save_instance", wraps=save_instance))
        self.calls.attach_mock(self.save, "save_instance")

    def refresh_live_backup(self, _instance):
        # A real backup first refreshes instance.json from the live panel.
        save_instance(self.path, self.live)
        return copy.deepcopy(self.live)

    def run_mode(self, mode="destinations"):
        cli.maintain(cli.parser().parse_args(["--set-monitoring", mode]), self.state)

    def test_success_changes_monitoring_only_after_backing_up_live_users(self):
        before = copy.deepcopy(self.live)
        self.run_mode()
        persisted = cli.load_instance(self.path)
        target = copy.deepcopy(before)
        target["monitoring"]["mode"] = "destinations"
        self.assertEqual(persisted, target)
        self.assertEqual(self.live, before)
        self.mocks["export_and_backup"].assert_called_once_with(self.saved)
        self.configure.assert_called_once_with(target, runner=system.run)
        self.mocks["apply_monitoring"].assert_called_once_with(self.client, target)
        self.mocks["verify_services"].assert_called_once_with(target)
        self.mocks["validate_monitoring"].assert_called_once_with(self.client, target)
        self.mocks["configure_instance"].assert_not_called()
        self.mocks["new_instance"].assert_not_called()
        self.client.save_xray_settings.assert_not_called()
        names = [call[0] for call in self.calls.mock_calls]
        ordered = ["export_and_backup", "collector_configure", "apply_monitoring", "run",
                   "verify_services", "validate_monitoring", "save_instance"]
        self.assertEqual([names.index(name) for name in ordered], sorted(names.index(name) for name in ordered))

    def test_failed_health_restores_template_collector_and_keeps_latest_users(self):
        self.mocks["verify_services"].side_effect = [system.InstallError("new monitoring did not start"), None]
        with self.assertRaises(system.InstallError):
            self.run_mode()
        self.assertEqual(cli.load_instance(self.path), self.live)
        self.client.save_xray_settings.assert_called_once_with(self.previous_template)
        self.assertEqual(self.configure.call_args.args[0], self.live)
        self.assertEqual(self.configure.call_count, 2)
        commands = [call.args[0] for call in self.runner.call_args_list]
        self.assertEqual(commands.count(["systemctl", "restart", "x-ui"]), 2)
        self.mocks["configure_instance"].assert_not_called()
        self.mocks["new_instance"].assert_not_called()
        self.save.assert_not_called()
        self.assertEqual(self.mocks['verify_services'].call_count, 2)
        self.assertEqual(self.mocks['verify_services'].call_args.args[0], self.live)

    def test_failed_rollback_core_start_is_reported_as_unconfirmed_recovery(self):
        self.mocks['verify_services'].side_effect = [system.InstallError('new mode failed'),
                                                    system.InstallError('old core did not start')]
        with self.assertRaisesRegex(system.InstallError, 'полный откат не подтверждён'):
            self.run_mode()
        self.assertEqual(cli.load_instance(self.path), self.live)
        self.save.assert_not_called()
        self.client.save_xray_settings.assert_called_once_with(self.previous_template)

    def test_failed_live_validation_cannot_persist_new_mode(self):
        self.mocks["validate_monitoring"].side_effect = [RuntimeError("mode disagrees with the core"), None]
        with self.assertRaises(RuntimeError):
            self.run_mode()
        self.assertEqual(cli.load_instance(self.path), self.live)
        self.client.save_xray_settings.assert_called_once_with(self.previous_template)
        self.assertEqual(self.configure.call_args.args[0], self.live)
        self.save.assert_not_called()

    def test_legacy_instance_is_rejected_before_backup_or_host_mutation(self):
        old = manifest()
        save_instance(self.path, old)
        before = self.path.read_bytes()
        with self.assertRaises(system.InstallError):
            self.run_mode()
        self.assertEqual(self.path.read_bytes(), before)
        for name in ("export_and_backup", "connected_panel", "apply_monitoring", "configure_instance"):
            self.mocks[name].assert_not_called()
        self.configure.assert_not_called()
        self.runner.assert_not_called()
        self.save.assert_not_called()

    def test_incomplete_install_cannot_change_monitoring(self):
        self.state["phase"] = "prepared"
        with self.assertRaises(system.InstallError):
            self.run_mode()
        self.mocks["export_and_backup"].assert_not_called()
        self.configure.assert_not_called()
        self.runner.assert_not_called()

    def test_archive_view_is_bounded_and_does_not_contact_panel_or_write(self):
        self.history.return_value = iter(["old entry", "middle entry", "latest entry"])
        args = cli.parser().parse_args(["--show-logs", "--log-user", "alice@example.com", "--log-lines", "2"])
        before = self.path.read_bytes()
        cli.maintain(args, self.state)
        self.assertNotIn("old entry", self.output.getvalue())
        self.assertIn("middle entry", self.output.getvalue())
        self.assertIn("latest entry", self.output.getvalue())
        self.history.assert_called_once_with(self.saved["monitoring"], user="alice@example.com")
        self.assertEqual(self.path.read_bytes(), before)
        for name in ("connected_panel", "export_and_backup", "apply_monitoring", "configure_instance", "verify_services"):
            self.mocks[name].assert_not_called()
        self.configure.assert_not_called()
        self.runner.assert_not_called()
        self.save.assert_not_called()

    def test_export_saves_latest_monitoring_and_users_in_both_portable_files(self):
        destination = self.root / "portable-export.json"
        with mock.patch.object(cli, "export_instance", return_value=self.live) as export:
            cli.maintain(cli.parser().parse_args(["--export-config", str(destination)]), self.state)
        export.assert_called_once_with(self.client, self.saved)
        self.assertEqual(cli.load_instance(destination), self.live)
        self.assertEqual(cli.load_instance(self.path), self.live)
        self.assertEqual(cli.load_instance(destination)["monitoring"], self.saved["monitoring"])
        self.configure.assert_not_called()
        self.runner.assert_not_called()
        self.mocks["apply_monitoring"].assert_not_called()


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
