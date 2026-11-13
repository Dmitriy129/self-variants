"""Exercise filesystem/network trust boundaries without touching host services."""

import contextlib
import errno
import hashlib
import io
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

from vpn_installer import system


def instance(profile="reality", version=1):
    data = {"profile": profile, "https_port": 8443, "schema_version": version}
    if profile == "reality":
        data["reality"] = {"target": "www.example.org:443", "server_name": "www.example.org"}
    if version == 2:
        data["https_port"] = 443
        if profile == "reality":
            data["site"] = {"domain": "journal.example.org", "template": "field-notes"}
            data["reality"].update(target="127.0.0.1:9443", server_name="journal.example.org")
    return data


def versions(payload=b"verified archive"):
    digest = hashlib.sha256(payload).hexdigest()
    return {
        "3x-ui": {"version": "3.11.0", "url": "https://github.com/MHSanaei/3x-ui/releases/download/v3.11.0/panel.tar.gz", "sha256": digest},
        "xray": {"version": "26.11.9", "url": "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/core.zip", "sha256": digest},
    }


class HostChecks(unittest.TestCase):
    def test_ssh_preserves_config_session_and_actual_listener_ports(self):
        responses = iter(("port 22\n", 'LISTEN 0 128 [::]:2222 [::]:* users:(("sshd",pid=42,fd=3))\n', '[::]:2223 (Stream)\n'))
        runner = mock.Mock(side_effect=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, stdout=next(responses)))
        with mock.patch.dict("os.environ", {"SSH_CONNECTION": "203.0.113.8 40123 203.0.113.9 2200"}):
            self.assertEqual(system.detect_ssh_ports(runner), [22, 2200, 2222, 2223])

    def test_ssh_discovery_failure_never_falls_back_to_port_22(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, stdout=""))
        with mock.patch.dict("os.environ", {}, clear=True), self.assertRaises(system.InstallError):
            system.detect_ssh_ports(runner)

    def test_clean_host_refuses_existing_install_firewall_or_nginx(self):
        cases = (
            ({str(system.APP_DIR)}, {}),
            ({str(system.DB_DIR / "x-ui.db")}, {}),
            ({"/etc/systemd/system/x-ui.service"}, {}),
            ({"/etc/ufw/user.rules"}, {"/etc/ufw/user.rules": "-A ufw-user-input -p tcp --dport 1234 -j ACCEPT\n"}),
            ({"/etc/ufw/user6.rules"}, {"/etc/ufw/user6.rules": "-A ufw-user-input -p tcp --dport 1234 -j ACCEPT\n"}),
            ({"/etc/nginx/conf.d"}, {}),
            ({"/etc/nginx/stream-conf.d"}, {}),
        )
        for present, contents in cases:
            with self.subTest(present=present), \
                    mock.patch.object(Path, "exists", autospec=True, side_effect=lambda path: str(path) in present), \
                    mock.patch.object(Path, "read_text", autospec=True, side_effect=lambda path: contents[str(path)]), \
                    mock.patch.object(Path, "iterdir", autospec=True, return_value=iter([Path("/etc/nginx/conf.d/customer.conf")])), \
                    mock.patch.object(system, "check_free_ports") as ports, \
                    self.assertRaises(system.InstallError):
                system.check_clean_host(instance())
            ports.assert_not_called()

    def test_clean_host_still_checks_ports(self):
        with mock.patch.object(Path, "exists", return_value=False), mock.patch.object(system, "check_free_ports") as ports:
            system.check_clean_host(instance())
        ports.assert_called_once()

    def test_clean_host_rejects_main_stream_block_or_orphaned_marker_before_ports(self):
        for content in ("events {}\nhttp {}\nstream { server { listen 4444; } }\n",
                        "events {}\nhttp {}\n# BEGIN vpn-installer stream\n"):
            with self.subTest(content=content), \
                    mock.patch.object(Path, "exists", autospec=True,
                                      side_effect=lambda path: str(path) == "/etc/nginx/nginx.conf"), \
                    mock.patch.object(Path, "read_text", return_value=content), \
                    mock.patch.object(system, "check_free_ports") as ports, \
                    self.assertRaises(system.InstallError):
                system.check_clean_host(instance("reality", 2))
            ports.assert_not_called()

    def test_clean_host_ignores_commented_or_quoted_stream_words(self):
        content = '# stream { ignored }\nevents {}\nhttp { log_format custom "stream { text"; }\n'
        with mock.patch.object(Path, "exists", autospec=True,
                               side_effect=lambda path: str(path) == "/etc/nginx/nginx.conf"), \
                mock.patch.object(Path, "read_text", return_value=content), \
                mock.patch.object(system, "check_free_ports") as ports:
            system.check_clean_host(instance("reality", 2))
        ports.assert_called_once()

    def test_port_checks_cover_ipv6_and_profile_transport(self):
        for profile, expected_kind in (("reality", socket.SOCK_STREAM), ("hysteria2", socket.SOCK_DGRAM)):
            bindings = []
            def factory(family, kind):
                probe = mock.MagicMock()
                probe.__enter__.return_value = probe
                probe.bind.side_effect = lambda address: bindings.append((family, kind, address[1]))
                return probe
            with self.subTest(profile=profile), mock.patch.object(system.socket, "socket", side_effect=factory):
                system.check_free_ports(instance(profile))
            self.assertIn((socket.AF_INET, expected_kind, 443), bindings)
            self.assertIn((socket.AF_INET6, expected_kind, 443), bindings)
            self.assertTrue({80, 2053, 2096, 8443}.issubset({port for _, kind, port in bindings if kind == socket.SOCK_STREAM}))

    def test_occupied_ipv6_port_refuses_install(self):
        def factory(family, kind):
            probe = mock.MagicMock()
            probe.__enter__.return_value = probe
            def bind(address):
                if family == socket.AF_INET6 and address[1] == 8443:
                    raise OSError(errno.EADDRINUSE, "already in use")
            probe.bind.side_effect = bind
            return probe
        with mock.patch.object(system.socket, "socket", side_effect=factory), self.assertRaisesRegex(system.InstallError, "8443"):
            system.check_free_ports(instance())

    def test_dns_refuses_one_foreign_aaaa_even_if_a_matches(self):
        dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 443)),
               (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::20", 443, 0, 0))]
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, stdout=json.dumps([{"addr_info": [{"local": "203.0.113.10"}]}])))
        with mock.patch.object(system.socket, "getaddrinfo", return_value=dns), self.assertRaises(system.InstallError):
            system.check_dns("vpn.example.com", runner)

    def test_v2_port_checks_include_each_public_and_backend_listener(self):
        for profile in ("reality", "hysteria2"):
            bindings = []
            def factory(family, kind):
                probe = mock.MagicMock()
                probe.__enter__.return_value = probe
                probe.bind.side_effect = lambda address: bindings.append((family, kind, address[1]))
                return probe
            with self.subTest(profile=profile), mock.patch.object(system.socket, "socket", side_effect=factory):
                system.check_free_ports(instance(profile, 2))
            tcp_ports = {80, 443, 2053, 2096}
            if profile == "reality":
                tcp_ports.update((7443, 9443, 10443))
            expected = {(family, socket.SOCK_STREAM, port)
                        for family in (socket.AF_INET, socket.AF_INET6) for port in tcp_ports}
            if profile == "hysteria2":
                expected.update((family, socket.SOCK_DGRAM, 443) for family in (socket.AF_INET, socket.AF_INET6))
            self.assertEqual(set(bindings), expected)
            self.assertEqual(len(bindings), len(expected))

    def test_v2_occupied_backend_refuses_install_for_either_address_family(self):
        for occupied_family in (socket.AF_INET, socket.AF_INET6):
            for occupied_port in (7443, 9443, 10443):
                def factory(family, kind):
                    probe = mock.MagicMock()
                    probe.__enter__.return_value = probe
                    def bind(address):
                        if family == occupied_family and address[1] == occupied_port:
                            raise OSError(errno.EADDRINUSE, "occupied backend")
                    probe.bind.side_effect = bind
                    return probe
                with self.subTest(family=occupied_family, port=occupied_port), \
                        mock.patch.object(system.socket, "socket", side_effect=factory), \
                        self.assertRaisesRegex(system.InstallError, str(occupied_port)):
                    system.check_free_ports(instance("reality", 2))

    def test_reality_target_probe_connects_locally_but_authenticates_site_hostname(self):
        for version, expected_address, expected_sni in (
            (1, ("www.example.org", 443), "www.example.org"),
            (2, ("127.0.0.1", 9443), "journal.example.org"),
        ):
            context = mock.MagicMock()
            connection = context.wrap_socket.return_value.__enter__.return_value
            connection.selected_alpn_protocol.return_value = "h2"
            raw_socket = mock.MagicMock()
            with self.subTest(version=version), \
                    mock.patch.object(system.ssl, "create_default_context", return_value=context), \
                    mock.patch.object(system.socket, "create_connection", return_value=raw_socket) as connect:
                system.check_reality_target(instance("reality", version))
            connect.assert_called_once_with(expected_address, timeout=12)
            context.wrap_socket.assert_called_once_with(raw_socket.__enter__.return_value, server_hostname=expected_sni)
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
            context.set_alpn_protocols.assert_called_once_with(["h2"])

    def test_local_reality_probe_rejects_untrusted_tls_or_missing_http2(self):
        for error in (None, ssl.SSLError("certificate mismatch")):
            context = mock.MagicMock()
            connection = context.wrap_socket.return_value.__enter__.return_value
            connection.selected_alpn_protocol.return_value = "http/1.1"
            context.wrap_socket.side_effect = error
            with self.subTest(error=error), \
                    mock.patch.object(system.ssl, "create_default_context", return_value=context), \
                    mock.patch.object(system.socket, "create_connection", return_value=mock.MagicMock()), \
                    self.assertRaises(system.InstallError):
                system.check_reality_target(instance("reality", 2))

    def test_hysteria_has_no_reality_probe(self):
        with mock.patch.object(system.ssl, "create_default_context") as tls, \
                mock.patch.object(system.socket, "create_connection") as connect:
            system.check_reality_target(instance("hysteria2", 2))
        tls.assert_not_called()
        connect.assert_not_called()

    def test_dependencies_include_dynamic_nginx_stream_module(self):
        runner = mock.Mock()
        system.install_dependencies(runner)
        packages = runner.call_args_list[1].args[0]
        self.assertEqual(packages[:3], ["apt-get", "install", "-y"])
        self.assertIn("nginx", packages)
        self.assertIn("libnginx-mod-stream", packages)
        self.assertIn("certbot", packages)
        self.assertEqual(runner.call_args.kwargs["env"]["DEBIAN_FRONTEND"], "noninteractive")


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_version_lock_rejects_unpinned_or_lookalike_download_hosts(self):
        path = self.root / "versions.json"
        for url in ("https://github.com.evil.test/MHSanaei/3x-ui/releases/download/v3.11.0/a", "http://github.com/MHSanaei/3x-ui/releases/download/v3.11.0/a", "https://github.com/MHSanaei/3x-ui/releases/latest/download/a"):
            data = versions()
            data["3x-ui"]["url"] = url
            path.write_text(json.dumps(data))
            with self.subTest(url=url), self.assertRaises(system.InstallError):
                system.read_versions(path)

    def test_verified_cache_does_not_need_network(self):
        cache = self.root / "cache"
        cache.mkdir()
        data = versions()
        digest = data["xray"]["sha256"]
        (cache / f"{digest}-panel.tar.gz").write_bytes(b"verified archive")
        (cache / f"{digest}-xray.zip").write_bytes(b"verified archive")
        with mock.patch.object(system.urllib.request, "urlopen", side_effect=AssertionError("cache must be used")):
            paths = system.download_artifacts(data, cache)
        self.assertEqual(set(paths), {"3x-ui", "xray"})

    def test_digest_mismatch_never_publishes_download_or_leaves_partial(self):
        response = io.BytesIO(b"corrupted archive")
        response.url = "https://release-assets.githubusercontent.com/object"
        cache = self.root / "cache"
        with mock.patch.object(system.urllib.request, "urlopen", return_value=response), self.assertRaisesRegex(system.InstallError, "Контрольная сумма"):
            system.download_artifacts(versions(), cache)
        self.assertEqual(list(cache.iterdir()), [])

    def test_https_downgrade_refused_even_if_content_would_match(self):
        response = io.BytesIO(b"verified archive")
        response.url = "http://downloads.example.com/object"
        cache = self.root / "cache"
        with mock.patch.object(system.urllib.request, "urlopen", return_value=response), self.assertRaisesRegex(system.InstallError, "HTTPS"):
            system.download_artifacts(versions(), cache)
        self.assertEqual(list(cache.iterdir()), [])

    def _archives(self, panel=True, symlink=False):
        panel_path = self.root / "panel.tar.gz"
        with tarfile.open(panel_path, "w:gz") as archive:
            for name, payload in (("../../escape", b"bad"), (str(self.root / "absolute-escape"), b"bad"),
                                  ("x-ui/bin/../../escape", b"bad"), ("x-ui/bin/geoip.dat", b"panel geo")):
                item = tarfile.TarInfo(name)
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            if panel:
                item = tarfile.TarInfo("x-ui/x-ui")
                item.size = 5
                archive.addfile(item, io.BytesIO(b"panel"))
            if symlink:
                item = tarfile.TarInfo("x-ui/x-ui")
                item.type = tarfile.SYMTYPE
                item.linkname = str(self.root / "outside")
                archive.addfile(item)
        core_path = self.root / "core.zip"
        with zipfile.ZipFile(core_path, "w") as archive:
            archive.writestr("../../zip-escape", b"bad")
            archive.writestr("xray", b"core")
            archive.writestr("geoip.dat", b"verified geo")
            archive.writestr("geosite.dat", b"verified sites")
        return {"3x-ui": panel_path, "xray": core_path}

    def test_extraction_never_follows_archive_paths_or_links(self):
        artifacts = self._archives(symlink=True)
        app = self.root / "app"
        outside = self.root / "outside"
        outside.write_bytes(b"preserve")
        system.install_binaries(artifacts, app)
        self.assertEqual(outside.read_bytes(), b"preserve")
        self.assertEqual((app / "x-ui").read_bytes(), b"panel")
        self.assertEqual((app / "bin/xray-linux-amd64").read_bytes(), b"core")
        self.assertEqual((app / "bin/geoip.dat").read_bytes(), b"verified geo")
        self.assertFalse((self.root / "escape").exists())
        self.assertFalse((self.root / "absolute-escape").exists())
        self.assertFalse((self.root / "zip-escape").exists())
        self.assertEqual(stat.S_IMODE((app / "x-ui").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((app / "bin/geoip.dat").stat().st_mode), 0o600)

    def test_symlink_instead_of_panel_binary_is_not_accepted(self):
        artifacts = self._archives(panel=False, symlink=True)
        with self.assertRaises(system.InstallError):
            system.install_binaries(artifacts, self.root / "app")

    def test_missing_new_panel_binary_cannot_silently_reuse_old_version(self):
        artifacts = self._archives(panel=False)
        app = self.root / "app"
        app.mkdir()
        (app / "x-ui").write_bytes(b"old version")
        with self.assertRaises(system.InstallError):
            system.install_binaries(artifacts, app)

    def test_backup_includes_committed_wal_users_and_private_files(self):
        state, database, output = (self.root / name for name in ("state", "database", "backups"))
        state.mkdir()
        database.mkdir()
        (state / "instance.json").write_text('{"secret":"preserve"}')
        (state / "state.json").write_text('{"phase":"complete"}')
        source = sqlite3.connect(database / "x-ui.db")
        self.addCleanup(source.close)
        source.execute("PRAGMA journal_mode=WAL")
        source.execute("CREATE TABLE users (sub_id TEXT)")
        source.execute("INSERT INTO users VALUES ('stable-link-123')")
        source.commit()
        backup = system.create_backup(state, database, output)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        with tarfile.open(backup, "r:gz") as archive:
            self.assertEqual(set(archive.getnames()), {"instance.json", "state.json", "x-ui.db"})
            self.assertEqual(archive.extractfile("instance.json").read(), b'{"secret":"preserve"}')
            restored = self.root / "restored.db"
            restored.write_bytes(archive.extractfile("x-ui.db").read())
        with contextlib.closing(sqlite3.connect(restored)) as connection:
            self.assertEqual(connection.execute("SELECT sub_id FROM users").fetchall(), [("stable-link-123",)])


if __name__ == "__main__":
    unittest.main()
