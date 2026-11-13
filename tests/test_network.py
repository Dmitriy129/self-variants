"""Boundary and command-order tests; these never change host services."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from vpn_installer import network


def instance(profile="reality"):
    return {
        "domain": "vpn.example.com", "email": "owner@example.com",
        "https_port": 8443, "profile": profile,
        "panel": {"path": "/panel_random/"},
        "subscription": {"path": "/sub/"},
    }


class Recorder:
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if kwargs != {"check": True}:
            raise AssertionError("commands must check failures and avoid shell=True")
        if argv == self.fail:
            raise subprocess.CalledProcessError(1, argv)
        return subprocess.CompletedProcess(argv, 0)


class RenderingTests(unittest.TestCase):
    def test_only_management_https_and_original_uris_are_proxied(self):
        text = network.render_nginx(instance())
        self.assertIn("listen 8443 ssl;", text)
        self.assertIn("listen [::]:8443 ssl;", text)
        self.assertNotIn("listen 443", text)
        self.assertNotIn("listen [::]:443", text)
        self.assertIn("location ^~ /panel_random/", text)
        self.assertIn("location ^~ /sub/", text)
        self.assertIn("proxy_pass http://127.0.0.1:2053;", text)
        self.assertIn("proxy_pass http://127.0.0.1:2096;", text)
        self.assertNotIn("proxy_pass http://127.0.0.1:2053/", text)
        self.assertNotIn("rewrite ", text)
        self.assertEqual(text.count("access_log off;"), 2)
        self.assertEqual(text.count("error_log /dev/null crit;"), 2)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", text)
        self.assertIn("proxy_set_header Connection $vpn_connection_upgrade;", text)
        self.assertIn("location / { return 404; }", text)

    def test_bootstrap_exposes_only_acme_not_credentials(self):
        text = network.render_nginx(instance(), tls_enabled=False)
        self.assertIn("/.well-known/acme-challenge/", text)
        self.assertIn("root /var/www/vpn-acme;", text)
        self.assertNotIn("panel_random", text)
        self.assertNotIn("/sub/", text)
        self.assertNotIn("ssl_certificate", text)
        self.assertNotIn("proxy_pass", text)

    def test_rejects_config_injection_and_overlapping_routes(self):
        mutations = [
            ("domain", "example.com; include /etc/passwd;"),
            ("domain", "../example.com"), ("domain", "127.0.0.1"),
            ("email", "hello@example.com\n--evil"),
            ("https_port", True), ("https_port", 443), ("https_port", 0),
            ("profile", "trojan"),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                config = instance()
                config[field] = value
                with self.assertRaises(ValueError):
                    network.render_nginx(config)
        for value in ("/", "/../", "/foo;bar/", "/foo\n/", "/foo%2fbar/", "/sub/child/"):
            with self.subTest(path=value):
                config = instance()
                config["panel"]["path"] = value
                with self.assertRaises(ValueError):
                    network.render_nginx(config)

    def test_renew_hook_filters_lineage_and_restarts_only_certificate_user(self):
        reality = network.render_renew_hook(instance())
        hysteria = network.render_renew_hook(instance("hysteria2"))
        self.assertIn('case "${RENEWED_LINEAGE:-}"', reality)
        self.assertIn("/etc/letsencrypt/live/vpn.example.com)", reality)
        self.assertNotIn("restart x-ui", reality)
        self.assertIn("restart x-ui", hysteria)
        self.assertLess(hysteria.index("nginx -t"), hysteria.index("reload nginx"))
        self.assertLess(hysteria.index("reload nginx"), hysteria.index("restart x-ui"))
        for script in (reality, hysteria):
            subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)


class ExecutionTests(unittest.TestCase):
    def test_challenge_paths_are_traversable_under_private_installer_umask(self):
        import os
        previous = os.umask(0o077)
        try:
            network.configure_http(instance(), self.runner, self.root)
        finally:
            os.umask(previous)
        for relative in ('var/www/vpn-acme', 'var/www/vpn-acme/.well-known',
                         'var/www/vpn-acme/.well-known/acme-challenge'):
            self.assertEqual((self.root / relative).stat().st_mode & 0o777, 0o755)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.runner = Recorder()

    def test_http_setup_validates_before_starting(self):
        path = network.configure_http(instance(), self.runner, self.root)
        self.assertEqual(path, self.root / "etc/nginx/conf.d/vpn-installer.conf")
        self.assertEqual(self.runner.calls, [
            ["nginx", "-t"], ["systemctl", "enable", "--now", "nginx"],
            ["systemctl", "reload", "nginx"],
        ])
        self.assertTrue((self.root / "var/www/vpn-acme/.well-known/acme-challenge").is_dir())

    def test_failed_nginx_validation_restores_prior_config(self):
        path = self.root / "etc/nginx/conf.d/vpn-installer.conf"
        path.parent.mkdir(parents=True)
        path.write_text("previous working configuration")
        runner = Recorder(fail=["nginx", "-t"])
        with self.assertRaises(subprocess.CalledProcessError):
            network.configure_http(instance(), runner, self.root)
        self.assertEqual(path.read_text(), "previous working configuration")
        self.assertEqual(runner.calls, [["nginx", "-t"]])

    def test_https_installs_executable_hook_before_enabling_renewal(self):
        network.configure_https(instance("hysteria2"), self.runner, self.root)
        hook = self.root / "etc/letsencrypt/renewal-hooks/deploy/vpn-installer"
        self.assertEqual(hook.stat().st_mode & 0o777, 0o750)
        self.assertIn("restart x-ui", hook.read_text())
        self.assertEqual(self.runner.calls[-1], ["systemctl", "enable", "--now", "certbot.timer"])

    def test_certificate_webroot_is_noninteractive_and_keeps_named_lineage(self):
        network.issue_certificate(instance(), self.runner, self.root)
        args = self.runner.calls[0]
        self.assertEqual(args[:3], ["certbot", "certonly", "--webroot"])
        self.assertIn("--non-interactive", args)
        self.assertIn("--agree-tos", args)
        self.assertIn("--keep-until-expiring", args)
        self.assertNotIn("--standalone", args)
        self.assertEqual(args[args.index("--cert-name") + 1], "vpn.example.com")

    def test_firewall_preserves_ssh_and_sets_ipv6_before_activation(self):
        defaults = self.root / "etc/default/ufw"
        defaults.parent.mkdir(parents=True)
        defaults.write_text("# keep this\nIPV6=no\nOTHER=value\n")
        network.configure_firewall(instance(), [2222, 22, 2222], self.runner, self.root)
        self.assertEqual(defaults.read_text(), "# keep this\nIPV6=yes\nOTHER=value\n")
        calls = self.runner.calls
        self.assertEqual(calls[:2], [["ufw", "allow", "22/tcp"], ["ufw", "allow", "2222/tcp"]])
        self.assertIn(["ufw", "allow", "80/tcp"], calls)
        self.assertIn(["ufw", "allow", "8443/tcp"], calls)
        self.assertIn(["ufw", "allow", "443/tcp"], calls)
        self.assertNotIn(["ufw", "allow", "443/udp"], calls)
        self.assertEqual(calls[-3:], [
            ["ufw", "default", "deny", "incoming"],
            ["ufw", "default", "allow", "outgoing"],
            ["ufw", "--force", "enable"],
        ])
        self.assertFalse(any("reset" in call or "delete" in call for call in calls))

    def test_hysteria_opens_udp_not_tcp_tunnel_port(self):
        network.configure_firewall(instance("hysteria2"), [22], self.runner, self.root)
        self.assertIn(["ufw", "allow", "443/udp"], self.runner.calls)
        self.assertNotIn(["ufw", "allow", "443/tcp"], self.runner.calls)

    def test_empty_or_invalid_ssh_ports_make_no_changes(self):
        for ports in ([], ["22"], [0], [True], [65536]):
            with self.subTest(ports=ports):
                with self.assertRaises(ValueError):
                    network.configure_firewall(instance(), ports, self.runner, self.root)
        self.assertEqual(self.runner.calls, [])
        self.assertFalse((self.root / "etc").exists())

    def test_test_root_cannot_accidentally_run_real_service_commands(self):
        with self.assertRaises(ValueError):
            network.configure_http(instance(), root=self.root)
        self.assertFalse((self.root / "etc").exists())

    def test_managed_symlink_is_refused(self):
        path = self.root / "etc/nginx/conf.d/vpn-installer.conf"
        path.parent.mkdir(parents=True)
        target = self.root / "unrelated.conf"
        target.write_text("keep")
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            network.configure_http(instance(), self.runner, self.root)
        self.assertEqual(target.read_text(), "keep")
        self.assertEqual(self.runner.calls, [])


if __name__ == "__main__":
    unittest.main()
