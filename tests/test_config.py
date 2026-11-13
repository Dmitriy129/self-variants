import base64
import copy
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from vpn_installer.config import (
    ConfigError, load_instance, new_instance, panel_url, save_instance,
    subscription_urls, validate_instance,
)


def manifest(profile="hysteria2"):
    data = {
        "schema_version": 1, "profile": profile, "domain": "vpn.example.com",
        "email": "owner@example.com", "https_port": 8443,
        "panel": {"path": "/Panel_Kept-Exactly/nested/", "username": "admin",
                  "password": "AdminPassword123!"},
        "subscription": {"path": "/My_Sub/nested/"},
        "users": [{"email": "alice@example.com", "sub_id": "Keep_This-Token01",
                   "enable": False, "expiry_time": 1770000000000,
                   "total_gb": 10737418240, "limit_ip": 3}],
    }
    if profile == "hysteria2":
        data["users"][0]["password"] = "UserPassword123!"
    else:
        # RFC 7748 X25519 Alice key pair, used only as public test data.
        encode = lambda value: base64.urlsafe_b64encode(bytes.fromhex(value)).decode().rstrip("=")
        data["reality"] = {
            "target": "www.example.org:443", "server_name": "www.example.org",
            "private_key": encode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            "public_key": encode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            "short_id": "aabbccddeeff0011",
        }
        data["users"][0]["uuid"] = "f26544bf-882a-4cc0-a336-927bc2e938b5"
    return data


class ManifestTests(unittest.TestCase):
    def test_panel_user_name_is_not_required_to_be_a_mailbox(self):
        data = manifest()
        data['users'][0]['email'] = 'phone-android-01'
        self.assertEqual(validate_instance(data), data)

    def test_revoking_all_users_survives_export_restore(self):
        data = manifest()
        data['users'] = []
        self.assertEqual(validate_instance(data), data)
        self.assertEqual(subscription_urls(data), {})

    def test_domain_rejected_before_network_renderer_would_reject_it(self):
        for domain in ('VPN.example.com', 'vpn.123abc'):
            data = manifest()
            data['domain'] = domain
            with self.assertRaises(ConfigError):
                validate_instance(data)

    def test_restore_preserves_exact_urls_credentials_and_limits(self):
        original = manifest()
        second = copy.deepcopy(original["users"][0])
        second.update(email="bob@example.com", sub_id="Another_Token02", password="SecondPassword123!")
        original["users"].append(second)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instance.json"
            with mock.patch("vpn_installer.config.secrets.token_urlsafe", side_effect=AssertionError("restore must not generate")):
                save_instance(path, original)
                restored = load_instance(path)
                self.assertEqual(restored, original)
                self.assertEqual(subscription_urls(restored), {
                    "alice@example.com": "https://vpn.example.com:8443/My_Sub/nested/Keep_This-Token01",
                    "bob@example.com": "https://vpn.example.com:8443/My_Sub/nested/Another_Token02",
                })
                self.assertEqual(panel_url(restored), "https://vpn.example.com:8443/Panel_Kept-Exactly/nested/")

    def test_validation_returns_detached_copy(self):
        original = manifest()
        validated = validate_instance(original)
        validated["users"][0]["sub_id"] = "changed123"
        self.assertEqual(original["users"][0]["sub_id"], "Keep_This-Token01")

    def test_save_has_private_permissions_even_when_replacing_public_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instance.json"
            path.write_text("old")
            path.chmod(0o644)
            save_instance(path, manifest())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_invalid_save_leaves_existing_file_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instance.json"
            path.write_text("preserve me")
            invalid = manifest()
            del invalid["subscription"]
            with self.assertRaises(ConfigError):
                save_instance(path, invalid)
            self.assertEqual(path.read_text(), "preserve me")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_save_size_limit_leaves_existing_file_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instance.json"
            path.write_text("preserve me")
            with mock.patch("vpn_installer.config._MAX_MANIFEST_BYTES", 32):
                with self.assertRaisesRegex(ConfigError, "size limit"):
                    save_instance(path, manifest())
            self.assertEqual(path.read_text(), "preserve me")

    def test_failed_replace_leaves_existing_file_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instance.json"
            path.write_text("preserve me")
            with mock.patch("vpn_installer.config.os.replace", side_effect=OSError("failed")):
                with self.assertRaises(OSError):
                    save_instance(path, manifest())
            self.assertEqual(path.read_text(), "preserve me")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_missing_or_unknown_fields_rejected(self):
        for location, name in (((), "email"), (("panel",), "username"), (("subscription",), "path"), (("users", 0), "sub_id")):
            for operation in ("missing", "extra"):
                data = manifest()
                current = data
                for key in location:
                    current = current[key]
                if operation == "missing":
                    del current[name]
                else:
                    current["unsupported"] = 1
                with self.subTest(location=location, operation=operation), self.assertRaises(ConfigError):
                    validate_instance(data)

    def test_malformed_values_refused_without_normalization(self):
        changes = [
            ("schema_version", True), ("schema_version", 2), ("https_port", True),
            ("https_port", 443), ("profile", "unknown"), ("domain", "example.com/path"),
            ("domain", "https://example.com"), ("domain", "127.0.0.1"),
            ("domain", "example.com."), ("domain", "*.example.com"),
            ("email", "owner\n@example.com"), ("email", "owner@example.com;command"),
        ]
        for field, value in changes:
            data = manifest()
            data[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ConfigError):
                validate_instance(data)
        for value in ("/", "missing/", "/missing", "/a//b/", "/../", "/a%2fb/", "/a?b/", "/a#b/", "/a\\b/", "/a b/", "/а/"):
            data = manifest()
            data["panel"]["path"] = value
            with self.subTest(path=value), self.assertRaises(ConfigError):
                validate_instance(data)

    def test_overlapping_paths_rejected(self):
        for path in ("/My_Sub/nested/", "/My_Sub/", "/My_Sub/nested/more/"):
            data = manifest()
            data["panel"]["path"] = path
            with self.subTest(path=path), self.assertRaises(ConfigError):
                validate_instance(data)

    def test_bad_user_values_rejected(self):
        for field, values in {
            "sub_id": ("short", "token with spaces", "../bad-token", "token%2Fbad"),
            "enable": (0, 1, "true"),
            "expiry_time": (True, -1, 1.0, "123", 2**63),
            "total_gb": (False, -1, 1.5, "10", 2**63),
            "limit_ip": (True, -1, 1.0),
            "password": ("short", "Password123\n", "Password 123456"),
        }.items():
            for value in values:
                data = manifest()
                data["users"][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ConfigError):
                    validate_instance(data)

    def test_duplicate_users_refused(self):
        for field in ("email", "sub_id", "password"):
            data = manifest()
            second = copy.deepcopy(data["users"][0])
            second.update(email="bob@example.com", sub_id="DifferentToken02", password="DifferentPass123!")
            second[field] = data["users"][0][field]
            data["users"].append(second)
            with self.subTest(field=field), self.assertRaises(ConfigError):
                validate_instance(data)

    def test_profile_specific_fields_are_strict(self):
        data = manifest()
        data["reality"] = {}
        with self.assertRaises(ConfigError):
            validate_instance(data)
        data = manifest()
        data["users"][0]["uuid"] = "f26544bf-882a-4cc0-a336-927bc2e938b5"
        with self.assertRaises(ConfigError):
            validate_instance(data)
        with self.assertRaises(ConfigError):
            new_instance("hysteria2", "vpn.example.com", "owner@example.com", reality_target="www.example.org:443")

    def test_json_duplicate_keys_and_invalid_json_rejected(self):
        cases = ('{"schema_version":1,"schema_version":1}', '{"broken":', '\ufeffbad', '[1,2]')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instance.json"
            for raw in cases:
                path.write_text(raw)
                with self.subTest(raw=raw), self.assertRaises(ConfigError):
                    load_instance(path)
            path.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaises(ConfigError):
                load_instance(path)

    def test_new_hysteria_credentials_are_independent(self):
        first = new_instance("hysteria2", "vpn.example.com", "owner@example.com")
        second = new_instance("hysteria2", "vpn.example.com", "owner@example.com", admin_password="ExplicitAdmin123!")
        self.assertEqual(second["panel"]["password"], "ExplicitAdmin123!")
        self.assertEqual(first["subscription"]["path"], "/sub/")
        self.assertNotEqual(first["panel"]["path"], second["panel"]["path"])
        self.assertNotEqual(first["users"][0]["sub_id"], second["users"][0]["sub_id"])
        self.assertNotEqual(first["users"][0]["password"], second["users"][0]["password"])

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for REALITY")
    def test_reality_known_key_pair_restores_exactly(self):
        original = manifest("reality")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "instance.json"
            save_instance(path, original)
            self.assertEqual(load_instance(path), original)
            self.assertEqual(subscription_urls(load_instance(path)), subscription_urls(original))

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for REALITY")
    def test_new_reality_has_matching_keys_and_explicit_target(self):
        data = new_instance("reality", "vpn.example.com", "owner@example.com", reality_target="www.example.org:8443")
        self.assertEqual(data["reality"]["target"], "www.example.org:8443")
        self.assertEqual(data["reality"]["server_name"], "www.example.org")
        self.assertEqual(validate_instance(data), data)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for REALITY")
    def test_invalid_reality_keys_and_mismatch_are_rejected(self):
        for field, value in (("private_key", "invalid"), ("public_key", "A" * 43),
                             ("short_id", "abc"), ("short_id", "AA"),
                             ("target", "www.example.org:0"), ("target", "www.example.org:65536")):
            data = manifest("reality")
            data["reality"][field] = value
            with self.subTest(field=field), self.assertRaises(ConfigError):
                validate_instance(data)
        data = manifest("reality")
        data["reality"]["public_key"] = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
        with self.assertRaisesRegex(ConfigError, "does not match"):
            validate_instance(data)

    def test_openssl_failure_does_not_disclose_secrets(self):
        data = manifest("reality")
        with mock.patch("vpn_installer.config.shutil.which", return_value=None):
            with self.assertRaises(ConfigError) as raised:
                validate_instance(data)
        self.assertNotIn(data["reality"]["private_key"], str(raised.exception))


if __name__ == "__main__":
    unittest.main()
