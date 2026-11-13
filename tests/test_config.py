import base64
import copy
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from vpn_installer.config import (
    ConfigError, load_instance, load_user_names, new_instance, panel_url, parse_user_names, save_instance,
    public_origin, normalize_path, subscription_urls, validate_instance, vpn_domain, SITE_TEMPLATES,
)


def manifest(profile="hysteria2", version=1):
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
    if version == 2:
        data.update(schema_version=2, https_port=443)
        if profile == "reality":
            data["site"] = {"domain": "journal.example.org", "template": "field-notes"}
            data["reality"].update(target="127.0.0.1:9443", server_name="journal.example.org")
    return data


class ManifestTests(unittest.TestCase):
    def test_explicit_paths_wrap_only_outer_slashes_without_normalizing_content(self):
        for raw, expected in (("app", "/app/"), ("/app", "/app/"), ("app/", "/app/"),
                              ("/app/", "/app/"), ("family/app", "/family/app/"),
                              ("/Admin_One/app-two/", "/Admin_One/app-two/")):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_path(raw, "subscription_path"), expected)
        self.assertEqual(normalize_path("a" * 254, "panel_path"), "/" + "a" * 254 + "/")
        for raw in (None, True, 123, [], "", "/", " app", "app ", "//app", "app//child",
                    ".", "..", "../app", "app/../", "app\n", "приложение", "app%2fchild", "a" * 255):
            with self.subTest(invalid_type=type(raw).__name__, raw=raw), self.assertRaises(ConfigError):
                normalize_path(raw, "subscription_path")

    def test_names_mode_recreates_exact_public_urls_with_fresh_credentials_for_both_profiles(self):
        expected = {name: f"https://panel.example.com/app/{name}" for name in ("fix", "ee", "fix-vps")}
        for profile in ("reality", "hysteria2"):
            options = {"site_domain": "site.example.com", "site_template": "field-notes"} if profile == "reality" else {}
            with self.subTest(profile=profile):
                kwargs = dict(user_names=["fix", "ee", "fix-vps"], subscription_ids="names",
                              subscription_path="app", panel_path="control", **options)
                first = new_instance(profile, "panel.example.com", "owner@example.com", **kwargs)
                second = new_instance(profile, "panel.example.com", "owner@example.com", **kwargs)
                self.assertEqual(subscription_urls(first), expected)
                self.assertEqual(subscription_urls(second), expected)
                self.assertEqual(panel_url(first), "https://panel.example.com/control/")
                self.assertEqual(first["subscription"], {"path": "/app/", "id_mode": "names"})
                credential = "uuid" if profile == "reality" else "password"
                for old, new in zip(first["users"], second["users"]):
                    self.assertEqual(old["sub_id"], old["email"])
                    self.assertEqual(old["sub_id"], new["sub_id"])
                    self.assertNotEqual(old[credential], new[credential])
                self.assertNotEqual(first["panel"]["password"], second["panel"]["password"])
                if profile == "reality":
                    for key in ("private_key", "public_key", "short_id"):
                        self.assertNotEqual(first["reality"][key], second["reality"][key])

    def test_names_mode_reordering_and_additions_preserve_existing_urls(self):
        options = dict(subscription_ids="names", subscription_path="family/app", panel_path="control")
        first = new_instance("hysteria2", "panel.example.com", "owner@example.com",
                             user_names=["fix", "ee"], **options)
        second = new_instance("hysteria2", "panel.example.com", "owner@example.com",
                              user_names=["fix-vps", "ee", "fix"], **options)
        urls = subscription_urls(second)
        self.assertEqual({name: urls[name] for name in ("fix", "ee")}, subscription_urls(first))
        self.assertEqual(urls["fix-vps"], "https://panel.example.com/family/app/fix-vps")

    def test_invalid_names_mode_or_paths_precede_all_identity_generation(self):
        variants = [dict(subscription_ids=value) for value in ("other", "", None, True)]
        for field in ("subscription_path", "panel_path"):
            variants.extend({field: value} for value in ("", "bad path", "a//b", "../a", "a" * 255))
        variants.extend((dict(panel_path="app"), dict(panel_path="app/child"),
                         dict(panel_path="control", subscription_path="control/child"),
                         dict(subscription_path="assets"), dict(subscription_path="/assets/private/")))
        variants.extend(dict(user_names=["fix", value]) for value in
                        ("мама", "mail@example.com", "a/b", "a.b", "a" * 129))
        with ExitStack() as stack:
            for target in ("secrets.token_urlsafe", "secrets.token_hex", "secrets.choice", "uuid.uuid4", "_openssl"):
                stack.enter_context(mock.patch("vpn_installer.config." + target,
                                               side_effect=AssertionError("invalid names/path must not generate identities")))
            for profile in ("reality", "hysteria2"):
                for variant in variants:
                    options = dict(subscription_ids="names", subscription_path="app", panel_path="control",
                                   user_names=["fix", "ee"])
                    options.update(variant)
                    if profile == "reality":
                        options["site_domain"] = "site.example.com"
                    with self.subTest(profile=profile, variant=variant), self.assertRaises(ConfigError):
                        new_instance(profile, "panel.example.com", "owner@example.com", **options)

    def test_names_marker_allows_short_ids_but_legacy_random_validation_stays_strict(self):
        legacy = manifest("hysteria2", 2)
        legacy["users"][0]["sub_id"] = "x"
        with self.assertRaises(ConfigError):
            validate_instance(legacy)
        named = copy.deepcopy(legacy)
        named["subscription"]["id_mode"] = "names"
        self.assertEqual(validate_instance(named), named)
        for mode in ("random", "other", "", None, True):
            invalid = copy.deepcopy(named)
            invalid["subscription"]["id_mode"] = mode
            with self.subTest(mode=mode), self.assertRaises(ConfigError):
                validate_instance(invalid)
        invalid = copy.deepcopy(named)
        invalid["subscription"]["unexpected"] = "names"
        with self.assertRaises(ConfigError):
            validate_instance(invalid)
        for token in ("", "мама", "a/b", "a.b", "two names", "x" * 129):
            invalid = copy.deepcopy(named)
            invalid["users"][0]["sub_id"] = token
            with self.subTest(token=token), self.assertRaises(ConfigError):
                validate_instance(invalid)
        named["users"][0]["sub_id"] = "x" * 128
        self.assertEqual(validate_instance(named), named)
        named['subscription']['path'] = '/assets/private/'
        with self.assertRaises(ConfigError):
            validate_instance(named)

    def test_names_manifest_roundtrip_preserves_urls_even_after_user_rename(self):
        original = new_instance("hysteria2", "panel.example.com", "owner@example.com",
                                user_names=["fix", "ee"], subscription_ids="names",
                                subscription_path="app", panel_path="control")
        original["users"][0]["email"] = "renamed@example.com"
        original["users"][1]["enable"] = False
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "portable.json"
            with mock.patch("vpn_installer.config.secrets.token_urlsafe", side_effect=AssertionError("restore must not generate IDs")):
                save_instance(path, original)
                restored = load_instance(path)
                self.assertEqual(restored, original)
                self.assertEqual(subscription_urls(restored), {
                    "renamed@example.com": "https://panel.example.com/app/fix",
                    "ee": "https://panel.example.com/app/ee",
                })

    def test_random_mode_keeps_legacy_defaults_and_names_mode_has_safe_personal_default(self):
        first = new_instance("hysteria2", "panel.example.com", "owner@example.com")
        second = new_instance("hysteria2", "panel.example.com", "owner@example.com", subscription_ids="random")
        self.assertEqual(first["subscription"], {"path": "/sub/"})
        self.assertEqual(second["subscription"], {"path": "/sub/"})
        self.assertEqual(first["users"][0]["email"], "personal@panel.example.com")
        self.assertNotEqual(first["users"][0]["sub_id"], second["users"][0]["sub_id"])
        self.assertNotEqual(first["panel"]["path"], second["panel"]["path"])
        named = new_instance("hysteria2", "panel.example.com", "owner@example.com", subscription_ids="names")
        self.assertEqual(named["users"][0]["email"], "personal")
        self.assertEqual(named["users"][0]["sub_id"], "personal")

    def test_cli_names_trim_separators_and_keep_valid_identifiers(self):
        names = parse_user_names(" owner , мама,sister-phone,guest@example.org ")
        self.assertEqual(names, ["owner", "мама", "sister-phone", "guest@example.org"])
        self.assertEqual(parse_user_names("x" * 254), ["x" * 254])
        for profile in ("reality", "hysteria2"):
            options = {"site_domain": "journal.example.org"} if profile == "reality" else {}
            with self.subTest(profile=profile):
                instance = new_instance(profile, "vpn.example.com", "owner@example.com", user_names=names, **options)
                self.assertEqual([user["email"] for user in instance["users"]], names)
                self.assertEqual(len(set(subscription_urls(instance).values())), len(names))

    def test_invalid_cli_names_are_rejected_before_identity_generation(self):
        invalid = (None, ["owner"], "", " ", ",", "owner,", ",owner", "owner,,family",
                   "owner,OWNER", "Мама,мама", "owner,two names", "owner,bad\nname",
                   "owner,bad\x00name", "owner,bad\x7fname", "owner," + "x" * 255,
                   "owner,\ud800", ",".join(str(index) for index in range(10001)),
                   "x" * (1024 * 1024 + 1))
        with ExitStack() as stack:
            for target in ("secrets.token_urlsafe", "secrets.token_hex", "secrets.choice", "uuid.uuid4", "_openssl"):
                stack.enter_context(mock.patch("vpn_installer.config." + target,
                                               side_effect=AssertionError("invalid names must not generate identities")))
            for index, value in enumerate(invalid):
                with self.subTest(case=index), self.assertRaises(ConfigError):
                    new_instance("hysteria2", "vpn.example.com", "owner@example.com",
                                 user_names=parse_user_names(value))

    def test_monitoring_is_explicit_and_portable_without_changing_urls_or_users(self):
        for version in (1, 2):
            for profile in ('reality', 'hysteria2'):
                original = manifest(profile, version)
                urls = subscription_urls(original)
                self.assertNotIn('monitoring', validate_instance(original))
                original['monitoring'] = {'mode': 'destinations', 'retention_days': 7, 'max_log_mb': 128}
                with self.subTest(version=version, profile=profile), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'instance.json'
                    save_instance(path, original)
                    self.assertEqual(load_instance(path), original)
                    self.assertEqual(subscription_urls(load_instance(path)), urls)

    def test_incomplete_or_invalid_monitoring_is_never_repaired_on_restore(self):
        valid = {'mode': 'basic', 'retention_days': 7, 'max_log_mb': 128}
        invalid = [None, {}, {'mode': 'basic'}, dict(valid, unexpected=True), dict(valid, mode='all')]
        for field, values in (('retention_days', (0, 31, True, '7')),
                              ('max_log_mb', (0, 15, 1025, False, '128'))):
            invalid.extend(dict(valid, **{field: value}) for value in values)
        for value in invalid:
            original = manifest()
            original['monitoring'] = value
            with self.subTest(value=value), self.assertRaises(ConfigError):
                validate_instance(original)

    def test_new_monitoring_defaults_and_invalid_choice_precede_identity_generation(self):
        self.assertEqual(new_instance('hysteria2', 'vpn.example.com', 'owner@example.com')['monitoring'],
                         {'mode': 'basic', 'retention_days': 7, 'max_log_mb': 128})
        self.assertEqual(new_instance('hysteria2', 'vpn.example.com', 'owner@example.com',
                                      monitoring_mode='destinations')['monitoring']['mode'], 'destinations')
        with mock.patch('vpn_installer.config.secrets.token_urlsafe', side_effect=AssertionError('must validate first')), \
                self.assertRaises(ConfigError):
            new_instance('hysteria2', 'vpn.example.com', 'owner@example.com', monitoring_mode='all')

    def test_startup_names_create_independent_portable_users_for_both_profiles(self):
        for profile in ("reality", "hysteria2"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                names = ["dad", "мама", "sister-phone"]
                options = {"site_domain": "journal.example.org"} if profile == "reality" else {}
                original = new_instance(profile, "vpn.example.com", "owner@example.com",
                                        user_names=names, **options)
                self.assertEqual([user["email"] for user in original["users"]], names)
                self.assertEqual(names, ["dad", "мама", "sister-phone"])
                credential = "uuid" if profile == "reality" else "password"
                self.assertEqual(len({user["sub_id"] for user in original["users"]}), len(names))
                self.assertEqual(len({user[credential] for user in original["users"]}), len(names))
                self.assertEqual(len(set(subscription_urls(original).values())), len(names))
                for user in original["users"]:
                    self.assertIs(user["enable"], True)
                    self.assertEqual((user["expiry_time"], user["total_gb"], user["limit_ip"]), (0, 0, 0))
                original["users"][1].update(enable=False, expiry_time=4102444800000,
                                            total_gb=5 * 1024**3, limit_ip=2)
                path = Path(directory) / "instance.json"
                with ExitStack() as stack:
                    for target in ("secrets.token_urlsafe", "secrets.token_hex", "secrets.choice",
                                   "uuid.uuid4", "load_user_names", "parse_user_names"):
                        stack.enter_context(mock.patch("vpn_installer.config." + target,
                                                       side_effect=AssertionError("restore must reuse identities")))
                    save_instance(path, original)
                    restored = load_instance(path)
                    self.assertEqual(restored, original)
                    self.assertEqual(subscription_urls(restored), subscription_urls(original))

    def test_startup_names_are_fully_validated_before_any_generation(self):
        invalid_lists = ([], "dad", {"users": ["dad"]}, ["dad", "DAD"],
                         ["Мама", "мама"], ["dad", ""], ["dad", 12],
                         ["dad", "two names"], ["dad", "bad\nname"], ["dad", "bad\x00name"],
                         ["dad", "bad\x7fname"], ["dad", "x" * 255], ["dad", "\ud800"],
                         [str(index) for index in range(10001)])
        with ExitStack() as stack:
            for target in ("secrets.token_urlsafe", "secrets.token_hex", "secrets.choice", "uuid.uuid4", "_openssl"):
                stack.enter_context(mock.patch("vpn_installer.config." + target,
                                               side_effect=AssertionError("must validate all names first")))
            for profile in ("reality", "hysteria2"):
                options = {"site_domain": "journal.example.org"} if profile == "reality" else {}
                for names in invalid_lists:
                    with self.subTest(profile=profile, value_type=type(names).__name__, count=len(names)), self.assertRaises(ConfigError):
                        new_instance(profile, "vpn.example.com", "owner@example.com", user_names=names, **options)

    def test_startup_names_file_is_a_strict_utf8_array_of_unique_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.json"
            path.write_text('["dad", "мама", "sister-phone"]', encoding="utf-8")
            self.assertEqual(load_user_names(path), ["dad", "мама", "sister-phone"])
            cases = (
                b'not-json', b'[]', b'null', b'"dad"', b'{"users":["dad"]}',
                b'["dad", "DAD"]', b'["dad", false]', b'["dad", "two names"]',
                b'["dad", "bad\\nname"]', b'["dad", "\\ud800"]', b'["dad", NaN]',
                b'["dad", "\xff"]', b'\xef\xbb\xbf["dad"]', b'["dad"] trailing',
            )
            for raw in cases:
                path.write_bytes(raw)
                with self.subTest(raw=raw), self.assertRaises(ConfigError):
                    load_user_names(path)
            path.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaisesRegex(ConfigError, "size limit"):
                load_user_names(path)

    def test_default_direct_api_still_creates_the_personal_user(self):
        data = new_instance("hysteria2", "vpn.example.com", "owner@example.com")
        self.assertEqual([user["email"] for user in data["users"]], ["personal@vpn.example.com"])

    def test_v2_distinct_hosts_and_default_tls_port_survive_restore(self):
        for profile in ("reality", "hysteria2"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                original = manifest(profile, 2)
                path = Path(directory) / "portable.json"
                with mock.patch("vpn_installer.config.secrets.token_urlsafe", side_effect=AssertionError("no generation")):
                    save_instance(path, original)
                    restored = load_instance(path)
                self.assertEqual(restored, original)
                self.assertEqual(public_origin(restored), "https://vpn.example.com")
                self.assertEqual(panel_url(restored), "https://vpn.example.com/Panel_Kept-Exactly/nested/")
                self.assertEqual(subscription_urls(restored), {
                    "alice@example.com": "https://vpn.example.com/My_Sub/nested/Keep_This-Token01"})
                self.assertEqual(vpn_domain(restored), "journal.example.org" if profile == "reality" else "vpn.example.com")

    def test_v2_site_requires_distinct_dns_name_known_template_and_fixed_target(self):
        for section, field, value in (
            ("site", "domain", "vpn.example.com"), ("site", "domain", "127.0.0.1"),
            ("site", "template", "../custom"), ("site", "template", "unknown"),
            ("reality", "target", "journal.example.org:443"),
            ("reality", "target", "127.0.0.1:443"),
            ("reality", "server_name", "vpn.example.com"),
        ):
            data = manifest("reality", 2)
            data[section][field] = value
            with self.subTest(section=section, field=field, value=value), self.assertRaises(ConfigError):
                validate_instance(data)
        for template in SITE_TEMPLATES:
            data = manifest("reality", 2)
            data["site"]["template"] = template
            self.assertEqual(validate_instance(data), data)

    def test_version_specific_fields_and_ports_cannot_be_silently_migrated(self):
        for profile, version in (("reality", 1), ("hysteria2", 1), ("hysteria2", 2)):
            data = manifest(profile, version)
            data["site"] = {"domain": "journal.example.org", "template": "field-notes"}
            with self.subTest(profile=profile, version=version), self.assertRaises(ConfigError):
                validate_instance(data)
        data = manifest("reality", 2)
        del data["site"]
        with self.assertRaises(ConfigError):
            validate_instance(data)
        for version, wrong_port in ((1, 443), (2, 8443)):
            data = manifest("hysteria2", version)
            data["https_port"] = wrong_port
            with self.subTest(version=version), self.assertRaises(ConfigError):
                validate_instance(data)

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
            ("schema_version", True), ("schema_version", 3), ("https_port", True),
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
        self.assertEqual(first["schema_version"], 2)
        self.assertEqual(first["https_port"], 443)
        self.assertNotIn("site", first)
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
    def test_new_reality_has_matching_keys_and_local_site(self):
        with mock.patch("vpn_installer.config.secrets.choice", side_effect=AssertionError("explicit template must not be randomized")):
            data = new_instance("reality", "vpn.example.com", "owner@example.com",
                                site_domain="journal.example.org", site_template="reading-room")
        self.assertEqual(data["reality"]["target"], "127.0.0.1:9443")
        self.assertEqual(data["reality"]["server_name"], "journal.example.org")
        self.assertEqual(data["site"], {"domain": "journal.example.org", "template": "reading-room"})
        self.assertEqual(data["schema_version"], 2)
        self.assertEqual(validate_instance(data), data)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for REALITY")
    def test_default_and_random_template_are_selected_once_and_survive_restore(self):
        for options in ({}, {"site_template": "random"}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                with mock.patch("vpn_installer.config.secrets.choice", return_value="ceramic-studio") as choose:
                    data = new_instance("reality", "vpn.example.com", "owner@example.com",
                                        site_domain="journal.example.org", **options)
                    choose.assert_called_once_with(SITE_TEMPLATES)
                self.assertEqual(data["site"]["template"], "ceramic-studio")
                path = Path(directory) / "instance.json"
                with mock.patch("vpn_installer.config.secrets.choice", side_effect=AssertionError("restore must not choose")):
                    with mock.patch("vpn_installer.config.secrets.token_urlsafe", side_effect=AssertionError("restore must not generate")):
                        save_instance(path, data)
                        restored = load_instance(path)
                        self.assertEqual(restored, data)
                        self.assertEqual(subscription_urls(restored), subscription_urls(data))

    def test_random_is_a_creation_option_not_a_portable_template(self):
        data = manifest("reality", 2)
        data["site"]["template"] = "random"
        with mock.patch("vpn_installer.config.secrets.choice", side_effect=AssertionError("validation must not choose")):
            with self.assertRaises(ConfigError):
                validate_instance(data)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "instance.json"
                path.write_text(json.dumps(data))
                with self.assertRaises(ConfigError):
                    load_instance(path)

    def test_hysteria_does_not_choose_a_site_and_rejects_explicit_site_options(self):
        with mock.patch("vpn_installer.config.secrets.choice", side_effect=AssertionError("Hysteria has no site")):
            self.assertNotIn("site", new_instance("hysteria2", "vpn.example.com", "owner@example.com"))
            for template in ("random", "field-notes"):
                with self.subTest(template=template), self.assertRaises(ConfigError):
                    new_instance("hysteria2", "vpn.example.com", "owner@example.com", site_template=template)

    def test_new_reality_site_errors_do_not_generate_any_credentials(self):
        for options in ({}, {"site_domain": "vpn.example.com"},
                        {"site_domain": "journal.example.org", "site_template": "not-a-template"},
                        {"site_domain": "journal.example.org", "reality_target": "www.example.org:443"}):
            with self.subTest(options=options):
                with mock.patch("vpn_installer.config.secrets.token_urlsafe", side_effect=AssertionError("must validate first")):
                    with self.assertRaises(ConfigError):
                        new_instance("reality", "vpn.example.com", "owner@example.com", **options)

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
