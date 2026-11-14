"""Pinned 3x-ui API contract tests, using a local HTTP peer and no server install."""

from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
import urllib.parse

from vpn_installer.panel import (
    ACCESS_LOG_PATH, PanelClient, PanelError, apply_fingerprint, apply_monitoring, build_inbound, configure_instance,
    export_instance, instance_settings, validate_monitoring,
)


def manifest(profile="reality", version=1):
    value = {
        "schema_version": 1, "profile": profile, "domain": "vpn.example.org",
        "email": "admin@example.org", "https_port": 8443,
        "panel": {"path": "/fixed-panel/", "username": "admin", "password": "panel-secret"},
        "subscription": {"path": "/fixed-subscription/"},
        "users": [{"email": "first@example.org", "sub_id": "fixed-sub-id",
                   "enable": True, "expiry_time": 0, "total_gb": 0, "limit_ip": 0}],
    }
    if profile == "reality":
        value["users"][0]["uuid"] = "47d4d68b-debe-45a7-8ea8-321f3f7d342b"
        value["reality"] = {
            "target": "www.example.org:443", "server_name": "www.example.org",
            "private_key": "fixed-private-key", "public_key": "fixed-public-key",
            "short_id": "9a8816de",
        }
    else:
        value["users"][0]["password"] = "hy2:secret&value"
    if version == 2:
        value.update(schema_version=2, https_port=443)
        if profile == "reality":
            value["site"] = {"domain": "journal.example.net", "template": "trail-journal"}
            value["reality"].update(target="127.0.0.1:9443", server_name="journal.example.net")
    return value


def normalized_user(profile="reality", **changes):
    row = {
        "id": 501, "email": "first@example.org", "subId": "fixed-sub-id",
        "uuid": "47d4d68b-debe-45a7-8ea8-321f3f7d342b", "auth": "hy2:secret&value",
        "enable": True, "expiryTime": 0, "totalGB": 0, "limitIp": 0,
        "flow": "xtls-rprx-vision" if profile == "reality" else "",
        "inboundIds": [42], "traffic": {"up": 1234, "down": 5678},
    }
    row.update(changes)
    return row


def imported_hosts(inbound):
    stream = inbound["streamSettings"]
    if isinstance(stream, str):
        stream = json.loads(stream)
    return [{"id": 17, "groupId": "generated-db-id", "inboundId": inbound["id"],
             "address": proxy["dest"], "port": proxy["port"], "security": proxy["forceTls"],
             "remark": proxy["remark"], "isDisabled": False, "isHidden": False,
             "randomCount": 1, "snis": None, "tags": None, "finalMask": None,
             "fingerprint": proxy.get("fingerprint", "")}
            for proxy in stream.get("externalProxy", [])]


def live_state(profile="reality", version=1):
    config = manifest(profile, version)
    inbound = build_inbound(config)
    inbound["id"] = 42
    # v3.11 returns nested database JSON fields as objects, while also accepting
    # the older JSON-string input shape used by existing API integrations.
    inbound["settings"] = json.loads(inbound["settings"])
    inbound["streamSettings"] = json.loads(inbound["streamSettings"])
    return {"settings": instance_settings(config), "inbounds": [inbound],
            "clients": [normalized_user(profile)], "hosts": imported_hosts(inbound)}


def xray_template(mode="basic", managed=True):
    user_policy = {"statsUserUplink": True, "statsUserDownlink": True, "connIdle": 300}
    if managed:
        user_policy["statsUserOnline"] = True
    return {
        "api": {"tag": "api", "services": ["StatsService", "HandlerService"]},
        "stats": {},
        "policy": {"levels": {"0": user_policy},
                   "system": {"statsInboundUplink": True, "statsInboundDownlink": True,
                              "statsOutboundUplink": False}},
        "log": {"access": ACCESS_LOG_PATH if mode == "destinations" else "none",
                "error": "", "loglevel": "warning", "dnsLog": False, "maskAddress": ""},
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"domainStrategy": "AsIs", "rules": [{"inboundTag": ["api"], "outboundTag": "api"}]},
    }


@contextmanager
def panel_peer(state=None):
    state = deepcopy(state or {"settings": {"sessionMaxAge": 1440,
                                           "smtpPassword": "", "hasSmtpPassword": True},
                               "inbounds": [], "clients": []})
    state.update(requests=[], csrf="before-login", logged_in=False)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, obj=None, *, success=True, status=200, cookie=None):
            body = json.dumps({"success": success, "obj": obj,
                               "msg": "panel-secret must never leak in errors"}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            if cookie:
                self.send_header("Set-Cookie", cookie + "; Path=/fixed-panel/; HttpOnly")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.handle_api()

        def do_POST(self):
            self.handle_api()

        def handle_api(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            content_type = self.headers.get("Content-Type", "")
            if body and content_type == "application/x-www-form-urlencoded":
                payload = dict(urllib.parse.parse_qsl(body.decode("utf-8"), keep_blank_values=True))
            else:
                payload = json.loads(body) if body else None
            state["requests"].append((self.command, self.path, payload))
            if not self.path.startswith("/fixed-panel/"):
                return self.reply(success=False, status=404)
            route = self.path[len("/fixed-panel/"):]
            cookie = self.headers.get("Cookie", "")
            if route == "csrf-token" and self.command == "GET":
                return self.reply(state["csrf"], cookie="session=anonymous" if not state["logged_in"] else None)
            if self.command != "GET" and self.headers.get("X-CSRF-Token") != state["csrf"]:
                return self.reply(success=False, status=403)
            if route == "login" and self.command == "POST":
                if "session=anonymous" not in cookie or payload != {"username": "admin", "password": "panel-secret"}:
                    return self.reply(success=False)
                state["logged_in"] = True
                state["csrf"] = "after-login"
                return self.reply(cookie="session=authenticated")
            if "session=authenticated" not in cookie:
                return self.reply(success=False, status=401)
            if route == "panel/api/setting/all" and self.command == "POST":
                return self.reply(state["settings"])
            if route == "panel/api/setting/update" and self.command == "POST":
                state["settings"] = payload
                return self.reply()
            if route == "panel/api/xray/" and self.command == "POST":
                response = state.get("xray_response", {
                    "xraySetting": state.get("xray_template", {}),
                    "outboundTestUrl": state.get("outbound_test_url", "https://probe.example.org/check?a=1&b=2"),
                    "inboundTags": [],
                })
                return self.reply(json.dumps(response))
            if route == "panel/api/xray/update" and self.command == "POST":
                if content_type != "application/x-www-form-urlencoded":
                    return self.reply(success=False)
                state["xray_template"] = json.loads(payload["xraySetting"])
                state["outbound_test_url"] = payload["outboundTestUrl"]
                return self.reply()
            if route == "panel/api/inbounds/list":
                if state.get("redirect"):
                    self.send_response(302)
                    self.send_header("Location", "/unexpected-login")
                    self.end_headers()
                    return
                return self.reply(state["inbounds"], success=not state.get("reject", False))
            if route == "panel/api/clients/list":
                return self.reply(state["clients"])
            if route == "panel/api/hosts/raw":
                return self.reply(state.get("hosts", []))
            if route.startswith('panel/api/hosts/get/'):
                host = state['hosts'][0]
                group = dict(host, inboundIds=[host['inboundId']], hosts=[host['address']])
                return self.reply(group)
            if route.startswith('panel/api/hosts/update/') and self.command == 'POST':
                state['hosts'][0]['fingerprint'] = payload['fingerprint']
                return self.reply(state['hosts'])
            if route.startswith('panel/api/inbounds/update/') and self.command == 'POST':
                for field in ('settings', 'streamSettings', 'sniffing'):
                    if isinstance(payload.get(field), str):
                        payload[field] = json.loads(payload[field])
                state['inbounds'][0] = payload
                return self.reply(payload)
            if route == "panel/api/server/status":
                return self.reply(state.get("status", {"xray": {"state": "running", "errorMsg": "",
                                                                 "version": "26.11.9"}}))
            if route.startswith("panel/api/clients/get/"):
                email = urllib.parse.unquote(route[len("panel/api/clients/get/"):])
                for row in state["clients"]:
                    if row["email"] == email:
                        detail = {"client": row, "inboundIds": row.get("inboundIds"),
                                  "externalLinks": []}
                        detail.update(state.get("detail_overrides", {}).get(email, {}))
                        return self.reply(detail)
                return self.reply(success=False)
            if route == "panel/api/inbounds/add" and self.command == "POST":
                payload["id"] = 42
                state["inbounds"].append(payload)
                state["hosts"] = imported_hosts(payload)
                return self.reply(payload)
            if route == "panel/api/setting/restartPanel" and self.command == "POST":
                return self.reply()
            return self.reply(success=False, status=404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    client = PanelClient("http://127.0.0.1:%d/fixed-panel/" % server.server_port,
                         "admin", "panel-secret")
    try:
        yield client, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class PanelHTTPTests(unittest.TestCase):
    def test_fingerprint_change_preserves_users_and_host_inheritance(self):
        for version, override in ((1, None), (2, None), (2, 'chrome')):
            baseline = manifest('reality', version)
            initial = live_state('reality', version)
            initial['clients'][0].update(enable=False, expiryTime=4102444800000, totalGB=70000)
            if override:
                initial['hosts'][0]['fingerprint'] = override
            with self.subTest(version=version, override=override), panel_peer(initial) as (client, state):
                client.login()
                before = export_instance(client, baseline)
                target = deepcopy(before)
                target['reality']['fingerprint'] = 'firefox'
                if override:
                    target['reality']['host_fingerprint'] = 'firefox'
                apply_fingerprint(client, target)
                self.assertEqual(export_instance(client, target), target)
                self.assertEqual(state['clients'], initial['clients'])  # Includes traffic counters.
                changed = deepcopy(state['inbounds'][0])
                changed['streamSettings']['realitySettings']['settings']['fingerprint'] = 'chrome'
                # Wire JSON representation may change; all other settings stay equal.
                original = deepcopy(initial['inbounds'][0])
                original['sniffing'] = json.loads(original['sniffing'])
                self.assertEqual(changed, original)
                count = len(state['requests'])
                apply_fingerprint(client, target)
                self.assertFalse(any('/update/' in path for _, path, _ in state['requests'][count:]))
                apply_fingerprint(client, before)
                self.assertEqual(export_instance(client, before), before)

    def test_monitoring_new_install_and_repeat_for_both_profiles(self):
        for profile in ("reality", "hysteria2"):
            for mode in ("basic", "destinations"):
                config = manifest(profile, 2)
                config["monitoring"] = {"mode": mode, "retention_days": 7, "max_log_mb": 128}
                original = xray_template(managed=False)
                with self.subTest(profile=profile, mode=mode), panel_peer({
                    "settings": {}, "inbounds": [], "clients": [], "xray_template": original,
                }) as (client, state):
                    inbound = configure_instance(client.login(), config)
                    self.assertEqual(state["xray_template"], xray_template(mode))
                    self.assertEqual(json.loads(inbound["sniffing"]), {"enabled": False})
                    count = len(state["requests"])
                    configure_instance(client, config)
                    self.assertFalse(any(path.endswith(("/add", "/update"))
                                         for _, path, _ in state["requests"][count:]))

    def test_monitoring_mode_changes_preserve_users_routes_and_limits(self):
        config = manifest("reality", 2)
        config["monitoring"] = {"mode": "destinations", "retention_days": 7, "max_log_mb": 128}
        initial = live_state("reality", 2)
        initial["clients"][0].update(enable=False, expiryTime=4102444800000, totalGB=70000)
        initial["xray_template"] = xray_template()
        with panel_peer(initial) as (client, state):
            client.login()
            apply_monitoring(client, config)
            self.assertEqual(state["clients"], initial["clients"])
            self.assertEqual(state["inbounds"], initial["inbounds"])
            self.assertEqual(state["xray_template"]["routing"], initial["xray_template"]["routing"])
            exported = export_instance(client, config)
            self.assertEqual(exported["monitoring"], config["monitoring"])
            self.assertFalse(exported["users"][0]["enable"])
            self.assertEqual(exported["users"][0]["expiry_time"], 4102444800000)
            config["monitoring"]["mode"] = "basic"
            apply_monitoring(client, config)
            self.assertEqual(state["xray_template"]["log"]["access"], "none")
            self.assertEqual(state["clients"], initial["clients"])

    def test_monitoring_export_rejects_panel_only_mode_and_log_changes(self):
        for log_change in ({"access": ACCESS_LOG_PATH}, {"access": "/tmp/other.log"},
                           {"error": "./error.log"}, {"dnsLog": True}, {"loglevel": "info"},
                           {"maskAddress": "quarter"}, {"extra": True}):
            config = manifest("reality", 2)
            config["monitoring"] = {"mode": "basic", "retention_days": 7, "max_log_mb": 128}
            state = live_state("reality", 2)
            state["xray_template"] = xray_template()
            state["xray_template"]["log"].update(log_change)
            with self.subTest(log_change=log_change), panel_peer(state) as (client, remote):
                with self.assertRaises(PanelError):
                    export_instance(client.login(), config)
                self.assertFalse(any(path.endswith("/update") for _, path, _ in remote["requests"]))

    def test_monitoring_requires_counters_and_disabled_sniffing(self):
        for field in ("statsUserUplink", "statsUserDownlink", "statsUserOnline", "sniffing"):
            config = manifest("hysteria2", 2)
            config["monitoring"] = {"mode": "basic", "retention_days": 7, "max_log_mb": 128}
            state = live_state("hysteria2", 2)
            state["xray_template"] = xray_template()
            if field == "sniffing":
                state["inbounds"][0]["sniffing"] = {"enabled": True, "destOverride": ["tls"]}
            else:
                state["xray_template"]["policy"]["levels"]["0"][field] = False
            with self.subTest(field=field), panel_peer(state) as (client, _):
                with self.assertRaises(PanelError):
                    export_instance(client.login(), config)

    def test_legacy_manifests_never_read_or_write_monitoring_template(self):
        for version in (1, 2):
            config = manifest("reality", version)
            with self.subTest(version=version), panel_peer(live_state("reality", version)) as (client, state):
                client.login()
                apply_monitoring(client, config)
                self.assertIsNone(validate_monitoring(client, config))
                self.assertEqual(export_instance(client, config), config)
                configure_instance(client, config)
                self.assertFalse(any("/api/xray/" in path for _, path, _ in state["requests"]))

    def test_xray_template_roundtrip_uses_form_and_preserves_outbound_probe(self):
        original = {"log": {"access": "none"}, "routing": {"rules": []},
                    "outbounds": [{"tag": "custom", "settings": {"password": "a&b+c=тест"}}]}
        with panel_peer({"settings": {}, "inbounds": [], "clients": [],
                         "xray_template": original}) as (client, state):
            client.login()
            template = client.get_xray_settings()
            self.assertEqual(template, original)
            template["log"]["access"] = "/var/log/x-ui/access.log"
            client.save_xray_settings(template)
            self.assertEqual(state["xray_template"], template)
            self.assertEqual(state["xray_template"]["outbounds"], original["outbounds"])
            self.assertEqual(state["outbound_test_url"], "https://probe.example.org/check?a=1&b=2")

    def test_xray_template_rejects_invalid_response_without_writing(self):
        for response in ({"xraySetting": []}, {"xraySetting": {}, "outboundTestUrl": 1},
                         {"xraySetting": "not-json", "outboundTestUrl": "https://example.org"}):
            with self.subTest(response=response), panel_peer({"settings": {}, "inbounds": [],
                                                            "clients": [], "xray_response": response}) as (client, state):
                with self.assertRaises(PanelError):
                    client.login().save_xray_settings({"log": {"access": "none"}})
                self.assertFalse(any(path.endswith("xray/update") for _, path, _ in state["requests"]))

    def test_v2_reality_uses_private_listener_but_public_host_on_443(self):
        config = manifest("reality", 2)
        with panel_peer() as (client, state):
            created = configure_instance(client.login(), config)
            self.assertEqual(created["listen"], "127.0.0.1")
            self.assertEqual(created["port"], 10443)
            self.assertEqual(created["shareAddr"], "journal.example.net")
            stream = json.loads(created["streamSettings"])
            self.assertEqual(stream["sockopt"], {"acceptProxyProtocol": True})
            self.assertEqual(stream["realitySettings"]["xver"], 0)
            self.assertEqual(stream["realitySettings"]["target"], "127.0.0.1:9443")
            self.assertEqual(stream["externalProxy"], [{"dest": "journal.example.net", "port": 443,
                              "forceTls": "same", "remark": "vpn-installer-reality"}])
            self.assertEqual(state["hosts"][0]["port"], 443)
            self.assertEqual(state["settings"]["subURI"], "https://vpn.example.org/fixed-subscription/")
            count = len(state["requests"])
            configure_instance(client, config)
            self.assertFalse(any(path.endswith(("/add", "/update"))
                                 for _, path, _ in state["requests"][count:]))

    def test_live_inbound_fingerprint_survives_export_and_fresh_restore(self):
        for version in (1, 2):
            baseline = manifest('reality', version)
            for fp in ('firefox', 'hellochrome_155'):
                with self.subTest(version=version, fp=fp), panel_peer(live_state('reality', version)) as (client, state):
                    state['inbounds'][0]['streamSettings']['realitySettings']['settings']['fingerprint'] = fp
                    exported = export_instance(client.login(), baseline)
                    self.assertEqual(exported['reality']['fingerprint'], fp)
                    self.assertEqual(exported['users'], baseline['users'])
                    self.assertEqual(exported['subscription'], baseline['subscription'])
                    before = len(state['requests'])
                    configure_instance(client, exported)
                    self.assertFalse(any(path.endswith(('/add', '/update')) for _, path, _ in state['requests'][before:]))
                with panel_peer() as (client, state):
                    created = configure_instance(client.login(), exported)
                    state['clients'] = [normalized_user(inboundIds=[created['id']])]
                    self.assertEqual(export_instance(client, exported), exported)

    def test_host_override_preserves_inheritance_and_clearing(self):
        baseline = manifest('reality', 2)
        with panel_peer(live_state('reality', 2)) as (client, state):
            state['hosts'][0]['fingerprint'] = 'firefox'
            exported = export_instance(client.login(), baseline)
            self.assertNotIn('fingerprint', exported['reality'])  # Legacy inbound remains chrome.
            self.assertEqual(exported['reality']['host_fingerprint'], 'firefox')
            configure_instance(client, exported)  # Stale inline externalProxy is not authoritative.
            self.assertEqual(export_instance(client, exported), exported)
        with panel_peer() as (client, state):
            created = configure_instance(client.login(), exported)
            state['clients'] = [normalized_user(inboundIds=[created['id']])]
            self.assertEqual(state['hosts'][0]['fingerprint'], 'firefox')
            self.assertEqual(export_instance(client, exported), exported)
            state['hosts'][0]['fingerprint'] = ''
            stream = json.loads(state['inbounds'][0]['streamSettings'])
            stream['realitySettings']['settings']['fingerprint'] = 'hellochrome_155'
            state['inbounds'][0]['streamSettings'] = json.dumps(stream)
            cleared = export_instance(client, exported)
            self.assertNotIn('host_fingerprint', cleared['reality'])
            self.assertEqual(cleared['reality']['fingerprint'], 'hellochrome_155')
            configure_instance(client, cleared)
            self.assertEqual(export_instance(client, cleared), cleared)

    def test_invalid_live_fingerprint_is_rejected(self):
        for where in ('host', 'inbound'):
            for value in (False, 17, ' Firefox', 'firefox\n'):
                state = live_state('reality', 2)
                target = state['hosts'][0] if where == 'host' else state['inbounds'][0]['streamSettings']['realitySettings']['settings']
                target['fingerprint'] = value
                with self.subTest(where=where, value=value), panel_peer(state) as (client, _):
                    with self.assertRaises(PanelError):
                        export_instance(client.login(), manifest('reality', 2))

    def test_both_v2_profiles_export_exact_identity_without_explicit_443(self):
        for profile in ("reality", "hysteria2"):
            with self.subTest(profile=profile), panel_peer(live_state(profile, 2)) as (client, state):
                baseline = manifest(profile, 2)
                self.assertEqual(export_instance(client.login(), baseline), baseline)
                state["clients"] = []
                exported = export_instance(client, baseline)
                self.assertEqual(exported["users"], [])
                self.assertEqual(exported.get("site"), baseline.get("site"))
                self.assertEqual(exported["schema_version"], 2)
                self.assertNotIn(":443", instance_settings(exported)["subURI"])

    def test_v2_hysteria_keeps_udp_listener_and_has_no_host_override(self):
        config = manifest("hysteria2", 2)
        with panel_peer() as (client, state):
            created = configure_instance(client.login(), config)
            self.assertEqual((created["listen"], created["port"]), ("::", 443))
            self.assertNotIn("externalProxy", json.loads(created["streamSettings"]))
            self.assertEqual(state["hosts"], [])
            state["hosts"] = None
            self.assertEqual(client.list_hosts(), [])

    def test_v2_export_rejects_live_host_edits_even_with_unchanged_external_proxy(self):
        changes = ({"port": 10443}, {"address": "vpn.example.org"}, {"security": "tls"},
                   {"isDisabled": True}, {"sni": "other.example.org"}, {"finalMask": {"tcp": [{}]}})
        for change in changes:
            state = live_state("reality", 2)
            state["hosts"][0].update(change)
            with self.subTest(change=change), panel_peer(state) as (client, _):
                with self.assertRaises(PanelError):
                    export_instance(client.login(), manifest("reality", 2))
        for hosts in ([], imported_hosts(live_state("reality", 2)["inbounds"][0]) * 2):
            state = live_state("reality", 2)
            state["hosts"] = hosts
            with self.subTest(host_count=len(hosts)), panel_peer(state) as (client, _):
                with self.assertRaisesRegex(PanelError, "exactly one managed"):
                    export_instance(client.login(), manifest("reality", 2))

    def test_v2_export_rejects_internal_listener_or_local_target_changes(self):
        for area, field, value in (
            ("inbound", "listen", "0.0.0.0"), ("inbound", "port", 443),
            ("stream", "sockopt", {"acceptProxyProtocol": False}),
            ("reality", "target", "journal.example.net:443"), ("reality", "xver", 1),
            ("reality", "serverNames", ["vpn.example.org"]),
        ):
            state = live_state("reality", 2)
            inbound = state["inbounds"][0]
            target = inbound if area == "inbound" else inbound["streamSettings"]
            if area == "reality":
                target = target["realitySettings"]
            target[field] = value
            with self.subTest(area=area, field=field), panel_peer(state) as (client, _):
                with self.assertRaises(PanelError):
                    export_instance(client.login(), manifest("reality", 2))

    def test_v2_export_does_not_normalize_explicit_443_or_change_saved_namespace(self):
        state = live_state("reality", 2)
        state["settings"]["subURI"] = "https://vpn.example.org:443/fixed-subscription/"
        with panel_peer(state) as (client, _):
            with self.assertRaisesRegex(PanelError, "layout changed"):
                export_instance(client.login(), manifest("reality", 2))

    def test_login_cookie_csrf_rotation_and_full_settings_merge(self):
        with panel_peer() as (client, state):
            self.assertIs(client.login(), client)
            client.save_settings({"subPath": "/reused-sub-path/"})
            self.assertEqual(state["settings"], {"sessionMaxAge": 1440, "smtpPassword": "",
                             "hasSmtpPassword": True, "subPath": "/reused-sub-path/"})
            self.assertEqual([item[:2] for item in state["requests"][:3]], [
                ("GET", "/fixed-panel/csrf-token"), ("POST", "/fixed-panel/login"),
                ("GET", "/fixed-panel/csrf-token")])

    def test_api_failure_does_not_echo_credentials(self):
        with panel_peer() as (client, state):
            client.login()
            state["reject"] = True
            with self.assertRaises(PanelError) as caught:
                client.list_inbounds()
            self.assertNotIn("panel-secret", str(caught.exception))

    def test_redirect_is_not_followed(self):
        with panel_peer() as (client, state):
            client.login()
            state["redirect"] = True
            with self.assertRaisesRegex(PanelError, "redirected"):
                client.list_inbounds()
            self.assertFalse(any(path == "/unexpected-login" for _, path, _ in state["requests"]))

    def test_status_checks_core_and_rejected_configuration(self):
        with panel_peer() as (client, state):
            client.login()
            self.assertTrue(client.xray_running())
            for status in ({"state": "stop", "errorMsg": ""},
                           {"state": "error", "errorMsg": "failed"},
                           {"state": "running", "errorMsg": "new configuration rejected"}):
                with self.subTest(status=status):
                    state["status"] = {"xray": status}
                    self.assertFalse(client.xray_running())
            state["status"] = {"panel": "running"}
            with self.assertRaisesRegex(PanelError, "invalid Xray status"):
                client.xray_running()

    def test_first_install_then_repeat_keeps_current_users(self):
        config = manifest()
        with panel_peer() as (client, state):
            client.login()
            created = configure_instance(client, config)
            self.assertEqual(created["id"], 42)
            state["clients"] = [normalized_user(email="added-in-panel@example.org")]
            request_count = len(state["requests"])
            configure_instance(client, config)
            later = state["requests"][request_count:]
            self.assertFalse(any(path.endswith(("/add", "/update")) for _, path, _ in later))
            self.assertEqual(state["clients"][0]["email"], "added-in-panel@example.org")
            self.assertEqual(state["settings"]["subURI"],
                             "https://vpn.example.org:8443/fixed-subscription/")
            self.assertEqual(state["settings"]["subListen"], "127.0.0.1")

    def test_missing_identity_fails_before_any_api_mutation(self):
        config = manifest()
        del config["users"][0]["sub_id"]
        with panel_peer() as (client, state):
            client.login()
            with self.assertRaisesRegex(PanelError, "sub_id"):
                configure_instance(client, config)
            self.assertFalse(any(path.endswith(("/add", "/update")) for _, path, _ in state["requests"]))

    def test_nonempty_foreign_panel_is_not_overwritten(self):
        state = live_state()
        state["inbounds"][0]["protocol"] = "trojan"
        with panel_peer(state) as (client, state):
            client.login()
            with self.assertRaises(PanelError):
                configure_instance(client, manifest())
            self.assertFalse(any(path.endswith(("/add", "/update")) for _, path, _ in state["requests"]))

    def test_export_reads_normalized_current_users_not_stale_inbound_clients(self):
        state = live_state()
        state["clients"] = [
            normalized_user(email="added+phone@example.org", subId="new-sub-id", enable=False,
                            expiryTime=1900000000000, totalGB=5 * 1024**3, limitIp=3,
                            uuid="c611d1cc-1ea2-41bb-ac78-6e975e04fe7d"),
            normalized_user(email="detached@example.org", inboundIds=[]),
        ]
        baseline = manifest()
        with panel_peer(state) as (client, state):
            result = export_instance(client.login(), baseline)
            self.assertEqual(result["users"], [{
                "email": "added+phone@example.org", "sub_id": "new-sub-id", "enable": False,
                "expiry_time": 1900000000000, "total_gb": 5 * 1024**3, "limit_ip": 3,
                "uuid": "c611d1cc-1ea2-41bb-ac78-6e975e04fe7d",
            }])
            self.assertEqual(result["subscription"], baseline["subscription"])
            self.assertEqual(result["reality"], baseline["reality"])
            self.assertEqual(baseline, manifest())
            self.assertTrue(any("added%2Bphone%40example.org" in path
                                for _, path, _ in state["requests"]))

    def test_hysteria_restores_auth_not_other_password_field(self):
        state = live_state("hysteria2")
        state["clients"][0]["password"] = "wrong-other-protocol-password"
        with panel_peer(state) as (client, _):
            result = export_instance(client.login(), manifest("hysteria2"))
            self.assertEqual(result["users"][0]["password"], "hy2:secret&value")
            inbound = build_inbound(result)
            settings = json.loads(inbound["settings"])
            stream = json.loads(inbound["streamSettings"])
            self.assertEqual(settings["version"], 2)
            self.assertEqual(stream["hysteriaSettings"]["version"], 2)
            self.assertEqual(settings["clients"][0]["auth"], "hy2:secret&value")
            self.assertNotIn("password", settings["clients"][0])
            self.assertEqual(stream["tlsSettings"]["certificates"][0]["keyFile"],
                             "/etc/letsencrypt/live/vpn.example.org/privkey.pem")

    def test_export_rejects_an_extra_inbound_instead_of_losing_it(self):
        state = live_state()
        state["inbounds"].append(dict(state["inbounds"][0], id=43))
        with panel_peer(state) as (client, _):
            with self.assertRaisesRegex(PanelError, "exactly one"):
                export_instance(client.login(), manifest())

    def test_export_rejects_external_links_and_unsupported_user_limits(self):
        for field in ("limitHwid", "resetDay", "clientHostRuleIds"):
            with self.subTest(field=field):
                state = live_state()
                state["clients"][0][field] = [1] if field == "clientHostRuleIds" else 1
                with panel_peer(state) as (client, _):
                    with self.assertRaisesRegex(PanelError, "User settings"):
                        export_instance(client.login(), manifest())
        state = live_state()
        state["detail_overrides"] = {"first@example.org": {"externalLinks": [{"url": "vless://external"}]}}
        with panel_peer(state) as (client, _):
            with self.assertRaisesRegex(PanelError, "User settings"):
                export_instance(client.login(), manifest())

    def test_export_uses_effective_flow_from_detail(self):
        state = live_state()
        state["clients"][0]["flow"] = ""
        detail = dict(state["clients"][0], flow="xtls-rprx-vision")
        state["detail_overrides"] = {"first@example.org": {"client": detail}}
        with panel_peer(state) as (client, _):
            self.assertEqual(len(export_instance(client.login(), manifest())["users"]), 1)

    def test_export_rejects_path_domain_and_listener_changes(self):
        changes = {
            "subURI": "https://other.example.org:8443/fixed-subscription/",
            "subPath": "/different-subscription/", "webBasePath": "/different-panel/",
            "webListen": "0.0.0.0", "subListen": "::", "subPort": 8090,
            "subCertFile": "/manual-certificate.pem", "trustedProxyCIDRs": "0.0.0.0/0",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                state = live_state()
                state["settings"][field] = value
                with panel_peer(state) as (client, _):
                    with self.assertRaisesRegex(PanelError, "layout changed"):
                        export_instance(client.login(), manifest())

    def test_export_rejects_hysteria_v1_even_when_stream_is_v2(self):
        state = live_state("hysteria2")
        state["inbounds"][0]["settings"]["version"] = 1
        with panel_peer(state) as (client, _):
            with self.assertRaisesRegex(PanelError, "version 2"):
                export_instance(client.login(), manifest("hysteria2"))


if __name__ == "__main__":
    unittest.main()
