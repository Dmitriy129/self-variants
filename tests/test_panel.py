"""Pinned 3x-ui API contract tests, using a local HTTP peer and no server install."""

from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
import urllib.parse

from vpn_installer.panel import (
    PanelClient, PanelError, build_inbound, configure_instance,
    export_instance, instance_settings,
)


def manifest(profile="reality"):
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


def live_state(profile="reality"):
    config = manifest(profile)
    inbound = build_inbound(config)
    inbound["id"] = 42
    # v3.11 returns nested database JSON fields as objects, while also accepting
    # the older JSON-string input shape used by existing API integrations.
    inbound["settings"] = json.loads(inbound["settings"])
    inbound["streamSettings"] = json.loads(inbound["streamSettings"])
    return {"settings": instance_settings(config), "inbounds": [inbound],
            "clients": [normalized_user(profile)]}


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
            payload = json.loads(self.rfile.read(length)) if length else None
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
            if route == "panel/api/inbounds/list":
                if state.get("redirect"):
                    self.send_response(302)
                    self.send_header("Location", "/unexpected-login")
                    self.end_headers()
                    return
                return self.reply(state["inbounds"], success=not state.get("reject", False))
            if route == "panel/api/clients/list":
                return self.reply(state["clients"])
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
