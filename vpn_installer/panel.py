"""3x-ui v3.11.0 API adapter; no database writes or installer execution.

The pinned controllers are the source of truth for the session CSRF envelope,
settings merge and normalized client records. Nested inbound fields are sent as
JSON strings, one of the input forms accepted by the pinned API.
"""

from copy import deepcopy
from http.cookiejar import CookieJar
import json
import urllib.error
import urllib.parse
import urllib.request

from .config import ConfigError, LOCAL_REALITY_TARGET, public_origin, validate_fingerprint, vpn_domain


ACCESS_LOG_PATH = "/var/log/x-ui/access.log"
_USER_STATS = ("statsUserUplink", "statsUserDownlink", "statsUserOnline")
_INBOUND_STATS = ("statsInboundUplink", "statsInboundDownlink")


class PanelError(RuntimeError):
    """An API or portability error, with no credentials in its message."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PanelError("Panel API redirected; check the panel base path")


class PanelClient:
    """Cookie/CSRF client. base_url includes the configured webBasePath."""

    def __init__(self, base_url, username, password, *, timeout=20):
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise PanelError("Invalid panel base URL")
        self.base_url = base_url.rstrip("/") + "/"
        self.username = username
        self.password = password
        self.timeout = timeout
        self._csrf = None
        self._cookies = CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self._cookies), _NoRedirect())

    def _request(self, method, path, payload=None, *, form=False):
        headers = {"Accept": "application/json"}
        data = None
        if payload is not None:
            if form:
                data = urllib.parse.urlencode(payload).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                headers["Content-Type"] = "application/json"
        if method not in ("GET", "HEAD"):
            if not self._csrf:
                raise PanelError("Log in before changing panel settings")
            headers["X-CSRF-Token"] = self._csrf
        request = urllib.request.Request(
            self.base_url + path.lstrip("/"), data=data, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            raise PanelError("Panel API returned HTTP %d" % exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise PanelError("Cannot reach the panel API") from None
        if len(raw) > 32 * 1024 * 1024:
            raise PanelError("Panel API response is too large")
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise PanelError("Panel API returned invalid JSON") from None
        if not isinstance(value, dict) or value.get("success") is not True:
            # API error messages can contain credentials or submitted config.
            raise PanelError("Panel API rejected the request")
        return value.get("obj")

    def _refresh_csrf(self):
        token = self._request("GET", "csrf-token")
        if not isinstance(token, str) or not token:
            raise PanelError("Panel returned an invalid CSRF token")
        self._csrf = token

    def login(self):
        self._refresh_csrf()
        self._request("POST", "login", {
            "username": self.username, "password": self.password})
        self._refresh_csrf()
        return self

    def get_settings(self):
        value = self._request("POST", "panel/api/setting/all", {})
        if not isinstance(value, dict):
            raise PanelError("Panel returned invalid settings")
        return value

    def save_settings(self, settings):
        # This endpoint replaces AllSetting, rather than patching it. Redacted
        # secrets remain blank; the server interprets those as unchanged.
        merged = self.get_settings()
        merged.update(deepcopy(settings))
        return self._request("POST", "panel/api/setting/update", merged)

    def _get_xray_settings_response(self):
        # Unlike AllSetting, this handler serializes the response object inside
        # obj as a JSON string. The template is nested under xraySetting.
        value = _json_object(self._request("POST", "panel/api/xray/", {}),
                             "Xray settings response")
        value["xraySetting"] = _json_object(value.get("xraySetting"), "xraySetting")
        if not isinstance(value.get("outboundTestUrl"), str):
            raise PanelError("Panel returned an invalid outbound test URL")
        return value

    def get_xray_settings(self):
        return self._get_xray_settings_response()["xraySetting"]

    def save_xray_settings(self, settings):
        if not isinstance(settings, dict):
            raise PanelError("Invalid Xray configuration template")
        current = self._get_xray_settings_response()
        # The pinned controller uses PostForm rather than binding JSON. Keep
        # its separate outbound test URL unchanged when writing the template.
        return self._request("POST", "panel/api/xray/update", {
            "xraySetting": _dump(settings),
            "outboundTestUrl": current["outboundTestUrl"],
        }, form=True)

    def _list(self, path):
        value = self._request("GET", path)
        if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
            raise PanelError("Panel returned an invalid collection")
        return value

    def list_inbounds(self):
        return self._list("panel/api/inbounds/list")

    def list_clients(self):
        return self._list("panel/api/clients/list")

    def list_hosts(self):
        value = self._request("GET", "panel/api/hosts/raw")
        # The pinned Go handler can serialize an empty slice as null.
        if value is None:
            return []
        if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
            raise PanelError("Panel returned invalid advertised hosts")
        return value

    def get_client(self, email):
        value = self._request("GET", "panel/api/clients/get/" +
                              urllib.parse.quote(email, safe=""))
        if not isinstance(value, dict) or not isinstance(value.get("client"), dict):
            raise PanelError("Panel returned an invalid client")
        return value

    def get_status(self):
        value = self._request("GET", "panel/api/server/status")
        if not isinstance(value, dict) or not isinstance(value.get("xray"), dict):
            raise PanelError("Panel returned invalid Xray status")
        xray = value["xray"]
        if (xray.get("state") not in ("running", "stop", "error")
                or not isinstance(xray.get("errorMsg"), str)):
            raise PanelError("Panel returned invalid Xray status")
        return value

    def xray_running(self):
        """Whether the core is running without a rejected pending config.

        The panel refreshes this snapshot every two seconds. Callers performing
        a restart should poll it with a deadline rather than assume readiness.
        """
        xray = self.get_status()["xray"]
        return xray["state"] == "running" and not xray["errorMsg"]

    def add_inbound(self, inbound):
        result = self._request("POST", "panel/api/inbounds/add", inbound)
        if not isinstance(result, dict) or not isinstance(result.get("id"), int):
            raise PanelError("Panel did not return the created inbound")
        return result

    def update_inbound(self, inbound):
        payload = deepcopy(inbound)
        for field in ('settings', 'streamSettings', 'sniffing'):
            if isinstance(payload.get(field), dict):
                payload[field] = _dump(payload[field])
        return self._request('POST', 'panel/api/inbounds/update/' + str(inbound['id']), payload)

    def get_host_group(self, group_id):
        return _json_object(self._request('GET', 'panel/api/hosts/get/' +
                                         urllib.parse.quote(group_id, safe='')), 'Host group')

    def update_host_group(self, group):
        return self._request('POST', 'panel/api/hosts/update/' +
                             urllib.parse.quote(group['groupId'], safe=''), group)

    def restart_panel(self):
        return self._request("POST", "panel/api/setting/restartPanel", {})


def _json_object(value, field):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise PanelError("Invalid JSON in panel field: " + field) from None
    if not isinstance(value, dict):
        raise PanelError("Invalid panel object: " + field)
    return value


def _nonempty_string(value, field):
    if not isinstance(value, str) or not value:
        raise PanelError("Missing required identity field: " + field)
    return value


def _dump(value):
    return json.dumps(value, separators=(",", ":"))


def _local_site(instance):
    return instance["schema_version"] == 2 and instance["profile"] == "reality"


def _external_proxy(instance):
    proxy = {"dest": vpn_domain(instance), "port": 443, "forceTls": "same",
             "remark": "vpn-installer-reality"}
    if "host_fingerprint" in instance.get("reality", {}):
        proxy["fingerprint"] = _fingerprint(instance["reality"]["host_fingerprint"])
    return [proxy]


def _fingerprint(value):
    try:
        return validate_fingerprint(value)
    except ConfigError as exc:
        raise PanelError(str(exc)) from None


def _without_host_fingerprint(stream):
    """Inline proxy data can be stale: 3x-ui's Hosts table is authoritative."""
    result = deepcopy(stream)
    proxies = result.get("externalProxy", [])
    if not isinstance(proxies, list) or any(not isinstance(row, dict) for row in proxies):
        raise PanelError("Invalid advertised hosts")
    for row in proxies:
        row.pop("fingerprint", None)
    return result


def instance_settings(instance):
    """Only the settings owned by this installer; merge with live settings."""
    domain = instance["domain"]
    prefix = public_origin(instance) + instance["subscription"]["path"]
    return {
        "webListen": "127.0.0.1", "webPort": 2053, "webDomain": "",
        "webBasePath": instance["panel"]["path"],
        "webCertFile": "", "webKeyFile": "",
        "subEnable": True, "subListen": "127.0.0.1", "subPort": 2096,
        "subDomain": domain, "subPath": instance["subscription"]["path"],
        "subURI": prefix, "subCertFile": "", "subKeyFile": "",
        "subEncrypt": True, "subJsonEnable": False, "subClashEnable": False,
        "subJsonAutoDetect": False, "subClashAutoDetect": False,
        "subInfoNodeEnable": False,
        "trustedProxyCIDRs": "127.0.0.1/32,::1/128",
    }


def _monitoring_log(mode):
    if mode not in ("basic", "destinations"):
        raise PanelError("Unsupported monitoring mode")
    return {"access": ACCESS_LOG_PATH if mode == "destinations" else "none",
            "error": "", "loglevel": "warning", "dnsLog": False, "maskAddress": ""}


def _monitoring_policy(template, *, create):
    """Return the level-zero and inbound policy without dropping other policy."""
    if create:
        template.setdefault("policy", {})
    policy = _json_object(template.get("policy"), "policy")
    if create:
        policy.setdefault("levels", {})
        policy.setdefault("system", {})
    levels = _json_object(policy.get("levels"), "policy.levels")
    if create:
        levels.setdefault("0", {})
    user = _json_object(levels.get("0"), "policy.levels.0")
    system = _json_object(policy.get("system"), "policy.system")
    # The API template contains nested objects, not JSON-encoded subfields.
    # Assign them back so even an accepted legacy encoded object is normalized.
    levels["0"] = user
    policy.update(levels=levels, system=system)
    template["policy"] = policy
    return user, system


def apply_monitoring(client, instance):
    """Apply an explicitly managed mode without changing client identities.

    Legacy manifests intentionally do not read or write the Xray template.
    Retention is owned by the operating-system collector, not 3x-ui settings.
    """
    monitoring = instance.get("monitoring")
    if monitoring is None:
        return
    expected_log = _monitoring_log(monitoring.get("mode"))
    current = client.get_xray_settings()
    desired = deepcopy(current)
    existing_log = _json_object(desired.get("log", {}), "log")
    if set(existing_log) - set(expected_log):
        raise PanelError("Extra Xray log settings are outside managed monitoring")
    desired["log"] = expected_log
    desired.setdefault("stats", {})
    _json_object(desired.get("stats"), "stats")
    user, system = _monitoring_policy(desired, create=True)
    user.update({field: True for field in _USER_STATS})
    system.update({field: True for field in _INBOUND_STATS})
    if desired != current:
        client.save_xray_settings(desired)


def validate_monitoring(client, instance):
    """Validate live monitoring; changing its mode requires the installer CLI.

    A panel-only mode change cannot synchronize archive collection or retention.
    Reject it during export/repeat instead of writing a misleading manifest.
    """
    monitoring = instance.get("monitoring")
    if monitoring is None:
        return None
    template = client.get_xray_settings()
    log = _json_object(template.get("log"), "log")
    access = log.get("access")
    mode = {"none": "basic", ACCESS_LOG_PATH: "destinations"}.get(access) if isinstance(access, str) else None
    if mode is None or log != _monitoring_log(mode):
        raise PanelError("Xray logs changed outside managed monitoring")
    if mode != monitoring.get("mode"):
        raise PanelError("Monitoring mode differs; change it through the installer CLI")
    _json_object(template.get("stats"), "stats")
    user, system = _monitoring_policy(template, create=False)
    if (any(user.get(field) is not True for field in _USER_STATS)
            or any(system.get(field) is not True for field in _INBOUND_STATS)):
        raise PanelError("Required client monitoring counters are disabled")
    return deepcopy(monitoring)


def build_inbound(instance):
    """Build the one supported inbound, preserving every supplied identity."""
    profile = instance["profile"]
    if profile not in ("reality", "hysteria2"):
        raise PanelError("Unsupported profile")
    clients = []
    for user in instance["users"]:
        client = {
            "email": _nonempty_string(user.get("email"), "email"),
            "subId": _nonempty_string(user.get("sub_id"), "sub_id"),
            "enable": user["enable"], "expiryTime": user["expiry_time"],
            "totalGB": user["total_gb"], "limitIp": user["limit_ip"],
            "reset": 0,
        }
        if profile == "reality":
            client.update(id=_nonempty_string(user.get("uuid"), "uuid"),
                          flow="xtls-rprx-vision")
        else:
            # 3x-ui's Hysteria credential is auth, not password.
            client["auth"] = _nonempty_string(user.get("password"), "password")
        clients.append(client)
    if profile == "reality":
        reality = instance["reality"]
        for key in ("target", "server_name", "private_key", "public_key", "short_id"):
            _nonempty_string(reality.get(key), "reality." + key)
        settings = {"clients": clients, "decryption": "none", "fallbacks": []}
        stream = {
            "network": "tcp", "security": "reality",
            "realitySettings": {
                "show": False, "xver": 0, "target": reality["target"],
                "serverNames": [reality["server_name"]],
                "privateKey": reality["private_key"], "shortIds": [reality["short_id"]],
                "settings": {"publicKey": reality["public_key"],
                             "fingerprint": _fingerprint(reality.get("fingerprint", "chrome")),
                             "serverName": reality["server_name"], "spiderX": "/"},
            },
        }
        if _local_site(instance):
            stream["sockopt"] = {"acceptProxyProtocol": True}
            # v3.11 imports this into its normalized Hosts table on inbound
            # creation. The public endpoint must not leak the internal port.
            stream["externalProxy"] = _external_proxy(instance)
        protocol = "vless"
    else:
        cert_dir = "/etc/letsencrypt/live/" + instance["domain"]
        settings = {"version": 2, "clients": clients}
        stream = {
            "network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2},
            "tlsSettings": {
                "serverName": instance["domain"], "alpn": ["h3"],
                "certificates": [{"certificateFile": cert_dir + "/fullchain.pem",
                                  "keyFile": cert_dir + "/privkey.pem"}],
            },
        }
        protocol = "hysteria"
    return {
        "enable": True, "listen": "127.0.0.1" if _local_site(instance) else "::",
        "port": 10443 if _local_site(instance) else 443,
        "protocol": protocol, "remark": "vpn-installer-" + profile,
        "tag": "vpn-installer-" + profile, "total": 0, "expiryTime": 0,
        "trafficReset": "never", "excludeFromSub": False,
        "settings": _dump(settings), "streamSettings": _dump(stream),
        "sniffing": _dump({"enabled": False}),
        "shareAddrStrategy": "custom", "shareAddr": vpn_domain(instance),
    }


def _one_inbound(inbounds, instance):
    if instance["profile"] not in ("reality", "hysteria2"):
        raise PanelError("Unsupported profile")
    if len(inbounds) != 1:
        raise PanelError("Portable configuration requires exactly one inbound")
    inbound = inbounds[0]
    protocol = "vless" if instance["profile"] == "reality" else "hysteria"
    expected_port = 10443 if _local_site(instance) else 443
    listeners = ("127.0.0.1",) if _local_site(instance) else ("", "0.0.0.0", "::")
    if (inbound.get("protocol") != protocol or inbound.get("port") != expected_port
            or inbound.get("nodeId") not in (None, 0)
            or inbound.get("listen", "") not in listeners
            or inbound.get("enable") is not True
            or inbound.get("excludeFromSub", False)
            or inbound.get("total", 0) or inbound.get("expiryTime", 0)
            or inbound.get("disableFlow", False)):
        raise PanelError("Inbound changes cannot be represented by the portable configuration")
    stream = _json_object(inbound.get("streamSettings"), "streamSettings")
    settings = _json_object(inbound.get("settings"), "settings")
    if instance.get("monitoring") is not None:
        sniffing = _json_object(inbound.get("sniffing"), "sniffing")
        if sniffing.get("enabled") is not False:
            raise PanelError("Managed monitoring requires sniffing to remain disabled")
    if stream.get("finalmask") or settings.get("fallbacks") or inbound.get("fallbackParent"):
        raise PanelError("Extra transport features cannot be represented by the portable configuration")
    if instance["profile"] == "reality":
        if (stream.get("network") not in ("tcp", "raw")
                or stream.get("security") != "reality"
                or settings.get("decryption", "none") != "none"):
            raise PanelError("Expected VLESS with TCP REALITY")
        if _local_site(instance):
            reality = _json_object(stream.get("realitySettings"), "realitySettings")
            if (stream.get("sockopt") != {"acceptProxyProtocol": True}
                    or _without_host_fingerprint(stream).get("externalProxy") !=
                    _without_host_fingerprint({"externalProxy": _external_proxy(instance)})["externalProxy"]
                    or reality.get("target") != LOCAL_REALITY_TARGET
                    or reality.get("serverNames") != [vpn_domain(instance)]
                    or reality.get("xver", 0) != 0):
                raise PanelError("Local REALITY site or public endpoint settings changed")
    else:
        hysteria = _json_object(stream.get("hysteriaSettings"), "hysteriaSettings")
        if (stream.get("network") != "hysteria" or stream.get("security") != "tls"
                or settings.get("version") != 2 or hysteria.get("version") != 2):
            raise PanelError("Expected Hysteria version 2 with TLS")
    return inbound, settings, stream


def _validate_hosts(client, instance, inbound):
    """Check normalized hosts: they supersede streamSettings.externalProxy."""
    if instance["schema_version"] == 1:
        return  # Keep the legacy API contract and direct-listener layout intact.
    hosts = client.list_hosts()
    if not _local_site(instance):
        if hosts:
            raise PanelError("Custom advertised hosts are outside the portable configuration")
        return
    if len(hosts) != 1:
        raise PanelError("Local REALITY requires exactly one managed advertised host")
    host = hosts[0]
    if (host.get("inboundId") != inbound["id"] or host.get("address") != vpn_domain(instance)
            or host.get("port") != 443 or host.get("security") != "same"
            or host.get("remark") != "vpn-installer-reality"
            or host.get("isDisabled", False) or host.get("isHidden", False)
            or host.get("randomCount", 1) != 1):
        raise PanelError("Managed advertised host changed; public VPN endpoint must remain on port 443")
    # These optional overrides would change the generated client config but
    # cannot be represented by schema 2. Ignore only row identity/timestamps.
    unsupported = (
        "serverDescription", "tags", "sni", "snis", "sniSharedRandom", "hostHeader", "path",
        "alpn", "cipherSuites", "overrideSniFromAddress", "keepSniBlank",
        "pinnedPeerCertSha256", "verifyPeerCertByName", "allowInsecure", "echConfigList",
        "muxParams", "sockoptParams", "finalMask", "vlessRoute", "excludeFromSubTypes",
        "mihomoIpVersion", "mihomoX25519", "shuffleHost", "nodeGuids",
    )
    if any(host.get(field) for field in unsupported):
        raise PanelError("Managed host overrides cannot be represented by the portable configuration")
    fingerprint = host.get("fingerprint")
    if fingerprint not in (None, ""):
        return _fingerprint(fingerprint)
    return None


def apply_fingerprint(client, instance):
    """Apply only the requested fingerprints; caller owns backup/rollback/restart."""
    if instance['profile'] != 'reality':
        raise PanelError('Fingerprint changes require the REALITY profile')
    fingerprint = _fingerprint(instance['reality'].get('fingerprint', 'chrome'))
    host_fingerprint = instance['reality'].get('host_fingerprint')
    if host_fingerprint is not None:
        host_fingerprint = _fingerprint(host_fingerprint)
    inbound, _, stream = _one_inbound(client.list_inbounds(), instance)
    live_host_fingerprint = _validate_hosts(client, instance, inbound)
    group = None
    if _local_site(instance) and live_host_fingerprint != host_fingerprint:
        host = client.list_hosts()[0]
        group_id = _nonempty_string(host.get('groupId'), 'Host groupId')
        group = client.get_host_group(group_id)
        if (group.get('groupId') != group_id or group.get('inboundIds') != [inbound['id']]
                or not isinstance(group.get('hosts'), list) or len(group['hosts']) != 1):
            raise PanelError('Managed Host group changed; refusing to replace other endpoints')
        group['fingerprint'] = host_fingerprint or ''
    stream = deepcopy(stream)
    settings = _json_object(stream['realitySettings'].get('settings'), 'REALITY client settings')
    if settings.get('fingerprint') != fingerprint:
        settings['fingerprint'] = fingerprint
        stream['realitySettings']['settings'] = settings
        payload = deepcopy(inbound)
        payload['streamSettings'] = _dump(stream)
        # Keep externalProxy byte-for-byte equivalent: editing it can trigger
        # upstream's legacy Host import. Only the normalized Hosts API owns overrides.
        client.update_inbound(payload)
    if group is not None:
        client.update_host_group(group)


def configure_instance(client, instance):
    """Initialize an empty panel. Existing instances are checked, not reset."""
    expected = build_inbound(instance)  # Validate identities before any mutation.
    existing = client.list_inbounds()
    if existing:
        inbound, _, stream = _one_inbound(existing, instance)
        expected_stream = json.loads(expected["streamSettings"])
        if (_without_host_fingerprint(stream) != _without_host_fingerprint(expected_stream)
                or inbound.get("shareAddr") != vpn_domain(instance)):
            raise PanelError("Existing inbound differs; export its current configuration first")
        if _validate_hosts(client, instance, inbound) != instance.get("reality", {}).get("host_fingerprint"):
            raise PanelError("Host fingerprint differs; export its current configuration first")
        desired = instance_settings(instance)
        live = client.get_settings()
        if any(live.get(key) != value for key, value in desired.items()):
            raise PanelError("Existing panel settings differ; export before reinstalling")
        validate_monitoring(client, instance)
        return inbound
    if client.list_clients():
        raise PanelError("Refusing to initialize a panel containing unattached users")
    if instance["schema_version"] == 2 and client.list_hosts():
        raise PanelError("Refusing to initialize a panel containing unattached advertised hosts")
    client.save_settings(instance_settings(instance))
    apply_monitoring(client, instance)
    inbound = client.add_inbound(expected)
    if _validate_hosts(client, instance, inbound) != instance.get("reality", {}).get("host_fingerprint"):
        raise PanelError("Panel did not preserve the Host fingerprint")
    return inbound


def export_instance(client, baseline):
    """Export current identities from normalized API records, never settings.clients."""
    result = deepcopy(baseline)
    live = client.get_settings()
    expected = instance_settings(baseline)
    layout_fields = (
        "webListen", "webPort", "webDomain", "webBasePath", "webCertFile", "webKeyFile",
        "subListen", "subPort", "subDomain", "subPath", "subURI", "subCertFile", "subKeyFile",
        "trustedProxyCIDRs",
    )
    # Nginx, TLS renewal and the firewall are managed outside the panel. A
    # settings-only edit cannot safely change this layout: exporting it would
    # publish new URLs while those other components still serve the old ones.
    if any(live.get(field) != expected[field] for field in layout_fields):
        raise PanelError("Panel listener or public URL layout changed; restore the managed settings before export")
    inbound, _, stream = _one_inbound(client.list_inbounds(), baseline)
    host_fingerprint = _validate_hosts(client, baseline, inbound)
    monitoring = validate_monitoring(client, baseline)
    if monitoring is not None:
        result["monitoring"] = monitoring
    path = _nonempty_string(live.get("subPath"), "subPath")
    raw_uri = _nonempty_string(live.get("subURI"), "subURI")
    uri = urllib.parse.urlsplit(raw_uri)
    try:
        port = uri.port
    except ValueError:
        raise PanelError("Invalid public subscription URL") from None
    if (uri.scheme != "https" or not uri.hostname or uri.username or uri.password
            or uri.query or uri.fragment or port != (8443 if baseline["schema_version"] == 1 else None)
            or uri.path != path
            or not path.startswith("/") or not path.endswith("/")):
        raise PanelError("Subscription URL is outside the portable deployment layout")
    if (live.get("subEnable") is not True or live.get("subEncrypt") is not True
            or live.get("subJsonAutoDetect", False) or live.get("subClashAutoDetect", False)):
        raise PanelError("Expected an enabled Base64 subscription without format autodetection")
    if raw_uri != public_origin(baseline) + path:
        raise PanelError("Subscription URL is not in its portable canonical form")
    if (inbound.get("shareAddrStrategy") != "custom"
            or inbound.get("shareAddr") != vpn_domain(result)):
        raise PanelError("VPN address differs from the portable public domain")
    if baseline["profile"] == "reality":
        reality = _json_object(stream.get("realitySettings"), "realitySettings")
        names, ids = reality.get("serverNames"), reality.get("shortIds")
        if not isinstance(names, list) or len(names) != 1 or not isinstance(ids, list) or len(ids) != 1:
            raise PanelError("Portable configuration supports one REALITY server name and short ID")
        client_settings = _json_object(reality.get("settings"), "realitySettings.settings")
        result["reality"] = {
            "target": _nonempty_string(reality.get("target") or reality.get("dest"), "target"),
            "server_name": _nonempty_string(names[0], "server_name"),
            "private_key": _nonempty_string(reality.get("privateKey"), "private_key"),
            "public_key": _nonempty_string(client_settings.get("publicKey"), "public_key"),
            "short_id": _nonempty_string(ids[0], "short_id"),
        }
        fingerprint = client_settings.get("fingerprint")
        fingerprint = "chrome" if fingerprint in (None, "") else _fingerprint(fingerprint)
        # Absence in legacy manifests means chrome, never the new-install default.
        if "fingerprint" in baseline["reality"] or fingerprint != "chrome":
            result["reality"]["fingerprint"] = fingerprint
        if host_fingerprint is not None:
            result["reality"]["host_fingerprint"] = host_fingerprint
    else:
        tls = _json_object(stream.get("tlsSettings"), "tlsSettings")
        cert_dir = "/etc/letsencrypt/live/" + result["domain"]
        certs = tls.get("certificates")
        if (tls.get("serverName") != result["domain"] or tls.get("alpn") != ["h3"]
                or not isinstance(certs, list) or len(certs) != 1
                or not isinstance(certs[0], dict)
                or certs[0].get("certificateFile") != cert_dir + "/fullchain.pem"
                or certs[0].get("keyFile") != cert_dir + "/privkey.pem"):
            raise PanelError("TLS changes cannot be represented by the portable configuration")
    users = []
    for row in client.list_clients():
        attached = row.get("inboundIds") or []
        if inbound["id"] not in attached:
            continue
        if attached != [inbound["id"]]:
            raise PanelError("A user is attached to unsupported additional inbounds")
        # The detail endpoint resolves per-inbound flow_override and external
        # links. The list endpoint alone does not carry those effective values.
        detail = client.get_client(_nonempty_string(row.get("email"), "email"))
        row = detail["client"]
        if detail.get("inboundIds") != attached:
            raise PanelError("User attachments changed during export; retry")
        if (detail.get("externalLinks") or row.get("clientHostRuleIds")
                or row.get("reverse") or row.get("limitHwid", 0)
                or any(row.get(key, 0) for key in ("reset", "resetDay", "resetWeekday", "resetMax"))
                or row.get("trafficReset", "never") not in ("", "never")
                or (baseline["profile"] == "reality" and row.get("flow") != "xtls-rprx-vision")):
            raise PanelError("User settings cannot be represented by the portable configuration")
        user = {
            "email": _nonempty_string(row.get("email"), "email"),
            "sub_id": _nonempty_string(row.get("subId"), "sub_id"),
            "enable": row.get("enable"), "expiry_time": row.get("expiryTime"),
            "total_gb": row.get("totalGB"), "limit_ip": row.get("limitIp"),
        }
        if not isinstance(user["enable"], bool) or any(
                type(user[key]) is not int for key in ("expiry_time", "total_gb", "limit_ip")):
            raise PanelError("Panel returned invalid user limits")
        field, source = ("uuid", "uuid") if baseline["profile"] == "reality" else ("password", "auth")
        user[field] = _nonempty_string(row.get(source), source)
        users.append(user)
    emails = [user["email"].lower() for user in users]
    sub_ids = [user["sub_id"] for user in users]
    if len(set(emails)) != len(emails) or len(set(sub_ids)) != len(sub_ids):
        raise PanelError("Duplicate user identities in live panel")
    result["users"] = users
    return result
