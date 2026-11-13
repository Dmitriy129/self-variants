"""Disposable-container smoke test of pinned 3x-ui, Xray and Nginx binaries.

The test creates self-signed certificates and fixture hostnames *inside* a
container.  It does not exercise public ACME, UFW, systemd, Russian networks,
or an Android client.  Tunnel traffic uses the returned subscription identity
and a narrow test-only route allowing the local HTTP fixture.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vpn_installer.config import new_instance, validate_instance
from vpn_installer.network import render_nginx
from vpn_installer.panel import PanelClient, configure_instance, export_instance
from vpn_installer.system import digest_file, download_artifacts, install_binaries, read_versions


DOMAIN = "vpn.example.test"
TARGET = "target.example.test"
FIXTURE_BODY = b"vpn-installer-real-protocol-smoke-test\n"
REDACTIONS: set[str] = set()
LOGS: list[Path] = []


def run(argv, **kwargs):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{Path(argv[0]).name} failed ({result.returncode}): {redact(result.stdout[-2500:])}")
    return result.stdout


def redact(text):
    for value in sorted(REDACTIONS, key=len, reverse=True):
        text = text.replace(value, "[redacted]")
    return text


def collect_secrets(instance):
    REDACTIONS.update((instance["panel"]["path"], instance["panel"]["password"]))
    for user in instance["users"]:
        REDACTIONS.update((user["sub_id"], user.get("uuid", user.get("password", ""))))
    if "reality" in instance:
        REDACTIONS.update(instance["reality"][key] for key in ("private_key", "public_key", "short_id"))
    REDACTIONS.discard("")


class ManagedProcess:
    def __init__(self, argv, logfile, **kwargs):
        self.logfile = Path(logfile)
        LOGS.append(self.logfile)
        self.stream = self.logfile.open("w")
        self.process = subprocess.Popen(argv, stdout=self.stream, stderr=subprocess.STDOUT,
                                        start_new_session=True, **kwargs)

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


def wait_for(callback, description, process=None, seconds=30):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        if process is not None and process.process.poll() is not None:
            raise RuntimeError(f"process exited while waiting for {description}")
        try:
            return callback()
        except (OSError, ValueError, RuntimeError) as error:
            last = error
            time.sleep(0.2)
    raise RuntimeError(f"timed out waiting for {description}: {last}")


def ready_port(port):
    with socket.create_connection(("127.0.0.1", port), timeout=1):
        return True


def prepare_certificates(work):
    certdir = Path("/etc/letsencrypt/live") / DOMAIN
    certdir.mkdir(parents=True)
    cert, key = certdir / "fullchain.pem", certdir / "privkey.pem"
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", str(key), "-out", str(cert), "-subj", f"/CN={DOMAIN}",
         "-addext", f"subjectAltName=DNS:{DOMAIN},DNS:{TARGET}"])
    with Path("/etc/hosts").open("a") as hosts:
        hosts.write(f"\n127.0.0.1 {DOMAIN} {TARGET}\n")
    return cert, key


def artifacts_from(directory, work):
    versions = read_versions()
    if directory is None:
        return download_artifacts(versions, work / "downloads")
    artifacts = {}
    for name, item in versions.items():
        basename = Path(urllib.parse.urlsplit(item["url"]).path).name
        suffix = "-panel.tar.gz" if name == "3x-ui" else "-xray.zip"
        candidates = [directory / basename, directory / (item["sha256"] + suffix)]
        found = next((path for path in candidates if path.is_file()), None)
        if found is None or digest_file(found) != item["sha256"]:
            raise RuntimeError(f"missing or incorrect pinned {name} archive")
        artifacts[name] = found
    return artifacts


def test_instance(profile):
    instance = new_instance(profile, DOMAIN, "owner@example.test",
                            reality_target=f"{TARGET}:9443" if profile == "reality" else None)
    # Test multiple independently portable users and both boolean states.
    for index in (2, 3):
        user = copy.deepcopy(instance["users"][0])
        user.update(email=f"user{index}@{DOMAIN}", sub_id=secrets.token_urlsafe(18),
                    enable=index == 2, total_gb=50 * 1024**3, limit_ip=2,
                    expiry_time=4102444800000 if index == 3 else 0)
        user["uuid" if profile == "reality" else "password"] = str(uuid.uuid4()) if profile == "reality" else secrets.token_urlsafe(24)
        instance["users"].append(user)
    collect_secrets(instance)
    return validate_instance(instance)


def launch_panel(app, database, instance, logfile):
    database.mkdir(mode=0o700)
    env = dict(os.environ, XUI_DB_FOLDER=str(database), XUI_BIN_FOLDER=str(app / "bin"),
               XUI_LOG_FOLDER=str(database / "logs"), XUI_LOG_LEVEL="warning",
               XRAY_LOCATION_ASSET=str(app / "bin"))
    run([str(app / "x-ui"), "setting", "-listenIP", "127.0.0.1", "-port", "2053",
         "-webBasePath", instance["panel"]["path"], "-username", instance["panel"]["username"],
         "-password", instance["panel"]["password"]], cwd=app, env=env)
    return ManagedProcess([str(app / "x-ui")], logfile, cwd=app, env=env), env


def login(instance):
    return PanelClient("http://127.0.0.1:2053" + instance["panel"]["path"],
                       instance["panel"]["username"], instance["panel"]["password"], timeout=3).login()


def get_subscription(instance, user):
    request = urllib.request.Request(
        "http://127.0.0.1:2096" + instance["subscription"]["path"] + user["sub_id"],
        headers={"Host": instance["domain"], "User-Agent": "v2rayNG/1.10.0"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as response:
        raw = response.read().strip()
    decoded = base64.b64decode(raw, validate=True).decode()
    uris = [line for line in decoded.splitlines() if line]
    if len(uris) != 1:
        raise RuntimeError("expected exactly one tunnel URI per enabled user")
    uri = urllib.parse.urlsplit(uris[0])
    credential = urllib.parse.unquote(uri.username or "")
    expected = user["uuid"] if instance["profile"] == "reality" else user["password"]
    if uri.hostname != DOMAIN or uri.port != 443 or credential != expected:
        raise RuntimeError("subscription address or identity differs from the manifest")
    if uri.scheme not in (("vless",) if instance["profile"] == "reality" else ("hysteria2", "hy2")):
        raise RuntimeError("subscription uses an unexpected protocol")
    return uris[0]


def generated_config(app, profile, empty=False):
    for candidate in (app / "bin/config.json", app / "config.json"):
        if candidate.exists():
            data = json.loads(candidate.read_text())
            matches = [inbound for inbound in data.get("inbounds", [])
                       if inbound.get("protocol") == ("vless" if profile == "reality" else "hysteria")]
            if empty and all(not inbound.get("settings", {}).get("clients") for inbound in matches):
                return data
            if not empty and matches:
                return data
    raise RuntimeError("panel has not generated its tunnel configuration")


def check_core_running(client):
    if not client.xray_running():
        raise RuntimeError("panel does not report a running, error-free Xray core")
    return True


def check_nginx(work, instance):
    include = work / "nginx-include.conf"
    main = work / "nginx.conf"
    main.write_text(f"pid {work}/nginx.pid;\nerror_log /dev/null;\nevents {{}}\nhttp {{ include {include}; }}\n")
    for enabled in (False, True):
        include.write_text(render_nginx(instance, tls_enabled=enabled))
        run(["nginx", "-t", "-c", str(main)])


def configure_export(app, work, profile, instance, number):
    process, env = launch_panel(app, work / f"db-{profile}-{number}", instance,
                                work / f"panel-{profile}-{number}.log")
    try:
        client = wait_for(lambda: login(instance), "panel API login", process)
        configure_instance(client, instance)
    finally:
        process.close()
    # Subscription settings take effect on process restart, just as after install.
    empty_export = None
    with ManagedProcess([str(app / "x-ui")], work / f"panel-{profile}-{number}-restart.log", cwd=app, env=env) as process:
        client = wait_for(lambda: login(instance), "restarted panel API", process)
        exported = validate_instance(export_instance(client, instance))
        if exported != instance:
            raise RuntimeError("API export did not preserve all portable identities and limits")
        subscriptions = {}
        for user in instance["users"]:
            if user["enable"]:
                subscriptions[user["email"]] = wait_for(lambda user=user: get_subscription(instance, user),
                                                        "Base64 subscription", process)
        data = wait_for(lambda: generated_config(app, profile, empty=not instance["users"]),
                        "generated Xray configuration", process)
        wait_for(lambda: check_core_running(client), "panel Xray health status", process)
        runtime_json = json.dumps(data)
        for user in instance["users"]:
            credential = user.get("uuid", user.get("password"))
            if not user["enable"] and credential in runtime_json:
                raise RuntimeError("disabled user credential is present in the generated Xray runtime")
        path = work / f"server-{profile}-{number}.json"
        path.write_text(json.dumps(data))
        run([str(app / "bin/xray-linux-amd64"), "run", "-test", "-config", str(path)], cwd=app, env=env)
        check_nginx(work, instance)
        if number == 2:
            for user in instance["users"]:
                client._request("POST", "panel/api/clients/del/" + urllib.parse.quote(user["email"], safe=""), {})
            empty_export = validate_instance(export_instance(client, instance))
            if empty_export["users"]:
                raise RuntimeError("deleted users reappeared in the live export")
    return exported, subscriptions, data, env, empty_export


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(FIXTURE_BODY)))
        self.end_headers()
        self.wfile.write(FIXTURE_BODY)

    def log_message(self, *unused):
        pass


def client_configuration(uri, server_address="127.0.0.1"):
    parsed = urllib.parse.urlsplit(uri)
    query = urllib.parse.parse_qs(parsed.query)
    value = lambda key, default="": query.get(key, [default])[0]
    credential = urllib.parse.unquote(parsed.username or "")
    if parsed.scheme == "vless":
        outbound = {
            "protocol": "vless", "settings": {"vnext": [{"address": server_address, "port": 443,
                "users": [{"id": credential, "encryption": "none", "flow": value("flow")}]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "serverName": value("sni"), "fingerprint": value("fp", "chrome"),
                "publicKey": value("pbk"), "shortId": value("sid"), "spiderX": value("spx", "/")}},
        }
    else:
        test_certificate = Path("/etc/letsencrypt/live") / DOMAIN / "fullchain.pem"
        pinned_certificate = hashlib.sha256(ssl.PEM_cert_to_DER_cert(test_certificate.read_text())).hexdigest()
        outbound = {
            "protocol": "hysteria", "settings": {"version": 2, "address": server_address, "port": 443},
            "streamSettings": {"network": "hysteria", "security": "tls",
                "hysteriaSettings": {"version": 2, "auth": credential},
                # Pin the self-signed test certificate without disabling verification.
                "tlsSettings": {"serverName": value("sni", DOMAIN), "pinnedPeerCertSha256": pinned_certificate, "alpn": ["h3"]}},
        }
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [outbound]}


def receive_exact(stream, length):
    data = b""
    while len(data) < length:
        part = stream.recv(length - len(data))
        if not part:
            raise RuntimeError("SOCKS connection closed unexpectedly")
        data += part
    return data


def request_through_tunnel():
    with socket.create_connection(("127.0.0.1", 10808), timeout=10) as stream:
        stream.sendall(b"\x05\x01\x00")
        if receive_exact(stream, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS negotiation failed")
        stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 18080))
        reply = receive_exact(stream, 4)
        if reply[:2] != b"\x05\x00":
            raise RuntimeError("SOCKS tunnel connection failed")
        address_size = {1: 4, 4: 16}.get(reply[3])
        if reply[3] == 3:
            address_size = receive_exact(stream, 1)[0]
        if address_size is None:
            raise RuntimeError("invalid SOCKS response")
        receive_exact(stream, address_size + 2)
        stream.sendall(b"GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
        data = b""
        while len(data) < 65536:
            part = stream.recv(4096)
            if not part:
                break
            data += part
        if FIXTURE_BODY not in data or not data.startswith(b"HTTP/1.0 200"):
            raise RuntimeError("HTTP payload did not traverse the real tunnel")


def tunnel_test(app, work, profile, server_config, subscriptions, env):
    server = copy.deepcopy(server_config)
    server["log"] = {"loglevel": "warning"}
    # The production template correctly blocks private destinations.  This
    # single exact test route permits only our local HTTP fixture.
    server.setdefault("outbounds", []).append({
        "tag": "smoke-direct", "protocol": "freedom", "settings": {"finalRules": [
            {"action": "allow", "ip": ["127.0.0.1/32"], "port": "18080"}]}})
    server.setdefault("routing", {}).setdefault("rules", []).insert(0, {
        "type": "field", "ip": ["127.0.0.1/32"], "port": "18080", "outboundTag": "smoke-direct"})
    server_path = work / f"traffic-server-{profile}.json"
    client_path = work / f"traffic-client-{profile}.json"
    server_path.write_text(json.dumps(server))
    binary = str(app / "bin/xray-linux-amd64")
    with ManagedProcess([binary, "run", "-config", str(server_path)], work / f"traffic-server-{profile}.log", cwd=app, env=env) as server_process:
        # QUIC has no TCP listener; allow its initial socket creation briefly.
        time.sleep(0.5)
        for index, uri in enumerate(subscriptions.values()):
            for family, address in (("ipv4", "127.0.0.1"), ("ipv6", "::1")):
                client_path.write_text(json.dumps(client_configuration(uri, address)))
                run([binary, "run", "-test", "-config", str(client_path)], cwd=app, env=env)
                with ManagedProcess([binary, "run", "-config", str(client_path)], work / f"traffic-client-{profile}-{index}-{family}.log", cwd=app, env=env) as client_process:
                    wait_for(lambda: ready_port(10808), "client SOCKS socket", client_process)
                    wait_for(request_through_tunnel, "real tunneled HTTP payload", client_process, seconds=20)
                if server_process.process.poll() is not None:
                    raise RuntimeError("test Xray server exited")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path)
    args = parser.parse_args()
    if not Path("/.dockerenv").exists() or os.environ.get("VPN_INSTALLER_INTEGRATION") != "1":
        raise SystemExit("Use tests/run-integration.sh: this test writes only inside its disposable container.")
    with tempfile.TemporaryDirectory(prefix="vpn-integration-") as directory:
        work = Path(directory)
        try:
            app = work / "app"
            install_binaries(artifacts_from(args.artifacts_dir, work), app)
            print("PASS: pinned release archives verified and binaries extracted", flush=True)
            cert, key = prepare_certificates(work)
            fixture = ThreadingHTTPServer(("127.0.0.1", 18080), FixtureHandler)
            thread = threading.Thread(target=fixture.serve_forever, daemon=True)
            thread.start()
            try:
                with ManagedProcess(["openssl", "s_server", "-accept", "9443", "-cert", str(cert),
                                     "-key", str(key), "-tls1_3", "-alpn", "h2,http/1.1", "-www"],
                                    work / "reality-target.log") as target:
                    wait_for(lambda: ready_port(9443), "local TLS 1.3 REALITY target", target)
                    for profile in ("reality", "hysteria2"):
                        original = test_instance(profile)
                        exported, first_urls, _, _, _ = configure_export(app, work, profile, original, 1)
                        restored, second_urls, runtime, env, empty = configure_export(app, work, profile, exported, 2)
                        if restored != original or first_urls != second_urls:
                            raise RuntimeError("fresh database restore changed identities or subscription URIs")
                        print(f"PASS: {profile}: real panel API, Base64 subscriptions, exact clean-DB restore, Xray config and Nginx syntax", flush=True)
                        tunnel_test(app, work, profile, runtime, second_urls, env)
                        print(f"PASS: {profile}: both enabled subscription identities carried HTTP through real Xray over IPv4 and IPv6", flush=True)
                        empty_restored, empty_urls, _, _, _ = configure_export(app, work, profile, empty, 3)
                        if empty_restored["users"] or empty_urls:
                            raise RuntimeError("empty restore resurrected deleted users")
                        print(f"PASS: {profile}: deleting all users and restoring their empty export preserved revocation", flush=True)
            finally:
                fixture.shutdown()
                fixture.server_close()
        except Exception:
            for path in LOGS:
                if path.exists():
                    tail = redact(path.read_text(errors="replace")[-2500:])
                    print(f"--- {path.name} (test-only, redacted) ---\n{tail}", file=sys.stderr)
            raise
    print("PASS: integration complete; no public ACME, UFW, systemd, Android or censorship test was performed", flush=True)


if __name__ == "__main__":
    main()
