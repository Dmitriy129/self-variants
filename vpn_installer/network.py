"""Manage the small public HTTP surface and host firewall.

Only the management panel and subscriptions are reverse-proxied by Nginx.
The selected tunnel owns port 443 directly.  Pass a subprocess.run-compatible
``runner`` and a temporary ``root`` to exercise this module without changing
the host.  Package installation and ownership/conflict checks belong to the
installer's preflight.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile
from collections.abc import Callable, Iterable, Mapping
from typing import Any


Runner = Callable[..., Any]
NGINX_CONFIG = Path("/etc/nginx/conf.d/vpn-installer.conf")
ACME_ROOT = Path("/var/www/vpn-acme")
RENEW_HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/vpn-installer")
_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PATH = re.compile(r"/(?:[A-Za-z0-9_-]+/)+\Z")


def _port(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError(f"{name} must be an integer from 1 to 65535")
    return value


def _settings(instance: Mapping[str, Any]) -> tuple[str, str, int, str, str, str]:
    """Defend the rendering boundary even when called outside the CLI."""
    if not isinstance(instance, Mapping):
        raise ValueError("instance must be a mapping")
    domain = instance.get("domain")
    email = instance.get("email")
    profile = instance.get("profile")
    if not isinstance(domain, str) or not _DOMAIN.fullmatch(domain):
        raise ValueError("domain must be a lowercase ASCII DNS hostname")
    if not isinstance(email, str) or not re.fullmatch(r"[^\s@\x00-\x1f]+@[^\s@\x00-\x1f]+\.[^\s@\x00-\x1f]+", email):
        raise ValueError("a valid certificate email is required")
    if profile not in ("reality", "hysteria2"):
        raise ValueError("profile must be reality or hysteria2")
    https_port = _port(instance.get("https_port", 8443), "https_port")
    if https_port in (80, 443, 2053, 2096):
        raise ValueError("https_port conflicts with an installer service")
    paths = []
    for section in ("panel", "subscription"):
        config = instance.get(section)
        path = config.get("path") if isinstance(config, Mapping) else None
        if not isinstance(path, str) or not _PATH.fullmatch(path):
            raise ValueError(f"{section}.path must contain safe path segments and start/end with /")
        paths.append(path)
    panel_path, subscription_path = paths
    if panel_path.startswith(subscription_path) or subscription_path.startswith(panel_path):
        raise ValueError("panel and subscription paths must not overlap")
    return domain, email, https_port, panel_path, subscription_path, profile


def render_nginx(instance: Mapping[str, Any], tls_enabled: bool = True) -> str:
    """Render an http-context include; proxy_pass deliberately has no URI."""
    domain, _, https_port, panel_path, subscription_path, _ = _settings(instance)
    http = f"""# Managed by vpn-installer. Local edits are replaced on reconfiguration.
server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    server_tokens off;
    access_log off;
    error_log /dev/null crit;
    if ($host != {domain}) {{ return 404; }}
    location ^~ /.well-known/acme-challenge/ {{
        root {ACME_ROOT};
        default_type text/plain;
        try_files $uri =404;
    }}
    location / {{ return 404; }}
}}
"""
    if not tls_enabled:
        return http

    locations = []
    for path, port in ((panel_path, 2053), (subscription_path, 2096)):
        locations.append(f"""    location ^~ {path} {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
        proxy_set_header Forwarded "";
        proxy_set_header Proxy "";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $vpn_connection_upgrade;
        proxy_redirect off;
        proxy_buffering off;
        proxy_read_timeout 300s;
    }}
""")
    return http + f"""
map $http_upgrade $vpn_connection_upgrade {{
    default upgrade;
    '' close;
}}

server {{
    listen {https_port} ssl;
    listen [::]:{https_port} ssl;
    server_name {domain};
    server_tokens off;
    access_log off;
    error_log /dev/null crit;
    if ($host != {domain}) {{ return 404; }}
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
{''.join(locations)}    location / {{ return 404; }}
}}
"""


def _target(root: Path, absolute: Path) -> Path:
    base = Path(root).resolve()
    target = base / absolute.relative_to("/")
    if target.is_symlink() or not target.resolve().is_relative_to(base):
        raise ValueError("refusing a managed file symlink or a path outside root")
    return target


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".vpn-installer-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _run(runner: Runner, root: Path, argv: list[str]) -> Any:
    if Path(root).resolve() != Path("/") and runner is subprocess.run:
        raise ValueError("a non-system root requires an injected runner")
    return runner(argv, check=True)


def _configure_nginx(instance: Mapping[str, Any], tls_enabled: bool, runner: Runner, root: Path) -> Path:
    content = render_nginx(instance, tls_enabled)
    # Reject accidental real service operations before even writing test files.
    if Path(root).resolve() != Path("/") and runner is subprocess.run:
        raise ValueError("a non-system root requires an injected runner")
    config = _target(root, NGINX_CONFIG)
    previous = config.read_bytes() if config.exists() else None
    previous_mode = config.stat().st_mode & 0o777 if previous is not None else 0o640
    acme = _target(root, ACME_ROOT / ".well-known/acme-challenge")
    acme.mkdir(parents=True, exist_ok=True)
    # The installer uses umask 077; Nginx's www-data worker must traverse the
    # public challenge directory, which contains no private certificate keys.
    for directory in (acme.parent.parent, acme.parent, acme):
        directory.chmod(0o755)
    _atomic_write(config, content.encode(), 0o640)
    try:
        _run(runner, root, ["nginx", "-t"])
    except Exception:
        if previous is None:
            config.unlink()
        else:
            _atomic_write(config, previous, previous_mode)
        raise
    _run(runner, root, ["systemctl", "enable", "--now", "nginx"])
    _run(runner, root, ["systemctl", "reload", "nginx"])
    return config


def configure_http(instance: Mapping[str, Any], runner: Runner = subprocess.run, root: Path = Path("/")) -> Path:
    """Start the challenge-only listener before requesting a certificate.

    The caller must remove/conflict-check any distribution default site during
    preflight; this module never removes unrelated Nginx sites.
    """
    return _configure_nginx(instance, False, runner, root)


def issue_certificate(instance: Mapping[str, Any], runner: Runner = subprocess.run, root: Path = Path("/")) -> None:
    """Issue/reuse the named certificate while configure_http's Nginx runs."""
    domain, email, *_ = _settings(instance)
    _run(runner, root, [
        "certbot", "certonly", "--webroot", "--webroot-path", str(ACME_ROOT),
        "--cert-name", domain, "--domain", domain, "--email", email,
        "--non-interactive", "--agree-tos", "--keep-until-expiring",
    ])


def render_renew_hook(instance: Mapping[str, Any]) -> str:
    """Renew only this instance's services; unrelated lineages are ignored."""
    domain, _, _, _, _, profile = _settings(instance)
    restart = "/usr/bin/systemctl restart x-ui\n" if profile == "hysteria2" else ""
    return f"""#!/bin/sh
# Managed by vpn-installer.
set -eu
case "${{RENEWED_LINEAGE:-}}" in
    /etc/letsencrypt/live/{domain}) ;;
    *) exit 0 ;;
esac
/usr/sbin/nginx -t
/usr/bin/systemctl reload nginx
{restart}"""


def configure_https(instance: Mapping[str, Any], runner: Runner = subprocess.run, root: Path = Path("/")) -> Path:
    """Activate TLS, then register renewal hooks and the apt Certbot timer."""
    hook = render_renew_hook(instance)
    path = _configure_nginx(instance, True, runner, root)
    _atomic_write(_target(root, RENEW_HOOK), hook.encode(), 0o750)
    _run(runner, root, ["systemctl", "enable", "--now", "certbot.timer"])
    return path


def configure_firewall(instance: Mapping[str, Any], ssh_ports: Iterable[int], runner: Runner = subprocess.run, root: Path = Path("/")) -> None:
    """Ensure required rules without resetting/deleting existing UFW rules.

    Fresh installs must pass the caller's clean-firewall preflight.  Managed
    reruns retain existing rules.  SSH rules are in place before deny policy
    or firewall activation, including when IPv6 was previously disabled.
    """
    _, _, https_port, _, _, profile = _settings(instance)
    ports = sorted({_port(port, "SSH port") for port in ssh_ports})
    if not ports:
        raise ValueError("at least one verified SSH listening port is required")
    if Path(root).resolve() != Path("/") and runner is subprocess.run:
        raise ValueError("a non-system root requires an injected runner")
    defaults = _target(root, Path("/etc/default/ufw"))
    text = defaults.read_text() if defaults.exists() else ""
    if re.search(r"(?m)^\s*IPV6\s*=", text):
        text = re.sub(r"(?m)^\s*IPV6\s*=.*$", "IPV6=yes", text)
    else:
        text = text.rstrip("\n") + "\nIPV6=yes\n"
    _atomic_write(defaults, text.encode(), 0o644)
    required = [(port, "tcp") for port in ports]
    required.extend([(80, "tcp"), (https_port, "tcp"), (443, "tcp" if profile == "reality" else "udp")])
    for port, protocol in dict.fromkeys(required):
        _run(runner, root, ["ufw", "allow", f"{port}/{protocol}"])
    _run(runner, root, ["ufw", "default", "deny", "incoming"])
    _run(runner, root, ["ufw", "default", "allow", "outgoing"])
    _run(runner, root, ["ufw", "--force", "enable"])

