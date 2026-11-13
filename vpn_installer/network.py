"""Manage the small public HTTP surface and host firewall.

Version 1 retains its separate management port.  Version 2 shares TCP 443
between management and REALITY using SNI, or serves management beside QUIC.
Pass a subprocess.run-compatible
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
NGINX_MAIN = Path("/etc/nginx/nginx.conf")
NGINX_STREAM = Path("/etc/nginx/stream-conf.d/vpn-installer.conf")
ACME_ROOT = Path("/var/www/vpn-acme")
SITE_ROOT = Path("/var/www/vpn-site")
RENEW_HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/vpn-installer")
TEMPLATES = frozenset(("field-notes", "ceramic-studio", "trail-journal", "reading-room"))
_STREAM_BEGIN = "# BEGIN vpn-installer stream"
_STREAM_END = "# END vpn-installer stream"
_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PATH = re.compile(r"/(?:[A-Za-z0-9_-]+/)+\Z")


def _port(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError(f"{name} must be an integer from 1 to 65535")
    return value


def _version(instance: Mapping[str, Any]) -> int:
    version = instance.get("schema_version", 1)
    if type(version) is not int or version not in (1, 2):
        raise ValueError("schema_version must be 1 or 2")
    return version


def _site_domain(instance: Mapping[str, Any]) -> str | None:
    if _version(instance) == 1 or instance.get("profile") != "reality":
        return None
    site = instance.get("site")
    if not isinstance(site, Mapping):
        raise ValueError("version 2 REALITY requires a site")
    domain = site.get("domain")
    if not isinstance(domain, str) or not _DOMAIN.fullmatch(domain):
        raise ValueError("site.domain must be a lowercase ASCII DNS hostname")
    if domain == instance.get("domain"):
        raise ValueError("site and management domains must be different")
    if site.get("template") not in TEMPLATES:
        raise ValueError("unknown site template")
    return domain


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
    version = _version(instance)
    https_port = _port(instance.get("https_port", 443 if version == 2 else 8443), "https_port")
    if version == 1 and https_port in (80, 443, 2053, 2096):
        raise ValueError("https_port conflicts with an installer service")
    if version == 2 and https_port != 443:
        raise ValueError("version 2 requires https_port 443")
    if version == 2:
        _site_domain(instance)
        if profile == "hysteria2" and "site" in instance:
            raise ValueError("Hysteria2 does not have a REALITY site")
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


def _http_server(domain: str, redirect: bool) -> str:
    fallback = f"return 301 https://{domain}$request_uri;" if redirect else "return 404;"
    return f"""server {{
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
    location / {{ {fallback} }}
}}
"""


def _proxy_locations(panel_path: str, subscription_path: str, public_port: str) -> str:
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
        proxy_set_header X-Forwarded-Port {public_port};
        proxy_set_header Forwarded "";
        proxy_set_header Proxy "";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $vpn_connection_upgrade;
        proxy_redirect off;
        proxy_buffering off;
        proxy_read_timeout 300s;
    }}
""")
    return ''.join(locations)


def _reject_server(listeners: list[str]) -> str:
    listen = '\n'.join(f"    listen {value} default_server;" for value in listeners)
    return f"""server {{
{listen}
    server_name _;
    access_log off;
    error_log /dev/null crit;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_reject_handshake on;
    return 421;
}}

"""


def render_nginx(instance: Mapping[str, Any], tls_enabled: bool = True) -> str:
    """Render an http-context include; proxy_pass deliberately has no URI."""
    domain, _, https_port, panel_path, subscription_path, profile = _settings(instance)
    version = _version(instance)
    site_domain = _site_domain(instance)
    http = "# Managed by vpn-installer. Local edits are replaced on reconfiguration.\n"
    http += _http_server(domain, redirect=version == 2)
    if site_domain:
        http += _http_server(site_domain, redirect=True)
    if not tls_enabled:
        return http
    real_ip = ""
    if version == 2 and profile == "reality":
        listeners = ["127.0.0.1:7443 ssl proxy_protocol"]
        real_ip = "    set_real_ip_from 127.0.0.1;\n    real_ip_header proxy_protocol;\n"
    else:
        listeners = [f"{https_port} ssl", f"[::]:{https_port} ssl"]
    reject = _reject_server(listeners) if version == 2 else ""
    listen = '\n'.join(f"    listen {value};" for value in listeners)
    locations = _proxy_locations(panel_path, subscription_path,
                                 "443" if version == 2 else "$server_port")
    http += f"""
map $http_upgrade $vpn_connection_upgrade {{
    default upgrade;
    '' close;
}}

{reject}server {{
{listen}
    server_name {domain};
    server_tokens off;
    access_log off;
    error_log /dev/null crit;
    if ($host != {domain}) {{ return 404; }}
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
{real_ip}{locations}    location / {{ return 404; }}
}}
"""
    if site_domain:
        http += "\n" + _reject_server(["127.0.0.1:9443 ssl http2"])
        http += f"""server {{
    listen 127.0.0.1:9443 ssl http2;
    server_name {site_domain};
    server_tokens off;
    access_log off;
    error_log /dev/null crit;
    if ($host != {site_domain}) {{ return 404; }}
    ssl_certificate /etc/letsencrypt/live/{site_domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{site_domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    root {SITE_ROOT};
    index index.html;
    location / {{ try_files $uri $uri/ =404; }}
}}
"""
    return http


def render_stream(instance: Mapping[str, Any]) -> str:
    """Render the stream-context SNI router without terminating TLS."""
    domain, *_ = _settings(instance)
    site_domain = _site_domain(instance)
    if not site_domain:
        return ""
    return f"""# Managed by vpn-installer. Included inside the top-level stream block.
map $ssl_preread_server_name $vpn_tls_upstream {{
    {domain} 127.0.0.1:7443;
    {site_domain} 127.0.0.1:10443;
    default 127.0.0.1:7443;
}}
server {{
    listen 443;
    listen [::]:443;
    ssl_preread on;
    proxy_protocol on;
    proxy_pass $vpn_tls_upstream;
    proxy_connect_timeout 5s;
    proxy_timeout 300s;
    access_log off;
    error_log /dev/null crit;
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


def _main_config(content: str, enable_stream: bool) -> str:
    """Change only our top-level block, refusing ambiguous existing ownership."""
    if content.count(_STREAM_BEGIN) != content.count(_STREAM_END) or content.count(_STREAM_BEGIN) > 1:
        raise ValueError("malformed managed Nginx stream block")
    pattern = re.compile(r"(?m)^" + re.escape(_STREAM_BEGIN) + r"\n.*?^" +
                         re.escape(_STREAM_END) + r"\n?", re.DOTALL)
    if _STREAM_BEGIN in content:
        content, removed = pattern.subn("", content)
        if removed != 1:
            raise ValueError("malformed managed Nginx stream block")
    if not enable_stream:
        return content
    # Comments and quoted strings must not create false block matches. An
    # existing unmanaged stream block is left to the installer's preflight.
    unquoted = re.sub(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\#[^\n]*''', "", content)
    if re.search(r"\bstream\s*\{", unquoted):
        raise ValueError("an unmanaged Nginx stream block already exists")
    separator = "" if not content or content.endswith("\n") else "\n"
    return content + separator + f"""{_STREAM_BEGIN}
stream {{
    include {NGINX_STREAM};
}}
{_STREAM_END}
"""


def _public_directory(path: Path) -> None:
    """Create traversable public directories even under the installer umask."""
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    path.mkdir(parents=True, exist_ok=True)
    for directory in missing:
        directory.chmod(0o755)
    path.chmod(0o755)


def install_static_site(instance: Mapping[str, Any], template_root: Path | None = None,
                        root: Path = Path("/")) -> Path | None:
    """Install the initial public page once; preserve an existing edited page."""
    _settings(instance)
    if not _site_domain(instance):
        return None
    target = _target(root, SITE_ROOT / "index.html")
    if target.exists():
        if not target.is_file():
            raise ValueError("the existing site index is not a regular file")
        return target
    templates = Path(template_root) if template_root is not None else Path(__file__).resolve().parents[1] / "sites"
    source = templates / instance["site"]["template"] / "index.html"
    if source.is_symlink() or not source.resolve().is_relative_to(templates.resolve()):
        raise ValueError("refusing a template outside the template directory")
    contents = source.read_bytes()
    _public_directory(target.parent)
    # The installer serializes its own operations. O_EXCL also preserves a
    # page created by the owner between the existence check and this write.
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        if target.is_symlink() or not target.is_file():
            raise ValueError("the existing site index is not a regular file")
        return target
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(contents)
            os.fchmod(stream.fileno(), 0o644)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return target


def _configure_nginx(instance: Mapping[str, Any], tls_enabled: bool, runner: Runner, root: Path) -> Path:
    content = render_nginx(instance, tls_enabled)
    # Reject accidental real service operations before even writing test files.
    if Path(root).resolve() != Path("/") and runner is subprocess.run:
        raise ValueError("a non-system root requires an injected runner")
    config = _target(root, NGINX_CONFIG)
    stream = _target(root, NGINX_STREAM)
    main = _target(root, NGINX_MAIN)
    stream_content = render_stream(instance) if tls_enabled else ""
    changes: dict[Path, tuple[bytes | None, int]] = {config: (content.encode(), 0o640)}
    if stream_content:
        if not main.is_file():
            raise ValueError("the packaged Nginx main configuration is missing")
        changes[stream] = (stream_content.encode(), 0o640)
    elif stream.exists():
        changes[stream] = (None, 0o640)
    if main.exists():
        old_main = main.read_text()
        new_main = _main_config(old_main, bool(stream_content))
        if old_main != new_main:
            changes[main] = (new_main.encode(), main.stat().st_mode & 0o777)
    previous = {path: (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists()
                else (None, mode) for path, (_, mode) in changes.items()}
    acme = _target(root, ACME_ROOT / ".well-known/acme-challenge")
    _public_directory(acme)
    for directory in (acme.parent.parent, acme.parent, acme):
        directory.chmod(0o755)
    validated = False
    try:
        for path, (data, mode) in changes.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_write(path, data, mode)
        _run(runner, root, ["nginx", "-t"])
        validated = True
        _run(runner, root, ["systemctl", "enable", "--now", "nginx"])
        _run(runner, root, ["systemctl", "reload", "nginx"])
    except Exception:
        for path, (data, mode) in previous.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_write(path, data, mode)
        if validated:
            # A failed reload can leave the old master running. Re-validate
            # and reload the restored files without masking the first error.
            try:
                _run(runner, root, ["nginx", "-t"])
                _run(runner, root, ["systemctl", "reload", "nginx"])
            except Exception:
                pass
        raise
    return config


def configure_http(instance: Mapping[str, Any], runner: Runner = subprocess.run, root: Path = Path("/")) -> Path:
    """Start HTTP challenges without any TLS/stream listener or certificate.

    The caller must remove/conflict-check any distribution default site during
    preflight; this module never removes unrelated Nginx sites.
    """
    return _configure_nginx(instance, False, runner, root)


def issue_certificate(instance: Mapping[str, Any], runner: Runner = subprocess.run, root: Path = Path("/")) -> None:
    """Issue/reuse independent named certificates while HTTP Nginx runs."""
    domain, email, *_ = _settings(instance)
    for name in (domain, _site_domain(instance)):
        if name:
            _run(runner, root, [
                "certbot", "certonly", "--webroot", "--webroot-path", str(ACME_ROOT),
                "--cert-name", name, "--domain", name, "--email", email,
                "--non-interactive", "--agree-tos", "--keep-until-expiring",
            ])


def render_renew_hook(instance: Mapping[str, Any]) -> str:
    """Renew only this instance's services; unrelated lineages are ignored."""
    domain, _, _, _, _, profile = _settings(instance)
    site_domain = _site_domain(instance)
    if site_domain:
        return f"""#!/bin/sh
# Managed by vpn-installer.
set -eu
restart_core=no
case "${{RENEWED_LINEAGE:-}}" in
    /etc/letsencrypt/live/{domain}) ;;
    /etc/letsencrypt/live/{site_domain}) restart_core=yes ;;
    *) exit 0 ;;
esac
/usr/sbin/nginx -t
/usr/bin/systemctl reload nginx
if [ "$restart_core" = yes ]; then
    /usr/bin/systemctl restart x-ui
fi
"""
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

