"""Host checks and explicit, verified installation of upstream binaries."""
from __future__ import annotations

import hashlib
from contextlib import closing
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile

STATE_DIR = Path('/etc/vpn-installer')
APP_DIR = Path('/usr/local/x-ui')
DB_DIR = Path('/etc/x-ui')
LOCK_FILE = Path(__file__).resolve().parent.parent / 'versions.json'


class InstallError(RuntimeError):
    pass


def run(args, **kwargs):
    """Never echo argv: commands may contain administrator credentials."""
    kwargs.setdefault('check', True)
    kwargs.setdefault('capture_output', True)
    kwargs.setdefault('text', True)
    return subprocess.run(args, **kwargs)


def require_host():
    if os.geteuid() != 0:
        raise InstallError('Запустите установщик через sudo.')
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        raise InstallError('Поддерживается Ubuntu 24.04 LTS x86_64.')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                   if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') != '24.04':
        raise InstallError('Поддерживается только Ubuntu 24.04 LTS.')
    if not Path('/run/systemd/system').is_dir():
        raise InstallError('Нужен VPS с работающим systemd.')


def detect_ssh_ports(runner=run):
    ports = set()
    result = runner(['/usr/sbin/sshd', '-T'])
    for line in result.stdout.splitlines():
        if line.startswith('port '):
            ports.add(int(line.split()[1]))
    # Preserve the actual SSH session even if socket activation overrides sshd_config.
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if len(connection) == 4 and connection[3].isdigit():
        ports.add(int(connection[3]))
    listeners = runner(['ss', '-H', '-ltnp']).stdout
    for line in listeners.splitlines():
        if 'sshd' in line:
            match = re.search(r':(\d+)\s', line.split(maxsplit=3)[3])
            if match:
                ports.add(int(match.group(1)))
    # Ubuntu 24.04 can use ssh.socket; its ListenStream need not agree with
    # sshd -T, and sudo may have removed SSH_CONNECTION from the environment.
    socket_config = runner(['systemctl', 'show', 'ssh.socket', '--property=Listen', '--value'], check=False)
    if socket_config.returncode == 0:
        for match in re.finditer(r'(?:^|\s)(?:[^\s]+:)?(\d+)\s+\(Stream\)', socket_config.stdout):
            ports.add(int(match.group(1)))
    if not ports or any(not 1 <= p <= 65535 for p in ports):
        raise InstallError('Не удалось определить SSH-порт; firewall не изменён.')
    return sorted(ports)


def check_clean_host(instance):
    for path in (APP_DIR, DB_DIR / 'x-ui.db', Path('/etc/systemd/system/x-ui.service')):
        if path.exists():
            raise InstallError(f'Найдена существующая установка: {path}. Автоматический импорт не выполняется.')
    for path in (Path('/etc/ufw/user.rules'), Path('/etc/ufw/user6.rules')):
        if path.exists() and re.search(r'^-A ufw-user-input ', path.read_text(), re.M):
            raise InstallError('Найдены пользовательские правила UFW. Нужен чистый VPS.')
    for folder in (Path('/etc/nginx/sites-enabled'), Path('/etc/nginx/conf.d'), Path('/etc/nginx/stream-conf.d')):
        if folder.exists() and any(p.name != 'default' for p in folder.iterdir()):
            raise InstallError('Найдена существующая конфигурация Nginx. Нужен чистый VPS.')
    nginx_main = Path('/etc/nginx/nginx.conf')
    if nginx_main.exists():
        content = nginx_main.read_text()
        unquoted = re.sub(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\#[^\n]*''', '', content)
        if re.search(r'\bstream\s*\{', unquoted) or '# BEGIN vpn-installer stream' in content:
            raise InstallError('Найдена существующая stream-конфигурация Nginx. Нужен чистый VPS.')
    check_free_ports(instance)


def check_free_ports(instance):
    listeners = {(80, socket.SOCK_STREAM), (instance['https_port'], socket.SOCK_STREAM),
                 (2053, socket.SOCK_STREAM), (2096, socket.SOCK_STREAM),
                 (443, socket.SOCK_STREAM if instance['profile'] == 'reality' else socket.SOCK_DGRAM)}
    if instance.get('site'):
        listeners.update((port, socket.SOCK_STREAM) for port in (7443, 9443, 10443))
    for port, kind in listeners:
        for family, address in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
            try:
                with socket.socket(family, kind) as probe:
                    if family == socket.AF_INET6:
                        probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    probe.bind((address, port))
            except OSError as exc:
                if family == socket.AF_INET6 and exc.errno in (97, 99):
                    continue
                raise InstallError(f'Порт {port} уже занят или недоступен.') from exc


def check_dns(domain, runner=run):
    try:
        addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(domain, 443)}
    except socket.gaierror as exc:
        raise InstallError('Домен не разрешается. Настройте A/AAAA или используйте --prepare.') from exc
    output = runner(['ip', '-j', 'address', 'show', 'scope', 'global']).stdout
    try:
        interfaces = json.loads(output)
        if not isinstance(interfaces, list):
            raise ValueError('expected an interface array')
        local = set()
        for iface in interfaces:
            if not isinstance(iface, dict):
                raise ValueError('expected an interface object')
            entries = iface.get('addr_info', [])
            if not isinstance(entries, list):
                raise ValueError('expected an address array')
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError('expected an address object')
                # iproute2 opens a JSON object before applying its scope filter,
                # so filtered addresses can appear as {}. Only local is assigned
                # to this host; address/peer may describe a remote tunnel endpoint.
                if 'local' not in entry:
                    continue
                if not isinstance(entry['local'], str):
                    raise ValueError('expected an IP address string')
                local.add(ipaddress.ip_address(entry['local']))
    except (ValueError, TypeError):
        raise InstallError('Не удалось прочитать IP-адреса интерфейсов. '
                           'Проверьте вывод: ip -j address show scope global.') from None
    if not addresses or not addresses.issubset(local):
        raise InstallError('Все A/AAAA домена должны указывать на публичные адреса этого VPS. '
                           'Для установки до смены DNS используйте --prepare. NAT/CDN не поддерживаются.')


def check_reality_target(instance):
    if instance['profile'] != 'reality':
        return
    reality = instance['reality']
    host, port = reality['target'].rsplit(':', 1)
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(['h2'])
    try:
        with socket.create_connection((host, int(port)), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=reality['server_name']) as conn:
                if conn.selected_alpn_protocol() != 'h2':
                    raise InstallError('Целевой сайт REALITY должен поддерживать HTTP/2.')
    except (OSError, ssl.SSLError) as exc:
        raise InstallError('Целевой сайт REALITY недоступен либо не поддерживает доверенный TLS 1.3.') from exc


def read_versions(path=LOCK_FILE):
    versions = json.loads(Path(path).read_text())
    if set(versions) != {'3x-ui', 'xray'}:
        raise InstallError('Некорректный versions.json.')
    for name, artifact in versions.items():
        if set(artifact) != {'version', 'url', 'sha256'} or not re.fullmatch(r'[0-9a-f]{64}', artifact['sha256']):
            raise InstallError('Некорректная контрольная сумма в versions.json.')
        repo = 'MHSanaei/3x-ui' if name == '3x-ui' else 'XTLS/Xray-core'
        if not artifact['url'].startswith(f'https://github.com/{repo}/releases/download/v{artifact["version"]}/'):
            raise InstallError('Ожидался закреплённый официальный GitHub release.')
    return versions


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def download_artifacts(versions, cache=Path('/var/cache/vpn-installer')):
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    paths = {}
    for name, artifact in versions.items():
        target = cache / (artifact['sha256'] + ('-panel.tar.gz' if name == '3x-ui' else '-xray.zip'))
        if target.exists() and digest_file(target) == artifact['sha256']:
            paths[name] = target
            continue
        temporary = target.with_suffix('.part')
        try:
            req = urllib.request.Request(artifact['url'], headers={'User-Agent': 'vpn-installer/1'})
            with urllib.request.urlopen(req, timeout=60) as response, temporary.open('wb') as output:
                if not response.url.startswith('https://'):
                    raise InstallError('Скачивание должно использовать HTTPS.')
                shutil.copyfileobj(response, output, 1024 * 1024)
            if digest_file(temporary) != artifact['sha256']:
                raise InstallError(f'Контрольная сумма {name} не совпала. Установка остановлена.')
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        paths[name] = target
    return paths


def install_binaries(artifacts, app_dir=APP_DIR):
    """Extract only known regular files, never upstream links or archive paths."""
    # Validate both archives before touching a previous installation. An old
    # executable on disk must not mask a missing executable in a new release.
    with tarfile.open(artifacts['3x-ui'], 'r:gz') as archive:
        names = [m.name for m in archive.getmembers() if m.isfile()]
        if names.count('x-ui/x-ui') != 1 or len(names) != len(set(names)):
            raise InstallError('Архив 3x-ui не содержит единственный новый бинарник x-ui.')
    with zipfile.ZipFile(artifacts['xray']) as archive:
        names = archive.namelist()
        if names.count('xray') != 1 or len(names) != len(set(names)):
            raise InstallError('Архив Xray не содержит единственный новый бинарник xray.')
    app_dir = Path(app_dir)
    app_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    (app_dir / 'bin').mkdir(exist_ok=True, mode=0o700)
    with tarfile.open(artifacts['3x-ui'], 'r:gz') as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            name = member.name
            if name == 'x-ui/x-ui' or (name.startswith('x-ui/bin/') and '/' not in name[len('x-ui/bin/'):]):
                relative = Path(name).relative_to('x-ui')
                if '..' in relative.parts:
                    raise InstallError('Небезопасный путь в архиве.')
                source = archive.extractfile(member)
                if source is None:
                    raise InstallError('Повреждён архив 3x-ui.')
                with source, (app_dir / relative).open('wb') as dest:
                    shutil.copyfileobj(source, dest)
                (app_dir / relative).chmod(0o700 if '.' not in relative.name else 0o600)
    if not (app_dir / 'x-ui').is_file():
        raise InstallError('В архиве отсутствует x-ui.')
    with zipfile.ZipFile(artifacts['xray']) as archive:
        if 'xray' not in archive.namelist():
            raise InstallError('В архиве отсутствует xray.')
        for filename in ('xray', 'geoip.dat', 'geosite.dat'):
            if filename in archive.namelist():
                dest = app_dir / 'bin' / ('xray-linux-amd64' if filename == 'xray' else filename)
                with archive.open(filename) as source, dest.open('wb') as output:
                    shutil.copyfileobj(source, output)
                dest.chmod(0o700 if filename == 'xray' else 0o600)


SERVICE = '''[Unit]
Description=3x-ui managed by vpn-installer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/x-ui
Environment=XUI_DB_FOLDER=/etc/x-ui
Environment=XUI_BIN_FOLDER=/usr/local/x-ui/bin
Environment=XUI_LOG_FOLDER=/var/log/x-ui
Environment=XUI_LOG_LEVEL=warning
ExecStart=/usr/local/x-ui/x-ui
Restart=on-failure
RestartSec=5
UMask=0077
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
'''


def install_dependencies(runner=run):
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    runner(['apt-get', 'update'], env=env)
    runner(['apt-get', 'install', '-y', '--no-install-recommends', 'ca-certificates',
            'nginx', 'libnginx-mod-stream', 'certbot', 'openssl', 'ufw', 'iproute2'], env=env)


def bootstrap_panel(instance, runner=run):
    DB_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not (DB_DIR / 'x-ui.db').exists():
        env = dict(os.environ, XUI_DB_FOLDER=str(DB_DIR), XUI_BIN_FOLDER=str(APP_DIR / 'bin'))
        runner([str(APP_DIR / 'x-ui'), 'setting', '-listenIP', '127.0.0.1', '-port', '2053',
                '-webBasePath', instance['panel']['path'], '-username', instance['panel']['username'],
                '-password', instance['panel']['password']], cwd=APP_DIR, env=env)
    Path('/etc/systemd/system/x-ui.service').write_text(SERVICE)
    runner(['systemctl', 'daemon-reload'])


def create_backup(state_dir=STATE_DIR, db_dir=DB_DIR, output_dir=None):
    state_dir, db_dir = Path(state_dir), Path(db_dir)
    output_dir = Path(output_dir) if output_dir else state_dir / 'backups'
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = output_dir / f'backup-{time.time_ns()}.tar.gz'
    with tempfile.TemporaryDirectory(prefix='vpn-backup-') as temporary:
        snapshot = Path(temporary) / 'x-ui.db'
        database = db_dir / 'x-ui.db'
        if database.exists():
            with closing(sqlite3.connect(f'file:{database}?mode=ro', uri=True)) as source:
                with closing(sqlite3.connect(snapshot)) as dest:
                    source.backup(dest)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream, tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for filename in ('instance.json', 'state.json'):
                if (state_dir / filename).exists():
                    archive.add(state_dir / filename, arcname=filename)
            if snapshot.exists():
                archive.add(snapshot, arcname='x-ui.db')
    return output
