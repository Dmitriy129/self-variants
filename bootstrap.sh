#!/usr/bin/env bash
# Download the complete pinned package; this file is not inside that archive.
set -euo pipefail
umask 077
export PATH="/usr/sbin:${PATH:-/usr/bin:/bin}"

RELEASE_TAG='v0.1.2'
ARCHIVE_SHA256='37d3115da97373d7d5f0a340d86b21c0bd7a9a79999afbfb03aa1e6ae715459b'
INSTALL_ROOT='/opt/vpn-installer'
OS_RELEASE='/etc/os-release'
SYSTEMD_ROOT='/run/systemd/system'
LOCK_FILE='/run/lock/vpn-installer-bootstrap.lock'
CA_BUNDLE='/etc/ssl/certs/ca-certificates.crt'
ARCHIVE_URL="https://github.com/Dmitriy129/self-variants/releases/download/${RELEASE_TAG}/vpn-installer.tar.gz"
OWNER='vpn-installer-bootstrap:v1:Dmitriy129/self-variants'

fail() { printf '%s\n' "Ошибка загрузчика: $1" >&2; exit 1; }

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    cat <<'HELP'
Загрузить проверенный пакет VPN и передать ему все параметры:
  sudo bash bootstrap.sh --profile reality --domain panel.example.com \
    --site-domain site.example.com --email owner@example.com
Нужен чистый Ubuntu 24.04 x86_64 VPS с systemd. Параметры не печатаются.
HELP
    exit 0
fi

# These checks precede every filesystem or package mutation.
[[ $(id -u) == 0 ]] || fail 'Запустите команду от root или через sudo.'
[[ $(uname -s) == Linux ]] || fail 'Поддерживается только Ubuntu 24.04 x86_64; запуск на этой ОС запрещён.'
[[ $(uname -m) == x86_64 ]] || fail 'Нужен процессор x86_64.'
[[ -r "$OS_RELEASE" ]] || fail 'Не удалось определить версию ОС.'
os_id='' os_version=''
while IFS='=' read -r key value; do
    value=${value#\"}; value=${value%\"}
    case "$key" in ID) os_id=$value ;; VERSION_ID) os_version=$value ;; esac
done < "$OS_RELEASE"
[[ "$os_id" == ubuntu && "$os_version" == 24.04 ]] || fail 'Поддерживается только Ubuntu 24.04.'
[[ -d "$SYSTEMD_ROOT" ]] || fail 'Нужен VPS с работающим systemd.'
[[ "$RELEASE_TAG" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'Некорректная закреплённая версия загрузчика.'
[[ "$ARCHIVE_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail 'В загрузчике ещё не закреплена контрольная сумма релиза.'

RELEASES_DIR="$INSTALL_ROOT/releases"
RELEASE_DIR="$RELEASES_DIR/$RELEASE_TAG"
CURRENT="$INSTALL_ROOT/current"
OWNERSHIP="$INSTALL_ROOT/.bootstrap-owner"

check_managed_paths() {
    [[ ! -L "$INSTALL_ROOT" && ! -L "${INSTALL_ROOT%/*}" ]] || fail 'Каталог установки не должен быть символической ссылкой.'
    if [[ -e "$INSTALL_ROOT" ]]; then
        [[ -d "$INSTALL_ROOT" && -f "$OWNERSHIP" && ! -L "$OWNERSHIP" ]] || fail 'Каталог /opt/vpn-installer уже существует и не принадлежит загрузчику.'
        [[ $(cat "$OWNERSHIP") == "$OWNER" ]] || fail 'Неизвестный владелец каталога установки.'
    fi
    if [[ -e "$RELEASES_DIR" || -L "$RELEASES_DIR" ]]; then
        [[ -d "$RELEASES_DIR" && ! -L "$RELEASES_DIR" ]] || fail 'Небезопасный каталог releases.'
    fi
    if [[ -e "$RELEASE_DIR" || -L "$RELEASE_DIR" ]]; then
        [[ -d "$RELEASE_DIR" && ! -L "$RELEASE_DIR" ]] || fail 'Закреплённый релиз занят посторонним объектом.'
        [[ -f "$RELEASE_DIR/.archive.sha256" && ! -L "$RELEASE_DIR/.archive.sha256" ]] || fail 'Существующий релиз не имеет маркера проверки.'
        [[ $(cat "$RELEASE_DIR/.archive.sha256") == "$ARCHIVE_SHA256" ]] || fail 'Существующий релиз имеет другую контрольную сумму; он не будет заменён.'
        [[ -f "$RELEASE_DIR/install.sh" && ! -L "$RELEASE_DIR/install.sh" ]] || fail 'В существующем релизе отсутствует безопасный install.sh.'
    fi
    if [[ -e "$CURRENT" || -L "$CURRENT" ]]; then
        [[ -L "$CURRENT" ]] || fail 'Путь current занят посторонним файлом или каталогом.'
        local destination relative
        destination=$(readlink "$CURRENT")
        [[ "$destination" == "$RELEASES_DIR/"* ]] || fail 'Ссылка current ведёт за пределы управляемых релизов.'
        relative=${destination#"$RELEASES_DIR/"}
        [[ -n "$relative" && "$relative" != */* && "$relative" != . && "$relative" != .. ]] || fail 'Небезопасная ссылка current.'
        [[ -d "$destination" && ! -L "$destination" && -f "$destination/.archive.sha256" && ! -L "$destination/.archive.sha256" ]] || fail 'Ссылка current ведёт на непроверенный релиз.'
        [[ $(cat "$destination/.archive.sha256") =~ ^[0-9a-f]{64}$ ]] || fail 'Некорректный маркер текущего релиза.'
    fi
}

check_managed_paths
# flock is part of Ubuntu's standard util-linux installation. Do not perform
# an unlocked package operation if this base-system command is unavailable.
command -v flock >/dev/null 2>&1 || fail 'В базовой системе отсутствует flock (пакет util-linux).'
[[ ! -L "$LOCK_FILE" ]] || fail 'Небезопасный файл блокировки.'
exec 9>"$LOCK_FILE"
flock -n 9 || fail 'Другой загрузчик уже работает.'
check_managed_paths

missing=0
for tool in python3 openssl ip curl tar; do
    command -v "$tool" >/dev/null 2>&1 || missing=1
done
[[ -s "$CA_BUNDLE" ]] || missing=1
if [[ "$missing" == 1 ]]; then
    command -v apt-get >/dev/null 2>&1 || fail 'В системе отсутствует apt-get.'
    export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_MODE=a
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        python3 openssl iproute2 ca-certificates curl tar
fi
for tool in python3 openssl ip curl tar; do
    command -v "$tool" >/dev/null 2>&1 || fail 'Не удалось установить необходимые команды.'
done
[[ -s "$CA_BUNDLE" ]] || fail 'В системе отсутствует набор доверенных CA-сертификатов.'

if [[ ! -d "$INSTALL_ROOT" ]]; then
    mkdir -m 700 "$INSTALL_ROOT"
    printf '%s\n' "$OWNER" > "$OWNERSHIP"
fi
mkdir -p -m 700 "$RELEASES_DIR"

work='' staging='' current_tmp=''
cleanup() {
    [[ -z "$work" ]] || rm -rf -- "$work"
    [[ -z "$staging" ]] || rm -rf -- "$staging"
    [[ -z "$current_tmp" ]] || rm -f -- "$current_tmp"
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

if [[ ! -d "$RELEASE_DIR" ]]; then
    work=$(mktemp -d "$INSTALL_ROOT/.download.XXXXXXXX")
    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 300 \
        --output "$work/package.tar.gz" "$ARCHIVE_URL"
    python3 - "$work/package.tar.gz" "$ARCHIVE_SHA256" <<'PY'
import hashlib
from pathlib import Path
import sys
digest = hashlib.sha256()
with Path(sys.argv[1]).open('rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
if digest.hexdigest() != sys.argv[2]:
    raise SystemExit('Ошибка загрузчика: контрольная сумма архива не совпала; запуск запрещён.')
PY
    staging=$(mktemp -d "$RELEASES_DIR/.${RELEASE_TAG}.XXXXXXXX")
    python3 - "$work/package.tar.gz" "$staging" <<'PY'
from pathlib import Path, PurePosixPath
import os
import shutil
import sys
import tarfile

destination = Path(sys.argv[2])
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    members = archive.getmembers()
    if len(members) > 10000 or sum(item.size for item in members) > 512 * 1024 * 1024:
        raise SystemExit('Ошибка загрузчика: слишком большой архив.')
    seen = set()
    for item in members:
        path = PurePosixPath(item.name)
        if (not path.parts or path.is_absolute() or path.parts[0] != 'vpn-installer'
                or '..' in item.name.split('/') or '\\' in item.name
                or not (item.isdir() or item.isfile()) or path in seen
                or path == PurePosixPath('vpn-installer/.archive.sha256')):
            raise SystemExit('Ошибка загрузчика: небезопасный путь или тип файла в архиве.')
        seen.add(path)
    for item in members:
        relative = PurePosixPath(item.name).parts[1:]
        target = destination.joinpath(*relative)
        if item.isdir():
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.chmod(0o700)
            continue
        if not relative:
            raise SystemExit('Ошибка загрузчика: корень архива должен быть каталогом.')
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        source = archive.extractfile(item)
        if source is None:
            raise SystemExit('Ошибка загрузчика: повреждённый архив.')
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with source, os.fdopen(fd, 'wb') as output:
            shutil.copyfileobj(source, output, 1024 * 1024)
        target.chmod(0o700 if item.mode & 0o111 else 0o600)
for required in ('install.sh', 'versions.json', 'vpn_installer/__init__.py', 'vpn_installer/cli.py'):
    if not (destination / required).is_file():
        raise SystemExit('Ошибка загрузчика: архив не содержит полного установщика.')
PY
    printf '%s\n' "$ARCHIVE_SHA256" > "$staging/.archive.sha256"
    python3 - "$staging" "$RELEASE_DIR" <<'PY'
import os
import sys
if os.path.lexists(sys.argv[2]):
    raise SystemExit('Ошибка загрузчика: путь релиза неожиданно занят.')
os.rename(sys.argv[1], sys.argv[2])
PY
    staging=''
fi

# Recheck before publishing the stable link; never overwrite an unmanaged path.
check_managed_paths
candidate="$INSTALL_ROOT/.current.$$"
ln -s "$RELEASE_DIR" "$candidate"
current_tmp=$candidate
python3 - "$current_tmp" "$CURRENT" <<'PY'
import os
import sys
os.replace(sys.argv[1], sys.argv[2])
PY
current_tmp=''
cleanup
work='' staging=''
trap - EXIT INT TERM HUP
# Keep descriptor 9 open: the lock covers the installer and all its arguments.
exec bash "$RELEASE_DIR/install.sh" "$@"
