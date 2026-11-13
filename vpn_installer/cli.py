"""Thin orchestration: upstream panel owns live users after bootstrap."""
from __future__ import annotations

import argparse
from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error

from .config import (ConfigError, load_instance, new_instance, panel_url,
                     save_instance, subscription_urls)
from . import network, system
from .panel import PanelClient, configure_instance, export_instance

STATE_DIR = system.STATE_DIR


def parser():
    p = argparse.ArgumentParser(description='Два VPN-пресета с переносимыми подписками для v2rayNG.')
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--profile', choices=('reality', 'hysteria2'), help='первая установка или повторный запуск')
    mode.add_argument('--config', type=Path, help='восстановить из переносимого JSON')
    mode.add_argument('--export-config', type=Path, help='экспортировать текущих пользователей панели')
    mode.add_argument('--check-config', type=Path, help='проверить файл без изменения системы, работает без sudo')
    mode.add_argument('--backup', action='store_true', help='сохранить БД, настройки и переносимый JSON')
    mode.add_argument('--status', action='store_true', help='проверить сервисы и доступ к панели')
    mode.add_argument('--update', action='store_true', help='явно установить версии из versions.json после backup')
    p.add_argument('--domain', help='DNS-имя VPS (первая установка)')
    p.add_argument('--email', help='email для Let’s Encrypt (первая установка)')
    p.add_argument('--reality-target', help='TLS-сайт REALITY в формате hostname:443')
    p.add_argument('--prepare', action='store_true', help='подготовить новый VPS до переключения DNS; без выпуска TLS')
    return p


def ask(value, prompt, default=None):
    if value:
        return value
    if not sys.stdin.isatty():
        if default:
            return default
        raise system.InstallError(f'Не задан параметр: {prompt}. Передайте его флагом.')
    answer = input(prompt + (f' [{default}]' if default else '') + ': ').strip()
    return answer or default or ''


def read_state(directory=STATE_DIR):
    path = Path(directory) / 'state.json'
    if not path.exists():
        if (Path(directory) / 'instance.json').exists():
            raise system.InstallError('Найден instance.json без маркера установки; автоматическое продолжение запрещено.')
        return None
    data = json.loads(path.read_text())
    if data.get('owner') != 'vpn-installer' or data.get('schema') != 1:
        raise system.InstallError('Неизвестный маркер установки.')
    return data


def write_state(state, directory=STATE_DIR):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = directory / '.state.json.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(state, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(directory / 'state.json')


def namespace(instance):
    return (instance['profile'], instance['domain'], instance['https_port'],
            instance['panel']['path'], instance['subscription']['path'])


def connected_panel(instance, attempts=1):
    last_error = None
    for _ in range(attempts):
        try:
            client = PanelClient(f'http://127.0.0.1:2053{instance["panel"]["path"]}',
                                 instance['panel']['username'], instance['panel']['password'])
            client.login()
            return client
        except (OSError, RuntimeError, ValueError) as exc:
            last_error = exc
            if attempts > 1:
                time.sleep(0.5)
    raise system.InstallError('Панель недоступна или изменены данные администратора. '
                              'Проверьте x-ui и защищённый instance.json.') from last_error


def export_live(instance, destination):
    live = export_instance(connected_panel(instance), instance)
    save_instance(destination, live)
    return live


def show_result(instance, show_password=False):
    lines = [f'Панель: {panel_url(instance)}', f'Администратор: {instance["panel"]["username"]}']
    if show_password:
        lines.append(f'Пароль: {instance["panel"]["password"]}')
    lines.extend(f'Подписка {email}: {url}' for email, url in subscription_urls(instance).items())
    lines.append(f'Переносимый файл: {STATE_DIR / "instance.json"}. Сохраните копию вне VPS.')
    print('\n'.join(lines))


def verify_services(instance):
    for service in ('x-ui', 'nginx'):
        system.run(['systemctl', 'is-active', '--quiet', service])
    system.run([str(system.APP_DIR / 'bin/xray-linux-amd64'), 'run', '-test',
                '-config', str(system.APP_DIR / 'bin/config.json')], cwd=system.APP_DIR)
    client = connected_panel(instance)
    for _ in range(20):
        if client.xray_running():
            return
        time.sleep(0.5)
    raise system.InstallError('Панель работает, но Xray не подтвердил успешный запуск конфигурации.')


def export_and_backup(instance):
    live = export_live(instance, STATE_DIR / 'instance.json')
    backup = system.create_backup()
    print(f'Резервная копия: {backup}')
    return live


def maintain(args, state):
    if not state or state.get('phase') != 'complete':
        raise system.InstallError('Сначала завершите установку.')
    instance = load_instance(STATE_DIR / 'instance.json')
    if args.export_config:
        live = export_live(instance, args.export_config)
        if args.export_config.resolve() != (STATE_DIR / 'instance.json').resolve():
            save_instance(STATE_DIR / 'instance.json', live)
        print(f'Настройки экспортированы: {args.export_config}. Сохраните файл вне VPS.')
    elif args.backup:
        export_and_backup(instance)
    elif args.status:
        verify_services(instance)
        print('Панель, Nginx и конфигурация Xray работают. Доступ из РФ проверяется отдельно клиентом.')
    elif args.update:
        live = export_and_backup(instance)
        versions = system.read_versions()
        artifacts = system.download_artifacts(versions)
        # Keep the old executable tree so a failed core/panel start can be rolled back.
        import shutil
        rollback = system.APP_DIR.with_name('x-ui.vpn-installer-rollback')
        if rollback.exists():
            raise system.InstallError('Найдена предыдущая копия отката; разберите её перед следующим обновлением.')
        import sqlite3
        database = system.DB_DIR / 'x-ui.db'
        snapshot = rollback / 'rollback.db'
        # Prepare rollback while the old service still runs. No binaries are
        # changed until both the executable tree and consistent DB exist.
        try:
            shutil.copytree(system.APP_DIR, rollback)
            with closing(sqlite3.connect(f'file:{database}?mode=ro', uri=True)) as source:
                with closing(sqlite3.connect(snapshot)) as dest:
                    source.backup(dest)
        except Exception:
            if rollback.exists():
                shutil.rmtree(rollback)
            raise
        stopped = False
        mutated = False
        try:
            system.run(['systemctl', 'stop', 'x-ui'])
            stopped = True
            # Refresh after stopping to include writes made during copytree.
            with closing(sqlite3.connect(f'file:{database}?mode=ro', uri=True)) as source:
                with closing(sqlite3.connect(snapshot)) as dest:
                    source.backup(dest)
            mutated = True
            system.install_binaries(artifacts)
            system.run(['systemctl', 'start', 'x-ui'])
            connected_panel(live, attempts=40)
            verify_services(live)
        except Exception:
            if not mutated:
                if stopped:
                    system.run(['systemctl', 'start', 'x-ui'], check=False)
                shutil.rmtree(rollback)
                raise
            # Never replace a database while a possibly migrated panel is
            # still writing it. A failed stop leaves recovery files intact.
            try:
                system.run(['systemctl', 'stop', 'x-ui'])
            except subprocess.CalledProcessError as exc:
                raise system.InstallError(f'Не удалось остановить x-ui для отката. '
                                          f'Рабочие файлы не заменены; копия сохранена в {rollback}.') from exc
            shutil.copy2(snapshot, database)
            for suffix in ('-wal', '-shm'):
                Path(str(database) + suffix).unlink(missing_ok=True)
            snapshot.unlink()
            shutil.rmtree(system.APP_DIR)
            rollback.rename(system.APP_DIR)
            system.run(['systemctl', 'start', 'x-ui'], check=False)
            raise
        shutil.rmtree(rollback)
        state['versions'] = versions
        write_state(state)
        print('Обновление завершено; пользователи и ссылки сохранены.')


def deploy(args, supplied=None):
    state = read_state()
    managed = state is not None
    if managed:
        instance = load_instance(STATE_DIR / 'instance.json')
        if supplied and namespace(supplied) != namespace(instance):
            raise system.InstallError('Домен, пути или пресет отличаются от этой установки. Используйте чистый VPS.')
        if args.profile and args.profile != instance['profile']:
            raise system.InstallError('Нельзя сменить пресет существующей установки.')
        if state.get('phase') == 'complete':
            # Do not replay an old manifest over live users or silently upgrade binaries.
            instance = export_live(instance, STATE_DIR / 'instance.json')
            verify_services(instance)
            print('Установка уже завершена. Текущие пользователи сохранены без изменений.')
            show_result(instance)
            return
    elif supplied:
        instance = supplied
    else:
        domain = ask(args.domain, 'Домен сервера (--domain)')
        email = ask(args.email, 'Email для сертификата (--email)')
        target = ask(args.reality_target, 'TLS-сайт REALITY (--reality-target)', 'www.microsoft.com:443') if args.profile == 'reality' else None
        instance = new_instance(args.profile, domain, email, reality_target=target)

    if not managed:
        system.check_clean_host(instance)
    if not args.prepare:
        system.check_dns(instance['domain'])
    system.check_reality_target(instance)
    ssh_ports = system.detect_ssh_ports()
    if managed:
        ssh_ports = sorted(set(ssh_ports) | set(state.get('ssh_ports', [])))
    versions = system.read_versions()
    artifacts = system.download_artifacts(versions)
    if not managed:
        STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        state = {'owner': 'vpn-installer', 'schema': 1, 'phase': 'initializing',
                 'ssh_ports': ssh_ports, 'versions': versions}
        write_state(state)
        save_instance(STATE_DIR / 'instance.json', instance)
    print('Устанавливаю зависимости и сохраняю доступ по SSH…', flush=True)
    system.install_dependencies()
    network.configure_firewall(instance, ssh_ports, runner=system.run)
    state['ssh_ports'] = ssh_ports
    write_state(state)
    if managed:
        system.run(['systemctl', 'stop', 'x-ui'], check=False)
    system.install_binaries(artifacts)
    system.bootstrap_panel(instance)
    default_site = Path('/etc/nginx/sites-enabled/default')
    if default_site.is_symlink():
        default_site.unlink()
    network.configure_http(instance, runner=system.run)
    state['phase'] = 'prepared'
    write_state(state)
    if args.prepare:
        print(f'VPS подготовлен. Сохраните {STATE_DIR / "instance.json"}, переключите A/AAAA на новый VPS '
              'и повторите команду без --prepare для выпуска сертификата.')
        return

    print('Выпускаю сертификат и настраиваю выбранный VPN…', flush=True)
    network.issue_certificate(instance, runner=system.run)
    system.run(['systemctl', 'enable', '--now', 'x-ui'])
    client = connected_panel(instance, attempts=40)
    configure_instance(client, instance)
    system.run(['systemctl', 'restart', 'x-ui'])
    connected_panel(instance, attempts=40)
    network.configure_https(instance, runner=system.run)
    verify_services(instance)
    instance = export_live(instance, STATE_DIR / 'instance.json')
    state['phase'] = 'complete'
    state['versions'] = versions
    write_state(state)
    print('Установка завершена.')
    show_result(instance, show_password=True)


def main(argv=None):
    args = parser().parse_args(argv)
    os.umask(0o077)
    try:
        # Validate restores before any installation, lock-file, package or firewall mutation.
        supplied = load_instance(args.config) if args.config else None
        if args.check_config:
            instance = load_instance(args.check_config)
            print(f'Файл корректен: {instance["profile"]}, {instance["domain"]}. Секреты не изменены.')
            return 0
        if args.prepare and not (args.profile or args.config):
            raise system.InstallError('--prepare применяется только к установке.')
        system.require_host()
        with open('/run/lock/vpn-installer.lock', 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise system.InstallError('Другой экземпляр установщика уже работает.') from exc
            if args.profile or args.config:
                deploy(args, supplied)
            else:
                maintain(args, read_state())
        return 0
    except subprocess.CalledProcessError as exc:
        # argv/stdout/stderr can contain panel passwords, tokens or subscription bodies.
        program = Path(str(exc.cmd[0])).name if isinstance(exc.cmd, list) else 'команда'
        print(f'Ошибка: {program} завершился с кодом {exc.returncode}. '
              'Установка не завершена; настройки сохранены, секреты не выведены.', file=sys.stderr)
        return 1
    except (ConfigError, system.InstallError, OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
