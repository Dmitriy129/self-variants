"""Thin orchestration: upstream panel owns live users after bootstrap."""
from __future__ import annotations

import argparse
from collections import deque
from contextlib import closing
from copy import deepcopy
import fcntl
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
import urllib.error

from .config import (ConfigError, load_instance, load_user_names, new_instance, panel_url, parse_user_names,
                     save_instance, subscription_urls, SITE_TEMPLATES)
from . import monitoring, network, system
from .panel import (PanelClient, apply_monitoring, configure_instance, export_instance,
                    validate_monitoring)

STATE_DIR = system.STATE_DIR
DEFAULT_USERS_FILE = Path(__file__).resolve().parents[1] / 'users.json'
EXAMPLE_USERS_FILE = Path(__file__).resolve().parents[1] / 'users.example.json'


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
    mode.add_argument('--set-monitoring', choices=('basic', 'destinations'),
                      help='сменить режим мониторинга установленного сервера без изменения пользователей')
    mode.add_argument('--show-logs', action='store_true', help='показать последние записи архива подключений')
    p.add_argument('--domain', help='домен панели и подписок (первая установка)')
    p.add_argument('--email', help='email для Let’s Encrypt (первая установка)')
    p.add_argument('--site-domain', help='отдельный домен сайта и REALITY на том же VPS')
    p.add_argument('--site-template', choices=('random', *SITE_TEMPLATES),
                   help='шаблон сайта; по умолчанию random, результат сохраняется в instance.json')
    p.add_argument('--fingerprint',
                   help='первая установка REALITY: uTLS-отпечаток, по умолчанию firefox; затем менять в панели')
    users = p.add_mutually_exclusive_group()
    users.add_argument('--users-file', type=Path,
                       help='JSON со стартовым списком пользователей; по умолчанию users.json или users.example.json')
    users.add_argument('--users', help='имена стартовых пользователей через запятую; например owner,family-1,family-2')
    p.add_argument('--subscription-ids', choices=('random', 'names'), default='random',
                   help='первая установка: random — случайные ID; names — имя пользователя в URL подписки')
    p.add_argument('--subscription-path', default='/sub/',
                   help='первая установка: постоянный префикс подписок, например private-prefix или /private-prefix/')
    p.add_argument('--panel-path',
                   help='первая установка: постоянный путь панели; без параметра создаётся случайный')
    p.add_argument('--monitoring', choices=('basic', 'destinations'),
                   help='первая установка: basic по умолчанию; destinations добавляет журнал назначений')
    p.add_argument('--log-user', help='имя клиента для --show-logs')
    p.add_argument('--log-lines', type=int, default=100, help='число последних записей --show-logs (1–10000)')
    p.add_argument('--reality-target', help=argparse.SUPPRESS)
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
    return (instance['schema_version'], instance['profile'], instance['domain'], instance['https_port'],
            instance['panel']['path'], instance['subscription']['path'], instance.get('site', {}).get('domain'))


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
    project_dir = Path(__file__).resolve().parents[1]
    lines = [f'Панель: {panel_url(instance)}', f'Администратор: {instance["panel"]["username"]}']
    if instance.get('site'):
        lines.append(f'Сайт: https://{instance["site"]["domain"]}/ (шаблон {instance["site"]["template"]})')
    if instance['profile'] == 'reality':
        reality = instance['reality']
        lines.append('Отпечаток в подписке: ' + reality.get('host_fingerprint', reality.get('fingerprint', 'chrome')))
    if instance.get('monitoring'):
        settings = instance['monitoring']
        lines.append(f'Мониторинг: {settings["mode"]}. Трафик и недавние IP — в карточке клиента.')
        if settings['mode'] == 'destinations':
            lines.append('Свежие назначения — в Xray Log панели; поиск по имени клиента, домену или IP.')
        lines.append(f'Архив: до {settings["retention_days"]} дней, бюджет {settings["max_log_mb"]} MiB; '
                     'при достижении лимита старые записи удаляются раньше.')
        lines.append(f'Просмотр архива: sudo bash {shlex.quote(str(project_dir / "install.sh"))} --show-logs --log-user ИМЯ')
    if show_password:
        lines.append(f'Пароль: {instance["panel"]["password"]}')
    lines.extend(f'Подписка {email}: {url}' for email, url in subscription_urls(instance).items())
    lines.append(f'Файл для полного восстановления: {STATE_DIR / "instance.json"}.')
    if instance['subscription'].get('id_mode') == 'names':
        lines.append('Для повторения стартовых ссылок на новом VPS используйте те же домен, '
                     '--subscription-path, --subscription-ids names и имена пользователей.')
        lines.append('После переключения DNS клиент получит новые параметры при обновлении подписки; '
                     'автоматическое обновление зависит от настроек приложения.')
    lines.extend([
        '', 'Что дальше:',
        '1. Откройте адрес «Панель» целиком, включая путь, и войдите под указанным администратором.',
        '2. В v2rayNG добавьте группу подписки с URL из строки «Подписка», обновите её и выберите профиль.',
        '3. Для subs-resolver используйте тот же URL подписки как HTTP-источник.',
        '4. Для полного переноса пользователей, ключей и лимитов сохраните instance.json вне VPS; '
        'после изменений в панели экспортируйте его заново:',
        f'   sudo bash {shlex.quote(str(project_dir / "install.sh"))} --export-config /root/instance.json',
        f'Инструкция: {project_dir / "README.md"}. Данные администратора хранятся в instance.json.',
    ])
    print('\n'.join(lines))


def verify_services(instance):
    for service in ('x-ui', 'nginx'):
        system.run(['systemctl', 'is-active', '--quiet', service])
    system.run([str(system.APP_DIR / 'bin/xray-linux-amd64'), 'run', '-test',
                '-config', str(system.APP_DIR / 'bin/config.json')], cwd=system.APP_DIR)
    client = connected_panel(instance)
    for _ in range(20):
        if client.xray_running():
            if instance.get('site'):
                system.check_reality_target(instance)
            if instance.get('monitoring'):
                validate_monitoring(client, instance)
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
    if args.show_logs:
        if 'monitoring' not in instance:
            raise system.InstallError('В этой старой конфигурации архив мониторинга не настроен.')
        lines = deque(monitoring.history_lines(instance['monitoring'], user=args.log_user), maxlen=args.log_lines)
        if not lines:
            print('Подходящих записей в архиве пока нет. Сбор выполняется раз в минуту.')
        for line in lines:
            # Logs may contain untrusted destination text; do not emit terminal controls.
            print(''.join(char for char in line.rstrip('\r\n') if char.isprintable() or char == '\t'))
    elif args.set_monitoring:
        if 'monitoring' not in instance:
            raise system.InstallError('Эта старая установка не управляет мониторингом через переносимый файл. '
                                      'Автоматическая смена её настроек журналов не выполняется.')
        live = export_and_backup(instance)
        target = deepcopy(live)
        target['monitoring']['mode'] = args.set_monitoring
        client = connected_panel(live)
        previous_template = client.get_xray_settings()
        try:
            monitoring.configure(target, runner=system.run)
            apply_monitoring(client, target)
            system.run(['systemctl', 'restart', 'x-ui'])
            connected_panel(target, attempts=40)
            verify_services(target)
            save_instance(STATE_DIR / 'instance.json', target)
        except Exception:
            failed = False
            try:
                connected_panel(live, attempts=40).save_xray_settings(previous_template)
                system.run(['systemctl', 'restart', 'x-ui'])
            except Exception:
                failed = True
            try:
                monitoring.configure(live, runner=system.run)
            except Exception:
                failed = True
            if not failed:
                try:
                    connected_panel(live, attempts=40)
                    verify_services(live)
                except Exception:
                    failed = True
            if failed:
                raise system.InstallError('Смена мониторинга не завершилась, полный откат не подтверждён. '
                                          f'Резервная копия находится в {STATE_DIR / "backups"}.') from None
            raise
        print(f'Режим мониторинга: {args.set_monitoring}. Пользователи и ссылки сохранены.')
    elif args.export_config:
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
        if args.monitoring and args.monitoring != instance.get('monitoring', {}).get('mode'):
            raise system.InstallError('Для смены мониторинга готовой установки используйте --set-monitoring.')
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
        domain = ask(args.domain, 'Домен панели и подписок (--domain)')
        email = ask(args.email, 'Email для сертификата (--email)')
        if args.reality_target:
            raise system.InstallError('Новые установки REALITY используют собственный сайт. '
                                      'Укажите --site-domain; старые настройки доступны через --config.')
        site_domain, site_template = None, None
        if args.profile == 'reality':
            site_domain = ask(getattr(args, 'site_domain', None), 'Домен сайта и REALITY (--site-domain)')
            site_template = getattr(args, 'site_template', None) or 'random'
        elif getattr(args, 'site_domain', None) or getattr(args, 'site_template', None):
            raise system.InstallError('--site-domain и --site-template используются с REALITY.')
        if args.users is not None:
            user_names = parse_user_names(args.users)
        else:
            default_users = DEFAULT_USERS_FILE if DEFAULT_USERS_FILE.exists() else EXAMPLE_USERS_FILE
            user_names = load_user_names(args.users_file or default_users)
        instance = new_instance(args.profile, domain, email, site_domain=site_domain,
                                site_template=site_template, user_names=user_names,
                                monitoring_mode=args.monitoring or 'basic',
                                subscription_ids=args.subscription_ids,
                                subscription_path=args.subscription_path, panel_path=args.panel_path,
                                fingerprint=args.fingerprint)

    if not managed:
        system.check_clean_host(instance)
    if not args.prepare:
        system.check_dns(instance['domain'])
        if instance.get('site'):
            system.check_dns(instance['site']['domain'])
    # Legacy targets exist independently. A new local target can only be
    # checked after its certificate and HTTPS listener have been installed.
    if not instance.get('site'):
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
    if instance.get('monitoring'):
        monitoring.configure(instance, runner=system.run)
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
    if instance.get('site'):
        network.install_static_site(instance)
    network.configure_https(instance, runner=system.run)
    if instance.get('site'):
        system.check_reality_target(instance)
    system.run(['systemctl', 'enable', '--now', 'x-ui'])
    client = connected_panel(instance, attempts=40)
    configure_instance(client, instance)
    system.run(['systemctl', 'restart', 'x-ui'])
    connected_panel(instance, attempts=40)
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
        if args.fingerprint is not None and args.profile != 'reality':
            raise system.InstallError('--fingerprint применяется только с --profile reality; '
                                      'при --config используется отпечаток из файла.')
        if args.check_config:
            instance = load_instance(args.check_config)
            print(f'Файл корректен: {instance["profile"]}, {instance["domain"]}. Секреты не изменены.')
            return 0
        if args.prepare and not (args.profile or args.config):
            raise system.InstallError('--prepare применяется только к установке.')
        if args.monitoring and not args.profile:
            raise system.InstallError('--monitoring применяется к первой установке через --profile; '
                                      'для смены режима используйте --set-monitoring.')
        if not 1 <= args.log_lines <= 10000 or (args.log_user and not args.show_logs):
            raise system.InstallError('--log-lines: от 1 до 10000; --log-user используется с --show-logs.')
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
