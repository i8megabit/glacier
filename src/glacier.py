#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import time
import yaml
import distro
import random
import syslog
import sys
import platform
from S3Client import *
from analyzer_utils import *
from analyzer_config import *
from firewall_info import *
from postgresql_info import *
from network_info import *
from disk_info import *
from other_info import *
from netflow_generator import NetFlowGenerator  # Поддержка NetFlow v9 стандартов (RFC 3954)
from datetime import datetime as dt
import os
import socket
import psutil

# Импортируем UDP трекер в зависимости от ОС
if platform.system() == 'Darwin':
    from udp_tracker_macos import get_udp_information_macos
else:
    from udp_tracker_module import get_udp_information

# Константы для ограничения размера данных
MAX_CONNECTIONS = 50  # Максимум соединений в отчете
MAX_PORTS = 100       # Максимум портов в отчете
MAX_CHANGES_LOG = 50  # Максимум записей в логе изменений
MAX_UDP_CONNECTIONS = 20  # Максимум UDP соединений

# Получаем версию из конфигурации
try:
    from analyzer_config import get_config
    VERSION = get_config().get('version', '2.3.0')
except:
    VERSION = '2.3.0'

def get_system_users():
    """Получает список пользователей системы"""
    users_info = {}
    try:
        import platform
        if platform.system() == 'Darwin':
            # На macOS используем dscl для получения пользователей
            result = execute_command(['dscl', '.', 'list', '/Users'])
            for line in result:
                username = line.strip()
                if username and not username.startswith('_') and username not in ['daemon', 'nobody']:
                    try:
                        # Получаем UID пользователя
                        uid_result = execute_command(['dscl', '.', 'read', f'/Users/{username}', 'UniqueID'])
                        gid_result = execute_command(['dscl', '.', 'read', f'/Users/{username}', 'PrimaryGroupID'])
                        home_result = execute_command(['dscl', '.', 'read', f'/Users/{username}', 'NFSHomeDirectory'])
                        shell_result = execute_command(['dscl', '.', 'read', f'/Users/{username}', 'UserShell'])
                        
                        uid = 'unknown'
                        gid = 'unknown'
                        home = 'unknown'
                        shell = 'unknown'
                        
                        for line in uid_result:
                            if 'UniqueID:' in line:
                                uid = line.split(':', 1)[1].strip()
                                break
                        
                        for line in gid_result:
                            if 'PrimaryGroupID:' in line:
                                gid = line.split(':', 1)[1].strip()
                                break
                        
                        for line in home_result:
                            if 'NFSHomeDirectory:' in line:
                                home = line.split(':', 1)[1].strip()
                                break
                        
                        for line in shell_result:
                            if 'UserShell:' in line:
                                shell = line.split(':', 1)[1].strip()
                                break
                        
                        try:
                            uid_int = int(uid)
                            # Показываем пользователей с UID >= 500
                            if uid_int >= 500:
                                users_info[username] = {
                                    'uid': uid,
                                    'gid': gid,
                                    'home': home,
                                    'shell': shell,
                                    'type': 'user' if uid_int >= 1000 else 'system'
                                }
                        except ValueError:
                            # Добавляем и пользователей с нечисловым UID (редко, но бывает)
                            users_info[username] = {
                                'uid': uid,
                                'gid': gid,
                                'home': home,
                                'shell': shell,
                                'type': 'user'
                            }
                    except Exception as e:
                        # Если не удалось получить подробности, добавляем базовую информацию
                        users_info[username] = {
                            'uid': 'unknown',
                            'gid': 'unknown',
                            'home': 'unknown',
                            'shell': 'unknown',
                            'type': 'user'
                        }
        else:
            # Для Linux и других систем используем /etc/passwd
            result = execute_command(['cat', '/etc/passwd'])
            for line in result:
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = parts[2]
                        gid = parts[3]
                        home = parts[5]
                        shell = parts[6]
                        
                        # Фильтруем системных пользователей
                        try:
                            uid_int = int(uid)
                            # Показываем только обычных пользователей (UID >= 1000 в Linux, >= 500 в других системах)
                            if uid_int >= 500:
                                users_info[username] = {
                                    'uid': uid,
                                    'gid': gid,
                                    'home': home,
                                    'shell': shell,
                                    'type': 'user' if uid_int >= 1000 else 'system'
                                }
                        except ValueError:
                            pass
    except Exception as e:
        print(f"⚠️ Ошибка получения пользователей: {e}")
    
    # Дополняем информацией о последних входах
    try:
        sessions = get_sessions_information()
        for username, user_info in users_info.items():
            if username in sessions:
                user_info['last_login'] = sessions[username].get('last_login', 'unknown')
    except Exception as e:
        print(f"⚠️ Ошибка получения сессий: {e}")
    
    return users_info

def collect_extended_system_info():
    """Собирает расширенную информацию о системе для детальных секций"""
    # Собираем информацию об ОС
    os_info = {
        'name': platform.system(),
        'version': platform.release(),
        'architecture': platform.machine(),
        'processor': platform.processor(),
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'last_updated': dt.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Информация о хосте
    try:
        hostname = socket.gethostname()
        fqdn = socket.getfqdn()
        local_ip = socket.gethostbyname(hostname)
    except:
        hostname = 'unknown'
        fqdn = 'unknown'
        local_ip = 'unknown'
    
    host_info = {
        'hostname': hostname,
        'fqdn': fqdn,
        'local_ip': local_ip,
        'boot_time': dt.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S') if hasattr(psutil, 'boot_time') else 'unknown',
        'uptime_seconds': int(time.time() - psutil.boot_time()) if hasattr(psutil, 'boot_time') else 0,
        'cpu_count': psutil.cpu_count(),
        'memory_total_gb': round(psutil.virtual_memory().total / (1024**3), 2),
        'disk_usage': {}
    }
    
    # Добавляем информацию о дисках
    try:
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                host_info['disk_usage'][partition.device] = {
                    'total_gb': round(usage.total / (1024**3), 2),
                    'used_gb': round(usage.used / (1024**3), 2),
                    'free_gb': round(usage.free / (1024**3), 2),
                    'percent': round((usage.used / usage.total) * 100, 1),
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype
                }
            except (PermissionError, OSError):
                pass
    except:
        pass
    
    # Информация о Glacier
    analyzer_info = {
        'version': VERSION,
        'name': 'Glacier',
        'description': 'Analysis tool',
        'features': [
            'Network connections monitoring',
            'Port scanning and analysis', 
            'UDP traffic tracking',
            'ICMP traffic monitoring',
            'System resource monitoring',
            'Change detection and logging',
            'Interactive HTML reports',
            'Cross-platform support'
        ],
        'supported_platforms': ['Darwin', 'Debian', 'Ubuntu', 'CentOS'],
        'python_requirements': 'Python 3.6+',
        'last_updated': dt.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Собираем информацию о Docker контейнерах
    docker_info = {}
    try:
        docker_containers = get_docker_information()
        docker_info = {
            'available': len(docker_containers) > 0 or check_docker_available(),
            'containers': docker_containers,
            'containers_count': len(docker_containers),
            'status': 'running' if docker_containers else 'no_containers'
        }
        print(f"🐳 Docker: {docker_info['containers_count']} контейнеров")
    except Exception as e:
        docker_info = {
            'available': False,
            'containers': [],
            'containers_count': 0,
            'status': 'unavailable',
            'error': str(e)
        }
        print(f"⚠️ Docker недоступен: {e}")
    
    # Собираем информацию о файрволе
    firewall_info = {}
    try:
        firewall_info = get_fw_information()
        rules_count = 0
        if 'iptables' in firewall_info:
            for chain, rules in firewall_info['iptables'].items():
                rules_count += len(rules)
        if 'firewall_rules' in firewall_info:
            for zone, rules in firewall_info['firewall_rules'].items():
                rules_count += len(rules)
        if 'ufw_state' in firewall_info:
            rules_count += len(firewall_info['ufw_state'])
            
        firewall_info['total_rules'] = rules_count
        print(f"🛡️ Файрвол: {rules_count} правил")
    except Exception as e:
        firewall_info = {
            'available': False,
            'total_rules': 0,
            'error': str(e)
        }
        print(f"⚠️ Ошибка получения правил файрвола: {e}")
    
    # Собираем информацию о пользователях
    users_info = {}
    try:
        users_info = get_system_users()
        print(f"👥 Пользователи: {len(users_info)} записей")
    except Exception as e:
        users_info = {}
        print(f"⚠️ Ошибка получения пользователей: {e}")
    
    return {
        'os_info': os_info,
        'host_info': host_info,
        'analyzer_info': analyzer_info,
        'docker_info': docker_info,
        'firewall_info': firewall_info,
        'users_info': users_info
    }

def check_docker_available():
    """Проверяет доступность Docker"""
    try:
        result = execute_command(['docker', '--version'])
        return len(result) > 0 and 'Docker version' in ' '.join(result)
    except:
        return False

def collect_system_data():
    """Собирает все данные системы в оптимизированном формате"""
    networks = {'connections': {}, 'remote': {}, 'tcp': [], 'udp': []}
    
    # Получаем сетевые данные
    networks = get_connections(networks,
                              configuration['outgoing_ports'],
                              configuration['local_address'],
                              configuration['except_ipv6'],
                              configuration['except_local_connection'])
    
    # Ограничиваем количество соединений
    if 'connections' in networks:
        for conn_type in ['incoming', 'outgoing']:
            if conn_type in networks['connections']:
                networks['connections'][conn_type] = networks['connections'][conn_type][:MAX_CONNECTIONS//2]
    
    # Ограничиваем количество портов
    networks['tcp'] = networks['tcp'][:MAX_PORTS//2]
    networks['udp'] = networks['udp'][:MAX_PORTS//2]
    
    # Получаем ICMP трафик
    try:
        from icmp_tracker import get_icmp_information
        icmp_info = get_icmp_information(False)
        
        print(f"🔍 ICMP tracker result: {icmp_info.get('total_connections', 0)} connections, {icmp_info.get('total_packets', 0)} packets")
        
        # Интегрируем ICMP соединения в основную структуру соединений
        if icmp_info and icmp_info.get('connections'):
            print(f"🔍 Found ICMP connections: {len(icmp_info['connections'])}")
            
            for icmp_conn in icmp_info['connections'][:MAX_UDP_CONNECTIONS]:
                # Парсим соединение
                connection_str = icmp_conn.get('connection', '')
                if ' -> ' in connection_str:
                    local_part, remote_part = connection_str.split(' -> ', 1)
                    
                    # Создаем структуру соединения в формате анализатора
                    conn_info = {
                        "local": local_part,
                        "remote": {"name": "unknown", "address": remote_part},
                        "process": icmp_conn.get('process', 'unknown'),
                        "protocol": "icmp",
                        "first_seen": 'unknown',
                        "last_seen": 'unknown',
                        "count": icmp_conn.get('packet_count', 1)
                    }
                    
                    # Определяем направление и добавляем в соответствующий список
                    direction = icmp_conn.get('direction', 'outgoing')
                    if direction == 'incoming':
                        networks['connections']['incoming'].append(conn_info)
                    else:
                        networks['connections']['outgoing'].append(conn_info)
                    
                    # Добавляем удаленный адрес в список (если это не псевдо-соединение)
                    if ':' in remote_part and '*' not in remote_part:
                        remote_ip = remote_part.split(':')[0]
                        networks['remote'][remote_ip] = {
                            'name': 'unknown',
                            'type': direction,
                            'port': remote_part.split(':')[1] if ':' in remote_part else 'icmp'
                        }
        else:
            print(f"⚠️ ICMP connections not found or empty")
        
    except Exception as e:
        print(f"⚠️ Error getting ICMP data: {e}")
        icmp_info = {}

    # Получаем UDP трафик и интегрируем его в основные соединения
    try:
        if platform.system() == 'Darwin':
            udp_info = get_udp_information_macos(False)
        else:
            udp_info = get_udp_information(False)
        
        print(f"🔍 UDP tracker result: {len(udp_info.get('udp_connections', []))} connections")
        
        # Интегрируем UDP соединения в основную структуру соединений
        if udp_info and udp_info.get('udp_connections'):
            print(f"🔍 Found UDP connections: {len(udp_info['udp_connections'])}")
            
            for udp_conn in udp_info['udp_connections'][:MAX_UDP_CONNECTIONS]:
                # Парсим соединение
                connection_str = udp_conn.get('connection', '')
                if ' -> ' in connection_str:
                    local_part, remote_part = connection_str.split(' -> ', 1)
                    
                    # Создаем структуру соединения в формате анализатора
                    conn_info = {
                        "local": local_part,
                        "remote": {"name": "unknown", "address": remote_part},
                        "process": udp_conn.get('process', 'unknown'),
                        "protocol": "udp",
                        "first_seen": udp_conn.get('first_seen', 'unknown'),
                        "last_seen": udp_conn.get('last_seen', 'unknown'),
                        "count": udp_conn.get('packet_count', 1)
                    }
                    
                    # Определяем направление и добавляем в соответствующий список
                    direction = udp_conn.get('direction', 'outgoing')
                    if direction == 'incoming':
                        networks['connections']['incoming'].append(conn_info)
                    else:
                        networks['connections']['outgoing'].append(conn_info)
                    
                    # Добавляем удаленный адрес в список
                    if ':' in remote_part:
                        remote_ip = remote_part.split(':')[0]
                        networks['remote'][remote_ip] = {
                            'name': 'unknown',
                            'type': direction,
                            'port': remote_part.split(':')[1] if ':' in remote_part else 'unknown'
                        }
        else:
            print(f"⚠️ UDP connections not found or empty")
        
        # Если UDP трекер не дал результатов, пытаемся получить UDP соединения из основного сканирования
        if not udp_info.get('udp_connections'):
            print(f"🔍 Trying to find UDP connections in main scanning...")
            # Проверяем, есть ли UDP соединения в networks
            all_connections = networks.get('connections', {})
            udp_found_in_main = 0
            for conn_type in ['incoming', 'outgoing']:
                for conn in all_connections.get(conn_type, []):
                    if conn.get('protocol') == 'udp':
                        udp_found_in_main += 1
            
            if udp_found_in_main > 0:
                print(f"✅ Found {udp_found_in_main} UDP connections in main scanning")
            else:
                print(f"ℹ️ UDP connections not found in tracker or main scanning")
        
        # Ограничиваем UDP соединения
        if udp_info and 'udp_connections' in udp_info:
            udp_info['udp_connections'] = udp_info['udp_connections'][:MAX_UDP_CONNECTIONS]
    except Exception as e:
        print(f"⚠️ Error getting UDP data: {e}")
        udp_info = {}
    
    # Получаем расширенную системную информацию
    extended_info = collect_extended_system_info()
    
    return {
        'connections': networks.get('connections', {}),
        'remote_addresses': networks.get('remote', {}),
        'tcp_ports': networks.get('tcp', []),
        'udp_ports': networks.get('udp', []),
        'icmp_connections': networks.get('icmp', 0),  # Добавляем ICMP в возвращаемые данные
        'interfaces': get_interfaces(configuration['local_interfaces']),
        'udp_traffic': udp_info,
        'icmp_traffic': icmp_info,  # Добавляем полную информацию об ICMP трафике
        'extended_system_info': extended_info
    }

def detect_changes(previous_state, current_state):
    """Обнаруживает изменения между предыдущим и текущим состоянием (оптимизированная версия)"""
    changes = {}
    
    # Основные категории для сравнения
    categories = ['connections', 'tcp_ports', 'udp_ports', 'udp_traffic', 'icmp_traffic']
    
    for category in categories:
        prev_data = previous_state.get(category, {})
        curr_data = current_state.get(category, {})
        
        category_changes = compare_data_structures(prev_data, curr_data, category)
        
        if category_changes:
            changes[category] = category_changes
    
    return changes

def compare_data_structures(prev_data, curr_data, category):
    """Сравнивает структуры данных (упрощенная версия)"""
    changes = {}
    
    if category in ['tcp_ports', 'udp_ports']:
        # Для портов сравниваем списки
        prev_set = set(prev_data) if isinstance(prev_data, list) else set()
        curr_set = set(curr_data) if isinstance(curr_data, list) else set()
        
        added = list(curr_set - prev_set)
        removed = list(prev_set - curr_set)
        
        if added:
            changes['added'] = added[:10]  # Ограничиваем до 10 элементов
        if removed:
            changes['removed'] = removed[:10]  # Ограничиваем до 10 элементов
            
    elif category == 'connections':
        # Упрощенное сравнение соединений
        prev_count = len(prev_data.get('incoming', [])) + len(prev_data.get('outgoing', []))
        curr_count = len(curr_data.get('incoming', [])) + len(curr_data.get('outgoing', []))
        
        if prev_count != curr_count:
            changes['count_changed'] = {
                'previous': prev_count,
                'current': curr_count,
                'delta': curr_count - prev_count
            }
            
    elif category == 'udp_traffic':
        # Сравниваем только ключевые метрики UDP
        prev_connections = prev_data.get('total_connections', 0) if isinstance(prev_data, dict) else 0
        curr_connections = curr_data.get('total_connections', 0) if isinstance(curr_data, dict) else 0
        
        if prev_connections != curr_connections:
            changes['connections_changed'] = {
                'previous': prev_connections,
                'current': curr_connections,
                'delta': curr_connections - prev_connections
            }
    
    elif category == 'icmp_traffic':
        # Сравниваем ключевые метрики ICMP
        prev_connections = prev_data.get('total_connections', 0) if isinstance(prev_data, dict) else 0
        curr_connections = curr_data.get('total_connections', 0) if isinstance(curr_data, dict) else 0
        
        prev_packets = prev_data.get('total_packets', 0) if isinstance(prev_data, dict) else 0
        curr_packets = curr_data.get('total_packets', 0) if isinstance(curr_data, dict) else 0
        
        if prev_connections != curr_connections:
            changes['connections_changed'] = {
                'previous': prev_connections,
                'current': curr_connections,
                'delta': curr_connections - prev_connections
            }
        
        if prev_packets != curr_packets:
            changes['packets_changed'] = {
                'previous': prev_packets,
                'current': curr_packets,
                'delta': curr_packets - prev_packets
            }
    
    return changes

def generate_measurements_statistics(cumulative_state):
    """Генерирует статистику измерений для секции"""
    changes_log = cumulative_state.get('changes_log', [])
    total_measurements = cumulative_state.get('total_measurements', 0)
    first_run = cumulative_state.get('first_run', 'unknown')
    last_update = cumulative_state.get('last_update', 'unknown')
    
    # Анализируем изменения по времени
    changes_by_hour = {}
    changes_by_category = {}
    measurement_durations = []
    
    for change in changes_log:
        # По часам
        timestamp = change.get('timestamp', '')
        if ' ' in timestamp:
            hour = timestamp.split(' ')[1].split(':')[0]
            changes_by_hour[hour] = changes_by_hour.get(hour, 0) + 1
        
        # По категориям
        changes_dict = change.get('changes', {})
        for category in changes_dict.keys():
            changes_by_category[category] = changes_by_category.get(category, 0) + 1
        
        # Время выполнения
        duration = change.get('time', 0)
        if duration > 0:
            measurement_durations.append(duration)
    
    # Вычисляем статистики
    avg_duration = sum(measurement_durations) / len(measurement_durations) if measurement_durations else 0
    min_duration = min(measurement_durations) if measurement_durations else 0
    max_duration = max(measurement_durations) if measurement_durations else 0
    
    return {
        'total_measurements': total_measurements,
        'total_changes': len(changes_log),
        'first_run': first_run,
        'last_update': last_update,
        'changes_by_hour': changes_by_hour,
        'changes_by_category': changes_by_category,
        'average_duration': round(avg_duration, 2),
        'min_duration': round(min_duration, 2),
        'max_duration': round(max_duration, 2),
        'most_active_hour': max(changes_by_hour.items(), key=lambda x: x[1]) if changes_by_hour else ('unknown', 0),
        'most_changed_category': max(changes_by_category.items(), key=lambda x: x[1]) if changes_by_category else ('unknown', 0)
    }

def generate_compact_html_report(cumulative_state, html_filename):
    """Генерирует улучшенный HTML отчет с кнопками навигации и интерактивным дизайном"""
    current_state = cumulative_state.get('current_state', {})
    changes_log = cumulative_state.get('changes_log', [])
    
    # Подготавливаем данные о соединениях
    connections = current_state.get('connections', {})
    incoming_connections = connections.get('incoming', [])
    outgoing_connections = connections.get('outgoing', [])
    total_connections = len(incoming_connections) + len(outgoing_connections)
    
    # Подсчитываем TCP, UDP и ICMP соединения отдельно
    tcp_connections = [c for c in incoming_connections + outgoing_connections if c.get('protocol') == 'tcp']
    udp_connections = [c for c in incoming_connections + outgoing_connections if c.get('protocol') == 'udp']
    icmp_connections = [c for c in incoming_connections + outgoing_connections if c.get('protocol') == 'icmp']
    
    # Получаем порты
    tcp_ports = current_state.get('tcp_ports', [])
    udp_ports = current_state.get('udp_ports', [])
    icmp_count_raw = current_state.get('icmp_connections', 0)
    
    # Получаем ICMP трафик
    icmp_traffic = current_state.get('icmp_traffic', {})
    icmp_traffic_connections = icmp_traffic.get('connections', [])
    icmp_total_packets = icmp_traffic.get('total_packets', 0)
    
    # Получаем UDP трафик
    udp_traffic = current_state.get('udp_traffic', {})
    udp_traffic_connections = udp_traffic.get('udp_connections', [])
    
    # Если UDP трекер не дал результатов, используем UDP соединения из основного сканирования
    if not udp_traffic_connections and udp_connections:
        print(f"🔍 UDP tracker empty, using {len(udp_connections)} UDP connections from main scanning")
        # Преобразуем UDP соединения в формат UDP трекера для отображения
        udp_traffic_connections = []
        for udp_conn in udp_connections:
            # Определяем направление на основе локального порта
            local_addr = udp_conn.get('local', '')
            remote_addr = udp_conn.get('remote', {}).get('address', '')
            
            # Простая логика определения направления
            direction = 'outgoing'
            if local_addr and ':' in local_addr:
                try:
                    local_port = int(local_addr.split(':')[-1])
                    if local_port <= 1024:  # Системные порты обычно входящие
                        direction = 'incoming'
                except ValueError:
                    pass
            
            udp_traffic_connections.append({
                'connection': f"{local_addr} -> {remote_addr}",
                'process': udp_conn.get('process', 'unknown'),
                'direction': direction,
                'packet_count': udp_conn.get('count', 1),
                'first_seen': udp_conn.get('first_seen', 'unknown'),
                'last_seen': udp_conn.get('last_seen', 'unknown')
            })
    
    # Подсчитываем уникальные процессы и хосты
    unique_processes = set()
    unique_hosts = set()
    for conn in incoming_connections + outgoing_connections:
        if conn.get('process') != 'unknown':
            unique_processes.add(conn.get('process', 'unknown'))
        remote_addr = conn.get('remote', {}).get('address', '')
        if remote_addr and ':' in remote_addr:
            host_ip = remote_addr.split(':')[0]
            unique_hosts.add(host_ip)
    
    # Аналитика для обзора
    # Топ процессы по количеству соединений
    process_stats = {}
    for conn in incoming_connections + outgoing_connections:
        process = conn.get('process', 'unknown')
        if process not in process_stats:
            process_stats[process] = {'count': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}
        process_stats[process]['count'] += conn.get('count', 1)
        if conn.get('protocol') == 'tcp':
            process_stats[process]['tcp'] += 1
        elif conn.get('protocol') == 'udp':
            process_stats[process]['udp'] += 1
        elif conn.get('protocol') == 'icmp':
            process_stats[process]['icmp'] += 1
    
    top_processes = sorted(process_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:5]
    
    # Топ удаленные хосты
    host_stats = {}
    for conn in outgoing_connections:
        remote_addr = conn.get('remote', {}).get('address', '')
        if remote_addr and ':' in remote_addr:
            host = remote_addr.split(':')[0]
            if host not in host_stats:
                host_stats[host] = 0
            host_stats[host] += conn.get('count', 1)
    
    top_hosts = sorted(host_stats.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Статистика по времени
    recent_connections = [c for c in incoming_connections + outgoing_connections if c.get('last_seen') != 'unknown']
    activity_hours = {}
    for conn in recent_connections:
        try:
            last_seen = conn.get('last_seen', '')
            if ' ' in last_seen:
                time_part = last_seen.split(' ')[1]
                hour = time_part.split(':')[0]
                activity_hours[hour] = activity_hours.get(hour, 0) + 1
        except:
            pass
    
    # Подготавливаем данные для JavaScript диаграмм
    hour_data_js = []
    for hour in range(24):
        hour_str = f"{hour:02d}"
        activity = activity_hours.get(hour_str, 0)
        hour_data_js.append(activity)
    
    # Подготавливаем переменные для подстановки в HTML
    tcp_count = len(tcp_connections)
    udp_count = len(udp_connections)
    icmp_count = len(icmp_connections)
    incoming_count = len(incoming_connections)
    outgoing_count = len(outgoing_connections)
    processes_count = len(unique_processes)
    hosts_count = len(unique_hosts)
    
    html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет анализатора - {cumulative_state.get('hostname', 'unknown')}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{ 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 20px; 
            box-shadow: 0 25px 50px rgba(0,0,0,0.15);
            
        }}
        
        .header {{ 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); 
            color: white; 
            padding: 40px; 
            position: relative;
            
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="8" height="8" patternUnits="userSpaceOnUse"><path d="M 8 0 L 0 0 0 8" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.4;
        }}
        
        .header-content {{ position: relative; z-index: 1; }}
        
        .header-title {{
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .logo {{
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }}
        
        .logo svg {{
            width: 30px;
            height: 30px;
            fill: white;
        }}
        
        .header h1 {{ 
            font-size: 2.8em; 
            font-weight: 700;
            font-family: 'Inter', sans-serif;
            letter-spacing: -0.02em;
            background: linear-gradient(135deg, #ffffff 0%, #e0e7ff 100%);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .header-info {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
            gap: 20px; 
            margin-top: 30px;
        }}
        
        .header-info-item {{ 
            background: rgba(255,255,255,0.1); 
            padding: 20px; 
            border-radius: 15px; 
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.1);
            transition: all 0.3s ease;
            position: relative;
            
        }}
        
        .header-info-item:hover {{
            transform: translateY(-2px);
            background: rgba(255,255,255,0.15);
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}
        
        .header-info-item.clickable {{
            cursor: pointer;
        }}
        
        .header-info-item.clickable:hover {{
            background: rgba(255,255,255,0.2);
        }}
        
        .header-info-item::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 15px 15px 0 0;
        }}
        
        .header-info-item strong {{
            font-weight: 600;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            opacity: 0.8;
            display: block;
            margin-bottom: 8px;
        }}
        
        .header-info-value {{
            font-size: 1.3em;
            font-weight: 500;
        }}
        
        .navigation {{ 
            background: #f8fafc; 
            padding: 25px 40px; 
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .nav-buttons {{ 
            display: flex; 
            gap: 15px; 
            flex-wrap: wrap;
        }}
        
        .nav-btn {{ 
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); 
            color: white; 
            border: none; 
            padding: 15px 30px; 
            border-radius: 30px; 
            cursor: pointer; 
            font-weight: 600; 
            font-size: 0.95em;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
            letter-spacing: 0.3px;
        }}
        
        .nav-btn:hover {{ 
            transform: translateY(-3px); 
            box-shadow: 0 8px 25px rgba(59, 130, 246, 0.4);
        }}
        
        .nav-btn.active {{ 
            background: linear-gradient(135deg, #10b981 0%, #047857 100%);
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }}
        
        .nav-btn.changes {{ 
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            box-shadow: 0 4px 15px rgba(245, 158, 11, 0.3);
        }}
        
        .content {{ padding: 40px; }}
        
        .overview-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 30px;
            margin-bottom: 40px;
        }}
        
        .stats {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); 
            gap: 25px; 
            margin-bottom: 30px;
        }}
        
        .stat-card {{ 
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%); 
            padding: 30px; 
            border-radius: 18px; 
            text-align: center; 
            border-left: 5px solid #3b82f6;
            transition: all 0.3s ease;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            position: relative;
            
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.05) 0%, rgba(16, 185, 129, 0.05) 100%);
            opacity: 0;
            transition: opacity 0.3s ease;
        }}
        
        .stat-card:hover {{ 
            transform: translateY(-8px); 
            box-shadow: 0 12px 40px rgba(0,0,0,0.15);
        }}
        
        .stat-card:hover::before {{
            opacity: 1;
        }}
        
        .stat-number {{ 
            font-size: 3em; 
            font-weight: 700; 
            color: #1e293b; 
            margin-bottom: 8px;
            position: relative;
            z-index: 1;
        }}
        
        .stat-label {{ 
            color: #64748b; 
            font-weight: 500;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.8px;
            position: relative;
            z-index: 1;
        }}
        
        .analytics-panel {{
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.08);
            border: 1px solid #e2e8f0;
        }}
        
        .analytics-title {{
            font-size: 1.4em;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .analytics-section {{
            margin-bottom: 25px;
        }}
        
        .analytics-section h4 {{
            font-size: 1.1em;
            font-weight: 600;
            color: #374151;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .analytics-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid #f1f5f9;
        }}
        
        .analytics-item:last-child {{
            border-bottom: none;
        }}
        
        .analytics-name {{
            font-weight: 500;
            color: #475569;
            font-size: 0.9em;
        }}
        
        .analytics-value {{
            font-weight: 600;
            color: #1e293b;
            background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
        }}
        
        .activity-chart {{
            display: flex;
            gap: 8px;
            align-items: end;
            height: 80px;
            margin-top: 15px;
            padding: 10px;
            background: #f8fafc;
            border-radius: 12px;
        }}
        
        .activity-bar {{
            background: linear-gradient(to top, #3b82f6, #60a5fa);
            border-radius: 3px 3px 0 0;
            min-width: 20px;
            position: relative;
            transition: all 0.3s ease;
        }}
        
        .activity-bar:hover {{
            background: linear-gradient(to top, #1d4ed8, #3b82f6);
        }}
        
        .section {{ 
            margin: 30px 0; 
            display: none;
        }}
        
        .section.active {{ display: block; }}
        
        .section h3 {{ 
            color: #1e293b; 
            border-bottom: 3px solid #3b82f6; 
            padding-bottom: 15px; 
            margin-bottom: 25px;
            font-size: 1.6em;
            font-weight: 600;
        }}
        
        .connections-table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px;
            background: white;
            border-radius: 12px;
            
            box-shadow: 0 8px 30px rgba(0,0,0,0.08);
            table-layout: fixed;
        }}
        
        .connections-table th {{ 
            background: linear-gradient(135deg, #1e293b 0%, #374151 100%); 
            color: white; 
            padding: 18px 15px; 
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.8px;
            position: relative;
        }}
        
        .connections-table td {{ 
            padding: 15px; 
            border-bottom: 1px solid #f1f5f9;
            transition: background-color 0.3s ease;
            word-wrap: break-word;
            
            
            max-width: 0;
            vertical-align: middle;
        }}
        
        .connections-table td:nth-child(1) {{ width: 10%; }}  /* Направление */
        .connections-table td:nth-child(2) {{ width: 16%; }}  /* Локальный адрес */
        .connections-table td:nth-child(3) {{ width: 16%; }}  /* Удаленный адрес */
        .connections-table td:nth-child(4) {{ width: 35%; }}  /* Процесс */
        .connections-table td:nth-child(5) {{ width: 8%; }}   /* Протокол */
        .connections-table td:nth-child(6) {{ width: 10%; }}  /* Время */
        .connections-table td:nth-child(7) {{ width: 5%; }}   /* Счетчик */
        
        .connections-table .process-name {{
            max-width: 300px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            display: inline-block;
            vertical-align: middle;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }}
        
        .connections-table .process-name-short {{
            white-space: nowrap;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            vertical-align: middle;
        }}
        
        .connections-table .process-name-long {{
            max-width: 250px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            display: inline-block;
            vertical-align: middle;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }}
        
        .connections-table .address-cell {{
            max-width: 180px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            vertical-align: middle;
        }}
        
        .connections-table tr:hover td {{ 
            background-color: #f8fafc; 
        }}
        
        
        
        .protocol-tcp {{ color: #3b82f6; font-weight: 600; }}
        .protocol-udp {{ color: #10b981; font-weight: 600; }}
        .protocol-icmp {{ color: #f59e0b; font-weight: 600; }}
        .direction-in {{ color: #ef4444; }}
        .direction-out {{ color: #06b6d4; }}
        
        .ports-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-top: 25px;
        }}
        
        .port-item {{ 
            background: linear-gradient(135deg, #f8fafc 0%, #ffffff 100%); 
            padding: 20px; 
            border-radius: 15px; 
            text-align: center;
            transition: all 0.3s ease;
            border: 2px solid transparent;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
        }}
        
        .port-item:hover {{ 
            transform: translateY(-5px);
            border-color: #3b82f6;
            box-shadow: 0 12px 30px rgba(59, 130, 246, 0.15);
        }}
        
        .port-number {{ 
            font-weight: 700; 
            color: #1e293b; 
            font-size: 1.3em;
            margin-bottom: 8px;
        }}
        
        .port-tcp {{ border-left: 5px solid #3b82f6; }}
        .port-udp {{ border-left: 5px solid #10b981; }}
        .port-icmp {{ border-left: 5px solid #f59e0b; }}
        
        .changes-timeline {{
            background: #f8fafc;
            border-radius: 15px;
            padding: 25px;
            margin: 25px 0;
        }}
        
        .change-item {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin: 15px 0;
            border-left: 5px solid #3b82f6;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
        }}
        
        .change-item:hover {{
            transform: translateX(5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.12);
        }}
        
        .change-timestamp {{
            font-weight: 600;
            color: #374151;
            margin-bottom: 10px;
            font-size: 1.05em;
        }}
        
        .change-details {{
            color: #6b7280;
            font-size: 0.95em;
        }}
        
        .udp-section {{ 
            background: linear-gradient(135deg, #ecfdf5 0%, #f0fdf4 100%); 
            padding: 25px; 
            border-radius: 15px; 
            margin: 20px 0; 
            border: 1px solid #bbf7d0;
        }}
        
        .warning {{ 
            background: linear-gradient(135deg, #fefce8 0%, #fef3c7 100%); 
            border: 1px solid #fde047; 
            padding: 25px; 
            border-radius: 15px; 
            margin: 25px 0;
            border-left: 5px solid #f59e0b;
        }}
        
        .footer {{ 
            text-align: center; 
            margin-top: 50px; 
            padding: 30px; 
            background: #f8fafc; 
            color: #64748b;
            border-top: 1px solid #e2e8f0;
            font-size: 0.9em;
        }}
        
        .footer p {{
            margin-bottom: 8px;
        }}
        
        /* Стили для диаграмм */
        .charts-container {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin: 30px 0;
        }}
        
        .chart-card {{
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            border-radius: 20px;
            padding: 25px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.08);
            border: 1px solid #e2e8f0;
            position: relative;
            
        }}
        
        .chart-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #667eea, #764ba2);
            border-radius: 20px 20px 0 0;
        }}
        
        .chart-title {{
            font-size: 1.2em;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .chart-wrapper {{
            position: relative;
            height: 300px;
            margin-bottom: 15px;
        }}
        
        .chart-small {{
            height: 200px !important;
        }}
        
        .chart-medium {{
            height: 250px !important;
        }}
        
        .progress-bars {{
            display: flex;
            flex-direction: column;
            gap: 15px;
        }}
        
        .progress-item {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .progress-label {{
            min-width: 80px;
            font-weight: 500;
            color: #374151;
            font-size: 0.9em;
        }}
        
        .progress-bar {{
            flex: 1;
            height: 12px;
            background: #f1f5f9;
            border-radius: 6px;
            
            position: relative;
        }}
        
        .progress-fill {{
            height: 100%;
            border-radius: 6px;
            transition: width 0.8s ease;
            position: relative;
        }}
        
        .progress-fill.tcp {{
            background: linear-gradient(90deg, #3b82f6, #60a5fa);
        }}
        
        .progress-fill.udp {{
            background: linear-gradient(90deg, #10b981, #34d399);
        }}
        
        .progress-fill.icmp {{
            background: linear-gradient(90deg, #f59e0b, #fbbf24);
        }}
        
        .progress-fill.incoming {{
            background: linear-gradient(90deg, #ef4444, #f87171);
        }}
        
        .progress-fill.outgoing {{
            background: linear-gradient(90deg, #06b6d4, #22d3ee);
        }}
        
        .progress-value {{
            min-width: 40px;
            text-align: right;
            font-weight: 600;
            color: #1e293b;
            font-size: 0.9em;
        }}
        
        .overview-charts {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin: 30px 0;
        }}
        
        .mini-chart {{
            height: 150px !important;
        }}
        
        .chart-stats {{
            display: flex;
            justify-content: space-around;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #f1f5f9;
        }}
        
        .chart-stat {{
            text-align: center;
        }}
        
        .chart-stat-value {{
            font-size: 1.4em;
            font-weight: 700;
            color: #1e293b;
        }}
        
        .chart-stat-label {{
            font-size: 0.8em;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }}
        
        /* Стили для блоков кода с кнопками копирования */
        .code-block {{
            background: linear-gradient(135deg, #f8fafc 0%, #ffffff 100%);
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            margin: 15px 0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            
        }}
        
        .code-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            background: linear-gradient(135deg, #1e293b 0%, #374151 100%);
            color: white;
            border-radius: 12px 12px 0 0;
            font-weight: 600;
            font-size: 0.9em;
        }}
        
        .copy-btn {{
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85em;
            font-weight: 500;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
        }}
        
        .copy-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4);
            background: linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%);
        }}
        
        .copy-btn:active {{
            transform: translateY(0);
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
        }}
        
        .copy-btn.copied {{
            background: linear-gradient(135deg, #10b981 0%, #047857 100%);
            box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
        }}
        
        .code-content {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 20px;
            margin: 0;
            font-family: 'Courier New', 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
            line-height: 1.6;
            border-radius: 0 0 12px 12px;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 300px;
            overflow-y: auto;
            border-top: 1px solid #374151;
        }}
        
        .code-content::-webkit-scrollbar {{
            width: 8px;
        }}
        
        .code-content::-webkit-scrollbar-track {{
            background: #374151;
            border-radius: 0 0 12px 0;
        }}
        
        .code-content::-webkit-scrollbar-thumb {{
            background: #6b7280;
            border-radius: 4px;
        }}
        
        .code-content::-webkit-scrollbar-thumb:hover {{
            background: #9ca3af;
        }}
        
        /* Стили для панели фильтров */
        .filters-panel {{
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
        }}
        
        .filters-row {{
            display: flex;
            gap: 20px;
            align-items: end;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}
        
        .filters-row:last-child {{
            margin-bottom: 0;
        }}
        
        .filter-group {{
            display: flex;
            flex-direction: column;
            gap: 8px;
            min-width: 180px;
        }}
        
        .filter-group label {{
            font-weight: 600;
            color: #374151;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .filter-group select,
        .filter-group input[type="text"] {{
            padding: 12px 15px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 0.95em;
            background: white;
            transition: all 0.3s ease;
            font-family: inherit;
        }}
        
        .filter-group select:focus,
        .filter-group input[type="text"]:focus {{
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }}
        
        .clear-filters-btn {{
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.9em;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.25);
        }}
        
        .clear-filters-btn:hover {{
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(239, 68, 68, 0.35);
        }}
        
        .table-info {{
            background: #f1f5f9;
            padding: 10px 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            font-size: 0.9em;
            color: #475569;
            font-weight: 500;
        }}
        
        /* Стили для скрытых строк при фильтрации */
        .connections-table tr.filtered-hidden {{
            display: none;
        }}
        
        /* Анимация для фильтрации */
        .connections-table tbody tr {{
            transition: opacity 0.3s ease;
        }}
        
        .connections-table tbody tr.filtering {{
            opacity: 0.5;
        }}
        
        /* Стили для кнопки технической документации */
        .tech-docs-btn {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 25px;
            font-weight: 600;
            font-size: 0.95em;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        
        .tech-docs-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
        }}
        
        .tech-docs-btn:active {{
            transform: translateY(0);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <div class="header-title">
                    <div class="logo">
                        <svg viewBox="0 0 24 24">
                            <path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm5-18v4h3V3h-3z"/>
                        </svg>
                    </div>
                    <div style="display: flex; align-items: center; gap: 20px; flex: 1;">
                        <h1>🔍 Анализатор сетевой активности</h1>
                        <button onclick="openTechDocs()" class="tech-docs-btn">
                            🚀 Как это работает?
                        </button>
                    </div>
                </div>
                <div class="header-info">
                    <div class="header-info-item clickable" onclick="showSection('host-info')">
                        <strong>🖥️ Хост</strong>
                        <div class="header-info-value">{cumulative_state.get('hostname', 'unknown')}</div>
                    </div>
                    <div class="header-info-item clickable" onclick="showSection('os-info')">
                        <strong>💻 Операционная система</strong>
                        <div class="header-info-value">{cumulative_state.get('os', {}).get('name', 'unknown')} {cumulative_state.get('os', {}).get('version', '')}</div>
                    </div>
                    <div class="header-info-item clickable" onclick="showSection('changes')">
                        <strong>📊 Измерений</strong>
                        <div class="header-info-value">{cumulative_state.get('total_measurements', 0)}</div>
                    </div>
                    <div class="header-info-item clickable" onclick="showSection('measurements-stats')">
                        <strong>🔄 Последнее обновление</strong>
                        <div class="header-info-value">{cumulative_state.get('last_update', 'unknown')}</div>
                    </div>
                    <div class="header-info-item clickable" onclick="showSection('analyzer-info')">
                        <strong>🔧 Версия анализатора</strong>
                        <div class="header-info-value">v{VERSION}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <div class="nav-buttons">
                <button class="nav-btn active" onclick="showSection('overview')">📊 Обзор</button>
                <button class="nav-btn" onclick="showSection('connections')">🔗 Соединения</button>
                <button class="nav-btn" onclick="showSection('ports')">🚪 Порты</button>
                <button class="nav-btn" onclick="showSection('udp')">📡 UDP трафик</button>
                <button class="nav-btn" onclick="showSection('icmp')">🏓 ICMP трафик</button>
                <button class="nav-btn" onclick="showSection('host-info')">🖥️ Хост</button>
                <button class="nav-btn" onclick="showSection('os-info')">💻 Система</button>
                <button class="nav-btn" onclick="showSection('firewall-rules')">🛡️ Правила файрвола</button>
                <button class="nav-btn" onclick="showSection('security-groups')">🔒 Группы безопасности</button>
                <button class="nav-btn" onclick="showSection('measurements-stats')">📈 Статистика</button>
                <button class="nav-btn changes" onclick="showSection('changes')">📝 История изменений</button>
                <button class="nav-btn" onclick="showSection('analyzer-info')">🔧 О программе</button>
            </div>
        </div>
        
        <div class="content">
            <!-- Секция обзора -->
            <div id="overview" class="section active">
                <h3>📊 Обзор системы</h3>
                <div class="overview-grid">
                    <div>
                        <div class="stats">
                            <div class="stat-card">
                                <div class="stat-number">{total_connections}</div>
                                <div class="stat-label">Всего соединений</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{len(tcp_connections)}</div>
                                <div class="stat-label">TCP соединений</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{len(udp_connections)}</div>
                                <div class="stat-label">UDP соединений</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{icmp_count}</div>
                                <div class="stat-label">ICMP соединений</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{len(incoming_connections)}</div>
                                <div class="stat-label">Входящих</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{len(outgoing_connections)}</div>
                                <div class="stat-label">Исходящих</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{len(unique_processes)}</div>
                                <div class="stat-label">Процессов</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{len(unique_hosts)}</div>
                                <div class="stat-label">Удаленных хостов</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{len(changes_log)}</div>
                                <div class="stat-label">Изменений</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="analytics-panel">
                        <div class="analytics-title">
                            📈 Аналитика
                        </div>
                        
                        <div class="analytics-section">
                            <h4>🔥 Топ процессы</h4>"""
    
    for process, stats in top_processes:
        html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">{process[:20]}</div>
                                <div class="analytics-value">{stats['count']}</div>
                            </div>"""
    
    html_content += f"""
                        </div>
                        
                        <div class="analytics-section">
                            <h4>🌐 Топ хосты</h4>"""
    
    for host, count in top_hosts:
        html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">{host[:25]}</div>
                                <div class="analytics-value">{count}</div>
                            </div>"""
    
    html_content += f"""
                        </div>
                        
                        <div class="analytics-section">
                            <h4>⏰ Активность по часам</h4>
                            <div class="activity-chart">"""
    
    # Создаем график активности по часам
    max_activity = max(activity_hours.values()) if activity_hours else 1
    for hour in range(24):
        hour_str = f"{hour:02d}"
        activity = activity_hours.get(hour_str, 0)
        height_percent = (activity / max_activity) * 100 if max_activity > 0 else 0
        html_content += f'<div class="activity-bar" style="height: {height_percent}%" title="{hour_str}:00 - {activity} соединений"></div>'
    
    html_content += f"""
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Современные диаграммы и графики -->
                <div class="overview-charts">
                    <!-- Диаграмма распределения протоколов -->
                    <div class="chart-card">
                        <div class="chart-title">
                            🔧 Распределение протоколов
                        </div>
                        <div class="chart-wrapper chart-small">
                            <canvas id="protocolChart"></canvas>
                        </div>
                        <div class="chart-stats">
                            <div class="chart-stat">
                                <div class="chart-stat-value">{tcp_count}</div>
                                <div class="chart-stat-label">TCP</div>
                            </div>
                            <div class="chart-stat">
                                <div class="chart-stat-value">{udp_count}</div>
                                <div class="chart-stat-label">UDP</div>
                            </div>
                            <div class="chart-stat">
                                <div class="chart-stat-value">{icmp_count}</div>
                                <div class="chart-stat-label">ICMP</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Диаграмма направления соединений -->
                    <div class="chart-card">
                        <div class="chart-title">
                            ↔️ Направление соединений
                        </div>
                        <div class="chart-wrapper chart-small">
                            <canvas id="directionChart"></canvas>
                        </div>
                        <div class="chart-stats">
                            <div class="chart-stat">
                                <div class="chart-stat-value">{incoming_count}</div>
                                <div class="chart-stat-label">Входящих</div>
                            </div>
                            <div class="chart-stat">
                                <div class="chart-stat-value">{outgoing_count}</div>
                                <div class="chart-stat-label">Исходящих</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- График активности процессов -->
                    <div class="chart-card">
                        <div class="chart-title">
                            🚀 Активность процессов
                        </div>
                        <div class="chart-wrapper chart-medium">
                            <canvas id="processChart"></canvas>
                        </div>
                    </div>
                    
                    <!-- График активности по времени -->
                    <div class="chart-card">
                        <div class="chart-title">
                            ⏰ Активность по часам
                        </div>
                        <div class="chart-wrapper chart-medium">
                            <canvas id="timelineChart"></canvas>
                        </div>
                    </div>
                </div>
                
                <!-- Прогресс-бары для детальной статистики -->
                <div class="chart-card">
                    <div class="chart-title">
                        📊 Детальная статистика соединений
                    </div>
                    <div class="progress-bars">
                        <div class="progress-item">
                            <div class="progress-label">TCP</div>
                            <div class="progress-bar">
                                <div class="progress-fill tcp" style="width: {(tcp_count / max(total_connections, 1)) * 100}%"></div>
                            </div>
                            <div class="progress-value">{tcp_count}</div>
                        </div>
                        <div class="progress-item">
                            <div class="progress-label">UDP</div>
                            <div class="progress-bar">
                                <div class="progress-fill udp" style="width: {(udp_count / max(total_connections, 1)) * 100}%"></div>
                            </div>
                            <div class="progress-value">{udp_count}</div>
                        </div>
                        <div class="progress-item">
                            <div class="progress-label">ICMP</div>
                            <div class="progress-bar">
                                <div class="progress-fill icmp" style="width: {(icmp_count / max(total_connections, 1)) * 100}%"></div>
                            </div>
                            <div class="progress-value">{icmp_count}</div>
                        </div>
                        <div class="progress-item">
                            <div class="progress-label">Входящие</div>
                            <div class="progress-bar">
                                <div class="progress-fill incoming" style="width: {(incoming_count / max(total_connections, 1)) * 100}%"></div>
                            </div>
                            <div class="progress-value">{incoming_count}</div>
                        </div>
                        <div class="progress-item">
                            <div class="progress-label">Исходящие</div>
                            <div class="progress-bar">
                                <div class="progress-fill outgoing" style="width: {(outgoing_count / max(total_connections, 1)) * 100}%"></div>
                            </div>
                            <div class="progress-value">{outgoing_count}</div>
                        </div>
                        <div class="progress-item">
                            <div class="progress-label">Процессы</div>
                            <div class="progress-bar">
                                <div class="progress-fill tcp" style="width: {min((processes_count / 10) * 100, 100)}%"></div>
                            </div>
                            <div class="progress-value">{processes_count}</div>
                        </div>
                        <div class="progress-item">
                            <div class="progress-label">Хосты</div>
                            <div class="progress-bar">
                                <div class="progress-fill udp" style="width: {min((hosts_count / 20) * 100, 100)}%"></div>
                            </div>
                            <div class="progress-value">{hosts_count}</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Секция соединений -->
            <div id="connections" class="section">
                <h3>🔗 Активные соединения (TCP + UDP)</h3>
                
                <!-- Панель фильтров -->
                <div class="filters-panel">
                    <div class="filters-row">
                        <div class="filter-group">
                            <label for="filter-direction">Направление:</label>
                            <select id="filter-direction" onchange="filterConnections()">
                                <option value="">Все</option>
                                <option value="incoming">📥 Входящие</option>
                                <option value="outgoing">📤 Исходящие</option>
                            </select>
                        </div>
                        
                        <div class="filter-group">
                            <label for="filter-protocol">Протокол:</label>
                            <select id="filter-protocol" onchange="filterConnections()">
                                <option value="">Все</option>
                                <option value="TCP">TCP</option>
                                <option value="UDP">UDP</option>
                                <option value="ICMP">ICMP</option>
                            </select>
                        </div>
                        
                        <div class="filter-group">
                            <label for="filter-process">Процесс:</label>
                            <input type="text" id="filter-process" placeholder="Фильтр по процессу..." onkeyup="filterConnections()">
                        </div>
                    </div>
                    
                    <div class="filters-row">
                        <div class="filter-group">
                            <label for="filter-local">Локальный адрес:</label>
                            <input type="text" id="filter-local" placeholder="Фильтр по локальному адресу..." onkeyup="filterConnections()">
                        </div>
                        
                        <div class="filter-group">
                            <label for="filter-remote">Удаленный адрес:</label>
                            <input type="text" id="filter-remote" placeholder="Фильтр по удаленному адресу..." onkeyup="filterConnections()">
                        </div>
                        
                        <div class="filter-group">
                            <button onclick="clearFilters()" class="clear-filters-btn">🗑️ Очистить фильтры</button>
                        </div>
                    </div>
                </div>
                
                <div class="table-info">
                    <span id="connections-count">Отображается соединений: 0</span>
                </div>
                
                <table class="connections-table" id="connections-table">
                    <thead>
                        <tr>
                            <th>Направление</th>
                            <th>Локальный адрес</th>
                            <th>Удаленный адрес</th>
                            <th>Процесс</th>
                            <th>Протокол</th>
                            <th>Последний раз</th>
                            <th>Счетчик</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    # Добавляем все соединения (TCP + UDP) и сортируем по счетчику
    all_connections = []
    
    # Добавляем входящие соединения
    for conn in incoming_connections:
        all_connections.append(('📥 Входящее', conn))
    
    # Добавляем исходящие соединения
    for conn in outgoing_connections:
        all_connections.append(('📤 Исходящее', conn))
    
    # Сортируем по счетчику от большего к меньшему
    all_connections.sort(key=lambda x: x[1].get('count', 1), reverse=True)
    
    # Добавляем информацию о количестве соединений после создания all_connections
    html_content = html_content.replace(
        '<span id="connections-count">Отображается соединений: {len(all_connections[:50])}</span>',
        f'<span id="connections-count">Отображается соединений: {len(all_connections[:50])}</span>'
    )
    
    # Показываем первые 50 соединений
    for direction, conn in all_connections[:50]:
        protocol = conn.get('protocol', 'unknown').upper()
        protocol_class = f"protocol-{protocol.lower()}"
        direction_class = "direction-in" if "Входящее" in direction else "direction-out"
        
        # Умная логика для определения CSS класса процесса
        process_name = conn.get('process', 'unknown')
        if len(process_name) > 60 or ('/' in process_name and len(process_name) > 40):
            # Длинные названия или системные пути - обрезаем
            process_class = "process-name-long"
        else:
            # Короткие названия - показываем полностью
            process_class = "process-name-short"
        
        html_content += f"""
                        <tr>
                            <td class="{direction_class}">{direction}</td>
                            <td class="address-cell">{conn.get('local', 'unknown')}</td>
                            <td class="address-cell">{conn.get('remote', {}).get('address', 'unknown')}</td>
                            <td class="{process_class}">{process_name}</td>
                            <td><span class="{protocol_class}">{protocol}</span></td>
                            <td>{conn.get('last_seen', 'unknown')}</td>
                            <td><strong>{conn.get('count', 1)}</strong></td>
                        </tr>
        """
    
    html_content += f"""
                    </tbody>
                </table>
            </div>
            
            <!-- Секция портов -->
            <div id="ports" class="section">
                <h3>🚪 TCP порты</h3>
                <div class="ports-grid">
    """
    
    for port in tcp_ports[:30]:
        html_content += f'<div class="port-item port-tcp"><div class="port-number">TCP {port}</div></div>'
    
    html_content += f"""
                </div>
                
                <h3>🚪 UDP порты</h3>
                <div class="ports-grid">
    """
    
    for port in udp_ports[:30]:
        html_content += f'<div class="port-item port-udp"><div class="port-number">UDP {port}</div></div>'
    
    html_content += f"""
                </div>
            </div>
            
            <!-- Секция UDP трафика -->
            <div id="udp" class="section">
    """
    
    # Добавляем секцию UDP трафика если есть данные
    if udp_traffic_connections:
        html_content += f"""
                <div class="udp-section">
                    <h3>📡 UDP трафик (детальная информация)</h3>
                    <p><strong>Всего UDP соединений:</strong> {len(udp_traffic_connections)}</p>
                    <p><strong>Удаленных хостов:</strong> {udp_traffic.get('total_remote_hosts', 0)}</p>
                    
                    <!-- Панель фильтров для UDP -->
                    <div class="filters-panel">
                        <div class="filters-row">
                            <div class="filter-group">
                                <label for="udp-filter-direction">Направление:</label>
                                <select id="udp-filter-direction" onchange="filterUdpTable()">
                                    <option value="">Все</option>
                                    <option value="incoming">📥 Входящие</option>
                                    <option value="outgoing">📤 Исходящие</option>
                                </select>
                            </div>
                            
                            <div class="filter-group">
                                <label for="udp-filter-process">Процесс:</label>
                                <input type="text" id="udp-filter-process" placeholder="Фильтр по процессу..." onkeyup="filterUdpTable()">
                            </div>
                            
                            <div class="filter-group">
                                <label for="udp-filter-connection">Соединение:</label>
                                <input type="text" id="udp-filter-connection" placeholder="Фильтр по адресу..." onkeyup="filterUdpTable()">
                            </div>
                            
                            <div class="filter-group">
                                <button onclick="clearUdpFilters()" class="clear-filters-btn">🗑️ Очистить фильтры</button>
                            </div>
                        </div>
                    </div>
                    
                    <table class="connections-table">
                        <thead>
                            <tr>
                                <th>Соединение</th>
                                <th>Процесс</th>
                                <th>Направление</th>
                                <th>Пакетов</th>
                                <th>Первый раз</th>
                                <th>Последний раз</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        for udp_conn in udp_traffic_connections[:20]:
            direction = udp_conn.get('direction', 'unknown')
            direction_icon = "📥" if direction == "incoming" else "📤"
            
            html_content += f"""
                            <tr>
                                <td class="address-cell">{udp_conn.get('connection', 'unknown')}</td>
                                <td class="process-name">{udp_conn.get('process', 'unknown')}</td>
                                <td>{direction_icon} {direction}</td>
                                <td>{udp_conn.get('packet_count', 0)}</td>
                                <td>{udp_conn.get('first_seen', 'unknown')}</td>
                                <td>{udp_conn.get('last_seen', 'unknown')}</td>
                            </tr>
            """
        
        html_content += f"""
                        </tbody>
                    </table>
                </div>
        """
    else:
        # Проверяем, есть ли UDP соединения в основных соединениях
        if udp_connections:
            html_content += f"""
                <div class="udp-section">
                    <h3>📡 UDP соединения (из основного сканирования)</h3>
                    <p><strong>Найдено UDP соединений:</strong> {len(udp_connections)}</p>
                    <p><strong>UDP портов:</strong> {len(udp_ports)}</p>
                    
                    <table class="connections-table">
                        <thead>
                            <tr>
                                <th>Локальный адрес</th>
                                <th>Удаленный адрес</th>
                                <th>Процесс</th>
                                <th>Последний раз</th>
                                <th>Счетчик</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            
            for udp_conn in udp_connections[:20]:
                html_content += f"""
                                <tr>
                                    <td class="address-cell">{udp_conn.get('local', 'unknown')}</td>
                                    <td class="address-cell">{udp_conn.get('remote', {}).get('address', 'unknown')}</td>
                                    <td class="process-name">{udp_conn.get('process', 'unknown')}</td>
                                    <td>{udp_conn.get('last_seen', 'unknown')}</td>
                                    <td><strong>{udp_conn.get('count', 1)}</strong></td>
                                </tr>
                """
            
            html_content += f"""
                        </tbody>
                    </table>
                    
                    <div class="warning" style="margin-top: 20px;">
                        💡 <strong>Совет:</strong> Для более детального мониторинга UDP трафика запустите анализатор с большим интервалом (10+ секунд) и правами администратора.
                    </div>
                </div>
            """
        else:
            html_content += f"""
                <div class="warning">
                    ℹ️ UDP трафик не обнаружен. Для мониторинга UDP соединений запустите анализатор с большим интервалом (10+ секунд) и правами администратора.
                    <br><br>
                    🔍 <strong>Возможные причины:</strong>
                    <ul style="margin-top: 10px; margin-left: 20px;">
                        <li>Недостаточно прав доступа (попробуйте sudo)</li>
                        <li>Короткий интервал сканирования (UDP соединения кратковременны)</li>
                        <li>Отсутствие активного UDP трафика в момент сканирования</li>
                    </ul>
                </div>
            """
    
    html_content += f"""
            </div>
            
            <!-- Секция ICMP трафика -->
            <div id="icmp" class="section">
                <h3>🏓 ICMP трафик</h3>
                
                <div class="warning" style="margin-bottom: 20px;">
                    💡 <strong>О данных ICMP:</strong> Анализатор отслеживает реальный ICMP трафик (ping, traceroute). 
                    Для получения данных о ICMP соединениях запустите анализатор с правами администратора: <code>sudo</code>.
                    Без прав администратора ICMP данные недоступны.
                </div>"""
    
    # Добавляем секцию ICMP трафика если есть данные
    if icmp_traffic_connections:
        html_content += f"""
                <div class="udp-section">
                    <h3>🏓 ICMP соединения (детальная информация)</h3>
                    <p><strong>Всего ICMP соединений:</strong> {len(icmp_traffic_connections)}</p>
                    <p><strong>Общее количество пакетов:</strong> {icmp_total_packets}</p>
                    
                    <!-- Панель фильтров для ICMP -->
                    <div class="filters-panel">
                        <div class="filters-row">
                            <div class="filter-group">
                                <label for="icmp-filter-process">Процесс:</label>
                                <input type="text" id="icmp-filter-process" placeholder="Фильтр по процессу..." onkeyup="filterIcmpTable()">
                            </div>
                            
                            <div class="filter-group">
                                <label for="icmp-filter-connection">Соединение:</label>
                                <input type="text" id="icmp-filter-connection" placeholder="Фильтр по адресу..." onkeyup="filterIcmpTable()">
                            </div>
                            
                            <div class="filter-group">
                                <label for="icmp-filter-type">Тип ICMP:</label>
                                <input type="text" id="icmp-filter-type" placeholder="Фильтр по типу..." onkeyup="filterIcmpTable()">
                            </div>
                            
                            <div class="filter-group">
                                <button onclick="clearIcmpFilters()" class="clear-filters-btn">🗑️ Очистить фильтры</button>
                            </div>
                        </div>
                    </div>
                    
                    <table class="connections-table">
                        <thead>
                            <tr>
                                <th>Соединение</th>
                                <th>Процесс</th>
                                <th>Направление</th>
                                <th>Пакетов</th>
                                <th>Тип</th>
                                <th>Последний раз</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        for icmp_conn in icmp_traffic_connections[:20]:
            direction = icmp_conn.get('direction', 'unknown')
            direction_icon = "📥" if direction == "incoming" else "📤"
            icmp_type = icmp_conn.get('icmp_type', 'unknown')
            
            html_content += f"""
                            <tr>
                                <td class="address-cell">{icmp_conn.get('connection', 'unknown')}</td>
                                <td class="process-name">{icmp_conn.get('process', 'unknown')}</td>
                                <td>{direction_icon} {direction}</td>
                                <td>{icmp_conn.get('packet_count', 0)}</td>
                                <td>{icmp_type}</td>
                                <td>{icmp_conn.get('last_seen', 'unknown')}</td>
                            </tr>"""
        
        html_content += f"""
                        </tbody>
                    </table>
                    
                    
                    <div class="analytics-panel" style="margin-top: 30px;">
                        <div class="analytics-title">
                            📊 Статистика ICMP трафика
                        </div>
                        
                        <div class="analytics-section">
                            <h4>📈 Метрики</h4>
                            <div class="analytics-item">
                                <div class="analytics-name">Всего соединений</div>
                                <div class="analytics-value">{len(icmp_traffic_connections)}</div>
                            </div>
                            <div class="analytics-item">
                                <div class="analytics-name">Общее количество пакетов</div>
                                <div class="analytics-value">{icmp_total_packets}</div>
                            </div>"""
        
        # Подсчитываем типы ICMP
        icmp_types = {}
        icmp_directions = {'incoming': 0, 'outgoing': 0}
        for conn in icmp_traffic_connections:
            icmp_type = conn.get('icmp_type', 'unknown')
            direction = conn.get('direction', 'unknown')
            icmp_types[icmp_type] = icmp_types.get(icmp_type, 0) + 1
            if direction in icmp_directions:
                icmp_directions[direction] += 1
        
        html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">Типов ICMP</div>
                                <div class="analytics-value">{len(icmp_types)}</div>
                            </div>
                            <div class="analytics-item">
                                <div class="analytics-name">Входящих</div>
                                <div class="analytics-value">{icmp_directions['incoming']}</div>
                            </div>
                            <div class="analytics-item">
                                <div class="analytics-name">Исходящих</div>
                                <div class="analytics-value">{icmp_directions['outgoing']}</div>
                            </div>
                        </div>
                        
                        <div class="analytics-section">
                            <h4>🔍 Типы ICMP пакетов</h4>"""
        
        for icmp_type, count in list(icmp_types.items())[:10]:
            html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">{icmp_type}</div>
                                <div class="analytics-value">{count}</div>
                            </div>"""
        
        html_content += f"""
                        </div>
                    </div>
                </div>"""
    elif icmp_connections:  # Если есть ICMP соединения из основного сканирования
        html_content += f"""
                <div class="udp-section">
                    <h3>🏓 ICMP соединения (из основного сканирования)</h3>
                    <p><strong>Найдено ICMP соединений:</strong> {len(icmp_connections)}</p>
                    
                    <table class="connections-table">
                        <thead>
                            <tr>
                                <th>Локальный адрес</th>
                                <th>Удаленный адрес</th>
                                <th>Процесс</th>
                                <th>Последний раз</th>
                                <th>Счетчик</th>
                            </tr>
                        </thead>
                        <tbody>"""
        
        for icmp_conn in icmp_connections[:20]:
            html_content += f"""
                            <tr>
                                <td class="address-cell">{icmp_conn.get('local', 'unknown')}</td>
                                <td class="address-cell">{icmp_conn.get('remote', {}).get('address', 'unknown')}</td>
                                <td class="process-name">{icmp_conn.get('process', 'unknown')}</td>
                                <td>{icmp_conn.get('last_seen', 'unknown')}</td>
                                <td><strong>{icmp_conn.get('count', 1)}</strong></td>
                            </tr>"""
        
        html_content += f"""
                        </tbody>
                    </table>
                    
                    <div class="warning" style="margin-top: 20px;">
                        💡 <strong>Совет:</strong> Для более детального мониторинга ICMP трафика запустите анализатор с правами администратора и большим интервалом сканирования.
                    </div>
                </div>"""
    else:
        html_content += f"""
                <div class="warning">
                    ℹ️ ICMP трафик не обнаружен. Для мониторинга ICMP соединений (ping, traceroute) запустите анализатор с правами администратора.
                    <br><br>
                    🔍 <strong>Возможные причины:</strong>
                    <ul style="margin-top: 10px; margin-left: 20px;">
                        <li>Недостаточно прав доступа (попробуйте sudo)</li>
                        <li>Отсутствие активного ICMP трафика в момент сканирования</li>
                        <li>ICMP пакеты блокируются файрволом</li>
                        <li>Система не поддерживает мониторинг raw sockets</li>
                    </ul>
                    <br>
                    📝 <strong>Примеры ICMP активности:</strong>
                    <ul style="margin-top: 10px; margin-left: 20px;">
                        <li>ping google.com (ICMP Echo Request/Reply)</li>
                        <li>traceroute 8.8.8.8 (ICMP Time Exceeded)</li>
                        <li>Сетевые ошибки (ICMP Destination Unreachable)</li>
                    </ul>
                </div>"""
    
    html_content += f"""
            </div>
            
            <!-- Секция истории изменений -->
            <div id="changes" class="section">
                <h3>📝 Последние изменения</h3>
    """
    
    if changes_log:
        html_content += '<div class="changes-timeline">'
        
        for change in changes_log[-10:]:
            timestamp = change.get('timestamp', 'unknown')
            changes_count = len(change.get('changes', {}))
            change_id = change.get('id', 'unknown')
            is_first = change.get('first_run', False)
            
            change_type = "🚀 Первый запуск" if is_first else "🔄 Обновление"
            
            html_content += f"""
                <div class="change-item">
                    <div class="change-timestamp">
                        {change_type} #{change_id} - {timestamp}
                    </div>
                    <div class="change-details">
                        Изменений в категориях: {changes_count}
                    </div>
                </div>
            """
        
        html_content += '</div>'
    else:
        html_content += f"""
                <div class="warning">
                    ℹ️ История изменений пуста. Изменения будут отображаться после нескольких запусков анализатора.
                </div>
        """
    
    html_content += f"""
            </div>
            
            <!-- Секция информации о хосте -->
            <div id="host-info" class="section">
                <h3>🖥️ Информация о хосте</h3>
    """
    
    # Получаем расширенную информацию о системе
    extended_info = current_state.get('extended_system_info', {})
    host_info = extended_info.get('host_info', {})
    docker_info = extended_info.get('docker_info', {})
    firewall_info = extended_info.get('firewall_info', {})
    users_info = extended_info.get('users_info', {})
    
    html_content += f"""
                <div class="overview-grid">
                    <div>
                        <div class="stats">
                            <div class="stat-card">
                                <div class="stat-number">{host_info.get('cpu_count', 'N/A')}</div>
                                <div class="stat-label">CPU ядер</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{host_info.get('memory_total_gb', 'N/A')}</div>
                                <div class="stat-label">ГБ памяти</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{len(host_info.get('disk_usage', {}))}</div>
                                <div class="stat-label">Дисков</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{round((time.time() - psutil.boot_time()) / 86400, 1) if hasattr(psutil, 'boot_time') else 'N/A'}</div>
                                <div class="stat-label">Дней работы</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{docker_info.get('containers_count', 0)}</div>
                                <div class="stat-label">Docker контейнеров</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{firewall_info.get('total_rules', 0)}</div>
                                <div class="stat-label">Правил файрвола</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{len(users_info)}</div>
                                <div class="stat-label">Пользователей</div>
                            </div>
                        </div>
                        
                        <div class="analytics-panel">
                            <div class="analytics-title">
                                📋 Детали хоста
                            </div>
                            
                            <div class="analytics-section">
                                <h4>🏷️ Идентификация</h4>
                                <div class="analytics-item">
                                    <div class="analytics-name">Hostname</div>
                                    <div class="analytics-value">{host_info.get('hostname', 'unknown')}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">FQDN</div>
                                    <div class="analytics-value">{host_info.get('fqdn', 'unknown')}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Local IP</div>
                                    <div class="analytics-value">{host_info.get('local_ip', 'unknown')}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Boot Time</div>
                                    <div class="analytics-value">{host_info.get('boot_time', 'unknown')}</div>
                                </div>
                            </div>
                            
                            <div class="analytics-section">
                                <h4>🐳 Docker контейнеры</h4>
                                <div class="analytics-item">
                                    <div class="analytics-name">Статус Docker</div>
                                    <div class="analytics-value">{'Доступен' if docker_info.get('available', False) else 'Недоступен'}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Запущено контейнеров</div>
                                    <div class="analytics-value">{docker_info.get('containers_count', 0)}</div>
                                </div>"""
    
    # Добавляем список контейнеров если они есть
    docker_containers = docker_info.get('containers', [])
    if docker_containers:
        for container in docker_containers[:5]:  # Показываем первые 5
            html_content += f"""
                                <div class="analytics-item">
                                    <div class="analytics-name">🐳 {container.get('name', 'Unknown')}</div>
                                    <div class="analytics-value">Запущен</div>
                                </div>"""
    
    html_content += f"""
                            </div>
                            
                            <div class="analytics-section">
                                <h4>🛡️ Безопасность</h4>
                                <div class="analytics-item">
                                    <div class="analytics-name">Файрвол</div>
                                    <div class="analytics-value">{'Активен' if firewall_info.get('total_rules', 0) > 0 else 'Неактивен'}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Правил всего</div>
                                    <div class="analytics-value">{firewall_info.get('total_rules', 0)}</div>
                                </div>"""
    
    # Краткая статистика по типам правил
    if firewall_info.get('iptables'):
        html_content += f"""
                                <div class="analytics-item">
                                    <div class="analytics-name">iptables цепочек</div>
                                    <div class="analytics-value">{len(firewall_info['iptables'])}</div>
                                </div>"""
    
    if firewall_info.get('firewall_rules'):
        html_content += f"""
                                <div class="analytics-item">
                                    <div class="analytics-name">firewalld зон</div>
                                    <div class="analytics-value">{len(firewall_info['firewall_rules'])}</div>
                                </div>"""
    
    html_content += f"""
                            </div>
                        </div>
                    </div>
                    
                    <div class="analytics-panel">
                        <div class="analytics-title">
                            👥 Пользователи системы
                        </div>"""
    
    if users_info:
        html_content += f"""
                        <div class="analytics-section">
                            <h4>👤 Активные пользователи</h4>"""
        
        # Показываем первых 10 пользователей
        for username, user_data in list(users_info.items())[:10]:
            user_type = user_data.get('type', 'unknown')
            uid = user_data.get('uid', 'unknown')
            last_login = user_data.get('last_login', 'unknown')
            
            html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">{username} (UID: {uid})</div>
                                <div class="analytics-value">{user_type}</div>
                            </div>"""
            
            if last_login != 'unknown':
                html_content += f"""
                            <div class="analytics-item" style="margin-left: 20px; font-size: 0.85em; opacity: 0.7;">
                                <div class="analytics-name">Последний вход</div>
                                <div class="analytics-value">{last_login}</div>
                            </div>"""
        
        html_content += f"""
                        </div>"""
    else:
        html_content += f"""
                        <div class="warning">
                            ℹ️ Информация о пользователях недоступна
                        </div>"""
    
    html_content += f"""
                        
                        <div class="analytics-title" style="margin-top: 20px;">
                            💾 Использование дисков
                        </div>"""
    
    disk_usage = host_info.get('disk_usage', {})
    if disk_usage:
        for device, info in list(disk_usage.items())[:5]:  # Показываем первые 5 дисков
            html_content += f"""
                        <div class="analytics-section">
                            <h4>📀 {device}</h4>
                            <div class="analytics-item">
                                <div class="analytics-name">Размер</div>
                                <div class="analytics-value">{info.get('total_gb', 'N/A')} ГБ</div>
                            </div>
                            <div class="analytics-item">
                                <div class="analytics-name">Использовано</div>
                                <div class="analytics-value">{info.get('used_gb', 'N/A')} ГБ ({info.get('percent', 'N/A')}%)</div>
                            </div>
                            <div class="analytics-item">
                                <div class="analytics-name">Свободно</div>
                                <div class="analytics-value">{info.get('free_gb', 'N/A')} ГБ</div>
                            </div>
                            <div class="analytics-item">
                                <div class="analytics-name">Тип ФС</div>
                                <div class="analytics-value">{info.get('fstype', 'N/A')}</div>
                            </div>
                        </div>"""
    else:
        html_content += f"""
                        <div class="warning">
                            ℹ️ Информация о дисках недоступна
                        </div>"""
    
    html_content += f"""
                    </div>
                </div>
            </div>
            
            <!-- Секция информации об ОС -->
            <div id="os-info" class="section">
                <h3>💻 Информация об операционной системе</h3>
    """
    
    os_info = extended_info.get('os_info', {})
    
    html_content += f"""
                <div class="overview-grid">
                    <div>
                        <div class="analytics-panel">
                            <div class="analytics-title">
                                🖥️ Системная информация
                            </div>
                            
                            <div class="analytics-section">
                                <h4>📋 Основные данные</h4>
                                <div class="analytics-item">
                                    <div class="analytics-name">Система</div>
                                    <div class="analytics-value">{os_info.get('name', 'unknown')}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Версия</div>
                                    <div class="analytics-value">{os_info.get('version', 'unknown')}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Архитектура</div>
                                    <div class="analytics-value">{os_info.get('architecture', 'unknown')}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Процессор</div>
                                    <div class="analytics-value">{os_info.get('processor', 'unknown')[:50]}...</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Платформа</div>
                                    <div class="analytics-value">{os_info.get('platform', 'unknown')[:50]}...</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Python версия</div>
                                    <div class="analytics-value">{os_info.get('python_version', 'unknown')}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="analytics-panel">
                        <div class="analytics-title">
                            ⚙️ Системные характеристики
                        </div>
                        
                        <div class="analytics-section">
                            <h4>🔧 Конфигурация</h4>
                            <div class="analytics-item">
                                <div class="analytics-name">Последнее обновление</div>
                                <div class="analytics-value">{os_info.get('last_updated', 'unknown')}</div>
                            </div>
                        </div>
                        
                        <div class="analytics-section">
                            <h4>📊 Ресурсы</h4>
                            <div class="analytics-item">
                                <div class="analytics-name">CPU ядер</div>
                                <div class="analytics-value">{host_info.get('cpu_count', 'N/A')}</div>
                            </div>
                            <div class="analytics-item">
                                <div class="analytics-name">Общая память</div>
                                <div class="analytics-value">{host_info.get('memory_total_gb', 'N/A')} ГБ</div>
                            </div>
                            <div class="analytics-item">
                                <div class="analytics-name">Время загрузки</div>
                                <div class="analytics-value">{host_info.get('boot_time', 'unknown')}</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Секция статистики измерений -->
            <div id="measurements-stats" class="section">
                <h3>📈 Статистика измерений</h3>
    """
    
    stats = generate_measurements_statistics(cumulative_state)
    
    html_content += f"""
                <div class="overview-grid">
                    <div>
                        <div class="stats">
                            <div class="stat-card">
                                <div class="stat-number">{stats['total_measurements']}</div>
                                <div class="stat-label">Всего измерений</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{stats['total_changes']}</div>
                                <div class="stat-label">Обнаружено изменений</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{stats['average_duration']}</div>
                                <div class="stat-label">Среднее время (сек)</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{stats['most_active_hour'][0]}</div>
                                <div class="stat-label">Самый активный час</div>
                            </div>
                        </div>
                        
                        <div class="analytics-panel">
                            <div class="analytics-title">
                                📊 Общая статистика
                            </div>
                            
                            <div class="analytics-section">
                                <h4>⏱️ Временные метрики</h4>
                                <div class="analytics-item">
                                    <div class="analytics-name">Первый запуск</div>
                                    <div class="analytics-value">{stats['first_run']}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Последнее обновление</div>
                                    <div class="analytics-value">{stats['last_update']}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Мин. время измерения</div>
                                    <div class="analytics-value">{stats['min_duration']} сек</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Макс. время измерения</div>
                                    <div class="analytics-value">{stats['max_duration']} сек</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="analytics-panel">
                        <div class="analytics-title">
                            🔥 Активность изменений
                        </div>
                        
                        <div class="analytics-section">
                            <h4>📈 По категориям</h4>"""
    
    for category, count in list(stats['changes_by_category'].items())[:5]:
        html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">{category}</div>
                                <div class="analytics-value">{count}</div>
                            </div>"""
    
    html_content += f"""
                        </div>
                        
                        <div class="analytics-section">
                            <h4>🕐 По часам</h4>
                            <div class="activity-chart">"""
    
    # График активности изменений по часам
    max_changes = max(stats['changes_by_hour'].values()) if stats['changes_by_hour'] else 1
    for hour in range(24):
        hour_str = f"{hour:02d}"
        changes = stats['changes_by_hour'].get(hour_str, 0)
        height_percent = (changes / max_changes) * 100 if max_changes > 0 else 0
        html_content += f'<div class="activity-bar" style="height: {height_percent}%" title="{hour_str}:00 - {changes} изменений"></div>'
    
    html_content += f"""
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Секция информации о Glacier -->
            <div id="analyzer-info" class="section">
                <h3>🔧 О программе Glacier</h3>
    """
    
    analyzer_info = extended_info.get('analyzer_info', {})
    
    html_content += f"""
                <div class="overview-grid">
                    <div>
                        <div class="analytics-panel">
                            <div class="analytics-title">
                                🚀 Информация о программе
                            </div>
                            
                            <div class="analytics-section">
                                <h4>📋 Основная информация</h4>
                                <div class="analytics-item">
                                    <div class="analytics-name">Название</div>
                                    <div class="analytics-value">{analyzer_info.get('name', 'Glacier')}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Версия</div>
                                    <div class="analytics-value">v{analyzer_info.get('version', VERSION)}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Описание</div>
                                    <div class="analytics-value">{analyzer_info.get('description', 'System monitoring tool')}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Требования</div>
                                    <div class="analytics-value">{analyzer_info.get('python_requirements', 'Python 3.6+')}</div>
                                </div>
                                <div class="analytics-item">
                                    <div class="analytics-name">Последнее обновление</div>
                                    <div class="analytics-value">{analyzer_info.get('last_updated', 'unknown')}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="analytics-panel">
                        <div class="analytics-title">
                            ⚡ Возможности
                        </div>
                        
                        <div class="analytics-section">
                            <h4>🛠️ Функции анализатора</h4>"""
    
    features = analyzer_info.get('features', [])
    for feature in features:
        html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">✅ {feature}</div>
                                <div class="analytics-value">Активно</div>
                            </div>"""
    
    html_content += f"""
                        </div>
                        
                        <div class="analytics-section">
                            <h4>🌍 Поддерживаемые платформы</h4>"""
    
    platforms = analyzer_info.get('supported_platforms', [])
    for platform_name in platforms:
        html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">{platform_name}</div>
                                <div class="analytics-value">✅ Поддерживается</div>
                            </div>"""
    
    html_content += f"""
                        </div>
                    </div>
                </div>
            </div>
        </div>"""
    
    # Добавляем секцию правил файрвола
    html_content += f"""
            
            <!-- Секция правил файрвола -->
            <div id="firewall-rules" class="section">
                <h3>🛡️ Правила файрвола</h3>"""
    
    firewall_info = extended_info.get('firewall_info', {})
    
    if firewall_info and firewall_info.get('total_rules', 0) > 0:
        html_content += f"""
                <div class="overview-grid">
                    <div>
                        <div class="stats">
                            <div class="stat-card">
                                <div class="stat-number">{firewall_info.get('total_rules', 0)}</div>
                                <div class="stat-label">Всего правил</div>
                            </div>"""
        
        # Статистика по типам правил
        iptables_count = 0
        firewalld_count = 0
        ufw_count = 0
        
        if firewall_info.get('iptables'):
            for chain, rules in firewall_info['iptables'].items():
                iptables_count += len(rules)
        
        if firewall_info.get('firewall_rules'):
            for zone, rules in firewall_info['firewall_rules'].items():
                firewalld_count += len(rules)
        
        if firewall_info.get('ufw_state'):
            ufw_count = len(firewall_info['ufw_state'])
        
        html_content += f"""
                            <div class="stat-card">
                                <div class="stat-number">{iptables_count}</div>
                                <div class="stat-label">iptables</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{firewalld_count}</div>
                                <div class="stat-label">firewalld</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-number">{ufw_count}</div>
                                <div class="stat-label">UFW</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="analytics-panel">
                        <div class="analytics-title">
                            📊 Краткая статистика
                        </div>
                        
                        <div class="analytics-section">
                            <h4>🔧 Типы файрволов</h4>"""
        
        if iptables_count > 0:
            html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">iptables активен</div>
                                <div class="analytics-value">✅ {iptables_count} правил</div>
                            </div>"""
        
        if firewalld_count > 0:
            html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">firewalld активен</div>
                                <div class="analytics-value">✅ {firewalld_count} правил</div>
                            </div>"""
        
        if ufw_count > 0:
            html_content += f"""
                            <div class="analytics-item">
                                <div class="analytics-name">UFW активен</div>
                                <div class="analytics-value">✅ {ufw_count} правил</div>
                            </div>"""
        
        html_content += f"""
                        </div>
                    </div>
                </div>
                
                <!-- Детальные правила файрвола -->"""
        
        # iptables правила
        if firewall_info.get('iptables'):
            html_content += f"""
                <div class="analytics-panel" style="margin-top: 30px;">
                    <div class="analytics-title">
                        🔧 iptables правила
                    </div>"""
            
            for chain, rules in firewall_info['iptables'].items():
                html_content += f"""
                    <div class="analytics-section">
                        <h4>Chain: {chain}</h4>"""
                
                if rules:
                    html_content += f"""
                        <div style="background: #f8fafc; padding: 15px; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 0.85em; white-space: pre-wrap; overflow-x: auto;">"""
                    
                    for rule in rules:
                        html_content += f"{rule}\n"
                    
                    html_content += f"""</div>"""
                else:
                    html_content += f"""
                        <div class="warning">Нет правил в цепочке {chain}</div>"""
                
                html_content += f"""
                    </div>"""
            
            html_content += f"""
                </div>"""
        
        # firewalld правила
        if firewall_info.get('firewall_rules'):
            html_content += f"""
                <div class="analytics-panel" style="margin-top: 30px;">
                    <div class="analytics-title">
                        🔥 firewalld правила
                    </div>"""
            
            for zone, rules in firewall_info['firewall_rules'].items():
                html_content += f"""
                    <div class="analytics-section">
                        <h4>Зона: {zone}</h4>"""
                
                if rules:
                    html_content += f"""
                        <div style="background: #f8fafc; padding: 15px; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 0.85em; white-space: pre-wrap; overflow-x: auto;">"""
                    
                    for rule in rules:
                        html_content += f"{rule}\n"
                    
                    html_content += f"""</div>"""
                else:
                    html_content += f"""
                        <div class="warning">Нет правил в зоне {zone}</div>"""
                
                html_content += f"""
                    </div>"""
            
            html_content += f"""
                </div>"""
        
        # UFW правила
        if firewall_info.get('ufw_state'):
            html_content += f"""
                <div class="analytics-panel" style="margin-top: 30px;">
                    <div class="analytics-title">
                        🔒 UFW статус и правила
                    </div>
                    
                    <div class="analytics-section">
                        <h4>Состояние UFW</h4>
                        <div style="background: #f8fafc; padding: 15px; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 0.85em; white-space: pre-wrap; overflow-x: auto;">"""
            
            for rule in firewall_info['ufw_state']:
                html_content += f"{rule}\n"
            
            html_content += f"""</div>
                    </div>
                </div>"""
        
        # Открытые порты файрвола
        if firewall_info.get('firewall_ports'):
            html_content += f"""
                <div class="analytics-panel" style="margin-top: 30px;">
                    <div class="analytics-title">
                        🚪 Открытые порты (firewalld)
                    </div>
                    
                    <div class="analytics-section">
                        <h4>Разрешенные порты</h4>
                        <div style="background: #f8fafc; padding: 15px; border-radius: 8px; font-family: 'Courier New', monospace; font-size: 0.85em; white-space: pre-wrap; overflow-x: auto;">"""
            
            for ports in firewall_info['firewall_ports']:
                html_content += f"{ports}\n"
            
            html_content += f"""</div>
                    </div>
                </div>"""
        
    else:
        html_content += f"""
                <div class="warning">
                    ℹ️ Правила файрвола не обнаружены или недоступны.
                    <br><br>
                    🔍 <strong>Возможные причины:</strong>
                    <ul style="margin-top: 10px; margin-left: 20px;">
                        <li>Файрвол не настроен или отключен</li>
                        <li>Недостаточно прав доступа (попробуйте sudo)</li>
                        <li>Используется другой тип файрвола</li>
                        <li>Система не поддерживает iptables/firewalld/ufw</li>
                    </ul>
                </div>"""
    
    html_content += f"""
            </div>
        </div>"""
    
    # Добавляем секцию групп безопасности
    html_content += f"""
            
            <!-- Секция групп безопасности -->
            <div id="security-groups" class="section">
                <h3>🔒 Группы безопасности</h3>
                
                <div class="warning" style="margin-bottom: 30px;">
                    💡 <strong>О правилах безопасности:</strong> Эта секция содержит автоматически сгенерированные правила групп безопасности 
                    на основе обнаруженных интеграционных соединений. Используйте блоки кода ниже для создания заявок в облачном UI.
                </div>"""
    
    # Анализируем интеграционные соединения
    integration_connections = analyze_integration_connections(current_state)
    security_rules = generate_security_group_rules(integration_connections)
    markup = format_security_group_markup(security_rules)
    
    html_content += f"""
                
                <!-- Статистика интеграций (квадраты) -->
                <div class="stats" style="margin-bottom: 30px;">
                    <div class="stat-card">
                        <div class="stat-number">{integration_connections['total_incoming']}</div>
                        <div class="stat-label">входящие интеграции</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{integration_connections['total_outgoing']}</div>
                        <div class="stat-label">исходящие интеграции</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(security_rules['incoming_rules'])}</div>
                        <div class="stat-label">входящих правил</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(security_rules['outgoing_rules'])}</div>
                        <div class="stat-label">исходящих правил</div>
                    </div>
                </div>
                
                <!-- Сводка интеграций -->
                <div class="analytics-panel" style="margin-bottom: 30px;">
                    <div class="analytics-title">
                        📋 Сводка интеграций
                    </div>
                    
                    <div class="analytics-section">
                        <h4>📥 Входящие соединения</h4>"""
    
    # Показываем краткую информацию о входящих интеграциях
    for conn in integration_connections['incoming'][:5]:
        remote_addr = conn.get('remote', {}).get('address', 'unknown')
        process = conn.get('process', 'unknown')[:30]
        protocol = conn.get('protocol', 'tcp').upper()
        
        html_content += f"""
                        <div class="analytics-item">
                            <div class="analytics-name">{remote_addr}</div>
                            <div class="analytics-value">{protocol} • {process}</div>
                        </div>"""
    
    html_content += f"""
                    </div>
                    
                    <div class="analytics-section">
                        <h4>📤 Исходящие соединения</h4>"""
    
    # Показываем краткую информацию об исходящих интеграциях
    outgoing_by_process = {}
    
    # Группируем исходящие соединения по процессам для разнообразия
    for conn in integration_connections['outgoing']:
        process = conn.get('process', 'unknown')[:30]
        if process not in outgoing_by_process:
            outgoing_by_process[process] = []
        outgoing_by_process[process].append(conn)
    
    # Показываем по одному соединению от каждого процесса (до 10 максимум)
    displayed_connections = []
    for process, connections in outgoing_by_process.items():
        if len(displayed_connections) < 10:
            displayed_connections.append(connections[0])  # Берем первое соединение от процесса
    
    # Если у нас меньше 10, добавляем еще соединения
    if len(displayed_connections) < 10:
        for conn in integration_connections['outgoing']:
            if len(displayed_connections) >= 10:
                break
            if conn not in displayed_connections:
                displayed_connections.append(conn)
    
    for conn in displayed_connections:
        remote_addr = conn.get('remote', {}).get('address', 'unknown')
        process = conn.get('process', 'unknown')[:30]
        protocol = conn.get('protocol', 'tcp').upper()
        
        html_content += f"""
                        <div class="analytics-item">
                            <div class="analytics-name">{remote_addr}</div>
                            <div class="analytics-value">{protocol} • {process}</div>
                        </div>"""
    
    html_content += f"""
                    </div>
                </div>"""
    
    # Добавляем блоки кода с правилами для копирования
    if markup['incoming_integrations'] or markup['outgoing_integrations']:
        # Входящие интеграции
        if markup['incoming_integrations']:
            html_content += f"""
                
                <!-- Правила для входящего трафика -->
                <div class="analytics-panel" style="margin-top: 30px;">
                    <div class="analytics-title">
                        📥 Входящие соединения
                    </div>"""
            
            for i, integration in enumerate(markup['incoming_integrations']):
                integration_id = f"incoming-{i}"
                html_content += f"""
                    
                    <div class="analytics-section">
                        <h4>🔗 {integration['title']}</h4>
                        <div class="code-block">
                            <div class="code-header">
                                <span>Описание и Endpoints для {integration['title']}</span>
                                <button class="copy-btn" onclick="copyToClipboard('{integration_id}')">📋 Копировать</button>
                            </div>
                            <pre id="{integration_id}" class="code-content">{integration['external_system']}
{integration['process_description']}

Описание информационного потока:
{integration['technical_description']}

---

{integration['endpoints_text']}</pre>
                        </div>
                    </div>"""
            
            # Добавляем суммарный блок для входящих
            if markup['incoming_summary']:
                incoming_summary_id = "incoming-summary"
                html_content += f"""
                    
                    <div class="analytics-section">
                        <h4>📋 Суммарные правила - Входящие</h4>
                        <div class="code-block">
                            <div class="code-header">
                                <span>Обобщенные правила для всех входящих соединений</span>
                                <button class="copy-btn" onclick="copyToClipboard('{incoming_summary_id}')">📋 Копировать</button>
                            </div>
                            <pre id="{incoming_summary_id}" class="code-content">{"<br>".join(markup['incoming_summary'])}</pre>
                        </div>
                    </div>"""
            
            html_content += f"""
                </div>"""
        
        # Исходящие интеграции
        if markup['outgoing_integrations']:
            html_content += f"""
                
                <!-- Правила для исходящего трафика -->
                <div class="analytics-panel" style="margin-top: 30px;">
                    <div class="analytics-title">
                        📤 Исходящие соединения
                    </div>"""
            
            for i, integration in enumerate(markup['outgoing_integrations']):
                integration_id = f"outgoing-{i}"
                html_content += f"""
                    
                    <div class="analytics-section">
                        <h4>🔗 {integration['title']}</h4>
                        <div class="code-block">
                            <div class="code-header">
                                <span>Описание и Endpoints для {integration['title']}</span>
                                <button class="copy-btn" onclick="copyToClipboard('{integration_id}')">📋 Копировать</button>
                            </div>
                            <pre id="{integration_id}" class="code-content">{integration['external_system']}
{integration['process_description']}

Описание информационного потока:
{integration['technical_description']}

---

{integration['endpoints_text']}</pre>
                        </div>
                    </div>"""
            
            # Добавляем суммарный блок для исходящих
            if markup['outgoing_summary']:
                outgoing_summary_id = "outgoing-summary"
                html_content += f"""
                    
                    <div class="analytics-section">
                        <h4>📋 Суммарные правила - Исходящие</h4>
                        <div class="code-block">
                            <div class="code-header">
                                <span>Обобщенные правила для всех исходящих соединений</span>
                                <button class="copy-btn" onclick="copyToClipboard('{outgoing_summary_id}')">📋 Копировать</button>
                            </div>
                            <pre id="{outgoing_summary_id}" class="code-content">{"<br>".join(markup['outgoing_summary'])}</pre>
                        </div>
                    </div>"""
            
            html_content += f"""
                </div>"""
    else:
        html_content += f"""
                <div class="warning" style="margin-top: 30px;">
                    ℹ️ Интеграционные соединения не обнаружены или все соединения являются локальными.
                    <br><br>
                    🔍 <strong>Возможные причины:</strong>
                    <ul style="margin-top: 10px; margin-left: 20px;">
                        <li>Все соединения происходят в пределах локальной сети</li>
                        <li>Система работает автономно без внешних интеграций</li>
                        <li>Интеграционные соединения не активны в момент сканирования</li>
                        <li>Требуется больше времени для сбора данных о соединениях</li>
                    </ul>
                </div>"""
    
    html_content += f"""
            </div>
        </div>"""
    
    html_content += f"""
        </div>
        
        <div class="footer">
            <p>Отчет создан: {dt.now().strftime('%d.%m.%Y в %H:%M:%S')}</p>
            <p>📊 TCP: {len(tcp_connections)} соединений | 📡 UDP: {len(udp_connections)} соединений | 🚪 Портов: {len(tcp_ports + udp_ports)}</p>
        </div>
    </div>
    
    <script>
        function showSection(sectionId) {{
            // Скрываем все секции
            const sections = document.querySelectorAll('.section');
            sections.forEach(section => section.classList.remove('active'));
            
            // Убираем активный класс у всех кнопок
            const buttons = document.querySelectorAll('.nav-btn');
            buttons.forEach(btn => btn.classList.remove('active'));
            
            // Показываем выбранную секцию
            document.getElementById(sectionId).classList.add('active');
            
            // Добавляем активный класс к нажатой кнопке
            event.target.classList.add('active');
        }}
        
        // Добавляем анимацию при загрузке
        document.addEventListener('DOMContentLoaded', function() {{
            const cards = document.querySelectorAll('.stat-card, .port-item, .change-item');
            cards.forEach((card, index) => {{
                card.style.opacity = '0';
                card.style.transform = 'translateY(20px)';
                setTimeout(() => {{
                    card.style.transition = 'all 0.5s ease';
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }}, index * 50);
            }});
            
            // Инициализируем диаграммы
            initializeCharts();
        }});
        
        function initializeCharts() {{
            // Цвета для диаграмм
            const colors = {{
                primary: '#667eea',
                secondary: '#764ba2',
                tcp: '#3b82f6',
                udp: '#10b981',
                incoming: '#ef4444',
                outgoing: '#06b6d4',
                success: '#22c55e',
                warning: '#f59e0b',
                danger: '#ef4444'
            }};
            
            // 1. Диаграмма распределения протоколов (Doughnut)
            const protocolCtx = document.getElementById('protocolChart').getContext('2d');
            new Chart(protocolCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['TCP', 'UDP'],
                    datasets: [{{
                        data: [{tcp_count}, {udp_count}],
                        backgroundColor: [colors.tcp, colors.udp],
                        borderWidth: 0,
                        hoverBackgroundColor: [colors.tcp + '80', colors.udp + '80']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 20,
                                usePointStyle: true,
                                font: {{
                                    family: 'Inter',
                                    size: 12
                                }}
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = Math.round((context.raw / total) * 100);
                                    return context.label + ': ' + context.raw + ' (' + percentage + '%)';
                                }}
                            }}
                        }}
                    }},
                    animation: {{
                        animateScale: true,
                        animateRotate: true
                    }}
                }}
            }});
            
            // 2. Диаграмма направления соединений (Pie)
            const directionCtx = document.getElementById('directionChart').getContext('2d');
            new Chart(directionCtx, {{
                type: 'pie',
                data: {{
                    labels: ['Входящие', 'Исходящие'],
                    datasets: [{{
                        data: [{incoming_count}, {outgoing_count}],
                        backgroundColor: [colors.incoming, colors.outgoing],
                        borderWidth: 0,
                        hoverBackgroundColor: [colors.incoming + '80', colors.outgoing + '80']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 20,
                                usePointStyle: true,
                                font: {{
                                    family: 'Inter',
                                    size: 12
                                }}
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = Math.round((context.raw / total) * 100);
                                    return context.label + ': ' + context.raw + ' (' + percentage + '%)';
                                }}
                            }}
                        }}
                    }},
                    animation: {{
                        animateScale: true,
                        animateRotate: true
                    }}
                }}
            }});
            
            // 3. График активности процессов (Bar)
            const processCtx = document.getElementById('processChart').getContext('2d');
            const processLabels = {[f'"{process[:15]}"' for process, _ in top_processes[:6]]};
            const processData = {[stats['count'] for _, stats in top_processes[:6]]};
            
            new Chart(processCtx, {{
                type: 'bar',
                data: {{
                    labels: processLabels,
                    datasets: [{{
                        label: 'Соединений',
                        data: processData,
                        backgroundColor: colors.primary,
                        borderColor: colors.secondary,
                        borderWidth: 1,
                        borderRadius: 6,
                        borderSkipped: false,
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleColor: '#fff',
                            bodyColor: '#fff',
                            borderColor: colors.primary,
                            borderWidth: 1
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            grid: {{
                                color: 'rgba(0, 0, 0, 0.05)'
                            }},
                            ticks: {{
                                font: {{
                                    family: 'Inter',
                                    size: 11
                                }}
                            }}
                        }},
                        x: {{
                            grid: {{
                                display: false
                            }},
                            ticks: {{
                                maxRotation: 45,
                                font: {{
                                    family: 'Inter',
                                    size: 10
                                }}
                            }}
                        }}
                    }},
                    animation: {{
                        duration: 1000,
                        easing: 'easeOutQuart'
                    }}
                }}
            }});
            
            // 4. График активности по времени (Line)
            const timelineCtx = document.getElementById('timelineChart').getContext('2d');
            const hourLabels = [];
            const hourData = {hour_data_js};
            
            for (let i = 0; i < 24; i++) {{
                const hour = i.toString().padStart(2, '0');
                hourLabels.push(hour + ':00');
            }}
            
            new Chart(timelineCtx, {{
                type: 'line',
                data: {{
                    labels: hourLabels,
                    datasets: [{{
                        label: 'Активность',
                        data: hourData,
                        borderColor: colors.primary,
                        backgroundColor: colors.primary + '20',
                        fill: true,
                        tension: 0.4,
                        pointBackgroundColor: colors.primary,
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleColor: '#fff',
                            bodyColor: '#fff',
                            borderColor: colors.primary,
                            borderWidth: 1,
                            callbacks: {{
                                title: function(context) {{
                                    return 'Час: ' + context[0].label;
                                }},
                                label: function(context) {{
                                    return 'Соединений: ' + context.raw;
                                }}
                            }}
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            grid: {{
                                color: 'rgba(0, 0, 0, 0.05)'
                            }},
                            ticks: {{
                                font: {{
                                    family: 'Inter',
                                    size: 11
                                }}
                            }}
                        }},
                        x: {{
                            grid: {{
                                color: 'rgba(0, 0, 0, 0.05)'
                            }},
                            ticks: {{
                                maxTicksLimit: 12,
                                font: {{
                                    family: 'Inter',
                                    size: 10
                                }}
                            }}
                        }}
                    }},
                    animation: {{
                        duration: 1500,
                        easing: 'easeOutQuart'
                    }},
                    interaction: {{
                        intersect: false,
                        mode: 'index'
                    }}
                }}
            }});
        }}
        
        // Функция для копирования текста в буфер обмена
        function copyToClipboard(elementId) {{
            const element = document.getElementById(elementId);
            const text = element.textContent || element.innerText;
            
            // Создаем временный элемент textarea для копирования
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            
            // Выделяем и копируем текст
            textarea.select();
            textarea.setSelectionRange(0, 99999); // Для мобильных устройств
            
            try {{
                const successful = document.execCommand('copy');
                document.body.removeChild(textarea);
                
                if (successful) {{
                    // Находим кнопку копирования и показываем успешное копирование
                    const button = document.querySelector(`button[onclick="copyToClipboard('${{elementId}}')"]`);
                    if (button) {{
                        const originalText = button.innerHTML;
                        button.innerHTML = '✅ Скопировано!';
                        button.classList.add('copied');
                        
                        // Возвращаем исходный текст через 2 секунды
                        setTimeout(() => {{
                            button.innerHTML = originalText;
                            button.classList.remove('copied');
                        }}, 2000);
                    }}
                    
                    console.log('Текст скопирован в буфер обмена');
                }} else {{
                    throw new Error('Копирование не поддерживается');
                }}
            }} catch (err) {{
                document.body.removeChild(textarea);
                
                // Fallback для современных браузеров с Clipboard API
                if (navigator.clipboard && window.isSecureContext) {{
                    navigator.clipboard.writeText(text).then(() => {{
                        const button = document.querySelector(`button[onclick="copyToClipboard('${{elementId}}')"]`);
                        if (button) {{
                            const originalText = button.innerHTML;
                            button.innerHTML = '✅ Скопировано!';
                            button.classList.add('copied');
                            
                            setTimeout(() => {{
                                button.innerHTML = originalText;
                                button.classList.remove('copied');
                            }}, 2000);
                        }}
                        console.log('Текст скопирован в буфер обмена (Clipboard API)');
                    }}).catch((clipboardErr) => {{
                        console.error('Ошибка копирования:', clipboardErr);
                        alert('Не удалось скопировать текст. Выделите и скопируйте вручную.');
                    }});
                }} else {{
                    console.error('Ошибка копирования:', err);
                    alert('Копирование не поддерживается в этом браузере. Выделите и скопируйте текст вручную.');
                }}
            }}
        }}
        
        // Функции фильтрации для таблиц соединений
        function filterConnections() {{
            const table = document.getElementById('connections-table');
            if (!table) return;
            
            const directionFilter = document.getElementById('filter-direction').value.toLowerCase();
            const protocolFilter = document.getElementById('filter-protocol').value.toLowerCase();
            const processFilter = document.getElementById('filter-process').value.toLowerCase();
            const localFilter = document.getElementById('filter-local').value.toLowerCase();
            const remoteFilter = document.getElementById('filter-remote').value.toLowerCase();
            
            const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
            let visibleCount = 0;
            
            for (let i = 0; i < rows.length; i++) {{
                const row = rows[i];
                const cells = row.getElementsByTagName('td');
                
                if (cells.length === 0) continue;
                
                const direction = cells[0].textContent.toLowerCase();
                const localAddr = cells[1].textContent.toLowerCase();
                const remoteAddr = cells[2].textContent.toLowerCase();
                const process = cells[3].textContent.toLowerCase();
                const protocol = cells[4].textContent.toLowerCase();
                
                let show = true;
                
                // Проверяем фильтр направления с правильным сопоставлением
                if (directionFilter) {{
                    let directionMatch = false;
                    if (directionFilter === 'incoming' && direction.includes('входящее')) {{
                        directionMatch = true;
                    }} else if (directionFilter === 'outgoing' && direction.includes('исходящее')) {{
                        directionMatch = true;
                    }}
                    if (!directionMatch) {{
                        show = false;
                    }}
                }}
                
                // Проверяем фильтр протокола
                if (protocolFilter && !protocol.includes(protocolFilter.toLowerCase())) {{
                    show = false;
                }}
                
                // Проверяем фильтр процесса
                if (processFilter && !process.includes(processFilter)) {{
                    show = false;
                }}
                
                // Проверяем фильтр локального адреса
                if (localFilter && !localAddr.includes(localFilter)) {{
                    show = false;
                }}
                
                // Проверяем фильтр удаленного адреса
                if (remoteFilter && !remoteAddr.includes(remoteFilter)) {{
                    show = false;
                }}
                
                if (show) {{
                    row.style.display = '';
                    row.classList.remove('filtered-hidden');
                    visibleCount++;
                }} else {{
                    row.style.display = 'none';
                    row.classList.add('filtered-hidden');
                }}
            }}
            
            // Обновляем счетчик
            const countElement = document.getElementById('connections-count');
            if (countElement) {{
                countElement.textContent = `Отображается соединений: ${{visibleCount}}`;
            }}
        }}
        
        function clearFilters() {{
            document.getElementById('filter-direction').value = '';
            document.getElementById('filter-protocol').value = '';
            document.getElementById('filter-process').value = '';
            document.getElementById('filter-local').value = '';
            document.getElementById('filter-remote').value = '';
            filterConnections();
        }}
        
        function clearUdpFilters() {{
            document.getElementById('udp-filter-direction').value = '';
            document.getElementById('udp-filter-process').value = '';
            document.getElementById('udp-filter-connection').value = '';
            filterUdpTable();
        }}
        
        function clearIcmpFilters() {{
            document.getElementById('icmp-filter-process').value = '';
            document.getElementById('icmp-filter-connection').value = '';
            document.getElementById('icmp-filter-type').value = '';
            filterIcmpTable();
        }}
        
        // Аналогичные функции для UDP таблицы
        function filterUdpTable() {{
            const tables = document.querySelectorAll('#udp .connections-table');
            if (tables.length === 0) return;
            
            const table = tables[0]; // Берем первую таблицу UDP
            const processFilter = document.getElementById('udp-filter-process')?.value.toLowerCase() || '';
            const connectionFilter = document.getElementById('udp-filter-connection')?.value.toLowerCase() || '';
            const directionFilter = document.getElementById('udp-filter-direction')?.value.toLowerCase() || '';
            
            const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
            let visibleCount = 0;
            
            for (let i = 0; i < rows.length; i++) {{
                const row = rows[i];
                const cells = row.getElementsByTagName('td');
                
                if (cells.length === 0) continue;
                
                const connection = cells[0]?.textContent.toLowerCase() || '';
                const process = cells[1]?.textContent.toLowerCase() || '';
                const direction = cells[2]?.textContent.toLowerCase() || '';
                
                let show = true;
                
                if (processFilter && !process.includes(processFilter)) {{
                    show = false;
                }}
                
                if (connectionFilter && !connection.includes(connectionFilter)) {{
                    show = false;
                }}
                
                // Исправляем фильтр направления для UDP
                if (directionFilter) {{
                    let directionMatch = false;
                    if (directionFilter === 'incoming' && direction.includes('incoming')) {{
                        directionMatch = true;
                    }} else if (directionFilter === 'outgoing' && direction.includes('outgoing')) {{
                        directionMatch = true;
                    }}
                    if (!directionMatch) {{
                        show = false;
                    }}
                }}
                
                if (show) {{
                    row.style.display = '';
                    visibleCount++;
                }} else {{
                    row.style.display = 'none';
                }}
            }}
        }}
        
        // Аналогичные функции для ICMP таблицы
        function filterIcmpTable() {{
            const tables = document.querySelectorAll('#icmp .connections-table');
            if (tables.length === 0) return;
            
            const table = tables[0]; // Берем первую таблицу ICMP
            const processFilter = document.getElementById('icmp-filter-process')?.value.toLowerCase() || '';
            const connectionFilter = document.getElementById('icmp-filter-connection')?.value.toLowerCase() || '';
            const typeFilter = document.getElementById('icmp-filter-type')?.value.toLowerCase() || '';
            
            const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
            let visibleCount = 0;
            
            for (let i = 0; i < rows.length; i++) {{
                const row = rows[i];
                const cells = row.getElementsByTagName('td');
                
                if (cells.length === 0) continue;
                
                const connection = cells[0]?.textContent.toLowerCase() || '';
                const process = cells[1]?.textContent.toLowerCase() || '';
                const type = cells[4]?.textContent.toLowerCase() || '';
                
                let show = true;
                
                if (processFilter && !process.includes(processFilter)) {{
                    show = false;
                }}
                
                if (connectionFilter && !connection.includes(connectionFilter)) {{
                    show = false;
                }}
                
                if (typeFilter && !type.includes(typeFilter)) {{
                    show = false;
                }}
                
                if (show) {{
                    row.style.display = '';
                    visibleCount++;
                }} else {{
                    row.style.display = 'none';
                }}
            }}
        }}
        
        // Инициализация при загрузке страницы
        document.addEventListener('DOMContentLoaded', function() {{
            // Обновляем счетчик соединений при загрузке
            const table = document.getElementById('connections-table');
            if (table) {{
                const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
                const countElement = document.getElementById('connections-count');
                if (countElement) {{
                    countElement.textContent = `Отображается соединений: ${{rows.length}}`;
                }}
            }}
        }});
        
        function openTechDocs() {{
            // Создаем техническую документацию
            const techDocsContent = `
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔥 Как работает анализатор | Tech Docs v2.3.0</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6; color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .hero-section {{
            text-align: center; color: white; padding: 60px 20px; margin-bottom: 40px;
        }}
        .hero-section h1 {{
            font-size: 3.5em; margin-bottom: 20px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        .hero-section p {{ font-size: 1.4em; opacity: 0.9; margin-bottom: 30px; }}
        .tech-badge {{
            display: inline-block; background: rgba(255,255,255,0.2);
            padding: 10px 20px; border-radius: 50px; margin: 5px;
            backdrop-filter: blur(10px);
        }}
        .main-content {{
            background: white; border-radius: 20px; padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1); margin-bottom: 40px;
        }}
        .section {{ margin-bottom: 50px; }}
        .section h2 {{
            font-size: 2.2em; margin-bottom: 25px; color: #2c3e50;
            position: relative; padding-left: 50px;
        }}
        .section h2:before {{ content: "🚀"; position: absolute; left: 0; font-size: 1.2em; }}
        .architecture-diagram {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border-radius: 15px; padding: 40px; margin: 30px 0; color: white;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }}
        .flow-diagram {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            border-radius: 15px; padding: 30px; margin: 30px 0; color: white;
        }}
        .netflow-section {{
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
            border-radius: 15px; padding: 30px; margin: 30px 0; color: #1a1a1a;
        }}
        .code-block {{
            background: #1a1a1a; color: #00ff00; padding: 20px;
            border-radius: 10px; font-family: 'Courier New', monospace;
            margin: 20px 0; overflow-x: auto;
        }}
        .back-button {{
            position: fixed; top: 20px; left: 20px;
            background: rgba(255,255,255,0.2); color: white;
            padding: 10px 20px; border-radius: 50px;
            text-decoration: none; backdrop-filter: blur(10px);
            transition: all 0.3s ease; border: none; cursor: pointer;
        }}
        .back-button:hover {{
            background: rgba(255,255,255,0.3); transform: translateX(-5px);
        }}
        .fun-fact {{
            background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
            padding: 20px; border-radius: 15px; margin: 20px 0;
            border-left: 5px solid #ff6b6b;
        }}
        .fun-fact::before {{ content: "💡 "; font-size: 1.5em; }}
        .tech-stack {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px; margin: 30px 0;
        }}
        .tech-item {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 20px; border-radius: 15px;
            text-align: center;
        }}
        .ascii-small {{ font-size: 0.8em; line-height: 1.2; }}
    </style>
</head>
<body>
    <button onclick="window.close()" class="back-button">← Назад к отчету</button>
    
    <div class="container">
        <div class="hero-section">
            <h1>🔥 Как работает анализатор</h1>
            <p>Техническая документация для DevOps и SRE</p>
            <div>
                <span class="tech-badge">🐍 Python 3.6+</span>
                <span class="tech-badge">📡 NetFlow v9</span>
                <span class="tech-badge">🎨 Chart.js</span>
                <span class="tech-badge">☁️ S3 Ready</span>
                <span class="tech-badge">🔧 Cross-Platform</span>
            </div>
        </div>
        
        <div class="main-content">
            <div class="section">
                <h2>Архитектура системы</h2>
                <div class="architecture-diagram">
                    <h3>🏗️ Детальная архитектурная схема</h3>
                    <pre class="ascii-small">
ANALYZER v2.3.0 - NETWORK ACTIVITY ANALYZER
=============================================

LAYER 1: DATA INPUT    ->    LAYER 2: PROCESSING    ->    LAYER 3: OUTPUT
      |                            |                           |
      v                            v                           v
Data Sources                Analytics Engine            Report Generation
- psutil                    - ReportEnhancer           - HTMLReportGenerator
- netstat                   - NetFlow v9               - YAML formatter
- ss                        - Security scan            - Chart.js visualizer
- lsof                      - Health check             - S3 uploader
- /proc/net                 - GeoIP lookup             - Legacy converter
      |                            |                           |
      v                            v                           v
Network Modules             Security Analysis           Cloud Integration
- ICMPTracker               - Firewall rules           - AWS S3
- UDPTracker                - Port analysis            - MinIO
- TCP Monitor               - Process audit            - Yandex Cloud
- IPv6 Support              - Anomaly detect           - Docker support

TECHNICAL STACK:
Backend: Python 3.6+, psutil, PyYAML, boto3
Analytics: pandas-style logic, GeoIP2, Pattern matching
Frontend: Chart.js 3.x, Bootstrap 5, Responsive CSS
Cloud: Docker containers, GitLab CI/CD, S3 API
SIEM: Splunk ready, Elastic compatible, Grafana integration
                    </pre>
                </div>
            </div>
            
            <div class="section">
                <h2>Алгоритм работы</h2>
                <div class="flow-diagram">
                    <h3>🔄 5-шаговый процесс анализа</h3>
                    <pre>
STEP 1: DATA COLLECTION -> STEP 2: NETFLOW V9 -> STEP 3: ANALYSIS -> STEP 4: REPORTS -> STEP 5: EXPORT
      |                        |                    |                 |                |
      v                        v                    v                 v                v
  - netstat                - RFC 3954          - Security        - HTML + CSS    - S3 Upload
  - ss                     - Templates         - Health check    - YAML format   - Docker logs
  - lsof                   - Flow records      - GeoIP lookup    - Chart.js viz  - API endpoints
  - psutil                 - Timestamps        - Pattern match   - Responsive UI - Webhook notify
  - /proc                  - Packet count      - Anomaly detect  - Print friendly - Log shipping
                    </pre>
                </div>
            </div>
            
            <div class="section">
                <h2>NetFlow v9 — стандарт индустрии</h2>
                <div class="netflow-section">
                    <h3>🎯 RFC 3954 Compliance</h3>
                    <p>Полная совместимость с NetFlow v9 для интеграции в корпоративные SIEM системы!</p>
                    
                    <div class="fun-fact">
                        <strong>Industry Standard:</strong> Данные совместимы с Splunk, Elastic, QRadar, ArcSight, Graylog!
                    </div>
                    
                    <div class="code-block">
NetFlow v9 Message Structure (RFC 3954)
=====================================

NETFLOW HEADER:
  Version=9 | Count | SysUptime
  Timestamp | Sequence | Source ID

TEMPLATE RECORD:
  FlowSet ID=0 | Length
  Template ID | Field Count
  Field Type | Field Length

DATA RECORD:
  FlowSet ID=256 | Length
  SrcAddr | DstAddr | SrcPort
  DstPort | Protocol | Packets
  Bytes | Flags | Duration

🔍 Поддерживаемые поля NetFlow v9:
• IP_SRC_ADDR (8)     • IP_DST_ADDR (12)
• L4_SRC_PORT (7)     • L4_DST_PORT (11)  
• PROTOCOL (4)        • IN_PKTS (2)
• IN_BYTES (1)        • TCP_FLAGS (6)
• FIRST_SWITCHED (22) • LAST_SWITCHED (21)
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Принципы безопасности</h2>
                <div style="background: #ffe6e6; padding: 20px; border-radius: 10px;">
                    <h4 style="color: #d63384; margin-bottom: 15px;">❌ Что НЕ собираем:</h4>
                    <ul style="color: #d63384;">
                        <li>🚫 Содержимое пакетов (packet capture)</li>
                        <li>🚫 HTTP payload или POST данные</li>
                        <li>🚫 Пароли, токены, API ключи</li>
                        <li>🚫 Содержимое файлов пользователей</li>
                        <li>🚫 Браузерную историю или cookies</li>
                    </ul>
                </div>
                
                <div style="background: #e6ffe6; padding: 20px; border-radius: 10px; margin-top: 20px;">
                    <h4 style="color: #28a745; margin-bottom: 15px;">✅ Собираем только метаданные:</h4>
                    <ul style="color: #28a745;">
                        <li>✅ IP адреса активных соединений</li>
                        <li>✅ Номера портов (source/destination)</li>
                        <li>✅ Имена процессов (без аргументов командной строки)</li>
                        <li>✅ Системные метрики (CPU, RAM, disk)</li>
                        <li>✅ Статистику сетевых интерфейсов</li>
                    </ul>
                </div>
            </div>
            
            <div class="section">
                <h2>Технический стек в деталях</h2>
                <div class="tech-stack">
                    <div class="tech-item">
                        <h4>🐍 Backend</h4>
                        <p>Python 3.6+<br>psutil, PyYAML<br>boto3, distro</p>
                    </div>
                    <div class="tech-item">
                        <h4>📊 Analytics</h4>
                        <p>ReportEnhancer<br>Pattern matching<br>Security scanning</p>
                    </div>
                    <div class="tech-item">
                        <h4>🎨 Frontend</h4>
                        <p>Chart.js 3.x<br>Bootstrap 5<br>Responsive CSS</p>
                    </div>
                    <div class="tech-item">
                        <h4>☁️ Cloud</h4>
                        <p>AWS S3<br>MinIO<br>Yandex Cloud</p>
                    </div>
                    <div class="tech-item">
                        <h4>🔧 DevOps</h4>
                        <p>Docker<br>GitLab CI<br>systemd</p>
                    </div>
                    <div class="tech-item">
                        <h4>🛡️ Security</h4>
                        <p>iptables<br>ufw<br>Process audit</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Поддерживаемые платформы</h2>
                <div class="code-block">
🐧 Linux Distributions:
   • Ubuntu 18.04+ LTS
   • CentOS 7/8, RHEL 7/8
   • Debian 10/11
   • Amazon Linux 2
   • Alpine Linux 3.14+

🍎 macOS:
   • macOS 10.15+ (Catalina)
   • Apple Silicon (M1/M2) ready
   • Intel x86_64 compatible

🐳 Containers:
   • Docker 20.10+
   • Podman 3.0+
   • Kubernetes ready
                </div>
            </div>
        </div>
    </div>
</body>
</html>
            `;
            
            // Открываем в новом окне
            const techWindow = window.open('', '_blank', 'width=1400,height=900,scrollbars=yes,resizable=yes');
            techWindow.document.write(techDocsContent);
            techWindow.document.close();
        }}
    </script>
</body>
</html>
    """
    
    with open(html_filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return html_filename

def upload_reports_to_s3(configuration, py_version, yaml_filename, html_filename):
    """
    Функция для загрузки отчетов в S3 (адаптировано из коммита 9d583bf5)
    Загружает все три файла: основной YAML, legacy backup и HTML
    """
    print("🔍 S3: Checking configuration...")
    s3_config = configuration.get('s3', {})
    
    # Выводим диагностическую информацию о конфигурации S3 (без секретов)
    print(f"📋 S3: URL = {s3_config.get('url', 'NOT_SET')}")
    print(f"📋 S3: User = {s3_config.get('user', 'NOT_SET')}")
    print(f"📋 S3: Region = {s3_config.get('region', 'NOT_SET')}")
    print(f"📋 S3: Bucket = {s3_config.get('bucket', 'NOT_SET')}")
    print(f"📋 S3: Access Key = {'SET' if s3_config.get('access_key') else 'NOT_SET'}")
    
    # Проверяем настройки S3
    required_fields = ['url', 'user', 'access_key']
    missing_fields = [field for field in required_fields if not s3_config.get(field)]
    
    if missing_fields:
        print(f"⚠️ S3: Configuration incomplete, missing: {', '.join(missing_fields)}")
        print("💡 S3: Set environment variables: S3_ENDPOINT_URL, S3_ACCESS_KEY_ID, S3_ACCESS_SECRET_KEY")
        return False
    
    try:
        # Проверяем доступность необходимых модулей
        print("🔍 S3: Checking dependencies...")
        try:
            import configparser
            print("✅ S3: configparser module available")
        except ImportError as ce:
            print(f"⚠️ S3: configparser import error: {ce}")
            try:
                import ConfigParser
                print("✅ S3: ConfigParser (Python 2 style) available")
            except ImportError:
                print("❌ S3: Neither configparser nor ConfigParser available")
                print("💡 S3: Try: pip install configparser")
                return False
        
        print("🔧 S3: Creating client...")
        # Создаем клиент S3 (аналогично оригиналу)
        s3_client = get_client_s3(
            url_s3=s3_config['url'],
            region=s3_config.get('region', 'endpoint'),
            user=s3_config['user'],
            access_key=s3_config['access_key'],
            py_version=py_version,
            is_cert=True
        )
        
        if s3_client is None:
            print("❌ S3: Client creation returned None")
            return False
            
        print("✅ S3: Client created successfully")
        
        bucket = s3_config.get('bucket', 'analyzer')
        upload_success = True
        uploaded_files = []
        
        # Определяем файлы для загрузки
        files_to_upload = [
            (yaml_filename, "основной YAML отчет"),
            (html_filename, "HTML отчет")
        ]
        
        # Добавляем legacy файл если он существует
        legacy_filename = f"{yaml_filename}.legacy"
        if os.path.exists(legacy_filename):
            files_to_upload.append((legacy_filename, "legacy backup файл"))
        else:
            print(f"ℹ️ S3: Legacy file {legacy_filename} not found, skipping")
        
        # Загружаем все файлы
        for file_path, file_description in files_to_upload:
            if os.path.exists(file_path):
                print(f"📄 S3: Uploading {file_description} ({file_path})...")
                try:
                    status = upload_file_s3(s3_client, bucket, file_path, file_path)
                    if status:
                        print(f"✅ S3: {file_description} uploaded: {file_path}")
                        uploaded_files.append(file_path)
                    else:
                        print(f"⚠️ S3: {file_description} upload failed")
                        upload_success = False
                except Exception as e:
                    print(f"❌ S3: {file_description} upload error: {e}")
                    upload_success = False
            else:
                print(f"⚠️ S3: File not found: {file_path}")
                upload_success = False
        
        if uploaded_files:
            print(f"✅ S3: Successfully uploaded {len(uploaded_files)} files: {', '.join(uploaded_files)}")
        
        return upload_success
        
    except Exception as e:
        print(f"❌ S3: Client creation failed: {e}")
        print(f"🔍 S3: Debug info - URL: {s3_config.get('url')}, Region: {s3_config.get('region')}")
        
        # Дополнительная диагностика для проблем с модулями
        import sys
        print(f"🐍 S3: Python version: {sys.version}")
        print(f"🐍 S3: Python path: {sys.path[:3]}...")  # Показываем первые 3 пути
        
        return False

def write_to_s3_scheduled(yaml_filename, html_filename, upload_time, upload_delay=60, is_upload=True, configuration=None, py_version=None):
    """
    Функция для загрузки отчетов в S3 по расписанию (улучшенная версия)
    Поддерживает диапазон времени для более надежного срабатывания
    """
    if not is_upload:
        return False
        
    try:
        # Парсим время загрузки (час:минута)
        hour, minute = map(int, upload_time.split(':'))
        current_time = dt.now()
        
        # Проверяем диапазон времени (плюс-минус 2 минуты от указанного времени)
        # чтобы учесть случаи когда анализатор не попадает точно в момент 8:00
        target_minutes = hour * 60 + minute
        current_minutes = current_time.hour * 60 + current_time.minute
        time_diff = abs(current_minutes - target_minutes)
        
        # Проверяем, попадаем ли в окно загрузки (+-2 минуты)
        if time_diff <= 2 or time_diff >= (24 * 60 - 2):  # Учитываем переход через полночь
            # Добавляем случайную задержку
            delay = random.randint(0, upload_delay)
            time.sleep(delay)
            
            print(f"⏰ S3: Upload time window reached (target: {upload_time}, current: {current_time.strftime('%H:%M')})")
            print(f"⏰ S3: Starting upload after {delay}s delay...")
            
            # Вызываем загрузку
            success = upload_reports_to_s3(configuration, py_version, yaml_filename, html_filename)
            if success:
                print(f"✅ S3: Scheduled upload completed successfully")
            else:
                print(f"⚠️ S3: Scheduled upload completed with warnings")
            return success
        else:
            # Выводим информацию только в режиме отладки
            if time_diff <= 30:  # Только если близко к времени загрузки
                print(f"⏰ S3: Waiting for upload time (target: {upload_time}, current: {current_time.strftime('%H:%M')}, diff: {time_diff}min)")
            
    except Exception as e:
        print(f"❌ S3: Scheduled upload error: {e}")
        return False
    
    return False

def upload_reports_at_end(yaml_filename, html_filename, configuration=None, py_version=None):
    """
    Функция для загрузки отчетов в S3 в конце всех измерений
    Загружает все три файла: основной YAML, legacy backup и HTML
    """
    try:
        print(f"\n☁️ Final S3 Upload Process")
        success = upload_reports_to_s3(configuration, py_version, yaml_filename, html_filename)
        if success:
            print(f"✅ S3: Final reports successfully uploaded (all files)")
        else:
            print(f"⚠️ S3: Final upload completed with warnings")
        return success
    except Exception as e:
        print(f"❌ S3: Final upload failed: {e}")
        return False

def analyze_integration_connections(current_state):
    """Анализирует соединения для создания правил групп безопасности"""
    connections = current_state.get('connections', {})
    incoming_connections = connections.get('incoming', [])
    outgoing_connections = connections.get('outgoing', [])
    
    # Фильтруем интеграционные соединения (исключаем localhost и локальные адреса)
    def is_integration_connection(conn):
        """Проверяет, является ли соединение интеграционным"""
        remote_addr = conn.get('remote', {}).get('address', '')
        local_addr = conn.get('local', '')
        
        # Исключаем соединения без удаленного адреса или с неизвестными адресами
        if not remote_addr or remote_addr == 'unknown' or '*' in remote_addr:
            return False
        
        # Исключаем явно неправильные адреса (пути к файлам, содержащие слеши)
        if '/' in remote_addr or '\\' in remote_addr:
            return False
            
        # Извлекаем IP из адреса правильно (учитывая IPv6)
        def extract_ip_properly(address):
            if not address:
                return address
            # IPv6 адрес в формате [IPv6]:port
            if address.startswith('[') and ']:' in address:
                return address.split(']:')[0][1:]
            # IPv4 адрес в формате IPv4:port
            elif address.count(':') == 1:  # Только один двоеточие = IPv4:port
                return address.split(':')[0]
            # Чистый IPv6 адрес без порта или с портом в конце
            elif address.count(':') > 1:
                # Проверяем, есть ли порт в конце
                parts = address.split(':')
                # Если последняя часть - число, то это порт
                try:
                    int(parts[-1])
                    # Это порт, убираем его
                    return ':'.join(parts[:-1])
                except ValueError:
                    # Последняя часть не число, значит это чистый IPv6
                    return address
            else:
                return address
        
        remote_ip = extract_ip_properly(remote_addr)
        local_ip = extract_ip_properly(local_addr) if local_addr else ''
        
        # Исключаем localhost
        if remote_ip in ['127.0.0.1', '::1', 'localhost']:
            return False
        
        # Исключаем IPv6 link-local адреса (fe80::/10)
        if remote_ip.startswith('fe80:') or remote_ip.startswith('fe80'):
            return False
            
        # Исключаем IPv6 unique local адреса (fc00::/7)
        if remote_ip.startswith(('fc00:', 'fd00:')):
            return False
        
        # Проверяем, что это похоже на IP-адрес
        import re
        # IPv4 адрес
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # IPv6 адрес (упрощенная проверка)
        ipv6_pattern = r'^[0-9a-fA-F:]+$'
        
        is_valid_ip = (re.match(ipv4_pattern, remote_ip) is not None or 
                      (re.match(ipv6_pattern, remote_ip) is not None and ':' in remote_ip))
        
        if not is_valid_ip:
            return False
        
        # Исключаем приватные адреса локальной сети
        if remote_ip.startswith(('192.168.', '10.', '172.')):
            # Если это разные подсети, то это интеграция
            if not local_ip.startswith(remote_ip.split('.')[0]):
                return True
            # Если адреса сильно отличаются в локальной сети
            try:
                if local_ip.split('.')[2] != remote_ip.split('.')[2]:
                    return True
            except IndexError:
                pass
            return False
        
        # Исключаем мультикаст и broadcast адреса
        if remote_ip.startswith(('224.', '225.', '226.', '227.', '228.', '229.', 
                                '230.', '231.', '232.', '233.', '234.', '235.',
                                '236.', '237.', '238.', '239.', '255.')):
            return False
            
        # Исключаем link-local адреса IPv4
        if remote_ip.startswith('169.254.'):
            return False
            
        # Исключаем зарезервированные диапазоны
        if remote_ip.startswith(('0.', '240.', '241.', '242.', '243.', '244.', 
                                '245.', '246.', '247.', '248.', '249.', '250.',
                                '251.', '252.', '253.', '254.')):
            return False
        
        return True
    
    # Анализируем входящие соединения
    incoming_integrations = []
    for conn in incoming_connections:
        if is_integration_connection(conn):
            incoming_integrations.append(conn)
    
    # Анализируем исходящие соединения
    outgoing_integrations = []
    for conn in outgoing_connections:
        if is_integration_connection(conn):
            outgoing_integrations.append(conn)
    
    return {
        'incoming': incoming_integrations,
        'outgoing': outgoing_integrations,
        'total_incoming': len(incoming_integrations),
        'total_outgoing': len(outgoing_integrations)
    }

def generate_security_group_rules(integration_connections):
    """Генерирует правила групп безопасности в текстовом формате"""
    
    def get_process_description(process_name):
        """Возвращает описание процесса для правила"""
        if 'postgres' in process_name.lower():
            return 'Подключение к базе данных PostgreSQL'
        elif 'mysql' in process_name.lower():
            return 'Подключение к базе данных MySQL'
        elif 'redis' in process_name.lower():
            return 'Подключение к Redis'
        elif 'http' in process_name.lower() or 'nginx' in process_name.lower():
            return 'HTTP/HTTPS трафик'
        elif 'ssh' in process_name.lower():
            return 'SSH соединение'
        elif 'docker' in process_name.lower():
            return 'Docker контейнер'
        elif 'java' in process_name.lower():
            return 'Java приложение'
        elif 'python' in process_name.lower():
            return 'Python приложение'
        else:
            return f'Трафик от {process_name}'
    
    def extract_port_from_address(address):
        """Извлекает порт из адреса (поддерживает IPv4 и IPv6)"""
        if not address or address == 'unknown':
            return 'unknown'
        
        # IPv6 адрес в формате [IPv6]:port
        if address.startswith('[') and ']:' in address:
            return address.split(']:')[-1]
        
        # IPv4 адрес в формате IPv4:port
        elif address.count(':') == 1:
            return address.split(':')[-1]
        
        # IPv6 адрес без скобок - порт в конце после последнего :
        elif address.count(':') > 1:
            parts = address.split(':')
            # Проверяем, является ли последняя часть портом (числом)
            try:
                int(parts[-1])
                return parts[-1]
            except ValueError:
                return 'unknown'
        
        return 'unknown'
    
    def extract_ip_from_address(address):
        """Извлекает IP из адреса (поддерживает IPv4 и IPv6)"""
        if not address or address == 'unknown':
            return address
        
        # IPv6 адрес в формате [IPv6]:port
        if address.startswith('[') and ']:' in address:
            return address.split(']:')[0][1:]  # Убираем [ в начале
        
        # IPv4 адрес в формате IPv4:port
        elif address.count(':') == 1:
            return address.split(':')[0]
        
        # IPv6 адрес без скобок
        elif address.count(':') > 1:
            parts = address.split(':')
            # Проверяем, является ли последняя часть портом
            try:
                int(parts[-1])
                # Последняя часть - порт, убираем его
                return ':'.join(parts[:-1])
            except ValueError:
                # Последняя часть не порт, возвращаем весь адрес
                return address
        
        # Просто IP без порта
        return address
    
    # Группируем соединения по процессам и портам
    incoming_rules = {}
    outgoing_rules = {}
    
    # Обрабатываем входящие соединения
    for conn in integration_connections['incoming']:
        remote_addr = conn.get('remote', {}).get('address', '')
        local_addr = conn.get('local', '')
        process = conn.get('process', 'unknown')
        protocol = conn.get('protocol', 'tcp').upper()
        
        remote_ip = extract_ip_from_address(remote_addr)
        local_port = extract_port_from_address(local_addr)
        
        rule_key = f"{protocol}_{local_port}_{process}"
        
        if rule_key not in incoming_rules:
            incoming_rules[rule_key] = {
                'direction': 'Входящий',
                'external_system': f'Внешняя система ({remote_ip})',
                'description': get_process_description(process),
                'endpoints': [],
                'protocol': protocol,
                'port': local_port,
                'process': process,
                'remote_ips': set()
            }
        
        incoming_rules[rule_key]['remote_ips'].add(remote_ip)
        incoming_rules[rule_key]['endpoints'].append(f"{remote_ip}|{local_port}|{protocol}")
    
    # Обрабатываем исходящие соединения
    for conn in integration_connections['outgoing']:
        remote_addr = conn.get('remote', {}).get('address', '')
        local_addr = conn.get('local', '')
        process = conn.get('process', 'unknown')
        protocol = conn.get('protocol', 'tcp').upper()
        
        remote_ip = extract_ip_from_address(remote_addr)
        remote_port = extract_port_from_address(remote_addr)
        
        rule_key = f"{protocol}_{remote_port}_{process}"
        
        if rule_key not in outgoing_rules:
            outgoing_rules[rule_key] = {
                'direction': 'Исходящий',
                'external_system': f'Внешняя система ({remote_ip})',
                'description': get_process_description(process),
                'endpoints': [],
                'protocol': protocol,
                'port': remote_port,
                'process': process,
                'remote_ips': set()
            }
        
        outgoing_rules[rule_key]['remote_ips'].add(remote_ip)
        outgoing_rules[rule_key]['endpoints'].append(f"0.0.0.0/0|{remote_port}|{protocol}")
    
    return {
        'incoming_rules': incoming_rules,
        'outgoing_rules': outgoing_rules
    }

def format_security_group_markup(security_rules):
    """Форматирует правила в текстовую разметку для групп безопасности с улучшенной структурой"""
    
    markup_sections = {
        'incoming_integrations': [],
        'outgoing_integrations': [],
        'incoming_summary': [],
        'outgoing_summary': []
    }
    
    # Форматируем входящие правила - по каждой интеграции отдельно
    if security_rules['incoming_rules']:
        for rule_key, rule in security_rules['incoming_rules'].items():
            # Получаем первый IP для заголовка внешней системы
            first_ip = list(rule['remote_ips'])[0] if rule['remote_ips'] else 'unknown'
            
            # Создаем детальный блок для каждой интеграции
            integration = {
                'title': f"{rule['process']} (порт {rule['port']})",
                'external_system': f"Внешняя система ({first_ip})",
                'process_description': rule['description'],
                'technical_description': f"Техническая группа безопасности для миграции ВМ в рамках проекта.",
                'endpoints': []
            }
            
            # Формируем конкретные endpoints для этой интеграции
            unique_ips = list(rule['remote_ips'])[:10]
            for ip in unique_ips:
                endpoint = f"{ip}|{rule['port']}|{rule['protocol']}"
                integration['endpoints'].append(endpoint)
            
            integration['endpoints_text'] = '\n'.join(integration['endpoints'])
            markup_sections['incoming_integrations'].append(integration)
            
            # Добавляем в суммарный блок (обобщенные правила)
            for remote_ip in list(rule['remote_ips'])[:5]:  # Ограничиваем до 5 IP для краткости
                summary_endpoint = f"{remote_ip}|{rule['port']}|{rule['protocol']}"
                if summary_endpoint not in markup_sections['incoming_summary']:
                    markup_sections['incoming_summary'].append(summary_endpoint)
    
    # Форматируем исходящие правила - по каждой интеграции отдельно
    if security_rules['outgoing_rules']:
        for rule_key, rule in security_rules['outgoing_rules'].items():
            # Получаем первый IP для заголовка внешней системы
            first_ip = list(rule['remote_ips'])[0] if rule['remote_ips'] else 'unknown'
            
            # Создаем детальный блок для каждой интеграции
            integration = {
                'title': f"{rule['process']} → порт {rule['port']}",
                'external_system': f"Внешняя система ({first_ip})",
                'process_description': rule['description'],
                'technical_description': f"Техническая группа безопасности для миграции ВМ в рамках проекта.",
                'endpoints': []
            }
            
            # Формируем конкретные endpoints
            if len(rule['remote_ips']) == 1:
                # Если только один IP, используем его
                ip = list(rule['remote_ips'])[0]
                endpoint = f"{ip}|{rule['port']}|{rule['protocol']}"
                integration['endpoints'].append(endpoint)
            else:
                # Если несколько IP, показываем каждый
                unique_ips = list(rule['remote_ips'])[:10]
                for ip in unique_ips:
                    endpoint = f"{ip}|{rule['port']}|{rule['protocol']}"
                    integration['endpoints'].append(endpoint)
            
            integration['endpoints_text'] = '\n'.join(integration['endpoints'])
            markup_sections['outgoing_integrations'].append(integration)
            
            # Добавляем в суммарный блок (обобщенные правила)
            port = rule['port']
            protocol = rule['protocol']
            
            # Показываем реальные IP-адреса вместо 0.0.0.0/0
            for remote_ip in list(rule['remote_ips'])[:5]:  # Ограничиваем до 5 IP для краткости
                summary_endpoint = f"{remote_ip}|{rule['port']}|{rule['protocol']}"
                if summary_endpoint not in markup_sections['outgoing_summary']:
                    markup_sections['outgoing_summary'].append(summary_endpoint)
    
    return markup_sections

##### Main function #####
def main():
    parser = argparse.ArgumentParser(description='Glacier (optimized version)')
    parser.add_argument('-w', '--wait', type=int, default=10, help='Wait time between measurements in seconds')
    parser.add_argument('-t', '--times', type=int, default=1, help='Number of measurements')
    parser.add_argument('--no-s3', action='store_true', help='Disable S3 upload of reports')
    parser.add_argument('--force-s3', action='store_true', help='Force immediate S3 upload after analysis completion')
    parser.add_argument('-v', '--version', action='version', version=f'Glacier v{VERSION}')
    parser.add_argument('--upload-time', default='8:0', dest='upload_time', help='Time to upload report to S3')

    args = parser.parse_args()
    
    upload_time = args.upload_time
    print(f"🚀 Starting optimized analyzer: {args.times} measurements with {args.wait} second interval")
    print("📊 YAML and HTML reports will be generated")
    
    # Получаем информацию о системе
    hostname = socket.gethostname()
    os_info = {
        'name': platform.system(),
        'version': platform.release()
    }
    
    # Создаем имена файлов
    os_name = os_info.get('name', 'unknown').lower()
    yaml_filename = f"{hostname}_{os_name}_report_analyzer.yaml"
    html_filename = f"{hostname}_{os_name}_report_analyzer.html"
    
    # Инициализируем оптимизированную структуру
    cumulative_state = {
        'hostname': hostname,
        'os': os_info,
        'first_run': dt.now().strftime('%Y-%m-%d %H:%M:%S'),
        'last_update': None,
        'total_measurements': 0,
        'current_state': {},
        'changes_log': []
    }
    
    # Загружаем существующий отчет (поддерживаем и NetFlow и legacy форматы)
    if os.path.exists(yaml_filename):
        try:
            with open(yaml_filename, 'r', encoding='utf-8') as f:
                loaded_data = yaml.safe_load(f)
            
            # Проверяем формат файла
            if (loaded_data and isinstance(loaded_data, dict) and 
                'current_state' in loaded_data and 'changes_log' in loaded_data):
                # Новый кумулятивный формат
                cumulative_state.update(loaded_data)
                print(f"📂 Loaded cumulative report: {cumulative_state.get('total_measurements', 0)} measurements")
            elif (loaded_data and isinstance(loaded_data, dict) and 
                  'netflow_message' in loaded_data):
                # NetFlow формат - конвертируем обратно в кумулятивные данные
                print(f"🌊 NetFlow format detected, converting to cumulative state...")
                try:
                    # Используем NetFlowGenerator для конвертации обратно
                    restored_data = NetFlowGenerator.convert_netflow_yaml_to_legacy_format(loaded_data)
                    
                    # Восстанавливаем базовую кумулятивную структуру
                    cumulative_state['current_state'] = restored_data
                    cumulative_state['total_measurements'] = 1  # Начинаем с 1, так как данные уже есть
                    cumulative_state['changes_log'] = [{
                        'id': 1,
                        'timestamp': loaded_data.get('netflow_message', {}).get('header', {}).get('export_time', cumulative_state['first_run']),
                        'time': 0.0,
                        'changes': {},
                        'first_run': True,
                        'note': 'Restored from NetFlow v9 format'
                    }]
                    print(f"✅ Restored cumulative state from NetFlow data")
                except Exception as e:
                    print(f"⚠️ Failed to restore from NetFlow: {e}, starting fresh")
            else:
                print(f"⚠️ Unknown format report detected, creating new one")
                # Переименовываем старый файл
                old_filename = f"{yaml_filename}.old_{int(time.time())}"
                os.rename(yaml_filename, old_filename)
                print(f"📁 Old report saved as: {old_filename}")
        except Exception as e:
            print(f"⚠️ Error loading report: {e}")
            
    # Дополнительно проверяем наличие legacy файла для восстановления состояния
    legacy_filename = f"{yaml_filename}.legacy"
    if os.path.exists(legacy_filename):
        try:
            with open(legacy_filename, 'r', encoding='utf-8') as f:
                legacy_backup = yaml.safe_load(f)
            
            if (legacy_backup and isinstance(legacy_backup, dict) and 
                'current_state' in legacy_backup and 'changes_log' in legacy_backup):
                cumulative_state.update(legacy_backup)
                print(f"📂 Loaded from legacy backup file: {cumulative_state.get('total_measurements', 0)} measurements")
        except Exception as e:
            print(f"⚠️ Error loading legacy backup: {e}")
    
    # Проверяем наличие отдельного кумулятивного файла (старый формат)
    cumulative_filename = f"{yaml_filename}.cumulative"
    if os.path.exists(cumulative_filename):
        try:
            with open(cumulative_filename, 'r', encoding='utf-8') as f:
                cumulative_backup = yaml.safe_load(f)
            
            if (cumulative_backup and isinstance(cumulative_backup, dict) and 
                'current_state' in cumulative_backup and 'changes_log' in cumulative_backup):
                cumulative_state.update(cumulative_backup)
                print(f"📂 Loaded from cumulative backup file: {cumulative_state.get('total_measurements', 0)} measurements")
        except Exception as e:
            print(f"⚠️ Error loading cumulative backup: {e}")
    
    start_time = time.time()
    
    # Переменная для отслеживания, была ли уже выполнена загрузка по расписанию
    scheduled_upload_done = False
    
    for i in range(args.times):
        print(f"\n--- Measurement {i+1}/{args.times} ---")
        
        measurement_start = time.time()
        measurement_timestamp = dt.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Собираем данные (оптимизированная версия)
        current_data = collect_system_data()
        measurement_time = time.time() - measurement_start
        
        # Сравниваем с предыдущим состоянием
        changes = detect_changes(cumulative_state.get('current_state', {}), current_data)
        
        # Увеличиваем счетчик измерений для каждого выполненного измерения
        cumulative_state['total_measurements'] += 1
        
        if changes or not cumulative_state.get('current_state'):
            # Есть изменения или первый запуск
            change_entry = {
                'id': cumulative_state['total_measurements'],
                'timestamp': measurement_timestamp,
                'time': round(measurement_time, 2),
                'changes': changes,
                'first_run': not cumulative_state.get('current_state')
            }
            
            cumulative_state['changes_log'].append(change_entry)
            cumulative_state['current_state'] = current_data
            cumulative_state['last_update'] = measurement_timestamp
            
            print(f"✅ Changes: {len(changes)} categories in {measurement_time:.2f}s (measurement #{cumulative_state['total_measurements']})")
        else:
            # Нет изменений, но обновляем время последнего измерения
            cumulative_state['last_update'] = measurement_timestamp
            print(f"ℹ️ No changes (measurement #{cumulative_state['total_measurements']} in {measurement_time:.2f}s)")
        
        # Сохраняем промежуточные отчеты только для локальных нужд
        if not args.no_s3:
            try:
                # Сохраняем промежуточные файлы
                with open(yaml_filename, 'w', encoding='utf-8') as f:
                    cumulative_state['session'] = {
                        'duration': round(time.time() - start_time, 2),
                        'measurements': cumulative_state['total_measurements']
                    }
                    yaml.dump(cumulative_state, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
                
                generate_compact_html_report(cumulative_state, html_filename)
                
                # Проверяем время загрузки в S3 только один раз (если еще не выполнена)
                if not args.no_s3 and not args.force_s3 and not scheduled_upload_done:
                    try:
                        # Проверяем расписание отправки (улучшенная логика с окном времени)
                        scheduled_upload_done = write_to_s3_scheduled(
                            yaml_filename, 
                            html_filename, 
                            upload_time=upload_time,
                            configuration=configuration, 
                            py_version=py_version
                        )
                    except Exception as e:
                        print(f"⚠️ S3 scheduled upload error: {e}")
                
            except Exception as e:
                print(f"⚠️ S3: Preparation error: {e}")
        
        if i < args.times - 1:
            time.sleep(args.wait)
    
    # Ограничиваем размер лога изменений
    if len(cumulative_state['changes_log']) > MAX_CHANGES_LOG:
        cumulative_state['changes_log'] = cumulative_state['changes_log'][-MAX_CHANGES_LOG:]
        print(f"🗂️ Changes log trimmed to {MAX_CHANGES_LOG} entries")
    
    # Финализируем сессию
    total_time = time.time() - start_time
    cumulative_state['session'] = {
        'duration': round(total_time, 2),
        'measurements': args.times
    }
    
    # Генерируем NetFlow отчет (стандарт RFC 3954)
    print(f"\n🌊 Generating NetFlow v9 standard report...")
    try:
        # Создаем NetFlow генератор
        netflow_generator = NetFlowGenerator(observation_domain_id=1)
        
        # Генерируем NetFlow отчет из собранных данных
        netflow_report = netflow_generator.generate_netflow_report(cumulative_state)
        
        # Форматируем для YAML
        netflow_yaml_data = netflow_generator.format_netflow_yaml(netflow_report)
        
        print(f"✅ NetFlow v9 report generated: {len(netflow_report['flow_records'])} flows, {netflow_report['statistics']['total_packets']} packets")
        print(f"📊 NetFlow header version: {netflow_report['message_header']['version']}, flows: {netflow_report['message_header']['count']}")
    except Exception as e:
        print(f"⚠️ NetFlow generation error: {e}")
        # Если NetFlow генерация не удалась, используем старый формат
        netflow_yaml_data = None
    
    # Сохраняем отчеты в оба формата для максимальной совместимости
    try:
        if netflow_yaml_data:
            # Сохраняем NetFlow стандартный отчет
            with open(yaml_filename, 'w', encoding='utf-8') as f:
                yaml.dump(netflow_yaml_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"✅ NetFlow v9 YAML report: {yaml_filename}")
            
            # Создаем legacy бэкап для совместимости и восстановления состояния
            legacy_filename = f"{yaml_filename}.legacy"
            try:
                with open(legacy_filename, 'w', encoding='utf-8') as f:
                    yaml.dump(cumulative_state, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
                print(f"✅ Legacy backup saved: {legacy_filename}")
            except Exception as e:
                print(f"⚠️ Failed to save legacy backup: {e}")
        else:
            # Fallback: сохраняем только legacy формат
            with open(yaml_filename, 'w', encoding='utf-8') as f:
                yaml.dump(cumulative_state, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"✅ Legacy YAML report (NetFlow failed): {yaml_filename}")
            
    except PermissionError:
        print(f"❌ Permission error for file: {yaml_filename}")
        print(f"💡 Try: sudo chown $USER:staff {yaml_filename}")
        print(f"📁 Or run analyzer with administrator rights")
        # Пытаемся сохранить в альтернативное место
        alt_filename = f"temp_{yaml_filename}"
        try:
            with open(alt_filename, 'w', encoding='utf-8') as f:
                yaml.dump(cumulative_state, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"✅ Alternative cumulative YAML report: {alt_filename}")
        except Exception as e:
            print(f"❌ Failed to save report: {e}")
    except Exception as e:
        print(f"❌ Error saving cumulative YAML report: {e}")
    
    print(f"📊 Total measurements: {cumulative_state['total_measurements']}")
    print(f"📝 Change records: {len(cumulative_state['changes_log'])}")
    
    # Создаем HTML отчет (конвертируем NetFlow в legacy формат для совместимости)
    try:
        if netflow_yaml_data:
            # Конвертируем NetFlow данные обратно в legacy формат для HTML генератора
            html_compatible_data = NetFlowGenerator.convert_netflow_yaml_to_legacy_format(netflow_yaml_data)
            print(f"🔄 Converting NetFlow data for HTML compatibility...")
        else:
            # Используем кумулятивные данные напрямую
            html_compatible_data = cumulative_state
        
        html_report_path = generate_compact_html_report(html_compatible_data, html_filename)
        print(f"✅ HTML report: {html_report_path}")
    except PermissionError:
        print(f"❌ Permission error for HTML file: {html_filename}")
        print(f"💡 Try: sudo chown $USER:staff {html_filename}")
        # Пытаемся сохранить в альтернативное место
        alt_html_filename = f"temp_{html_filename}"
        try:
            html_report_path = generate_compact_html_report(html_compatible_data, alt_html_filename)
            print(f"✅ Alternative HTML report: {alt_html_filename}")
        except Exception as e:
            print(f"❌ Failed to create HTML report: {e}")
    except Exception as e:
        print(f"❌ Error creating HTML report: {e}")
    
    # Принудительная загрузка в S3 если установлен флаг --force-s3
    if args.force_s3:
        print(f"\n☁️ Force S3 Upload Process")
        try:
            upload_success = upload_reports_to_s3(configuration, py_version, yaml_filename, html_filename)
            if upload_success:
                print(f"🌐 S3: All reports successfully uploaded (forced)")
            else:
                print(f"⚠️ S3: Upload completed with warnings (forced)")
        except Exception as e:
            print(f"❌ S3: Force upload failed: {e}")
    
    # Загрузка в S3 в конце всех измерений (если не было принудительной загрузки и не выполнялась по расписанию)
    elif not args.no_s3 and not scheduled_upload_done:
        try:
            upload_reports_at_end(yaml_filename, html_filename, configuration=configuration, py_version=py_version)
        except Exception as e:
            print(f"❌ S3: End upload failed: {e}")
    
    print(f"\n🎉 Analysis completed in {total_time:.2f} seconds")

# Get attribute from user
if __name__ == "__main__":
    configuration = get_config()
    hostname = socket.gethostname()
    os_info = {"name": distro.name(), "version": distro.version()}

    try:
        py_major = sys.version_info[0]
        py_minor = sys.version_info[1]
    except IndexError:
        py_major = 3
        py_minor = 0

    py_version = {'major': py_major, 'minor': py_minor}

    # Запускаем оптимизированную версию анализатора
    main()
