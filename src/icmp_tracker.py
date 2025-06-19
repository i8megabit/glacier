#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ICMP трекер для анализатора сетевых соединений

Этот модуль отслеживает ICMP трафик (ping, traceroute и другие ICMP пакеты)
на различных операционных системах.
"""

import socket
import psutil
import time
import platform
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

# Константы для ICMP
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_TIME_EXCEEDED = 11

class ICMPTracker:
    """Трекер ICMP соединений"""
    
    def __init__(self, max_entries: int = 1000, history_duration: int = 3600):
        """
        Инициализация ICMP трекера
        
        Args:
            max_entries: Максимальное количество записей
            history_duration: Длительность хранения истории в секундах
        """
        self.max_entries = max_entries
        self.history_duration = history_duration
        self.icmp_traffic = defaultdict(lambda: {
            'count': 0,
            'first_seen': None,
            'last_seen': None,
            'icmp_type': None,
            'direction': 'unknown',
            'bytes_sent': 0,
            'bytes_received': 0,
            'process': 'unknown',
            'status': 'active'
        })
        self.traffic_history = deque(maxlen=max_entries)
        self.start_time = time.time()

    def get_icmp_connections_netstat(self) -> List[Dict[str, Any]]:
        """Получает ICMP соединения через netstat"""
        icmp_connections = []
        
        try:
            from analyzer_utils import execute_command
            
            system = platform.system()
            
            if system == 'Linux':
                # Для Linux используем netstat с опцией -i для ICMP статистики
                result = execute_command(['netstat', '-s', '--icmp'], debug=False)
                icmp_stats = self._parse_linux_icmp_stats(result)
                icmp_connections.extend(icmp_stats)
                
                # Дополнительно пытаемся получить активные ICMP соединения
                try:
                    result = execute_command(['ss', '-u', '-a', '-n'], debug=False)
                    # ss не показывает ICMP напрямую, но можем получить raw сокеты
                except Exception:
                    pass
                    
            elif system == 'Darwin':
                # Для macOS используем netstat с другими опциями
                result = execute_command(['netstat', '-s', '-p', 'icmp'], debug=False)
                icmp_stats = self._parse_macos_icmp_stats(result)
                icmp_connections.extend(icmp_stats)
                
        except Exception as e:
            print(f"⚠️ Ошибка получения ICMP статистики через netstat: {e}")
            
        return icmp_connections

    def get_icmp_connections_proc(self) -> List[Dict[str, Any]]:
        """Получает ICMP соединения через /proc (только Linux)"""
        icmp_connections = []
        
        if platform.system() != 'Linux':
            return icmp_connections
            
        try:
            # Читаем /proc/net/icmp
            with open('/proc/net/icmp', 'r') as f:
                lines = f.readlines()
                
            for line in lines[1:]:  # Пропускаем заголовок
                parts = line.strip().split()
                if len(parts) >= 4:
                    icmp_conn = self._parse_proc_icmp_line(parts)
                    if icmp_conn:
                        icmp_connections.append(icmp_conn)
                        
            # Читаем /proc/net/snmp для статистики ICMP
            try:
                with open('/proc/net/snmp', 'r') as f:
                    snmp_data = f.read()
                    
                icmp_stats = self._parse_snmp_icmp_stats(snmp_data)
                icmp_connections.extend(icmp_stats)
                
            except Exception as e:
                print(f"⚠️ Не удалось прочитать /proc/net/snmp: {e}")
                
        except FileNotFoundError:
            print(f"⚠️ /proc/net/icmp не найден (нужны права root)")
        except Exception as e:
            print(f"⚠️ Ошибка чтения /proc/net/icmp: {e}")
            
        return icmp_connections

    def get_icmp_connections_psutil(self) -> List[Dict[str, Any]]:
        """Получает ICMP соединения через psutil"""
        icmp_connections = []
        
        try:
            # psutil может показать raw сокеты, включая ICMP
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if hasattr(conn, 'type') and conn.type == socket.SOCK_RAW:
                    # Raw сокеты могут быть ICMP
                    icmp_conn = self._analyze_raw_socket(conn)
                    if icmp_conn:
                        icmp_connections.append(icmp_conn)
                        
        except psutil.AccessDenied:
            print(f"⚠️ Недостаточно прав для получения raw сокетов (нужен root/sudo)")
        except Exception as e:
            print(f"⚠️ Ошибка получения ICMP через psutil: {e}")
            
        return icmp_connections

    def monitor_ping_activity(self) -> List[Dict[str, Any]]:
        """Мониторит активность ping (ping, traceroute и т.д.)"""
        ping_activity = []
        
        try:
            from analyzer_utils import execute_command
            
            system = platform.system()
            
            if system == 'Linux':
                # Ищем активные ping процессы
                result = execute_command(['ps', 'aux'], debug=False)
                ping_activity.extend(self._parse_ping_processes_linux(result))
                
            elif system == 'Darwin':
                # Для macOS
                result = execute_command(['ps', 'aux'], debug=False)
                ping_activity.extend(self._parse_ping_processes_macos(result))
                
        except Exception as e:
            print(f"⚠️ Ошибка мониторинга ping активности: {e}")
            
        return ping_activity

    def get_icmp_connections_lsof(self) -> List[Dict[str, Any]]:
        """Получает ICMP соединения через lsof (macOS/Linux)"""
        icmp_connections = []
        
        try:
            from analyzer_utils import execute_command
            
            # lsof может показать сетевые соединения, включая raw сокеты
            result = execute_command(['lsof', '-i', '-n'], debug=False)
            
            for line in result[1:]:  # Пропускаем заголовок
                if 'raw' in line.lower() or 'icmp' in line.lower():
                    icmp_conn = self._parse_lsof_icmp_line(line)
                    if icmp_conn:
                        icmp_connections.append(icmp_conn)
                        
        except Exception as e:
            print(f"⚠️ Ошибка получения ICMP через lsof: {e}")
            
        return icmp_connections

    def update_icmp_data(self) -> Dict[str, Any]:
        """Обновляет данные ICMP трафика"""
        current_time = datetime.now()
        
        # Собираем данные из всех источников
        all_connections = []
        real_icmp_connections = []  # Только реальные ICMP сокеты
        ping_process_connections = []  # Процессы ping
        
        # Метод 1: netstat
        try:
            netstat_connections = self.get_icmp_connections_netstat()
            all_connections.extend(netstat_connections)
            real_icmp_connections.extend(netstat_connections)
        except Exception as e:
            print(f"⚠️ Ошибка netstat для ICMP: {e}")
        
        # Метод 2: /proc (только Linux)
        try:
            proc_connections = self.get_icmp_connections_proc()
            all_connections.extend(proc_connections)
            real_icmp_connections.extend(proc_connections)
        except Exception as e:
            print(f"⚠️ Ошибка /proc для ICMP: {e}")
        
        # Метод 3: psutil raw sockets
        try:
            psutil_connections = self.get_icmp_connections_psutil()
            all_connections.extend(psutil_connections)
            real_icmp_connections.extend(psutil_connections)
        except Exception as e:
            print(f"⚠️ Ошибка psutil для ICMP: {e}")
        
        # Метод 4: lsof
        try:
            lsof_connections = self.get_icmp_connections_lsof()
            all_connections.extend(lsof_connections)
            real_icmp_connections.extend(lsof_connections)
        except Exception as e:
            print(f"⚠️ Ошибка lsof для ICMP: {e}")
        
        # Метод 5: ping activity - показываем всегда, это реальная ICMP активность
        try:
            ping_activity = self.monitor_ping_activity()
            ping_process_connections.extend(ping_activity)
            # Ping процессы - это реальная ICMP активность, показываем их всегда
            all_connections.extend(ping_activity)
        except Exception as e:
            print(f"⚠️ Ошибка мониторинга ping: {e}")
        
        # Показываем результат если есть любая ICMP активность (сокеты или процессы)
        if not all_connections:
            print("🔍 ICMP соединения не найдены")
        else:
            print(f"🔍 Найдено ICMP активности: {len(real_icmp_connections)} сокетов, {len(ping_process_connections)} ping процессов")
        
        # Ping процессы - это тоже реальная ICMP активность, не очищаем их
        # Очищаем все соединения только если вообще нет ICMP активности
        if not all_connections:
            print("🔍 ICMP соединения не найдены (нужны права root для мониторинга ICMP трафика)")
        
        # Обновляем историю трафика
        for conn in all_connections:
            connection_key = self._create_connection_key(conn)
            
            if connection_key not in self.icmp_traffic:
                self.icmp_traffic[connection_key] = {
                    'first_seen': current_time.strftime("%d.%m.%Y %H:%M:%S"),
                    'icmp_type': conn.get('icmp_type', 'echo'),
                    'direction': conn.get('direction', 'outgoing'),
                    'process': conn.get('process', 'unknown'),
                    'count': 0,
                    'last_seen': '',
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'status': 'active'
                }
            
            self.icmp_traffic[connection_key]['count'] += conn.get('packet_count', 1)
            self.icmp_traffic[connection_key]['last_seen'] = current_time.strftime("%d.%m.%Y %H:%M:%S")
            self.icmp_traffic[connection_key]['bytes_sent'] += conn.get('bytes_sent', 0)
            self.icmp_traffic[connection_key]['bytes_received'] += conn.get('bytes_received', 0)
        
        # Очищаем старые записи
        self._cleanup_old_entries()
        
        return {
            'total_connections': len(self.icmp_traffic),
            'active_connections': len([c for c in self.icmp_traffic.values() if c['status'] == 'active']),
            'total_packets': sum(c['count'] for c in self.icmp_traffic.values()),
            'connections': all_connections[:50]  # Ограничиваем для отчета
        }

    def _parse_linux_icmp_stats(self, netstat_output: List[str]) -> List[Dict[str, Any]]:
        """Парсит статистику ICMP из netstat Linux"""
        connections = []
        
        try:
            icmp_section = False
            for line in netstat_output:
                if 'icmp:' in line.lower() or 'Icmp:' in line:
                    icmp_section = True
                    continue
                    
                if icmp_section and line.strip():
                    # Парсим ICMP статистику
                    if 'echo requests' in line.lower():
                        count = self._extract_number_from_line(line)
                        if count > 0:
                            connections.append({
                                'connection': 'system -> *',
                                'icmp_type': 'echo_request',
                                'direction': 'outgoing',
                                'packet_count': count,
                                'process': 'kernel',
                                'bytes_sent': count * 64,  # Примерный размер
                                'bytes_received': 0
                            })
                    
                    elif 'echo replies' in line.lower():
                        count = self._extract_number_from_line(line)
                        if count > 0:
                            connections.append({
                                'connection': '* -> system',
                                'icmp_type': 'echo_reply',
                                'direction': 'incoming',
                                'packet_count': count,
                                'process': 'kernel',
                                'bytes_sent': 0,
                                'bytes_received': count * 64
                            })
                    
                    # Переходим к следующей секции если встретили пустую строку
                    if not line.strip():
                        icmp_section = False
                        
        except Exception as e:
            print(f"⚠️ Ошибка парсинга Linux ICMP статистики: {e}")
            
        return connections

    def _parse_macos_icmp_stats(self, netstat_output: List[str]) -> List[Dict[str, Any]]:
        """Парсит статистику ICMP из netstat macOS"""
        connections = []
        
        try:
            for line in netstat_output:
                if 'echo' in line.lower():
                    if 'requests' in line.lower():
                        count = self._extract_number_from_line(line)
                        if count > 0:
                            connections.append({
                                'connection': 'system -> *',
                                'icmp_type': 'echo_request',
                                'direction': 'outgoing',
                                'packet_count': count,
                                'process': 'kernel',
                                'bytes_sent': count * 64,
                                'bytes_received': 0
                            })
                    
                    elif 'replies' in line.lower():
                        count = self._extract_number_from_line(line)
                        if count > 0:
                            connections.append({
                                'connection': '* -> system',
                                'icmp_type': 'echo_reply',
                                'direction': 'incoming',
                                'packet_count': count,
                                'process': 'kernel',
                                'bytes_sent': 0,
                                'bytes_received': count * 64
                            })
                            
        except Exception as e:
            print(f"⚠️ Ошибка парсинга macOS ICMP статистики: {e}")
            
        return connections

    def _parse_proc_icmp_line(self, parts: List[str]) -> Optional[Dict[str, Any]]:
        """Парсит строку из /proc/net/icmp"""
        try:
            # Формат /proc/net/icmp может отличаться в разных версиях ядра
            local_addr = parts[1] if len(parts) > 1 else "0.0.0.0"
            remote_addr = parts[2] if len(parts) > 2 else "0.0.0.0"
            
            return {
                'connection': f"{local_addr} -> {remote_addr}",
                'icmp_type': 'raw',
                'direction': 'outgoing' if remote_addr != "0.0.0.0" else 'listening',
                'packet_count': 1,
                'process': 'kernel',
                'bytes_sent': 0,
                'bytes_received': 0
            }
            
        except Exception as e:
            print(f"⚠️ Ошибка парсинга строки /proc/net/icmp: {e}")
            return None

    def _parse_snmp_icmp_stats(self, snmp_data: str) -> List[Dict[str, Any]]:
        """Парсит ICMP статистику из /proc/net/snmp"""
        connections = []
        
        try:
            lines = snmp_data.split('\n')
            icmp_header = None
            icmp_values = None
            
            for line in lines:
                if line.startswith('Icmp:'):
                    if icmp_header is None:
                        icmp_header = line.split()
                    else:
                        icmp_values = line.split()
                        break
            
            if icmp_header and icmp_values and len(icmp_header) == len(icmp_values):
                for i, field in enumerate(icmp_header[1:], 1):  # Пропускаем 'Icmp:'
                    if i < len(icmp_values):
                        value = int(icmp_values[i])
                        if value > 0:
                            connections.append({
                                'connection': f"system -> *",
                                'icmp_type': field.lower(),
                                'direction': 'system',
                                'packet_count': value,
                                'process': 'kernel',
                                'bytes_sent': value * 32,  # Примерный размер
                                'bytes_received': 0
                            })
                            
        except Exception as e:
            print(f"⚠️ Ошибка парсинга SNMP ICMP статистики: {e}")
            
        return connections

    def _analyze_raw_socket(self, connection) -> Optional[Dict[str, Any]]:
        """Анализирует raw сокет на предмет ICMP"""
        try:
            # Проверяем, является ли raw сокет ICMP сокетом
            if hasattr(connection, 'laddr') and connection.laddr:
                local_addr = f"{connection.laddr.ip}:{connection.laddr.port}"
                remote_addr = f"{connection.raddr.ip}:{connection.raddr.port}" if connection.raddr else "*:*"
                
                return {
                    'connection': f"{local_addr} -> {remote_addr}",
                    'icmp_type': 'raw',
                    'direction': 'outgoing' if connection.raddr else 'listening',
                    'packet_count': 1,
                    'process': self._get_process_name_by_pid(connection.pid) if connection.pid else 'unknown',
                    'bytes_sent': 0,
                    'bytes_received': 0
                }
                
        except Exception as e:
            print(f"⚠️ Ошибка анализа raw сокета: {e}")
            
        return None

    def _parse_ping_processes_linux(self, ps_output: List[str]) -> List[Dict[str, Any]]:
        """Парсит процессы ping в Linux"""
        ping_processes = []
        
        try:
            for line in ps_output[1:]:  # Пропускаем заголовок
                if any(cmd in line for cmd in ['ping', 'ping6', 'traceroute', 'tracepath']):
                    parts = line.split()
                    if len(parts) > 10:
                        process_name = parts[10]
                        user = parts[0]
                        
                        # Извлекаем целевой адрес
                        target = 'unknown'
                        for part in parts[11:]:
                            if '.' in part or ':' in part:  # IP адрес
                                target = part
                                break
                        
                        ping_processes.append({
                            'connection': f"system -> {target}",
                            'icmp_type': 'echo_request',
                            'direction': 'outgoing',
                            'packet_count': 10,  # Примерное количество
                            'process': process_name,
                            'user': user,
                            'bytes_sent': 640,  # 10 пакетов по 64 байта
                            'bytes_received': 0
                        })
                        
        except Exception as e:
            print(f"⚠️ Ошибка парсинга ping процессов Linux: {e}")
            
        return ping_processes

    def _parse_ping_processes_macos(self, ps_output: List[str]) -> List[Dict[str, Any]]:
        """Парсит процессы ping в macOS"""
        return self._parse_ping_processes_linux(ps_output)  # Логика аналогична Linux

    def _parse_lsof_icmp_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Парсит строку lsof для ICMP"""
        try:
            parts = line.split()
            if len(parts) >= 8:
                process_name = parts[0]
                protocol_info = parts[7] if len(parts) > 7 else ''
                
                if 'raw' in protocol_info.lower():
                    return {
                        'connection': f"system -> *",
                        'icmp_type': 'raw',
                        'direction': 'outgoing',
                        'packet_count': 1,
                        'process': process_name,
                        'bytes_sent': 0,
                        'bytes_received': 0
                    }
                    
        except Exception as e:
            print(f"⚠️ Ошибка парсинга lsof ICMP: {e}")
            
        return None

    def _create_connection_key(self, connection: Dict[str, Any]) -> str:
        """Создает ключ для соединения"""
        conn_str = connection.get('connection', 'unknown')
        icmp_type = connection.get('icmp_type', 'unknown')
        return f"{conn_str}:{icmp_type}"

    def _cleanup_old_entries(self):
        """Очищает старые записи"""
        current_time = time.time()
        cutoff_time = current_time - self.history_duration
        
        keys_to_remove = []
        for key, data in self.icmp_traffic.items():
            if data['first_seen']:
                try:
                    first_seen_time = datetime.strptime(data['first_seen'], "%d.%m.%Y %H:%M:%S").timestamp()
                    if first_seen_time < cutoff_time:
                        keys_to_remove.append(key)
                except Exception:
                    pass
        
        for key in keys_to_remove:
            del self.icmp_traffic[key]

    def _extract_number_from_line(self, line: str) -> int:
        """Извлекает число из строки"""
        try:
            import re
            numbers = re.findall(r'\d+', line)
            return int(numbers[0]) if numbers else 0
        except Exception:
            return 0

    def _get_process_name_by_pid(self, pid: int) -> str:
        """Получает имя процесса по PID"""
        try:
            process = psutil.Process(pid)
            return process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 'unknown'

    def get_icmp_report(self) -> Dict[str, Any]:
        """Генерирует отчет по ICMP трафику"""
        report_data = self.update_icmp_data()
        
        # Группируем по типам ICMP
        by_type = defaultdict(int)
        by_direction = defaultdict(int)
        by_process = defaultdict(int)
        
        for connection in report_data['connections']:
            icmp_type = connection.get('icmp_type', 'unknown')
            direction = connection.get('direction', 'unknown')
            process = connection.get('process', 'unknown')
            
            by_type[icmp_type] += connection.get('packet_count', 1)
            by_direction[direction] += connection.get('packet_count', 1)
            by_process[process] += connection.get('packet_count', 1)
        
        return {
            'total_connections': report_data['total_connections'],
            'active_connections': report_data['active_connections'],
            'total_packets': report_data['total_packets'],
            'connections': report_data['connections'],
            'by_type': dict(by_type),
            'by_direction': dict(by_direction),
            'by_process': dict(by_process),
            'uptime_seconds': time.time() - self.start_time
        }


def get_icmp_information(debug: bool = False) -> Dict[str, Any]:
    """
    Основная функция для получения информации об ICMP трафике
    
    Args:
        debug: Флаг отладки
        
    Returns:
        Словарь с информацией об ICMP трафике
    """
    tracker = ICMPTracker()
    
    try:
        result = tracker.get_icmp_report()
        
        if debug:
            print(f"🧪 ICMP Tracker Debug:")
            print(f"   - Всего соединений: {result['total_connections']}")
            print(f"   - Активных соединений: {result['active_connections']}")
            print(f"   - Всего пакетов: {result['total_packets']}")
            print(f"   - По типам: {result['by_type']}")
            print(f"   - По направлениям: {result['by_direction']}")
        
        return result
        
    except Exception as e:
        print(f"❌ Ошибка получения ICMP информации: {e}")
        return {
            'total_connections': 0,
            'active_connections': 0,
            'total_packets': 0,
            'connections': [],
            'by_type': {},
            'by_direction': {},
            'by_process': {},
            'error': str(e)
        }


def test_icmp_tracker():
    """Тестирует функциональность ICMP трекера"""
    print("🧪 Тестирование ICMP трекера...")
    
    result = get_icmp_information(debug=True)
    
    if result['total_connections'] > 0:
        print("✅ ICMP трекер работает корректно")
        print(f"   Найдено соединений: {result['total_connections']}")
    else:
        print("⚠️ ICMP соединения не найдены (возможно нужны права root)")
    
    return result


if __name__ == "__main__":
    test_icmp_tracker() 