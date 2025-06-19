#!/usr/bin/env python3
"""
Модуль для мониторинга коротких сетевых соединений
Демонстрирует различные подходы к захвату быстрых соединений
"""

import time
import subprocess
import re
import json
import threading
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import defaultdict
import platform


@dataclass
class ShortConnection:
    """Структура для представления короткого соединения"""
    timestamp: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    process_name: str
    duration_ms: Optional[int] = None
    bytes_transferred: Optional[int] = None
    status: str = 'completed'


class LogBasedMonitor:
    """Мониторинг на основе логов веб-серверов"""
    
    def __init__(self):
        self.log_patterns = {
            'nginx': r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(.*?)".*?(\d+)\s+(\d+)',
            'apache': r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(.*?)".*?(\d+)\s+(\d+)',
            'syslog': r'(\w+\s+\d+\s+\d+:\d+:\d+).*kernel:.*TCP.*(\d+\.\d+\.\d+\.\d+):(\d+).*(\d+\.\d+\.\d+\.\d+):(\d+)'
        }
    
    def monitor_nginx_logs(self, log_path: str = '/var/log/nginx/access.log') -> List[ShortConnection]:
        """Мониторинг логов nginx"""
        connections = []
        try:
            # Читаем последние 100 строк лога
            result = subprocess.run(['tail', '-n', '100', log_path], 
                                  capture_output=True, text=True, timeout=5)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    conn = self._parse_nginx_log(line)
                    if conn:
                        connections.append(conn)
        except Exception as e:
            print(f"⚠️ Ошибка чтения логов nginx: {e}")
        
        return connections
    
    def _parse_nginx_log(self, line: str) -> Optional[ShortConnection]:
        """Парсинг строки лога nginx"""
        # 192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] "GET /api/health HTTP/1.1" 200 1234
        pattern = r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(.*?)".*?(\d+)\s+(\d+)'
        match = re.match(pattern, line)
        
        if match:
            return ShortConnection(
                timestamp=match.group(2),
                source_ip=match.group(1),
                source_port=0,  # Неизвестен из лога
                dest_ip='local',  # Текущий хост
                dest_port=443 if 'https' in line else 80,
                protocol='http',
                process_name='nginx',
                bytes_transferred=int(match.group(5))
            )
        return None


class SnapshotDiffMonitor:
    """Мониторинг на основе частого сравнения снимков"""
    
    def __init__(self, interval_ms: int = 500):
        self.interval = interval_ms / 1000.0
        self.previous_connections = set()
        self.running = False
        
    def start_monitoring(self) -> None:
        """Запуск мониторинга в отдельном потоке"""
        self.running = True
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        print(f"🔍 Запущен мониторинг коротких соединений (интервал: {self.interval*1000}ms)")
    
    def stop_monitoring(self) -> None:
        """Остановка мониторинга"""
        self.running = False
    
    def _monitor_loop(self) -> None:
        """Основной цикл мониторинга"""
        while self.running:
            try:
                current_connections = self._get_current_connections()
                new_connections = current_connections - self.previous_connections
                
                if new_connections:
                    print(f"🆕 Обнаружено новых соединений: {len(new_connections)}")
                    for conn in new_connections:
                        print(f"   📡 {conn}")
                
                self.previous_connections = current_connections
                time.sleep(self.interval)
                
            except Exception as e:
                print(f"⚠️ Ошибка в цикле мониторинга: {e}")
                time.sleep(1)
    
    def _get_current_connections(self) -> set:
        """Получение текущих соединений"""
        connections = set()
        try:
            # Проверяем доступность ss (Linux) или используем netstat (macOS/универсальный)
            if platform.system() == 'Darwin':
                # macOS: используем netstat
                result = subprocess.run(['netstat', '-tn'], capture_output=True, text=True, timeout=2)
            else:
                # Linux: пытаемся использовать ss, если недоступен - netstat
                try:
                    result = subprocess.run(['ss', '-tn'], capture_output=True, text=True, timeout=2)
                except FileNotFoundError:
                    result = subprocess.run(['netstat', '-tn'], capture_output=True, text=True, timeout=2)
            
            for line in result.stdout.split('\n')[1:]:  # Пропускаем заголовок
                if 'ESTABLISHED' in line or 'SYN_SENT' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        # Для netstat формат: tcp4 0 0 local_addr remote_addr ESTABLISHED
                        # Для ss формат: ESTAB 0 0 local_addr remote_addr
                        if platform.system() == 'Darwin' and len(parts) >= 6:
                            local_addr = parts[3]
                            remote_addr = parts[4]
                        elif len(parts) >= 5:
                            local_addr = parts[3] if 'ss' in result.args[0] else parts[3]
                            remote_addr = parts[4] if 'ss' in result.args[0] else parts[4]
                        else:
                            continue
                            
                        conn_str = f"{local_addr} -> {remote_addr}"
                        connections.add(conn_str)
                        
        except Exception as e:
            print(f"⚠️ Ошибка получения соединений: {e}")
        
        return connections


class ProcessMonitor:
    """Мониторинг сетевой активности через мониторинг процессов"""
    
    def __init__(self):
        self.process_connections = defaultdict(list)
    
    def monitor_process_network_activity(self, process_name: str) -> List[ShortConnection]:
        """Мониторинг сетевой активности конкретного процесса"""
        connections = []
        try:
            # Получаем PID процесса
            pids = self._get_process_pids(process_name)
            
            for pid in pids:
                proc_connections = self._get_process_connections(pid)
                connections.extend(proc_connections)
                
        except Exception as e:
            print(f"⚠️ Ошибка мониторинга процесса {process_name}: {e}")
        
        return connections
    
    def _get_process_pids(self, process_name: str) -> List[int]:
        """Получение PID процессов по имени"""
        try:
            result = subprocess.run(['pgrep', process_name], 
                                  capture_output=True, text=True)
            pids = [int(pid.strip()) for pid in result.stdout.split() if pid.strip()]
            return pids
        except Exception:
            return []
    
    def _get_process_connections(self, pid: int) -> List[ShortConnection]:
        """Получение соединений конкретного процесса"""
        connections = []
        try:
            # Используем lsof для получения сетевых соединений процесса
            result = subprocess.run(['lsof', '-p', str(pid), '-i'], 
                                  capture_output=True, text=True, timeout=3)
            
            for line in result.stdout.split('\n')[1:]:  # Пропускаем заголовок
                if line.strip() and ('TCP' in line or 'UDP' in line):
                    conn = self._parse_lsof_line(line, pid)
                    if conn:
                        connections.append(conn)
                        
        except Exception as e:
            print(f"⚠️ Ошибка получения соединений процесса {pid}: {e}")
        
        return connections
    
    def _parse_lsof_line(self, line: str, pid: int) -> Optional[ShortConnection]:
        """Парсинг строки вывода lsof"""
        try:
            parts = line.split()
            if len(parts) >= 9:
                process_name = parts[0]
                protocol = 'tcp' if 'TCP' in parts[7] else 'udp'
                addresses = parts[8]
                
                if '->' in addresses:
                    local, remote = addresses.split('->', 1)
                    local_ip, local_port = self._parse_address(local)
                    remote_ip, remote_port = self._parse_address(remote)
                    
                    return ShortConnection(
                        timestamp=datetime.now().isoformat(),
                        source_ip=local_ip,
                        source_port=local_port,
                        dest_ip=remote_ip,
                        dest_port=remote_port,
                        protocol=protocol,
                        process_name=process_name
                    )
        except Exception:
            pass
        return None
    
    def _parse_address(self, addr_str: str) -> tuple:
        """Парсинг адреса вида ip:port"""
        try:
            if ':' in addr_str:
                ip, port = addr_str.rsplit(':', 1)
                return ip, int(port)
        except Exception:
            pass
        return addr_str, 0


class ShortConnectionsAnalyzer:
    """Главный анализатор коротких соединений"""
    
    def __init__(self):
        self.log_monitor = LogBasedMonitor()
        self.snapshot_monitor = SnapshotDiffMonitor()
        self.process_monitor = ProcessMonitor()
        self.discovered_connections = []
    
    def analyze_short_connections(self, duration_seconds: int = 30) -> Dict:
        """Анализ коротких соединений за указанный период"""
        print(f"🔍 Начинаем анализ коротких соединений на {duration_seconds} секунд...")
        
        # Запускаем мониторинг снимков
        self.snapshot_monitor.start_monitoring()
        
        # Собираем данные из разных источников
        all_connections = []
        
        try:
            start_time = time.time()
            while time.time() - start_time < duration_seconds:
                # Мониторинг логов веб-серверов
                nginx_connections = self.log_monitor.monitor_nginx_logs()
                all_connections.extend(nginx_connections)
                
                # Мониторинг конкретных процессов
                for process in ['nginx', 'apache2', 'httpd', 'python', 'node']:
                    proc_connections = self.process_monitor.monitor_process_network_activity(process)
                    all_connections.extend(proc_connections)
                
                time.sleep(2)  # Пауза между итерациями
                
        finally:
            self.snapshot_monitor.stop_monitoring()
        
        # Анализируем собранные данные
        analysis = self._analyze_collected_connections(all_connections)
        return analysis
    
    def _analyze_collected_connections(self, connections: List[ShortConnection]) -> Dict:
        """Анализ собранных соединений"""
        analysis = {
            'total_connections': len(connections),
            'unique_source_ips': len(set(c.source_ip for c in connections)),
            'unique_dest_ports': len(set(c.dest_port for c in connections)),
            'protocols': defaultdict(int),
            'processes': defaultdict(int),
            'connections_by_port': defaultdict(int),
            'timeline': [],
            'recommendations': []
        }
        
        for conn in connections:
            analysis['protocols'][conn.protocol] += 1
            analysis['processes'][conn.process_name] += 1
            analysis['connections_by_port'][conn.dest_port] += 1
            analysis['timeline'].append({
                'timestamp': conn.timestamp,
                'source': f"{conn.source_ip}:{conn.source_port}",
                'destination': f"{conn.dest_ip}:{conn.dest_port}",
                'protocol': conn.protocol,
                'process': conn.process_name
            })
        
        # Генерируем рекомендации
        if analysis['connections_by_port'][443] > 0:
            analysis['recommendations'].append(
                "Обнаружены HTTPS соединения на порт 443. "
                "Для полного мониторинга рекомендуется использовать packet capture."
            )
        
        if analysis['connections_by_port'][80] > 0:
            analysis['recommendations'].append(
                "Обнаружены HTTP соединения на порт 80. "
                "Рекомендуется анализ логов веб-сервера для детальной статистики."
            )
        
        return analysis


def demonstrate_short_connections_monitoring():
    """Демонстрация мониторинга коротких соединений"""
    print("=" * 60)
    print("🔍 ДЕМОНСТРАЦИЯ МОНИТОРИНГА КОРОТКИХ СОЕДИНЕНИЙ")
    print("=" * 60)
    
    analyzer = ShortConnectionsAnalyzer()
    
    print("\n1. Анализ в течение 10 секунд...")
    print("   (Выполните curl запросы в другом терминале для тестирования)")
    print("   Пример: curl -s https://localhost:443 || curl -s http://localhost:80")
    
    results = analyzer.analyze_short_connections(duration_seconds=10)
    
    print("\n" + "=" * 40)
    print("📊 РЕЗУЛЬТАТЫ АНАЛИЗА")
    print("=" * 40)
    print(f"Всего соединений: {results['total_connections']}")
    print(f"Уникальных IP-адресов: {results['unique_source_ips']}")
    print(f"Уникальных портов назначения: {results['unique_dest_ports']}")
    
    print("\n📈 Протоколы:")
    for protocol, count in results['protocols'].items():
        print(f"  {protocol}: {count}")
    
    print("\n🔧 Процессы:")
    for process, count in results['processes'].items():
        print(f"  {process}: {count}")
    
    print("\n🚪 Порты назначения:")
    for port, count in results['connections_by_port'].items():
        print(f"  {port}: {count}")
    
    if results['timeline']:
        print("\n⏱️ Временная линия (последние 5 событий):")
        for event in results['timeline'][-5:]:
            print(f"  {event['timestamp']} | {event['source']} → {event['destination']} | {event['protocol']} | {event['process']}")
    
    if results['recommendations']:
        print("\n💡 Рекомендации:")
        for i, rec in enumerate(results['recommendations'], 1):
            print(f"  {i}. {rec}")
    
    print("\n" + "=" * 60)
    print("✅ Демонстрация завершена")


if __name__ == '__main__':
    demonstrate_short_connections_monitoring() 