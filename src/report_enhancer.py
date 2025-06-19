#!/usr/bin/env python3
"""
Модуль для улучшения отчетов анализатора
Добавляет аналитику, группировку, приоритизацию и улучшенную читаемость
"""

import re
import socket
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import ipaddress

# Константы для категоризации
SUSPICIOUS_PORTS = {443, 80, 22, 3389, 5432, 3306, 1433, 6379, 27017}
CLOUD_PROVIDERS = {
    'portal.salt.ru': 'Salt Cloud'
}
COMMON_SERVICES = {
    443: 'HTTPS',
    80: 'HTTP', 
    22: 'SSH',
    53: 'DNS',
    993: 'IMAPS',
    5223: 'Apple Push',
    3389: 'RDP',
    5432: 'PostgreSQL',
    3306: 'MySQL'
}

class ReportEnhancer:
    """Класс для улучшения отчетов анализатора"""
    
    def __init__(self):
        self.security_alerts = []
        self.performance_insights = []
        self.recommendations = []
    
    def enhance_report(self, original_report: Dict[str, Any]) -> Dict[str, Any]:
        """Улучшает исходный отчет, добавляя аналитику и структурирование"""
        enhanced_report = {
            'metadata': self._create_metadata(original_report),
            'executive_summary': self._create_executive_summary(original_report),
            'security_analysis': self._analyze_security(original_report),
            'network_analysis': self._analyze_network(original_report),
            'system_health': self._analyze_system_health(original_report),
            'recommendations': self.recommendations,
            'detailed_data': self._structure_detailed_data(original_report)
        }
        
        return enhanced_report
    
    def _create_metadata(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Создает метаданные отчета"""
        return {
            'report_version': '2.2',
            'generated_at': datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
            'hostname': report.get('hostname', 'unknown'),
            'os': report.get('os', {}),
            'analysis_period': {
                'start': report.get('start'),
                'end': report.get('end'),
                'duration_minutes': report.get('worktime', 0) // 60
            },
            'data_quality': self._assess_data_quality(report)
        }
    
    def _create_executive_summary(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Создает краткую сводку отчета"""
        connections = report.get('connections', {})
        incoming = connections.get('incoming', [])
        outgoing = connections.get('outgoing', [])
        
        # Подсчет уникальных процессов и хостов
        processes = set()
        remote_hosts = set()
        
        for conn in incoming + outgoing:
            if 'process' in conn:
                processes.add(conn['process'])
            if 'remote' in conn and 'address' in conn['remote']:
                remote_hosts.add(conn['remote']['address'].split(':')[0])
        
        return {
            'total_connections': len(incoming) + len(outgoing),
            'incoming_connections': len(incoming),
            'outgoing_connections': len(outgoing),
            'unique_processes': len(processes),
            'unique_remote_hosts': len(remote_hosts),
            'tcp_listening_ports': len(report.get('listen_ports', {}).get('tcp', [])),
            'udp_listening_ports': len(report.get('listen_ports', {}).get('udp', [])),
            'security_alerts_count': len(self.security_alerts),
            'top_processes': self._get_top_processes(incoming + outgoing),
            'top_destinations': self._get_top_destinations(outgoing)
        }
    
    def _analyze_security(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует безопасность системы"""
        security_analysis = {
            'alerts': [],
            'open_ports_analysis': self._analyze_open_ports(report),
            'connection_patterns': self._analyze_connection_patterns(report),
            'suspicious_activity': self._detect_suspicious_activity(report)
        }
        
        return security_analysis
    
    def _analyze_network(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует сетевую активность"""
        connections = report.get('connections', {})
        outgoing = connections.get('outgoing', [])
        
        # Группировка по провайдерам облачных услуг
        cloud_connections = self._group_by_cloud_provider(outgoing)
        
        # Анализ протоколов
        protocol_stats = self._analyze_protocols(connections)
        
        # Географический анализ (упрощенный)
        geographic_distribution = self._analyze_geographic_distribution(outgoing)
        
        return {
            'cloud_services': cloud_connections,
            'protocol_distribution': protocol_stats,
            'geographic_distribution': geographic_distribution,
            'bandwidth_analysis': self._analyze_bandwidth(report),
            'connection_duration_analysis': self._analyze_connection_duration(connections)
        }
    
    def _analyze_system_health(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует состояние системы"""
        disks = report.get('disks', {})
        interfaces = report.get('interfaces', {})
        
        # Анализ дискового пространства
        disk_analysis = self._analyze_disk_usage(disks)
        
        # Анализ сетевых интерфейсов
        network_interfaces = self._analyze_network_interfaces(interfaces, report)
        
        # Анализ сервисов
        services_analysis = self._analyze_services(report)
        
        return {
            'disk_health': disk_analysis,
            'network_interfaces': network_interfaces,
            'services_status': services_analysis,
            'overall_health_score': self._calculate_health_score(disk_analysis, services_analysis)
        }
    
    def _structure_detailed_data(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Структурирует детальные данные для лучшей читаемости"""
        connections = report.get('connections', {})
        
        return {
            'connections_by_process': self._group_connections_by_process(connections),
            'connections_by_destination': self._group_connections_by_destination(connections),
            'listening_services': self._structure_listening_services(report),
            'system_resources': self._structure_system_resources(report),
            'raw_data': {
                'firewall_rules': report.get('firewall', {}),
                'routes': report.get('routes', []),
                'udp_traffic': report.get('udp_traffic', {})
            }
        }
    
    def _get_top_processes(self, connections: List[Dict]) -> List[Dict]:
        """Получает топ процессов по количеству соединений"""
        process_counter = Counter()
        for conn in connections:
            process = conn.get('process', 'unknown')
            process_counter[process] += 1
        
        return [{'process': proc, 'connections': count} 
                for proc, count in process_counter.most_common(5)]
    
    def _get_top_destinations(self, outgoing: List[Dict]) -> List[Dict]:
        """Получает топ назначений по количеству соединений"""
        dest_counter = Counter()
        for conn in outgoing:
            if 'remote' in conn and 'name' in conn['remote']:
                dest = conn['remote']['name']
                dest_counter[dest] += 1
        
        return [{'destination': dest, 'connections': count} 
                for dest, count in dest_counter.most_common(5)]
    
    def _analyze_open_ports(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует открытые порты"""
        tcp_ports = report.get('listen_ports', {}).get('tcp', [])
        udp_ports = report.get('listen_ports', {}).get('udp', [])
        
        # Классификация портов
        critical_tcp = [p for p in tcp_ports if p in SUSPICIOUS_PORTS]
        standard_tcp = [p for p in tcp_ports if p not in SUSPICIOUS_PORTS]
        
        analysis = {
            'critical_tcp_ports': critical_tcp,
            'standard_tcp_ports': standard_tcp[:10],  # Ограничиваем вывод
            'udp_ports_summary': {
                'total': len(udp_ports),
                'dns_ports': [p for p in udp_ports if p == 53],
                'high_ports': [p for p in udp_ports if p > 1024][:5]
            }
        }
        
        # Добавляем предупреждения
        if critical_tcp:
            self.security_alerts.append({
                'level': 'WARNING',
                'message': f'Обнаружены критические открытые порты: {critical_tcp}'
            })
        
        return analysis
    
    def _analyze_connection_patterns(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует паттерны соединений"""
        connections = report.get('connections', {})
        outgoing = connections.get('outgoing', [])
        
        # Анализ временных паттернов
        time_patterns = self._analyze_time_patterns(outgoing)
        
        # Анализ частоты соединений
        frequency_analysis = self._analyze_connection_frequency(outgoing)
        
        return {
            'time_patterns': time_patterns,
            'frequency_analysis': frequency_analysis,
            'connection_types': self._categorize_connections(outgoing)
        }
    
    def _detect_suspicious_activity(self, report: Dict[str, Any]) -> List[Dict]:
        """Обнаруживает подозрительную активность"""
        suspicious = []
        connections = report.get('connections', {})
        outgoing = connections.get('outgoing', [])
        
        # Проверка на множественные соединения к одному хосту
        host_connections = defaultdict(int)
        for conn in outgoing:
            if 'remote' in conn and 'address' in conn['remote']:
                host = conn['remote']['address'].split(':')[0]
                host_connections[host] += 1
        
        for host, count in host_connections.items():
            if count > 10:
                suspicious.append({
                    'type': 'MULTIPLE_CONNECTIONS',
                    'description': f'Множественные соединения к хосту {host} ({count} соединений)',
                    'severity': 'MEDIUM'
                })
        
        # Проверка на неизвестные процессы с сетевой активностью
        unknown_processes = [conn for conn in outgoing 
                           if conn.get('process', '').lower() in ['unknown', '']]
        
        if len(unknown_processes) > 5:
            suspicious.append({
                'type': 'UNKNOWN_PROCESSES',
                'description': f'Обнаружено {len(unknown_processes)} соединений от неизвестных процессов',
                'severity': 'HIGH'
            })
        
        return suspicious
    
    def _group_by_cloud_provider(self, outgoing: List[Dict]) -> Dict[str, List]:
        """Группирует соединения по облачным провайдерам"""
        cloud_groups = defaultdict(list)
        
        for conn in outgoing:
            if 'remote' in conn and 'name' in conn['remote']:
                hostname = conn['remote']['name']
                provider = 'Other'
                
                for pattern, name in CLOUD_PROVIDERS.items():
                    if pattern in hostname:
                        provider = name
                        break
                
                cloud_groups[provider].append({
                    'destination': hostname,
                    'process': conn.get('process', 'unknown'),
                    'protocol': conn.get('protocol', 'unknown')
                })
        
        return dict(cloud_groups)
    
    def _analyze_protocols(self, connections: Dict) -> Dict[str, int]:
        """Анализирует распределение протоколов"""
        protocol_count = defaultdict(int)
        
        all_connections = connections.get('incoming', []) + connections.get('outgoing', [])
        for conn in all_connections:
            protocol = conn.get('protocol', 'unknown')
            protocol_count[protocol] += 1
        
        return dict(protocol_count)
    
    def _analyze_geographic_distribution(self, outgoing: List[Dict]) -> Dict[str, Any]:
        """Упрощенный географический анализ на основе доменных имен"""
        regions = defaultdict(int)
        
        for conn in outgoing:
            if 'remote' in conn and 'name' in conn['remote']:
                hostname = conn['remote']['name']
                
                # Простая классификация по доменам
                if any(cloud in hostname for cloud in ['amazonaws.com', 'cloudfront.net']):
                    if 'compute-1.amazonaws.com' in hostname:
                        regions['US-East (Virginia)'] += 1
                    else:
                        regions['AWS Global'] += 1
                elif hostname.endswith('.ru') or '.ru' in hostname:
                    regions['Russia'] += 1
                elif any(tld in hostname for tld in ['.ru', '.su']):
                    regions['Russia'] += 1
                else:
                    regions['International'] += 1
        
        return dict(regions)
    
    def _analyze_bandwidth(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует использование пропускной способности"""
        udp_traffic = report.get('udp_traffic', {})
        network_activity = udp_traffic.get('network_activity', {})
        
        total_in = sum(iface.get('packets_in', 0) for iface in network_activity.values())
        total_out = sum(iface.get('packets_out', 0) for iface in network_activity.values())
        
        # Находим самые активные интерфейсы
        active_interfaces = []
        for iface, stats in network_activity.items():
            total_packets = stats.get('packets_in', 0) + stats.get('packets_out', 0)
            if total_packets > 1000:  # Только активные интерфейсы
                active_interfaces.append({
                    'interface': iface,
                    'packets_in': stats.get('packets_in', 0),
                    'packets_out': stats.get('packets_out', 0),
                    'total_packets': total_packets
                })
        
        active_interfaces.sort(key=lambda x: x['total_packets'], reverse=True)
        
        return {
            'total_packets_in': total_in,
            'total_packets_out': total_out,
            'active_interfaces': active_interfaces[:5],
            'traffic_ratio': round(total_out / max(total_in, 1), 2)
        }
    
    def _analyze_connection_duration(self, connections: Dict) -> Dict[str, Any]:
        """Анализирует продолжительность соединений"""
        all_connections = connections.get('incoming', []) + connections.get('outgoing', [])
        
        short_lived = 0  # < 1 минуты
        medium_lived = 0  # 1-60 минут
        long_lived = 0   # > 60 минут
        
        for conn in all_connections:
            first_seen = conn.get('first_seen', '')
            last_seen = conn.get('last_seen', '')
            
            if first_seen and last_seen:
                try:
                    first_time = datetime.strptime(first_seen, "%d.%m.%Y %H:%M:%S")
                    last_time = datetime.strptime(last_seen, "%d.%m.%Y %H:%M:%S")
                    duration = (last_time - first_time).total_seconds()
                    
                    if duration < 60:
                        short_lived += 1
                    elif duration < 3600:
                        medium_lived += 1
                    else:
                        long_lived += 1
                except ValueError:
                    continue
        
        return {
            'short_lived_connections': short_lived,
            'medium_lived_connections': medium_lived,
            'long_lived_connections': long_lived
        }
    
    def _analyze_disk_usage(self, disks: Dict) -> Dict[str, Any]:
        """Анализирует использование дискового пространства"""
        total_space = 0
        used_space = 0
        critical_disks = []
        
        for disk_name, disk_info in disks.items():
            disk_total = disk_info.get('total', 0)
            disk_used = disk_info.get('used', 0)
            
            total_space += disk_total
            used_space += disk_used
            
            if disk_total > 0:
                usage_percent = (disk_used / disk_total) * 100
                if usage_percent > 90:
                    critical_disks.append({
                        'disk': disk_name,
                        'usage_percent': round(usage_percent, 1),
                        'free_gb': disk_total - disk_used
                    })
        
        usage_percent = (used_space / max(total_space, 1)) * 100
        
        analysis = {
            'total_space_gb': total_space,
            'used_space_gb': used_space,
            'free_space_gb': total_space - used_space,
            'usage_percent': round(usage_percent, 1),
            'critical_disks': critical_disks,
            'health_status': 'CRITICAL' if critical_disks else 'GOOD' if usage_percent < 80 else 'WARNING'
        }
        
        if critical_disks:
            self.recommendations.append({
                'category': 'STORAGE',
                'priority': 'HIGH',
                'message': f'Критически мало места на дисках: {[d["disk"] for d in critical_disks]}'
            })
        
        return analysis
    
    def _analyze_network_interfaces(self, interfaces: Dict, report: Dict) -> Dict[str, Any]:
        """Анализирует сетевые интерфейсы"""
        active_interfaces = []
        inactive_interfaces = []
        
        network_activity = report.get('udp_traffic', {}).get('network_activity', {})
        
        for iface_name, iface_info in interfaces.items():
            activity = network_activity.get(iface_name, {})
            total_packets = activity.get('packets_in', 0) + activity.get('packets_out', 0)
            
            iface_data = {
                'name': iface_name,
                'mtu': iface_info.get('mtu', 0),
                'packets_in': activity.get('packets_in', 0),
                'packets_out': activity.get('packets_out', 0),
                'total_packets': total_packets
            }
            
            if total_packets > 100:
                active_interfaces.append(iface_data)
            else:
                inactive_interfaces.append(iface_data)
        
        return {
            'active_interfaces': sorted(active_interfaces, key=lambda x: x['total_packets'], reverse=True)[:5],
            'inactive_interfaces_count': len(inactive_interfaces),
            'total_interfaces': len(interfaces)
        }
    
    def _analyze_services(self, report: Dict) -> Dict[str, Any]:
        """Анализирует состояние сервисов"""
        postgresql = report.get('postgresql', {})
        docker = report.get('docker', [])
        firewall = report.get('firewall', {})
        
        services = {
            'postgresql': {
                'status': 'active' if postgresql else 'inactive',
                'databases_count': len(postgresql.get('databases', {})),
                'version': postgresql.get('version', 'unknown')
            },
            'docker': {
                'status': 'active' if docker else 'inactive',
                'containers_count': len(docker)
            },
            'firewall': {
                'status': 'configured' if firewall else 'not_configured',
                'rules_count': len(firewall.get('iptables', {}))
            }
        }
        
        return services
    
    def _calculate_health_score(self, disk_analysis: Dict, services_analysis: Dict) -> int:
        """Вычисляет общий балл здоровья системы (0-100)"""
        score = 100
        
        # Штрафы за проблемы с дисками
        if disk_analysis['health_status'] == 'CRITICAL':
            score -= 30
        elif disk_analysis['health_status'] == 'WARNING':
            score -= 15
        
        # Штрафы за неактивные сервисы
        inactive_services = sum(1 for service in services_analysis.values() 
                              if service['status'] in ['inactive', 'not_configured'])
        score -= inactive_services * 10
        
        # Штрафы за security alerts
        score -= len(self.security_alerts) * 5
        
        return max(0, min(100, score))
    
    def _group_connections_by_process(self, connections: Dict) -> Dict[str, List]:
        """Группирует соединения по процессам"""
        process_groups = defaultdict(list)
        
        all_connections = connections.get('incoming', []) + connections.get('outgoing', [])
        for conn in all_connections:
            process = conn.get('process', 'unknown')
            process_groups[process].append(conn)
        
        # Ограничиваем количество соединений для каждого процесса
        for process in process_groups:
            if len(process_groups[process]) > 5:
                process_groups[process] = process_groups[process][:5]
        
        return dict(process_groups)
    
    def _group_connections_by_destination(self, connections: Dict) -> Dict[str, List]:
        """Группирует соединения по назначению"""
        dest_groups = defaultdict(list)
        
        outgoing = connections.get('outgoing', [])
        for conn in outgoing:
            if 'remote' in conn and 'name' in conn['remote']:
                dest = conn['remote']['name']
                dest_groups[dest].append(conn)
        
        # Ограничиваем количество соединений для каждого назначения
        for dest in dest_groups:
            if len(dest_groups[dest]) > 3:
                dest_groups[dest] = dest_groups[dest][:3]
        
        return dict(dest_groups)
    
    def _structure_listening_services(self, report: Dict) -> Dict[str, Any]:
        """Структурирует информацию о прослушиваемых сервисах"""
        tcp_ports = report.get('listen_ports', {}).get('tcp', [])
        udp_ports = report.get('listen_ports', {}).get('udp', [])
        
        tcp_services = []
        for port in sorted(tcp_ports)[:20]:  # Ограничиваем вывод
            service_name = COMMON_SERVICES.get(port, f'Port {port}')
            tcp_services.append({
                'port': port,
                'service': service_name,
                'protocol': 'TCP'
            })
        
        udp_services = []
        for port in sorted(udp_ports)[:10]:  # Ограничиваем вывод
            service_name = COMMON_SERVICES.get(port, f'Port {port}')
            udp_services.append({
                'port': port,
                'service': service_name,
                'protocol': 'UDP'
            })
        
        return {
            'tcp_services': tcp_services,
            'udp_services': udp_services,
            'total_tcp_ports': len(tcp_ports),
            'total_udp_ports': len(udp_ports)
        }
    
    def _structure_system_resources(self, report: Dict) -> Dict[str, Any]:
        """Структурирует информацию о системных ресурсах"""
        return {
            'hostname': report.get('hostname', 'unknown'),
            'os': report.get('os', {}),
            'interfaces_summary': {
                'total': len(report.get('interfaces', {})),
                'active': len([iface for iface, info in report.get('interfaces', {}).items() 
                             if info.get('mtu', 0) > 0])
            },
            'storage_summary': {
                'total_disks': len(report.get('disks', {})),
                'total_space_gb': sum(disk.get('total', 0) for disk in report.get('disks', {}).values())
            }
        }
    
    def _assess_data_quality(self, report: Dict) -> Dict[str, Any]:
        """Оценивает качество собранных данных"""
        quality_score = 100
        issues = []
        
        # Проверяем наличие основных секций
        required_sections = ['connections', 'listen_ports', 'interfaces', 'disks']
        missing_sections = [section for section in required_sections 
                          if not report.get(section)]
        
        if missing_sections:
            quality_score -= len(missing_sections) * 20
            issues.append(f'Отсутствуют секции: {missing_sections}')
        
        # Проверяем количество соединений
        total_connections = (len(report.get('connections', {}).get('incoming', [])) + 
                           len(report.get('connections', {}).get('outgoing', [])))
        
        if total_connections == 0:
            quality_score -= 30
            issues.append('Не обнаружено сетевых соединений')
        
        return {
            'score': max(0, quality_score),
            'issues': issues,
            'completeness': 'GOOD' if quality_score > 80 else 'PARTIAL' if quality_score > 50 else 'POOR'
        }
    
    def _analyze_time_patterns(self, connections: List[Dict]) -> Dict[str, Any]:
        """Анализирует временные паттерны соединений"""
        # Упрощенный анализ - в реальности нужно больше данных
        return {
            'peak_activity_detected': len(connections) > 20,
            'connection_frequency': 'HIGH' if len(connections) > 50 else 'MEDIUM' if len(connections) > 10 else 'LOW'
        }
    
    def _analyze_connection_frequency(self, connections: List[Dict]) -> Dict[str, Any]:
        """Анализирует частоту соединений"""
        frequent_connections = []
        
        for conn in connections:
            count = conn.get('count', 1)
            if count > 5:
                frequent_connections.append({
                    'destination': conn.get('remote', {}).get('name', 'unknown'),
                    'process': conn.get('process', 'unknown'),
                    'count': count
                })
        
        return {
            'frequent_connections': sorted(frequent_connections, key=lambda x: x['count'], reverse=True)[:5],
            'total_frequent': len(frequent_connections)
        }
    
    def _categorize_connections(self, connections: List[Dict]) -> Dict[str, int]:
        """Категоризирует соединения по типам"""
        categories = defaultdict(int)
        
        for conn in connections:
            remote_name = conn.get('remote', {}).get('name', '')
            process = conn.get('process', '').lower()
            
            if any(cloud in remote_name for cloud in CLOUD_PROVIDERS.keys()):
                categories['cloud_services'] += 1
            elif 'browser' in process or 'chrome' in process or 'firefox' in process:
                categories['web_browsing'] += 1
            elif 'mail' in process or 'email' in process:
                categories['email'] += 1
            elif any(dev in process for dev in ['cursor', 'vscode', 'git']):
                categories['development'] += 1
            else:
                categories['other'] += 1
        
        return dict(categories)


def enhance_analyzer_report(original_report: Dict[str, Any]) -> Dict[str, Any]:
    """Функция для интеграции в основной анализатор"""
    enhancer = ReportEnhancer()
    return enhancer.enhance_report(original_report)


if __name__ == "__main__":
    # Тестирование модуля
    print("=== Тест модуля улучшения отчетов ===")
    
    # Создаем тестовый отчет
    test_report = {
        'hostname': 'test-host',
        'os': {'name': 'Ubuntu', 'version': '20.04'},
        'start': '01.01.2025 12:00:00',
        'end': '01.01.2025 12:30:00',
        'worktime': 1800,
        'connections': {
            'incoming': [],
            'outgoing': [
                {
                    'local': '192.168.1.100:12345',
                    'remote': {'name': 'example.com', 'address': '93.184.216.34:443'},
                    'process': 'curl',
                    'protocol': 'tcp',
                    'first_seen': '01.01.2025 12:00:00',
                    'last_seen': '01.01.2025 12:00:30',
                    'count': 1
                }
            ]
        },
        'listen_ports': {'tcp': [22, 80, 443], 'udp': [53]},
        'interfaces': {'eth0': {'mtu': 1500}},
        'disks': {'/dev/sda1': {'total': 100, 'used': 50}},
        'firewall': {},
        'postgresql': {},
        'docker': []
    }
    
    enhanced = enhance_analyzer_report(test_report)
    
    print(f"Уровень риска: {enhanced['security_analysis']['risk_level']}")
    print(f"Общий балл здоровья: {enhanced['system_health']['overall_health_score']}")
    print(f"Всего соединений: {enhanced['executive_summary']['total_connections']}") 