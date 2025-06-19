#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetFlow генератор для анализатора сети
Соответствует стандартам RFC 3954 (NetFlow Version 9) и RFC 7011 (IPFIX)
"""

import time
import socket
import struct
from datetime import datetime as dt
from typing import Dict, List, Any, Optional

# NetFlow v9 стандартные поля (согласно RFC 3954)
NETFLOW_V9_FIELDS = {
    'IN_BYTES': 1,          # Количество байт входящих пакетов
    'IN_PKTS': 2,           # Количество входящих пакетов
    'FLOWS': 3,             # Количество потоков
    'PROTOCOL': 4,          # IP протокол (TCP=6, UDP=17, ICMP=1)
    'SRC_TOS': 5,           # Type of Service
    'TCP_FLAGS': 6,         # Флаги TCP (OR логика)
    'L4_SRC_PORT': 7,       # TCP/UDP порт источника
    'IPV4_SRC_ADDR': 8,     # IPv4 адрес источника
    'SRC_MASK': 9,          # Маска подсети источника
    'INPUT_SNMP': 10,       # SNMP индекс входного интерфейса
    'L4_DST_PORT': 11,      # TCP/UDP порт назначения
    'IPV4_DST_ADDR': 12,    # IPv4 адрес назначения
    'DST_MASK': 13,         # Маска подсети назначения
    'OUTPUT_SNMP': 14,      # SNMP индекс выходного интерфейса
    'IPV4_NEXT_HOP': 15,    # IPv4 адрес следующего хопа
    'SRC_AS': 16,           # BGP AS источника
    'DST_AS': 17,           # BGP AS назначения
    'BGP_IPV4_NEXT_HOP': 18, # BGP IPv4 следующий хоп
    'MUL_DST_PKTS': 19,     # Multicast пакеты назначения
    'MUL_DST_BYTES': 20,    # Multicast байты назначения
    'LAST_SWITCHED': 21,    # Время последнего пакета (системное время)
    'FIRST_SWITCHED': 22,   # Время первого пакета (системное время)
    'OUT_BYTES': 23,        # Количество исходящих байт
    'OUT_PKTS': 24,         # Количество исходящих пакетов
    'MIN_PKT_LNGTH': 25,    # Минимальная длина пакета
    'MAX_PKT_LNGTH': 26,    # Максимальная длина пакета
    'IPV6_SRC_ADDR': 27,    # IPv6 адрес источника
    'IPV6_DST_ADDR': 28,    # IPv6 адрес назначения
    'IPV6_SRC_MASK': 29,    # IPv6 маска подсети источника
    'IPV6_DST_MASK': 30,    # IPv6 маска подсети назначения
}

# Размеры полей в байтах
FIELD_LENGTHS = {
    'IN_BYTES': 4,
    'IN_PKTS': 4,
    'FLOWS': 4,
    'PROTOCOL': 1,
    'SRC_TOS': 1,
    'TCP_FLAGS': 1,
    'L4_SRC_PORT': 2,
    'IPV4_SRC_ADDR': 4,
    'SRC_MASK': 1,
    'INPUT_SNMP': 2,
    'L4_DST_PORT': 2,
    'IPV4_DST_ADDR': 4,
    'DST_MASK': 1,
    'OUTPUT_SNMP': 2,
    'IPV4_NEXT_HOP': 4,
    'SRC_AS': 2,
    'DST_AS': 2,
    'BGP_IPV4_NEXT_HOP': 4,
    'MUL_DST_PKTS': 4,
    'MUL_DST_BYTES': 4,
    'LAST_SWITCHED': 4,
    'FIRST_SWITCHED': 4,
    'OUT_BYTES': 4,
    'OUT_PKTS': 4,
    'MIN_PKT_LNGTH': 2,
    'MAX_PKT_LNGTH': 2,
    'IPV6_SRC_ADDR': 16,
    'IPV6_DST_ADDR': 16,
    'IPV6_SRC_MASK': 1,
    'IPV6_DST_MASK': 1,
}

# Протоколы
PROTOCOL_NUMBERS = {
    'icmp': 1,
    'tcp': 6,
    'udp': 17
}

class NetFlowGenerator:
    """Генератор NetFlow отчетов"""
    
    def __init__(self, observation_domain_id: int = 1):
        self.observation_domain_id = observation_domain_id
        self.sequence_number = 0
        self.start_time = time.time()
        self.templates = {}
        self.flows = []
    
    def create_netflow_header(self, count: int, export_time: Optional[int] = None) -> Dict[str, Any]:
        """Создает NetFlow Message Header согласно RFC 3954"""
        if export_time is None:
            export_time = int(time.time())
        
        header = {
            'version': 9,  # NetFlow Version 9
            'count': count,  # Количество записей в этом сообщении
            'sys_uptime': int((time.time() - self.start_time) * 1000),  # Время работы системы в мс
            'unix_secs': export_time,  # Unix timestamp экспорта
            'sequence_number': self.sequence_number,  # Порядковый номер
            'source_id': self.observation_domain_id  # ID источника наблюдения
        }
        
        self.sequence_number += 1
        return header
    
    def create_template_record(self, template_id: int, fields: List[str]) -> Dict[str, Any]:
        """Создает Template Record для описания структуры данных"""
        field_specs = []
        
        for field_name in fields:
            if field_name in NETFLOW_V9_FIELDS:
                field_specs.append({
                    'field_type': NETFLOW_V9_FIELDS[field_name],
                    'field_length': FIELD_LENGTHS.get(field_name, 4),
                    'field_name': field_name
                })
        
        template = {
            'template_id': template_id,
            'field_count': len(field_specs),
            'field_specs': field_specs
        }
        
        self.templates[template_id] = template
        return template
    
    def parse_connection_address(self, address_str: str) -> tuple:
        """Парсит адрес в формате 'ip:port' или просто 'ip'"""
        try:
            # Обработка IPv6 адресов в квадратных скобках [IPv6]:port
            if address_str.startswith('[') and ']:' in address_str:
                bracket_end = address_str.find(']:')
                ip_str = address_str[1:bracket_end]  # Убираем квадратные скобки
                port_str = address_str[bracket_end+2:]
                try:
                    port = int(port_str)
                except ValueError:
                    # Обрабатываем имена сервисов
                    port_map = {
                        'https': 443, 'http': 80, 'ssh': 22,
                        'imaps': 993, 'imap': 143, 'smtp': 25,
                        'pop3': 110, 'pop3s': 995, 'ftp': 21
                    }
                    port = port_map.get(port_str, 0)
            elif ':' in address_str and not address_str.startswith('['):
                # IPv4 адрес в формате IP:port или просто port  
                ip_str, port_str = address_str.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    # Обрабатываем имена сервисов
                    port_map = {
                        'https': 443, 'http': 80, 'ssh': 22,
                        'imaps': 993, 'imap': 143, 'smtp': 25,
                        'pop3': 110, 'pop3s': 995, 'ftp': 21
                    }
                    port = port_map.get(port_str, 0)
            else:
                # Только IP адрес без порта
                ip_str = address_str.strip('[]')
                port = 0
            
            # Определяем тип IP адреса и конвертируем для NetFlow
            try:
                # Пытаемся как IPv4
                ip_int = struct.unpack('!I', socket.inet_aton(ip_str))[0]
                return ip_str, port, ip_int, 4  # IPv4
            except socket.error:
                # Это IPv6 адрес - для NetFlow v9 мы не можем использовать IPv6 напрямую
                # Сохраняем оригинальный IPv6 адрес в строковом виде
                # и используем специальное значение для индикации IPv6
                if ip_str and ip_str != '0.0.0.0' and ip_str != '*':
                    # Для IPv6 адресов в NetFlow v9 мы сохраняем только строковое представление
                    # и помечаем как IPv6, но в IPV4_SRC_ADDR/IPV4_DST_ADDR ставим 0
                    return ip_str, port, 0, 6  # IPv6, ip_int=0 означает что это IPv6
                else:
                    # Псевдо-адреса, неизвестные адреса
                    return ip_str, port, 0, 4
        except Exception:
            return address_str, 0, 0, 4
    
    def convert_connection_to_flow(self, connection: Dict[str, Any], direction: str) -> Dict[str, Any]:
        """Конвертирует соединение из текущего формата в NetFlow поток"""
        
        # Парсим адреса
        local_addr = connection.get('local', '0.0.0.0:0')
        remote_addr_info = connection.get('remote', {})
        remote_addr = remote_addr_info.get('address', '0.0.0.0:0') if isinstance(remote_addr_info, dict) else str(remote_addr_info)
        
        local_ip, local_port, local_ip_int, local_ip_version = self.parse_connection_address(local_addr)
        remote_ip, remote_port, remote_ip_int, remote_ip_version = self.parse_connection_address(remote_addr)
        
        # ИСПРАВЛЕНИЕ: Правильная логика определения направления для NetFlow
        # В NetFlow source и destination определяются по инициатору соединения, а не по тегу direction
        
        # Анализируем порты для определения фактического направления
        is_server_connection = False
        
        # Определяем, является ли это серверным соединением (локальная система предоставляет сервис)
        if local_port <= 1024:  # Системные порты
            is_server_connection = True
        elif local_port in [22, 80, 443, 993, 995, 143, 110, 25, 587, 465, 53, 8080, 8443, 3306, 5432, 6379, 27017]:
            # Известные серверные порты
            is_server_connection = True
        elif remote_port <= 1024 or remote_port in [22, 80, 443, 993, 995, 143, 110, 25, 587, 465, 53, 8080, 8443]:
            # Удаленный порт является серверным - значит мы клиент
            is_server_connection = False
        elif local_port > 32768:  # Эфемерные порты (обычно клиентские)
            is_server_connection = False
        else:
            # Если не можем определить, используем оригинальный тег direction
            is_server_connection = (direction == 'incoming')
        
        # Устанавливаем source и destination в соответствии с NetFlow стандартом
        if is_server_connection:
            # Локальная система - сервер, принимает входящие соединения
            # NetFlow: remote_client -> local_server
            src_ip, src_port, src_ip_int, src_ip_version = remote_ip, remote_port, remote_ip_int, remote_ip_version
            dst_ip, dst_port, dst_ip_int, dst_ip_version = local_ip, local_port, local_ip_int, local_ip_version
            netflow_direction = 'incoming'
        else:
            # Локальная система - клиент, инициирует исходящие соединения  
            # NetFlow: local_client -> remote_server
            src_ip, src_port, src_ip_int, src_ip_version = local_ip, local_port, local_ip_int, local_ip_version
            dst_ip, dst_port, dst_ip_int, dst_ip_version = remote_ip, remote_port, remote_ip_int, remote_ip_version
            netflow_direction = 'outgoing'
        
        # Определяем протокол
        protocol_str = connection.get('protocol', 'tcp').lower()
        protocol_num = PROTOCOL_NUMBERS.get(protocol_str, 6)  # по умолчанию TCP
        
        # Парсим временные метки
        current_time = int(time.time())
        first_switched = current_time - 300  # 5 минут назад как пример
        last_switched = current_time
        
        try:
            if connection.get('first_seen') and connection['first_seen'] != 'unknown':
                if isinstance(connection['first_seen'], str):
                    # Пытаемся парсить различные форматы времени
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%d.%m.%Y %H:%M:%S']:
                        try:
                            dt_obj = dt.strptime(connection['first_seen'], fmt)
                            first_switched = int(dt_obj.timestamp())
                            break
                        except ValueError:
                            continue
                else:
                    first_switched = int(connection['first_seen'])
            
            if connection.get('last_seen') and connection['last_seen'] != 'unknown':
                if isinstance(connection['last_seen'], str):
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%d.%m.%Y %H:%M:%S']:
                        try:
                            dt_obj = dt.strptime(connection['last_seen'], fmt)
                            last_switched = int(dt_obj.timestamp())
                            break
                        except ValueError:
                            continue
                else:
                    last_switched = int(connection['last_seen'])
        except Exception:
            pass
        
        # Оценка трафика на основе количества пакетов
        packet_count = connection.get('count', 1)
        estimated_bytes = packet_count * 1024  # Оценка: 1KB на пакет
        
        # Создаем NetFlow запись
        flow_record = {
            'IPV4_SRC_ADDR': src_ip_int if (src_ip_int != 0 and src_ip_version == 4) else 0,
            'IPV4_DST_ADDR': dst_ip_int if (dst_ip_int != 0 and dst_ip_version == 4) else 0,
            'L4_SRC_PORT': src_port,
            'L4_DST_PORT': dst_port,
            'PROTOCOL': protocol_num,
            'IN_PKTS': packet_count,
            'IN_BYTES': estimated_bytes,
            'FIRST_SWITCHED': first_switched,
            'LAST_SWITCHED': last_switched,
            'TCP_FLAGS': 0x18 if protocol_str == 'tcp' else 0,  # ACK+PSH для TCP
            'INPUT_SNMP': 1,   # Интерфейс по умолчанию
            'OUTPUT_SNMP': 2,  # Интерфейс по умолчанию
            # Дополнительная информация для отладки
            '_meta': {
                'direction': netflow_direction,  # Корректированное направление
                'original_direction': direction,  # Оригинальное направление из анализатора
                'process': connection.get('process', 'unknown'),
                'src_addr_str': src_ip,
                'dst_addr_str': dst_ip,
                'protocol_str': protocol_str,
                'connection_count': packet_count,
                'is_server_connection': is_server_connection,
                'local_original': local_addr,
                'remote_original': remote_addr,
                'src_ip_version': src_ip_version,
                'dst_ip_version': dst_ip_version
            }
        }
        
        return flow_record
    
    def generate_netflow_report(self, analyzer_data: Dict[str, Any]) -> Dict[str, Any]:
        """Генерирует полный NetFlow отчет из данных анализатора"""
        
        # Очищаем потоки для новой генерации
        self.flows = []
        
        # Конвертируем соединения в потоки
        connections = analyzer_data.get('current_state', {}).get('connections', {})
        
        # Обрабатываем входящие соединения
        for connection in connections.get('incoming', []):
            flow = self.convert_connection_to_flow(connection, 'incoming')
            self.flows.append(flow)
        
        # Обрабатываем исходящие соединения
        for connection in connections.get('outgoing', []):
            flow = self.convert_connection_to_flow(connection, 'outgoing')
            self.flows.append(flow)
        
        # Создаем шаблон для наших полей
        template_fields = [
            'IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'L4_SRC_PORT', 'L4_DST_PORT',
            'PROTOCOL', 'IN_PKTS', 'IN_BYTES', 'FIRST_SWITCHED', 'LAST_SWITCHED',
            'TCP_FLAGS', 'INPUT_SNMP', 'OUTPUT_SNMP'
        ]
        
        template = self.create_template_record(template_id=256, fields=template_fields)
        
        # Создаем заголовок сообщения
        total_records = 1 + len(self.flows)  # 1 template record + flow records
        header = self.create_netflow_header(count=total_records)
        
        # Собираем итоговый NetFlow отчет
        netflow_report = {
            'message_header': header,
            'template_records': [template],
            'flow_records': self.flows,
            'statistics': {
                'total_flows': len(self.flows),
                'total_bytes': sum(flow.get('IN_BYTES', 0) for flow in self.flows),
                'total_packets': sum(flow.get('IN_PKTS', 0) for flow in self.flows),
                'flow_duration': time.time() - self.start_time,
                'protocols': self._get_protocol_statistics()
            },
            # Сохраняем дополнительную информацию из анализатора для HTML отчета
            'additional_info': {
                'hostname': analyzer_data.get('hostname', 'unknown'),
                'os': analyzer_data.get('os', {}),
                'first_run': analyzer_data.get('first_run', dt.now().strftime('%Y-%m-%d %H:%M:%S')),
                'last_update': analyzer_data.get('last_update', dt.now().strftime('%Y-%m-%d %H:%M:%S')),
                'total_measurements': analyzer_data.get('total_measurements', 1),
                'extended_system_info': analyzer_data.get('current_state', {}).get('extended_system_info', {}),
                'session': analyzer_data.get('session', {}),
                'changes_log': analyzer_data.get('changes_log', [])
            }
        }
        
        return netflow_report
    
    def _get_protocol_statistics(self) -> Dict[str, int]:
        """Подсчитывает статистику по протоколам"""
        protocol_stats = {}
        
        for flow in self.flows:
            protocol_num = flow.get('PROTOCOL', 0)
            protocol_name = 'unknown'
            
            for name, num in PROTOCOL_NUMBERS.items():
                if num == protocol_num:
                    protocol_name = name
                    break
            
            if protocol_name not in protocol_stats:
                protocol_stats[protocol_name] = 0
            protocol_stats[protocol_name] += 1
        
        return protocol_stats
    
    def format_netflow_yaml(self, netflow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Форматирует NetFlow данные для сохранения в YAML"""
        
        # Форматируем заголовок сообщения
        header = netflow_data['message_header']
        formatted_header = {
            'netflow_version': header['version'],
            'record_count': header['count'],
            'system_uptime_ms': header['sys_uptime'],
            'export_timestamp': header['unix_secs'],
            'export_time': dt.fromtimestamp(header['unix_secs']).strftime('%Y-%m-%d %H:%M:%S'),
            'sequence_number': header['sequence_number'],
            'observation_domain_id': header['source_id']
        }
        
        # Форматируем шаблоны
        formatted_templates = []
        for template in netflow_data['template_records']:
            formatted_template = {
                'template_id': template['template_id'],
                'field_count': template['field_count'],
                'fields': []
            }
            
            for field_spec in template['field_specs']:
                formatted_template['fields'].append({
                    'name': field_spec['field_name'],
                    'type': field_spec['field_type'],
                    'length': field_spec['field_length']
                })
            
            formatted_templates.append(formatted_template)
        
        # Форматируем записи потоков
        formatted_flows = []
        for flow in netflow_data['flow_records']:
            # Получаем реальные IP адреса из метаданных для правильного отображения IPv6
            meta = flow.get('_meta', {})
            
            # Если в метаданных есть реальные адреса, используем их (но проверяем, что это не псевдо-адреса)
            if (meta.get('src_addr_str') and meta.get('dst_addr_str') and 
                meta['src_addr_str'] not in ['*', '0.0.0.0', 'None'] and 
                meta['dst_addr_str'] not in ['*', '0.0.0.0', 'None']):
                src_ip = meta['src_addr_str']
                dst_ip = meta['dst_addr_str']
            else:
                # Для псевдо-адресов или IPv4 используем специальную обработку
                src_ip_int = flow.get('IPV4_SRC_ADDR', 0)
                dst_ip_int = flow.get('IPV4_DST_ADDR', 0)
                
                # Проверяем псевдо-адреса в метаданных
                if meta.get('src_addr_str') == '*':
                    src_ip = '*'
                elif src_ip_int == 0:
                    # Если это IPv6 или псевдо-адрес, используем оригинальную строку
                    src_ip = meta.get('src_addr_str', '0.0.0.0')
                else:
                    # Конвертируем IPv4
                    src_ip = self._int_to_ip(src_ip_int)
                
                if meta.get('dst_addr_str') == '*':
                    dst_ip = '*'
                elif dst_ip_int == 0:
                    # Если это IPv6 или псевдо-адрес, используем оригинальную строку
                    dst_ip = meta.get('dst_addr_str', '0.0.0.0')
                else:
                    # Конвертируем IPv4
                    dst_ip = self._int_to_ip(dst_ip_int)
            
            formatted_flow = {
                'source_address': src_ip,
                'destination_address': dst_ip,
                'source_port': flow.get('L4_SRC_PORT', 0),
                'destination_port': flow.get('L4_DST_PORT', 0),
                'protocol': flow.get('PROTOCOL', 0),
                'protocol_name': self._get_protocol_name(flow.get('PROTOCOL', 0)),
                'packet_count': flow.get('IN_PKTS', 0),
                'byte_count': flow.get('IN_BYTES', 0),
                'first_switched': flow.get('FIRST_SWITCHED', 0),
                'last_switched': flow.get('LAST_SWITCHED', 0),
                'first_switched_time': dt.fromtimestamp(flow.get('FIRST_SWITCHED', 0)).strftime('%Y-%m-%d %H:%M:%S') if flow.get('FIRST_SWITCHED', 0) > 0 else 'unknown',
                'last_switched_time': dt.fromtimestamp(flow.get('LAST_SWITCHED', 0)).strftime('%Y-%m-%d %H:%M:%S') if flow.get('LAST_SWITCHED', 0) > 0 else 'unknown',
                'tcp_flags': flow.get('TCP_FLAGS', 0),
                'input_interface': flow.get('INPUT_SNMP', 0),
                'output_interface': flow.get('OUTPUT_SNMP', 0)
            }
            
            # Добавляем метаданные если есть
            if '_meta' in flow:
                formatted_flow['meta'] = flow['_meta']
            
            formatted_flows.append(formatted_flow)
        
        # Собираем итоговую структуру
        yaml_structure = {
            'netflow_message': {
                'header': formatted_header,
                'templates': formatted_templates,
                'flows': formatted_flows
            },
            'flow_statistics': netflow_data['statistics'],
            'system_information': netflow_data['additional_info']
        }
        
        return yaml_structure
    
    def _int_to_ip(self, ip_int: int) -> str:
        """Конвертирует целое число в IP адрес"""
        try:
            if ip_int == 0:
                return '0.0.0.0'
            return socket.inet_ntoa(struct.pack('!I', ip_int))
        except (struct.error, socket.error):
            return '0.0.0.0'
    
    def _get_protocol_name(self, protocol_num: int) -> str:
        """Получает имя протокола по номеру"""
        for name, num in PROTOCOL_NUMBERS.items():
            if num == protocol_num:
                return name
        return f'protocol_{protocol_num}'
    
    @staticmethod
    def convert_netflow_yaml_to_legacy_format(netflow_yaml_data: Dict[str, Any]) -> Dict[str, Any]:
        """Конвертирует NetFlow YAML обратно в формат, понятный HTML генератору"""
        
        # Извлекаем системную информацию
        system_info = netflow_yaml_data.get('system_information', {})
        flows = netflow_yaml_data.get('netflow_message', {}).get('flows', [])
        
        # Создаем структуру connections из flows
        incoming_connections = []
        outgoing_connections = []
        
        for flow in flows:
            # Получаем реальные адреса из метаданных для правильного восстановления
            meta = flow.get('meta', {})
            
            # ВСЕГДА используем оригинальные адреса из метаданных если доступны
            # Это правильно обрабатывает IPv6 адреса, UDP listening порты и псевдо-адреса
            if meta.get('local_original') and meta.get('remote_original'):
                local_addr = meta['local_original']
                remote_addr = meta['remote_original']
            else:
                # Fallback: используем стандартный формат из source/destination
                src_addr = flow.get('source_address', '0.0.0.0')
                dst_addr = flow.get('destination_address', '0.0.0.0')
                src_port = flow.get('source_port', 0)
                dst_port = flow.get('destination_port', 0)
                
                # Для псевдо-адресов сохраняем оригинальный формат
                if src_addr == '*':
                    local_addr = f"*:{src_port}" if src_port > 0 else "*:*"
                else:
                    local_addr = f"{src_addr}:{src_port}"
                    
                if dst_addr == '*':
                    remote_addr = f"*:{dst_port}" if dst_port > 0 else "*:*"
                else:
                    remote_addr = f"{dst_addr}:{dst_port}"
            
            # Восстанавливаем структуру соединения
            connection = {
                'local': local_addr,
                'remote': {
                    'address': remote_addr,
                    'name': 'unknown'
                },
                'process': meta.get('process', 'unknown'),
                'protocol': flow.get('protocol_name', 'tcp'),
                'first_seen': flow.get('first_switched_time', 'unknown'),
                'last_seen': flow.get('last_switched_time', 'unknown'),
                'count': flow.get('packet_count', 1)
            }
            
            # Определяем направление из метаданных
            direction = meta.get('direction', 'outgoing')
            if direction == 'incoming':
                incoming_connections.append(connection)
            else:
                outgoing_connections.append(connection)
        
        # Извлекаем порты из потоков
        tcp_ports = []
        udp_ports = []
        
        for flow in flows:
            protocol_name = flow.get('protocol_name', 'tcp')
            src_port = flow.get('source_port', 0)
            dst_port = flow.get('destination_port', 0)
            
            # Добавляем порты в соответствующие списки
            if protocol_name == 'tcp':
                if src_port not in tcp_ports and src_port > 0:
                    tcp_ports.append(src_port)
                if dst_port not in tcp_ports and dst_port > 0:
                    tcp_ports.append(dst_port)
            elif protocol_name == 'udp':
                if src_port not in udp_ports and src_port > 0:
                    udp_ports.append(src_port)
                if dst_port not in udp_ports and dst_port > 0:
                    udp_ports.append(dst_port)
        
        # Создаем UDP трафик для HTML
        udp_traffic = {
            'udp_connections': [],
            'total_connections': 0,
            'total_packets': 0
        }
        
        # ICMP трафик
        icmp_traffic = {
            'connections': [],
            'total_connections': 0,
            'total_packets': 0
        }
        
        # Обрабатываем UDP и ICMP потоки
        for flow in flows:
            protocol_name = flow.get('protocol_name', 'tcp')
            meta = flow.get('meta', {})
            
            if protocol_name == 'udp':
                # ВСЕГДА используем оригинальные адреса из метаданных если доступны
                if meta.get('local_original') and meta.get('remote_original'):
                    connection_str = f"{meta['local_original']} -> {meta['remote_original']}"
                else:
                    # Fallback для UDP
                    src_addr = flow.get('source_address', '0.0.0.0')
                    dst_addr = flow.get('destination_address', '0.0.0.0')
                    src_port = flow.get('source_port', 0)
                    dst_port = flow.get('destination_port', 0)
                    
                    # Для псевдо-адресов сохраняем правильный формат
                    if src_addr == '*':
                        src_part = f"*:{src_port}" if src_port > 0 else "*:*"
                    else:
                        src_part = f"{src_addr}:{src_port}"
                        
                    if dst_addr == '*':
                        dst_part = f"*:{dst_port}" if dst_port > 0 else "*:*"
                    else:
                        dst_part = f"{dst_addr}:{dst_port}"
                    
                    connection_str = f"{src_part} -> {dst_part}"
                
                udp_conn = {
                    'connection': connection_str,
                    'process': meta.get('process', 'unknown'),
                    'direction': meta.get('direction', 'outgoing'),
                    'packet_count': flow.get('packet_count', 1),
                    'first_seen': flow.get('first_switched_time', 'unknown'),
                    'last_seen': flow.get('last_switched_time', 'unknown')
                }
                udp_traffic['udp_connections'].append(udp_conn)
                udp_traffic['total_packets'] += flow.get('packet_count', 1)
            
            elif protocol_name == 'icmp':
                # ВСЕГДА используем оригинальные адреса из метаданных если доступны
                if meta.get('local_original') and meta.get('remote_original'):
                    connection_str = f"{meta['local_original']} -> {meta['remote_original']}"
                else:
                    # Fallback для ICMP
                    connection_str = f"{flow.get('source_address', '0.0.0.0')} -> {flow.get('destination_address', '0.0.0.0')}"
                
                icmp_conn = {
                    'connection': connection_str,
                    'process': meta.get('process', 'unknown'),
                    'direction': meta.get('direction', 'outgoing'),
                    'packet_count': flow.get('packet_count', 1)
                }
                icmp_traffic['connections'].append(icmp_conn)
                icmp_traffic['total_packets'] += flow.get('packet_count', 1)
        
        udp_traffic['total_connections'] = len(udp_traffic['udp_connections'])
        icmp_traffic['total_connections'] = len(icmp_traffic['connections'])
        
        # Собираем legacy формат
        legacy_format = {
            'hostname': system_info.get('hostname', 'unknown'),
            'os': system_info.get('os', {}),
            'first_run': system_info.get('first_run', dt.now().strftime('%Y-%m-%d %H:%M:%S')),
            'last_update': system_info.get('last_update', dt.now().strftime('%Y-%m-%d %H:%M:%S')),
            'total_measurements': system_info.get('total_measurements', 1),
            'current_state': {
                'connections': {
                    'incoming': incoming_connections,
                    'outgoing': outgoing_connections
                },
                'tcp_ports': tcp_ports,
                'udp_ports': udp_ports,
                'udp_traffic': udp_traffic,
                'icmp_traffic': icmp_traffic,
                'extended_system_info': system_info.get('extended_system_info', {})
            },
            'changes_log': system_info.get('changes_log', []),
            'session': system_info.get('session', {})
        }
        
        return legacy_format 