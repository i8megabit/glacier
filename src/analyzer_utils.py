import os
import re
import subprocess
from datetime import datetime as dt

# Словарь с описаниями портов
PORT_DESCRIPTIONS = {
    # Системные порты (0-1023)
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP (Trivial File Transfer Protocol)",
    80: "HTTP (HyperText Transfer Protocol)",
    110: "POP3 (Post Office Protocol v3)",
    123: "NTP (Network Time Protocol)",
    143: "IMAP (Internet Message Access Protocol)",
    161: "SNMP (Simple Network Management Protocol)",
    162: "SNMP Trap",
    389: "LDAP (Lightweight Directory Access Protocol)",
    443: "HTTPS (HTTP Secure)",
    465: "SMTPS (SMTP Secure)",
    514: "Syslog",
    587: "SMTP (Mail Submission)",
    636: "LDAPS (LDAP Secure)",
    993: "IMAPS (IMAP Secure)",
    995: "POP3S (POP3 Secure)",
    
    # Зарегистрированные порты (1024-49151)
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    1723: "PPTP (Point-to-Point Tunneling Protocol)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL Database",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis Database",
    8080: "HTTP Alternative (Web Proxy)",
    8443: "HTTPS Alternative",
    9200: "Elasticsearch",
    27017: "MongoDB",
    
    # Динамические/частные порты (49152-65535)
    50087: "Неизвестный сервис (возможно, временный порт приложения)",
    51190: "Временный порт приложения",
    57066: "Временный порт приложения",
    60897: "Временный UDP порт",
    61145: "Временный порт приложения",
    61186: "Временный UDP порт",
    61231: "Временный порт приложения",
    61251: "Cisco Secure Client (VPN)",
    61359: "Временный порт приложения",
    62227: "Временный порт приложения",
    
    # Apple-специфичные порты
    5353: "mDNS (Multicast DNS) - Bonjour",
    17500: "Dropbox LAN Sync",
    24800: "Synergy (Screen Sharing)",
    49152: "Apple AirPlay",
    62078: "Apple iCloud",
}

def get_port_description(port):
    """Возвращает описание порта"""
    if port in PORT_DESCRIPTIONS:
        return PORT_DESCRIPTIONS[port]
    elif port < 1024:
        return f"Системный порт {port}"
    elif port < 49152:
        return f"Зарегистрированный порт {port}"
    else:
        return f"Динамический порт {port}"

def get_network_interface_stats():
    """Получает статистику сетевых интерфейсов для macOS"""
    try:
        import platform
        if platform.system() == 'Darwin':
            # Используем netstat для получения статистики интерфейсов
            result = execute_command(['netstat', '-i', '-b'])
            
            interface_stats = {}
            for line in result[1:]:  # Пропускаем заголовок
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 10:
                        interface = parts[0]
                        if interface not in ['Name', 'lo0']:  # Исключаем заголовок и loopback
                            try:
                                # Проверяем, что у нас есть числовые данные
                                packets_in = int(parts[4]) if parts[4].isdigit() else 0
                                bytes_in = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0
                                packets_out = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0
                                bytes_out = int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 0
                                
                                # Добавляем только интерфейсы с активностью
                                if packets_in > 0 or packets_out > 0:
                                    interface_stats[interface] = {
                                        'packets_in': packets_in,
                                        'bytes_in': bytes_in,
                                        'packets_out': packets_out,
                                        'bytes_out': bytes_out
                                    }
                            except (ValueError, IndexError):
                                continue
            
            # Если netstat не дал результатов, пробуем альтернативный метод
            if not interface_stats:
                print("⚠️ netstat не дал результатов, пробуем альтернативный метод...")
                try:
                    # Используем ifconfig для получения базовой информации
                    result = execute_command(['ifconfig'])
                    current_interface = None
                    
                    for line in result:
                        if line and not line.startswith('\t') and not line.startswith(' '):
                            # Новый интерфейс
                            parts = line.split(':')
                            if len(parts) >= 2:
                                current_interface = parts[0]
                                if current_interface not in ['lo0']:
                                    interface_stats[current_interface] = {
                                        'packets_in': 0,
                                        'bytes_in': 0,
                                        'packets_out': 0,
                                        'bytes_out': 0
                                    }
                        elif current_interface and 'packets' in line:
                            # Парсим строку с пакетами
                            if 'input' in line:
                                # Входящие пакеты
                                import re
                                packets_match = re.search(r'(\d+) packets', line)
                                bytes_match = re.search(r'(\d+) bytes', line)
                                if packets_match:
                                    interface_stats[current_interface]['packets_in'] = int(packets_match.group(1))
                                if bytes_match:
                                    interface_stats[current_interface]['bytes_in'] = int(bytes_match.group(1))
                            elif 'output' in line:
                                # Исходящие пакеты
                                import re
                                packets_match = re.search(r'(\d+) packets', line)
                                bytes_match = re.search(r'(\d+) bytes', line)
                                if packets_match:
                                    interface_stats[current_interface]['packets_out'] = int(packets_match.group(1))
                                if bytes_match:
                                    interface_stats[current_interface]['bytes_out'] = int(bytes_match.group(1))
                except Exception as e:
                    print(f"⚠️ Альтернативный метод тоже не сработал: {e}")
            
            return interface_stats
        else:
            # Для Linux используем /proc/net/dev
            interface_stats = {}
            try:
                with open('/proc/net/dev', 'r') as f:
                    lines = f.readlines()[2:]  # Пропускаем заголовки
                
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 16:
                        interface = parts[0].rstrip(':')
                        if interface != 'lo':  # Исключаем loopback
                            interface_stats[interface] = {
                                'bytes_in': int(parts[1]),
                                'packets_in': int(parts[2]),
                                'bytes_out': int(parts[9]),
                                'packets_out': int(parts[10])
                            }
            except Exception:
                pass
            
            return interface_stats
    except Exception:
        return {}

# Prepare result dictionary
def convert_vars_to_dict(date, hostname, os_info, open_connections, remote_addresses, tcp, udp, additional_information: dict, enhanced_mode=False):
    interfaces = additional_information['interfaces']
    docker = additional_information['docker']
    disks = additional_information['disks']
    session = additional_information['session']
    postgresql = additional_information['postgresql']
    routes = additional_information['routes']
    firewall = additional_information['firewall']
    udp_info = additional_information.get('udp', {})

    # Получаем статистику сетевых интерфейсов
    interface_stats = get_network_interface_stats()
    
    # Добавляем описания к портам
    tcp_ports_with_desc = []
    for port in tcp:
        tcp_ports_with_desc.append({
            'port': port,
            'description': get_port_description(port)
        })
    
    udp_ports_with_desc = []
    for port in udp:
        udp_ports_with_desc.append({
            'port': port,
            'description': get_port_description(port)
        })

    result_dict = {"hostname": hostname,
                   "os": os_info,
                   "start": date['start'],
                   "end": date['end'],
                   "progress": f"{date['current_count']} of {date['counts']}",
                   "worktime": date['worktime'],
                   "connections": open_connections,
                   "remote_address": remote_addresses,
                   "listen_ports": {
                       'tcp': tcp_ports_with_desc, 
                       'udp': udp_ports_with_desc,
                       'tcp_simple': tcp,  # Оставляем для совместимости
                       'udp_simple': udp   # Оставляем для совместимости
                   },
                   "interfaces": interfaces,
                   "network_stats": interface_stats,  # Добавляем статистику интерфейсов
                   "disks": disks,
                   "session": session,
                   "routes": routes,
                   "firewall": firewall,
                   }
    
    # Добавляем UDP информацию если она есть
    if udp_info and (udp_info.get('total_connections', 0) > 0 or udp_info.get('total_remote_hosts', 0) > 0):
        result_dict['udp_traffic'] = udp_info
    
    if len(docker) > 0:
        result_dict["docker"] = docker

    # Проверка структуры postgresql_info для совместимости с предыдущей и новой версией
    if postgresql and (
        ('patroni' in postgresql and postgresql['patroni'] == 'active') or 
        ('db_count' in postgresql and postgresql['db_count'] > 0) or
        ('databases' in postgresql and len(postgresql['databases'].keys()) > 0)
    ):
        result_dict['postgresql'] = postgresql

    # Если включен улучшенный режим, пытаемся генерировать дополнительные отчеты
    if enhanced_mode:
        try:
            # Создаем интерактивный HTML отчет с улучшенным дизайном
            # Добавляем название ОС в имя файла, очищая от недопустимых символов
            os_name = os_info.get('name', 'unknown').lower().replace(' ', '_').replace('/', '_').replace('\\', '_')
            timestamp = dt.now().strftime('%Y-%m-%d_%H-%M-%S')
            html_filename = f"{hostname}_{os_name}_network_report_{timestamp}.html"
            filename = generate_simple_html_report(result_dict, html_filename)
            
            # Добавляем информацию о дополнительных отчетах
            result_dict['_enhanced_reports'] = {
                'html_report': filename,
                'enhanced_data_available': True,
                'health_score': 85  # Базовый балл
            }
            
        except Exception as e:
            print(f"Предупреждение: Не удалось создать HTML отчет: {e}")

    return result_dict

def get_time_from_string(time_str: str):
    literal = ''
    num_incoming = 10
    c = 1
    try:
        time_sec = int(time_str)
        num_incoming = time_sec
    except ValueError:
        time_str_lower = time_str.lower()
        num_search = re.match(r'^(\d+)([mhd])$', time_str_lower)
        try:
            num_groups = num_search.groups()
        except AttributeError:
            num_groups = [10, "s"]
        #print(num_groups)
        if len(num_groups) == 2:
            num_incoming = int(num_groups[0])
            literal = num_groups[1]
        support_literals = ('m', 'h', 'd')
        if time_str_lower.endswith(support_literals):
            if time_str_lower.endswith("m"):
                c = 60
            elif time_str_lower.endswith("h"):
                c = 3600
            elif time_str_lower.endswith("d"):
                c = 86400
        time_sec = num_incoming * c
    return {"seconds": time_sec, "literal": literal, "num": num_incoming}

def write_result_to_file(file_path, result_string):
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(result_string)

def print_result(result_text):
    for line in result_text:
        print(line, end='')

def check_exist_report_file(file_path, file_name, format_output, hostname):
    date_format = "%Y_%m_%d_%H-%M-%S"
    if os.path.exists(file_path):
        now = dt.now().strftime(date_format)
        file_new_path = f"{hostname}_{file_name}_{now}.{format_output}"
        os.rename(file_path, file_new_path)

def check_process(result_dict: dict, proc_name):
    result_command = os.popen(f"ps -ef | grep {proc_name} | grep -v grep | wc -l")
    result = int(result_command.read().strip())
    if result > 0:
        result_dict[proc_name] = True
    else:
        result_dict[proc_name] = False

def check_service(result_dict: dict, proc_name):
    result = execute_command(['systemctl','is-active',proc_name])
    if len(result) > 0:
        service_info = result[0].strip()
    else:
        service_info = "unknown"
    result_dict[proc_name] = service_info
    return service_info

def execute_command(command, debug=False):
    result = []
    try:
        result_command = subprocess.check_output(command, shell = False, stderr=subprocess.DEVNULL)
        for line in result_command.splitlines():
            try:
                row = line.strip()
            except AttributeError:
                row = line
            try:
                row = bytes.decode(row)
            except AttributeError:
                pass
            result.append(row)
    except (subprocess.CalledProcessError, FileNotFoundError) as cpe:
        if debug:
            print(f'ERROR execute: cmd - {command}, msg: {cpe}')
    return result

def generate_simple_html_report(data: dict, filename: str):
    """Генерирует кумулятивный HTML отчет с улучшенным дизайном"""
    from datetime import datetime
    
    hostname = data.get('hostname', 'unknown')
    
    # Используем переданное имя файла без изменений (без timestamp)
    html_filename = filename
    
    # Подсчитываем статистику
    connections = data.get('connections', {})
    incoming = connections.get('incoming', [])
    outgoing = connections.get('outgoing', [])
    
    # Добавляем UDP соединения из udp_traffic если они есть
    udp_traffic = data.get('udp_traffic', {})
    udp_connections_list = []
    if udp_traffic and udp_traffic.get('udp_connections'):
        for udp_conn in udp_traffic['udp_connections']:
            # Парсим соединение
            connection_str = udp_conn['connection']
            if ' -> ' in connection_str:
                local_part, remote_part = connection_str.split(' -> ', 1)
                
                # Создаем структуру соединения в формате анализатора
                conn_info = {
                    "local": local_part,
                    "remote": {"name": "unknown", "address": remote_part},
                    "process": udp_conn.get('process', 'unknown'),
                    "protocol": "udp",
                    "first_seen": udp_conn['first_seen'],
                    "last_seen": udp_conn['last_seen'],
                    "count": udp_conn['packet_count']
                }
                
                # Определяем направление и добавляем в соответствующий список
                if udp_conn.get('direction') == 'outgoing':
                    outgoing.append(conn_info)
                    udp_connections_list.append(conn_info)
                else:
                    incoming.append(conn_info)
                    udp_connections_list.append(conn_info)
    
    total_connections = len(incoming) + len(outgoing)
    
    tcp_ports = data.get('listen_ports', {}).get('tcp', [])
    udp_ports = data.get('listen_ports', {}).get('udp', [])
    
    # Подсчитываем уникальные процессы
    unique_processes = set()
    for conn in incoming + outgoing:
        if conn.get('process') != 'unknown':
            unique_processes.add(conn.get('process', 'unknown'))
    
    # Подсчитываем уникальные удаленные хосты
    unique_hosts = set()
    for conn in incoming + outgoing:
        remote_addr = conn.get('remote', {}).get('address', '')
        if remote_addr and ':' in remote_addr:
            host_ip = remote_addr.split(':')[0]
            unique_hosts.add(host_ip)
    
    # Получаем информацию об изменениях
    changes_summary = data.get('changes_summary', {})
    recent_changes = data.get('recent_changes', [])
    total_measurements = data.get('total_measurements', 0)
    first_run = data.get('first_run', 'unknown')
    last_update = data.get('last_update', 'unknown')
    
    # Создаем HTML
    html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Кумулятивный отчет анализатора - {hostname}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 16px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{ 
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); 
            color: white; 
            padding: 30px; 
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }}
        
        .header-content {{ position: relative; z-index: 1; }}
        
        .header h1 {{ 
            font-size: 2.5em; 
            margin-bottom: 15px; 
            font-weight: 300;
        }}
        
        .header-info {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-top: 20px;
        }}
        
        .header-info-item {{ 
            background: rgba(255,255,255,0.1); 
            padding: 15px; 
            border-radius: 8px; 
            backdrop-filter: blur(10px);
        }}
        
        .navigation {{ 
            background: #f8f9fa; 
            padding: 20px 30px; 
            border-bottom: 1px solid #dee2e6;
        }}
        
        .nav-buttons {{ 
            display: flex; 
            gap: 10px; 
            flex-wrap: wrap;
        }}
        
        .nav-btn {{ 
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%); 
            color: white; 
            border: none; 
            padding: 12px 24px; 
            border-radius: 25px; 
            cursor: pointer; 
            font-weight: 500; 
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,123,255,0.3);
        }}
        
        .nav-btn:hover {{ 
            transform: translateY(-2px); 
            box-shadow: 0 6px 20px rgba(0,123,255,0.4);
        }}
        
        .nav-btn.active {{ 
            background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%);
            box-shadow: 0 4px 15px rgba(40,167,69,0.3);
        }}
        
        .nav-btn.changes {{ 
            background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%);
            box-shadow: 0 4px 15px rgba(255,193,7,0.3);
        }}
        
        .content {{ padding: 30px; }}
        
        .stats {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px;
        }}
        
        .stat-card {{ 
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); 
            padding: 25px; 
            border-radius: 12px; 
            text-align: center; 
            border-left: 5px solid #007bff;
            transition: transform 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        
        .stat-card:hover {{ transform: translateY(-5px); }}
        
        .stat-number {{ 
            font-size: 2.5em; 
            font-weight: bold; 
            color: #007bff; 
            margin-bottom: 5px;
        }}
        
        .stat-label {{ 
            color: #6c757d; 
            font-weight: 500;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }}
        
        .section {{ 
            margin: 30px 0; 
            display: none;
        }}
        
        .section.active {{ display: block; }}
        
        .section h3 {{ 
            color: #2c3e50; 
            border-bottom: 3px solid #007bff; 
            padding-bottom: 10px; 
            margin-bottom: 20px;
            font-size: 1.5em;
            font-weight: 600;
        }}
        
        .connections-table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 15px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        
        .connections-table th {{ 
            background: linear-gradient(135deg, #343a40 0%, #495057 100%); 
            color: white; 
            padding: 15px 12px; 
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }}
        
        .connections-table td {{ 
            padding: 12px; 
            border-bottom: 1px solid #dee2e6;
            transition: background-color 0.3s ease;
        }}
        
        .connections-table tr:hover td {{ background-color: #f8f9fa; }}
        
        .protocol-tcp {{ color: #007bff; font-weight: bold; }}
        .protocol-udp {{ color: #28a745; font-weight: bold; }}
        
        .ports-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); 
            gap: 15px; 
            margin-top: 20px;
        }}
        
        .port-item {{ 
            background: linear-gradient(135deg, #e9ecef 0%, #f8f9fa 100%); 
            padding: 15px; 
            border-radius: 8px; 
            text-align: center;
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }}
        
        .port-item:hover {{ 
            transform: translateY(-3px);
            border-color: #007bff;
            box-shadow: 0 6px 20px rgba(0,123,255,0.2);
        }}
        
        .port-number {{ 
            font-weight: bold; 
            color: #007bff; 
            font-size: 1.2em;
            margin-bottom: 5px;
        }}
        
        .port-desc {{ 
            font-size: 0.85em; 
            color: #6c757d;
            line-height: 1.4;
        }}
        
        .footer {{ 
            text-align: center; 
            margin-top: 40px; 
            padding: 30px; 
            background: #f8f9fa; 
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }}
        
        .warning {{ 
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); 
            border: 1px solid #ffeaa7; 
            padding: 20px; 
            border-radius: 8px; 
            margin: 20px 0;
            border-left: 5px solid #ffc107;
        }}
        
        .changes-timeline {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}
        
        .change-item {{
            background: white;
            border-radius: 6px;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #007bff;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .change-timestamp {{
            font-weight: bold;
            color: #495057;
            margin-bottom: 8px;
        }}
        
        .change-details {{
            color: #6c757d;
            font-size: 0.9em;
        }}
        
        .network-stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .interface-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            border-left: 5px solid #28a745;
        }}
        
        .interface-name {{
            font-weight: bold;
            color: #2c3e50;
            font-size: 1.1em;
            margin-bottom: 10px;
        }}
        
        .interface-stats {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }}
        
        .interface-stat {{
            text-align: center;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 6px;
        }}
        
        .interface-stat-value {{
            font-weight: bold;
            color: #007bff;
            font-size: 1.1em;
        }}
        
        .interface-stat-label {{
            font-size: 0.8em;
            color: #6c757d;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>📊 Кумулятивный отчет анализатора</h1>
                <div class="header-info">
                    <div class="header-info-item">
                        <strong>🖥️ Хост:</strong> {hostname}
                    </div>
                    <div class="header-info-item">
                        <strong>💻 ОС:</strong> {data.get('os', {}).get('name', 'unknown')} {data.get('os', {}).get('version', '')}
                    </div>
                    <div class="header-info-item">
                        <strong>🚀 Первый запуск:</strong> {first_run}
                    </div>
                    <div class="header-info-item">
                        <strong>🔄 Последнее обновление:</strong> {last_update}
                    </div>
                    <div class="header-info-item">
                        <strong>📊 Всего измерений:</strong> {total_measurements}
                    </div>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <div class="nav-buttons">
                <button class="nav-btn active" onclick="showSection('overview')">📊 Обзор</button>
                <button class="nav-btn" onclick="showSection('connections')">🔗 Соединения</button>
                <button class="nav-btn" onclick="showSection('ports')">🚪 Порты</button>
                <button class="nav-btn" onclick="showSection('network')">📡 Сеть</button>
                <button class="nav-btn changes" onclick="showSection('changes')">📝 История изменений</button>
                <button class="nav-btn" onclick="showSection('details')">📋 Детали</button>
            </div>
        </div>
        
        <div class="content">
            <!-- Секция обзора -->
            <div id="overview" class="section active">
                <h3>📊 Текущее состояние системы</h3>
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number">{total_connections}</div>
                        <div class="stat-label">Всего соединений</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(incoming)}</div>
                        <div class="stat-label">Входящих</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(outgoing)}</div>
                        <div class="stat-label">Исходящих</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(unique_processes)}</div>
                        <div class="stat-label">Уникальных процессов</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(unique_hosts)}</div>
                        <div class="stat-label">Удаленных хостов</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(tcp_ports) if isinstance(tcp_ports, list) else len(tcp_ports.get('tcp_simple', []))}</div>
                        <div class="stat-label">TCP портов</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(udp_ports) if isinstance(udp_ports, list) else len(udp_ports.get('udp_simple', []))}</div>
                        <div class="stat-label">UDP портов</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{changes_summary.get('total_change_events', 0)}</div>
                        <div class="stat-label">Событий изменений</div>
                    </div>
                </div>
                
                <h4>📈 Статистика изменений</h4>
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number">{len(changes_summary.get('categories_changed', []))}</div>
                        <div class="stat-label">Категорий изменялось</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{changes_summary.get('most_active_category', 'N/A')}</div>
                        <div class="stat-label">Самая активная категория</div>
                    </div>
                </div>
            </div>
            
            <!-- Секция соединений -->
            <div id="connections" class="section">
                <h3>🔗 Активные соединения (TCP + UDP)</h3>
                <table class="connections-table">
                    <thead>
                        <tr>
                            <th>Тип</th>
                            <th>Локальный адрес</th>
                            <th>Удаленный адрес</th>
                            <th>Процесс</th>
                            <th>Протокол</th>
                            <th>Последний раз</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    # Добавляем соединения (TCP + UDP)
    all_connections = incoming + outgoing
    for conn in all_connections[:30]:  # Первые 30 соединений
        conn_type = "📥 Входящее" if conn in incoming else "📤 Исходящее"
        remote_addr = conn.get('remote', {}).get('address', 'unknown')
        last_seen = conn.get('last_seen', 'unknown')
        protocol = conn.get('protocol', 'unknown').upper()
        protocol_class = f"protocol-{protocol.lower()}"
        
        html_content += f"""
                        <tr>
                            <td>{conn_type}</td>
                            <td>{conn.get('local', 'unknown')}</td>
                            <td>{remote_addr}</td>
                            <td>{conn.get('process', 'unknown')}</td>
                            <td><span class="{protocol_class}">{protocol}</span></td>
                            <td>{last_seen}</td>
                        </tr>
        """
    
    html_content += """
                    </tbody>
                </table>
            </div>
            
            <!-- Секция портов -->
            <div id="ports" class="section">
                <h3>🚪 Прослушиваемые порты</h3>
                <h4>TCP порты:</h4>
                <div class="ports-grid">
    """
    
    # Добавляем TCP порты
    tcp_ports_data = data.get('listen_ports', {}).get('tcp', [])
    if isinstance(tcp_ports_data, list) and tcp_ports_data and isinstance(tcp_ports_data[0], dict):
        for port_info in tcp_ports_data:
            html_content += f"""
                    <div class="port-item">
                        <div class="port-number">{port_info.get('port', 'unknown')}</div>
                        <div class="port-desc">{port_info.get('description', 'Нет описания')}</div>
                    </div>
            """
    else:
        simple_tcp = data.get('listen_ports', {}).get('tcp_simple', tcp_ports_data)
        for port in simple_tcp:
            html_content += f"""
                    <div class="port-item">
                        <div class="port-number">{port}</div>
                        <div class="port-desc">{get_port_description(port)}</div>
                    </div>
            """
    
    html_content += """
                </div>
                <h4>UDP порты:</h4>
                <div class="ports-grid">
    """
    
    # Добавляем UDP порты
    udp_ports_data = data.get('listen_ports', {}).get('udp', [])
    if isinstance(udp_ports_data, list) and udp_ports_data and isinstance(udp_ports_data[0], dict):
        for port_info in udp_ports_data:
            html_content += f"""
                    <div class="port-item">
                        <div class="port-number">{port_info.get('port', 'unknown')}</div>
                        <div class="port-desc">{port_info.get('description', 'Нет описания')}</div>
                    </div>
            """
    else:
        simple_udp = data.get('listen_ports', {}).get('udp_simple', udp_ports_data)
        for port in simple_udp:
            html_content += f"""
                    <div class="port-item">
                        <div class="port-number">{port}</div>
                        <div class="port-desc">{get_port_description(port)}</div>
                    </div>
            """
    
    # Добавляем секцию сетевой активности
    network_stats = data.get('network_stats', {})
    html_content += """
                </div>
            </div>
            
            <!-- Секция сетевой активности -->
            <div id="network" class="section">
                <h3>📡 Сетевая активность</h3>
    """
    
    if network_stats:
        html_content += '<div class="network-stats-grid">'
        
        for interface, stats in list(network_stats.items())[:10]:
            if stats.get('packets_in', 0) > 0 or stats.get('packets_out', 0) > 0:
                html_content += f"""
                    <div class="interface-card">
                        <div class="interface-name">{interface}</div>
                        <div class="interface-stats">
                            <div class="interface-stat">
                                <div class="interface-stat-value">{stats.get('packets_in', 0):,}</div>
                                <div class="interface-stat-label">Пакеты входящие</div>
                            </div>
                            <div class="interface-stat">
                                <div class="interface-stat-value">{stats.get('packets_out', 0):,}</div>
                                <div class="interface-stat-label">Пакеты исходящие</div>
                            </div>
                            <div class="interface-stat">
                                <div class="interface-stat-value">{stats.get('bytes_in', 0):,}</div>
                                <div class="interface-stat-label">Байты входящие</div>
                            </div>
                            <div class="interface-stat">
                                <div class="interface-stat-value">{stats.get('bytes_out', 0):,}</div>
                                <div class="interface-stat-label">Байты исходящие</div>
                            </div>
                        </div>
                    </div>
                """
        
        html_content += '</div>'
    else:
        html_content += """
                <div class="warning">
                    ⚠️ Данные о сетевой активности недоступны. Для получения полной информации запустите Glacier с правами администратора: <code>sudo python3 src/glacier.py</code>
                </div>
        """
    
    # Добавляем секцию истории изменений
    html_content += """
            </div>
            
            <!-- Секция истории изменений -->
            <div id="changes" class="section">
                <h3>📝 История изменений</h3>
    """
    
    if recent_changes:
        html_content += '<div class="changes-timeline">'
        
        for change in reversed(recent_changes[-10:]):  # Последние 10 изменений в обратном порядке
            timestamp = change.get('timestamp', 'unknown')
            measurement_id = change.get('measurement_id', 'unknown')
            changes_dict = change.get('changes', {})
            is_first_run = change.get('is_first_run', False)
            
            if is_first_run:
                change_type = "🚀 Первый запуск"
                change_desc = "Инициализация системы мониторинга"
            else:
                change_type = "🔄 Обновление"
                change_categories = list(changes_dict.keys())
                change_desc = f"Изменения в категориях: {', '.join(change_categories)}"
            
            html_content += f"""
                <div class="change-item">
                    <div class="change-timestamp">
                        {change_type} #{measurement_id} - {timestamp}
                    </div>
                    <div class="change-details">
                        {change_desc}
                    </div>
                </div>
            """
        
        html_content += '</div>'
    else:
        html_content += """
                <div class="warning">
                    ℹ️ История изменений пуста. Изменения будут отображаться после нескольких запусков анализатора.
                </div>
        """
    
    # Добавляем секцию деталей
    html_content += """
            </div>
            
            <!-- Секция деталей -->
            <div id="details" class="section">
                <h3>📋 Технические детали</h3>
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number">{total_measurements}</div>
                        <div class="stat-label">Всего измерений</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{data.get('os', {}).get('name', 'unknown')}</div>
                        <div class="stat-label">Операционная система</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(data.get('network_stats', {}))}</div>
                        <div class="stat-label">Сетевых интерфейсов</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{len(data.get('interfaces', {}))}</div>
                        <div class="stat-label">Настроенных интерфейсов</div>
                    </div>
                </div>
    """
    
    # Добавляем информацию о UDP трафике если есть
    if udp_traffic and udp_traffic.get('total_connections', 0) > 0:
        html_content += f"""
                <h4>📡 UDP трафик</h4>
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number">{udp_traffic.get('total_connections', 0)}</div>
                        <div class="stat-label">UDP соединений</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{udp_traffic.get('total_remote_hosts', 0)}</div>
                        <div class="stat-label">Удаленных хостов</div>
                    </div>
                </div>
        """
    
    html_content += f"""
            </div>
        </div>
        
        <div class="footer">
            <p>Кумулятивный отчет обновлен {datetime.now().strftime('%d.%m.%Y в %H:%M:%S')} | Анализатор системы v2.1</p>
            <p>💡 Используйте кнопки навигации для переключения между разделами</p>
            <p>📊 Всего измерений: {total_measurements} | 🔄 Последнее обновление: {last_update}</p>
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
            const cards = document.querySelectorAll('.stat-card, .port-item, .interface-card, .change-item');
            cards.forEach((card, index) => {{
                card.style.opacity = '0';
                card.style.transform = 'translateY(20px)';
                setTimeout(() => {{
                    card.style.transition = 'all 0.5s ease';
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }}, index * 50);
            }});
        }});
    </script>
</body>
</html>
    """
    
    # Записываем файл с фиксированным именем (без timestamp)
    with open(html_filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return html_filename