import socket
import psutil
import time
from datetime import datetime
from analyzer_utils import execute_command

def format_timestamp(timestamp):
    """Форматирует timestamp в человекочитаемый вид"""
    try:
        return datetime.fromtimestamp(timestamp).strftime("%d.%m.%Y %H:%M:%S")
    except (ValueError, TypeError):
        return str(timestamp)

def get_process_details(pid):
    """Получает детальную информацию о процессе"""
    try:
        if pid is None or pid <= 0:
            return "unknown", "unknown"
            
        proc = psutil.Process(pid)
        proc_name = proc.name()
        
        # Пытаемся получить более детальную информацию
        try:
            proc_exe = proc.exe()
            if proc_exe:
                # Извлекаем имя из полного пути
                import os
                proc_name = os.path.basename(proc_exe)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        # Пытаемся получить командную строку для лучшей идентификации
        try:
            cmdline = proc.cmdline()
            if cmdline and len(cmdline) > 1:
                # Если это скрипт Python, Java и т.д., показываем что именно запущено
                if 'python' in proc_name.lower() and len(cmdline) > 1:
                    script_name = cmdline[1]
                    if script_name.endswith('.py'):
                        import os
                        proc_name = f"python({os.path.basename(script_name)})"
                elif 'java' in proc_name.lower() and len(cmdline) > 1:
                    # Ищем класс или jar файл
                    for arg in cmdline[1:]:
                        if arg.endswith('.jar'):
                            import os
                            proc_name = f"java({os.path.basename(arg)})"
                            break
                        elif not arg.startswith('-') and '.' in arg:
                            proc_name = f"java({arg.split('.')[-1]})"
                            break
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        return proc_name, "identified"
        
    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, TypeError):
        return "unknown", "no_access"

def get_process_name_by_port(port, protocol='tcp'):
    """Получает имя процесса по порту через lsof (для macOS)"""
    try:
        import platform
        if platform.system() == 'Darwin':
            # Используем lsof для получения процесса по порту
            cmd = ['lsof', '-i', f'{protocol}:{port}', '-n']
            result = execute_command(cmd)
            
            for line in result:
                if line.strip() and not line.startswith('COMMAND'):
                    parts = line.split()
                    if len(parts) >= 2:
                        process_name = parts[0]
                        pid = parts[1]
                        
                        # Пытаемся получить более детальную информацию
                        detailed_name, status = get_process_details(int(pid) if pid.isdigit() else None)
                        if status == "identified":
                            return detailed_name
                        return process_name
        
        return "unknown"
    except Exception:
        return "unknown"

def filter_unique_connections(stored_connections, l_addr, l_port, r_addr, r_port, type_conn, protocol):
    """
    Проверяет наличие соединения в хранилище и добавляет его, если оно новое
    Возвращает True, если соединение новое, False если оно уже было обнаружено ранее
    """
    if type_conn == 'incoming':
        connect_key = f'''{l_addr}:{l_port}-{r_addr}:{protocol}'''
    else:
        connect_key = f'''{l_addr}-{r_addr}:{r_port}:{protocol}'''
    
    # Проверяем размер хранилища и очищаем самые старые записи при необходимости
    if len(stored_connections) > 10000:  # Увеличиваем лимит, но контролируем его
        # Удаляем 20% самых старых записей
        keys_to_delete = sorted(stored_connections.keys(), 
                                key=lambda k: stored_connections[k].get('last_seen', 0))[:2000]
        for key in keys_to_delete:
            del stored_connections[key]
    
    current_time = time.time()
    
    if connect_key not in stored_connections:
        # Новое соединение - добавляем его
        stored_connections[connect_key] = {
            'first_seen': current_time,
            'last_seen': current_time,
            'type': type_conn,
            'protocol': protocol,
            'count': 1
        }
        is_new = True
    else:
        # Уже видели это соединение - обновляем timestamp и счетчик
        stored_connections[connect_key]['last_seen'] = current_time
        stored_connections[connect_key]['count'] += 1
        is_new = False

    return is_new, connect_key

def finalize_result(networks, snapshot_connections, outgoing_ports, local_addresses, except_local: bool):
    # Используем соединения со статусом ESTABLISHED для TCP, все UDP соединения с удаленным адресом и ICMP соединения
    open_connections = list(set(snapshot_connections['connections_all']))
    
    # Инициализируем структуру для накапливания соединений, если её ещё нет
    if 'stored_connections' not in networks:
        networks['stored_connections'] = {}
        
    stored_connections = networks['stored_connections']
    
    # Инициализируем или получаем существующие списки для текущего отчета
    if 'connections' not in networks:
        current_connections = {"incoming": [], "outgoing": []}
    else:
        current_connections = networks['connections']
        # Очищаем текущие соединения для этого отчета (но не историю)
        current_connections["incoming"] = []
        current_connections["outgoing"] = []

    if 'remote' not in networks:
        current_remote = {}
    else:
        current_remote = networks['remote']
        # Очищаем текущий список удаленных адресов (но не историю)
        current_remote.clear()

    # Рабочий набор соединений (не более 100)
    max_connections = 100
    if len(open_connections) > max_connections:
        open_connections = open_connections[:max_connections]

    # Счетчики для отладки
    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    for conn in open_connections:
        # Для TCP проверяем статус ESTABLISHED
        if conn.type == socket.SOCK_STREAM and conn.status != psutil.CONN_ESTABLISHED:
            continue
        # Для UDP обрабатываем как соединения с удаленным адресом, так и listening порты
        elif conn.type == socket.SOCK_DGRAM:
            # UDP соединения обрабатываем всегда (и с удаленным адресом, и без него)
            pass
        # Для ICMP (raw сокеты) обрабатываем всегда
        elif conn.type == socket.SOCK_RAW:
            # ICMP соединения обрабатываем всегда
            pass
            
        conn_type = conn.type

        # Обрабатываем локальный адрес
        if hasattr(conn, 'laddr') and conn.laddr:
            conn_local_addr = conn.laddr.ip
            conn_local_port = conn.laddr.port if hasattr(conn.laddr, 'port') else 0
        else:
            conn_local_addr = "0.0.0.0"
            conn_local_port = 0
        
        conn_local_full = f'{conn_local_addr}:{conn_local_port}'

        # Обрабатываем удаленный адрес
        if hasattr(conn, 'raddr') and conn.raddr:
            # Есть удаленный адрес - это реальное соединение
            conn_remote_addr = conn.raddr.ip
            conn_remote_port = conn.raddr.port if hasattr(conn.raddr, 'port') else 0
            conn_remote_full = f'{conn_remote_addr}:{conn_remote_port}'
        else:
            # Нет удаленного адреса - это listening порт или ICMP
            if conn.type == socket.SOCK_DGRAM:
                # Для UDP портов создаем псевдо-соединение
                conn_remote_addr = "0.0.0.0"  # Псевдо-адрес для listening UDP
                conn_remote_port = 0
                conn_remote_full = f"*:* (UDP listening on {conn_local_port})"
            elif conn.type == socket.SOCK_RAW:
                # Для ICMP создаем псевдо-соединение
                conn_remote_addr = "*"
                conn_remote_port = 0
                conn_remote_full = f"*:* (ICMP raw socket)"
            else:
                # Для TCP без удаленного адреса пропускаем
                continue

        if conn_local_port <= outgoing_ports:
            type_conn = 'incoming'  # Локальные порты ≤ 1024 обычно серверные (принимают входящие соединения)
        else:
            type_conn = 'outgoing'  # Локальные порты > 1024 обычно клиентские (инициируют исходящие соединения)

        # Определяем протокол
        if conn_type == socket.SOCK_DGRAM:
            protocol = 'udp'
            udp_count += 1
        elif conn_type == socket.SOCK_RAW:
            protocol = 'icmp'
            icmp_count += 1
        else:
            protocol = 'tcp'
            tcp_count += 1

        # Проверяем, новое ли это соединение и получаем его ключ
        is_new, conn_key = filter_unique_connections(
            stored_connections, conn_local_addr, conn_local_port, conn_remote_addr, conn_remote_port, type_conn, protocol)
            
        # Для новых соединений или для обновления данных существующих
        if is_new or time.time() - stored_connections[conn_key].get('info_updated', 0) > 3600:
            try:
                # Проверяем, что у нас есть валидный IP адрес
                if hasattr(conn, 'raddr') and conn.raddr and hasattr(conn.raddr, 'ip'):
                    remote_hostname = socket.gethostbyaddr(conn.raddr.ip)
                else:
                    # Для UDP listening портов и ICMP
                    if protocol == 'udp' and not (hasattr(conn, 'raddr') and conn.raddr):
                        remote_hostname = ["UDP_LISTENING"]
                    elif protocol == 'icmp':
                        remote_hostname = ["ICMP_RAW"]
                    else:
                        remote_hostname = ["unknown"]
            except (socket.herror, socket.gaierror, AttributeError):
                remote_hostname = ["unknown"]

            conn_pid = getattr(conn, 'pid', None)
            
            # Улучшенная идентификация процесса
            conn_proc_name, proc_status = get_process_details(conn_pid)
            
            # Если не удалось получить через PID, пробуем через порт (только для TCP/UDP)
            if (proc_status == "no_access" or conn_proc_name == "unknown") and protocol != 'icmp':
                port_based_name = get_process_name_by_port(conn_local_port, protocol)
                if port_based_name != "unknown":
                    conn_proc_name = port_based_name
            elif protocol == 'icmp' and conn_proc_name == "unknown":
                # Для ICMP обычно это kernel процессы
                conn_proc_name = "kernel/system"

            conn_info = {
                "local": conn_local_full,
                "remote": {"name": remote_hostname[0], "address": conn_remote_full},
                "process": conn_proc_name,
                "protocol": protocol,
                "first_seen": format_timestamp(stored_connections[conn_key]['first_seen']),
                "last_seen": format_timestamp(stored_connections[conn_key]['last_seen']),
                "count": stored_connections[conn_key]['count']
            }
            
            # Сохраняем информацию о соединении
            stored_connections[conn_key]['info'] = conn_info
            stored_connections[conn_key]['info_updated'] = time.time()
            
            # Сохраняем информацию о хосте (только для реальных удаленных адресов)
            if (hasattr(conn, 'raddr') and conn.raddr and hasattr(conn.raddr, 'ip') and 
                (conn_remote_addr not in local_addresses or not except_local)):
                info_remote = {"name": remote_hostname[0], 'type': type_conn}
                if type_conn == "outgoing":
                    info_remote['port'] = conn_remote_port
                else:
                    info_remote['port'] = conn_local_port
                
                # Обновляем информацию о хосте в хранилище и для текущего отчета
                current_remote[conn_remote_addr] = info_remote
        
        # Добавляем соединение в текущий отчет, даже если оно не новое
        if conn_key in stored_connections and 'info' in stored_connections[conn_key]:
            # Для UDP listening портов и ICMP добавляем всегда, для остальных проверяем локальность
            if (protocol in ['udp', 'icmp'] and not (hasattr(conn, 'raddr') and conn.raddr)) or \
               ((hasattr(conn, 'raddr') and conn.raddr and hasattr(conn.raddr, 'ip')) and 
                (conn_remote_addr not in local_addresses or not except_local)):
                current_connections[type_conn].append(stored_connections[conn_key]['info'])

    # Обрабатываем TCP, UDP и ICMP порты
    join_ports(snapshot_connections, networks, 'tcp')
    join_ports(snapshot_connections, networks, 'udp')
    
    # Добавляем поддержку ICMP портов (псевдо-порты для raw сокетов)
    if 'icmp' in snapshot_connections:
        if 'icmp' not in networks:
            networks['icmp'] = []
        # Для ICMP сохраняем информацию о количестве raw сокетов
        networks['icmp'] = len(snapshot_connections['icmp'])

    # Добавляем все сохраненные соединения в отчет
    # Ограничиваем количество соединений в отчете
    for conn_type in ['incoming', 'outgoing']:
        # Если в текущем отчете мало соединений, добавляем из истории
        if len(current_connections[conn_type]) < 20:
            # Добавляем соединения из истории, отсортированные по последнему времени наблюдения
            conn_history = []
            for conn_key, conn_data in stored_connections.items():
                if conn_data.get('type') == conn_type and 'info' in conn_data:
                    conn_history.append(conn_data['info'])
            
            # Сортируем по последнему наблюдению (в обратном порядке)
            conn_history.sort(key=lambda x: x.get('last_seen', 0), reverse=True)
            
            # Добавляем в текущий отчет, но не больше 50 соединений
            for conn_info in conn_history[:50]:
                if conn_info not in current_connections[conn_type]:
                    current_connections[conn_type].append(conn_info)

    # Обновляем текущие данные для отчёта
    networks['connections'] = current_connections
    networks['remote'] = current_remote

    print(f"🔍 Финальная обработка: TCP соединений: {tcp_count}, UDP соединений: {udp_count}, ICMP соединений: {icmp_count}")

    return networks

def join_ports(current_ports, networks, type_of_port):
    if type_of_port not in networks:
        networks[type_of_port] = []
    
    # Сохраняем уже имеющиеся порты
    existing_ports = set(networks[type_of_port])
    
    # Добавляем новые порты
    for p in current_ports[type_of_port]:
        if p not in existing_ports:
            networks[type_of_port].append(p)
            existing_ports.add(p)
    
    # Сортируем список портов
    networks[type_of_port].sort()
    
    # Ограничиваем количество портов в отчете
    if len(networks[type_of_port]) > 200:
        networks[type_of_port] = networks[type_of_port][:200]

def get_connections_alternative_macos():
    """Альтернативный метод получения активных соединений для macOS через lsof"""
    connections = []
    tcp_ports = []
    udp_ports = []
    
    try:
        from analyzer_utils import execute_command
        
        # Получаем все сетевые соединения через lsof
        result = execute_command(['lsof', '-i', '-n'])
        
        # Объединяем многострочные записи
        combined_lines = []
        current_line = ""
        
        for line in result[1:]:  # Пропускаем заголовок
            if line.strip():
                # Если строка начинается с пробела, это продолжение предыдущей строки
                if line.startswith(' ') or line.startswith('\t') or line.startswith('->'):
                    current_line += " " + line.strip()
                else:
                    if current_line:
                        combined_lines.append(current_line)
                    current_line = line.strip()
        
        # Добавляем последнюю строку
        if current_line:
            combined_lines.append(current_line)
        
        print(f"🔍 Обрабатываем {len(combined_lines)} строк lsof")
        
        for line in combined_lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 8:
                    process = parts[0]
                    pid = parts[1]
                    user = parts[2]
                    protocol_info = parts[7] if len(parts) > 7 else ''
                    node_info = ' '.join(parts[8:]) if len(parts) > 8 else ''  # Объединяем все части после 8-й
                    
                    print(f"🔍 Парсим: {process} {protocol_info} {node_info}")
                    
                    # Парсим TCP соединения
                    if 'TCP' in protocol_info:
                        if 'LISTEN' in line:
                            # LISTEN порт
                            if ':' in node_info:
                                try:
                                    port_str = node_info.split(':')[-1].split()[0]  # Берем первую часть после :
                                    port_str = port_str.split('(')[0].strip()
                                    port = int(port_str)
                                    if port not in tcp_ports:
                                        tcp_ports.append(port)
                                        print(f"✅ TCP порт: {port}")
                                except (ValueError, IndexError):
                                    continue
                        elif '->' in node_info:
                            # Активное соединение
                            try:
                                # Ищем паттерн local->remote
                                arrow_pos = node_info.find('->')
                                if arrow_pos > 0:
                                    local_part = node_info[:arrow_pos].strip()
                                    remote_part = node_info[arrow_pos+2:].strip()
                                    
                                    # Убираем статус соединения из remote_part
                                    if '(' in remote_part:
                                        remote_part = remote_part.split('(')[0].strip()
                                    
                                    print(f"✅ TCP соединение: {local_part} -> {remote_part}")
                                    
                                    # Создаем псевдо-объект соединения
                                    class MockConnection:
                                        def __init__(self, local_addr, remote_addr, conn_type, status, pid):
                                            self.laddr = MockAddr(local_addr)
                                            self.raddr = MockAddr(remote_addr) if remote_addr else None
                                            self.type = conn_type
                                            self.status = status
                                            self.pid = int(pid) if pid.isdigit() else None
                                    
                                    class MockAddr:
                                        def __init__(self, addr_str):
                                            # Обработка IPv6 адресов в квадратных скобках
                                            if addr_str.startswith('[') and ']:' in addr_str:
                                                # IPv6 адрес в формате [IPv6]:port
                                                bracket_end = addr_str.find(']:')
                                                self.ip = addr_str[1:bracket_end]  # Убираем квадратные скобки
                                                port_str = addr_str[bracket_end+2:]
                                                # Если порт - это имя сервиса, пытаемся преобразовать
                                                try:
                                                    self.port = int(port_str)
                                                except ValueError:
                                                    # Стандартные порты для известных сервисов
                                                    port_map = {
                                                        'https': 443, 'http': 80, 'ssh': 22,
                                                        'imaps': 993, 'imap': 143, 'smtp': 25,
                                                        'pop3': 110, 'pop3s': 995, 'ftp': 21
                                                    }
                                                    self.port = port_map.get(port_str, 0)
                                            elif ':' in addr_str and not addr_str.startswith('['):
                                                # IPv4 адрес в формате IP:port
                                                parts = addr_str.rsplit(':', 1)
                                                self.ip = parts[0]
                                                port_str = parts[1]
                                                # Если порт - это имя сервиса, пытаемся преобразовать
                                                try:
                                                    self.port = int(port_str)
                                                except ValueError:
                                                    # Стандартные порты для известных сервисов
                                                    port_map = {
                                                        'https': 443, 'http': 80, 'ssh': 22,
                                                        'imaps': 993, 'imap': 143, 'smtp': 25,
                                                        'pop3': 110, 'pop3s': 995, 'ftp': 21
                                                    }
                                                    self.port = port_map.get(port_str, 0)
                                            else:
                                                # Только IP адрес без порта
                                                self.ip = addr_str.strip('[]')  # Убираем скобки если есть
                                                self.port = 0
                                    
                                    conn = MockConnection(
                                        local_part, 
                                        remote_part, 
                                        socket.SOCK_STREAM,  # TCP
                                        psutil.CONN_ESTABLISHED,
                                        pid
                                    )
                                    connections.append(conn)
                                    
                            except (ValueError, IndexError) as e:
                                print(f"⚠️ Ошибка парсинга TCP: {e}")
                                continue
                    
                    # Парсим UDP соединения
                    elif 'UDP' in protocol_info:
                        if ':' in node_info and '*:*' not in node_info:
                            try:
                                # Для UDP портов
                                if '->' not in node_info:
                                    # Это UDP порт без удаленного адреса
                                    port_str = node_info.split(':')[-1].split()[0]
                                    port_str = port_str.split('(')[0].strip()
                                    if port_str != '*':
                                        try:
                                            port = int(port_str)
                                        except ValueError:
                                            # Обрабатываем имена сервисов
                                            port_map = {
                                                'mdns': 5353, 'dns': 53, 'dhcp': 67,
                                                'bootps': 67, 'bootpc': 68, 'ntp': 123,
                                                'snmp': 161, 'syslog': 514, 'tftp': 69
                                            }
                                            port = port_map.get(port_str, 0)
                                        
                                        if port > 0 and port not in udp_ports:
                                            udp_ports.append(port)
                                            print(f"✅ UDP порт: {port} ({port_str})")
                                            
                                            # Создаем псевдо-соединение для UDP порта (как listening)
                                            # Это поможет показать UDP активность в отчете
                                            local_addr = node_info.split(':')[0] if ':' in node_info else '*'
                                            if local_addr == '*':
                                                local_addr = '0.0.0.0'
                                            
                                            class MockConnection:
                                                def __init__(self, local_addr, local_port, conn_type, status, pid):
                                                    self.laddr = MockAddr(f"{local_addr}:{local_port}")
                                                    self.raddr = None  # UDP порт без удаленного адреса
                                                    self.type = conn_type
                                                    self.status = status
                                                    self.pid = int(pid) if pid.isdigit() else None
                                            
                                            class MockAddr:
                                                def __init__(self, addr_str):
                                                    # Обработка IPv6 адресов в квадратных скобках
                                                    if addr_str.startswith('[') and ']:' in addr_str:
                                                        # IPv6 адрес в формате [IPv6]:port
                                                        bracket_end = addr_str.find(']:')
                                                        self.ip = addr_str[1:bracket_end]  # Убираем квадратные скобки
                                                        port_str = addr_str[bracket_end+2:]
                                                        # Если порт - это имя сервиса, пытаемся преобразовать
                                                        try:
                                                            self.port = int(port_str)
                                                        except ValueError:
                                                            # Стандартные порты для известных сервисов
                                                            port_map = {
                                                                'https': 443, 'http': 80, 'ssh': 22,
                                                                'imaps': 993, 'imap': 143, 'smtp': 25,
                                                                'pop3': 110, 'pop3s': 995, 'ftp': 21
                                                            }
                                                            self.port = port_map.get(port_str, 0)
                                                    elif ':' in addr_str and not addr_str.startswith('['):
                                                        # IPv4 адрес в формате IP:port
                                                        parts = addr_str.rsplit(':', 1)
                                                        self.ip = parts[0]
                                                        port_str = parts[1]
                                                        # Если порт - это имя сервиса, пытаемся преобразовать
                                                        try:
                                                            self.port = int(port_str)
                                                        except ValueError:
                                                            # Стандартные порты для известных сервисов
                                                            port_map = {
                                                                'https': 443, 'http': 80, 'ssh': 22,
                                                                'imaps': 993, 'imap': 143, 'smtp': 25,
                                                                'pop3': 110, 'pop3s': 995, 'ftp': 21
                                                            }
                                                            self.port = port_map.get(port_str, 0)
                                                    else:
                                                        # Только IP адрес без порта
                                                        self.ip = addr_str.strip('[]')  # Убираем скобки если есть
                                                        self.port = 0
                                            
                                            # Создаем UDP "соединение" для порта
                                            conn = MockConnection(
                                                local_addr, 
                                                port, 
                                                socket.SOCK_DGRAM,  # UDP
                                                None,  # UDP не имеет статуса LISTEN
                                                pid
                                            )
                                            # Добавляем UDP порт как псевдо-соединение для отображения в отчете
                                            connections.append(conn)
                                else:
                                    # UDP соединение с удаленным адресом
                                    arrow_pos = node_info.find('->')
                                    if arrow_pos > 0:
                                        local_part = node_info[:arrow_pos].strip()
                                        remote_part = node_info[arrow_pos+2:].strip()
                                        
                                        if '(' in remote_part:
                                            remote_part = remote_part.split('(')[0].strip()
                                        
                                        print(f"✅ UDP соединение: {local_part} -> {remote_part}")
                                        
                                        class MockConnection:
                                            def __init__(self, local_addr, remote_addr, conn_type, status, pid):
                                                self.laddr = MockAddr(local_addr)
                                                self.raddr = MockAddr(remote_addr) if remote_addr else None
                                                self.type = conn_type
                                                self.status = status
                                                self.pid = int(pid) if pid.isdigit() else None
                                        
                                        class MockAddr:
                                            def __init__(self, addr_str):
                                                # Обработка IPv6 адресов в квадратных скобках
                                                if addr_str.startswith('[') and ']:' in addr_str:
                                                    # IPv6 адрес в формате [IPv6]:port
                                                    bracket_end = addr_str.find(']:')
                                                    self.ip = addr_str[1:bracket_end]  # Убираем квадратные скобки
                                                    port_str = addr_str[bracket_end+2:]
                                                    # Если порт - это имя сервиса, пытаемся преобразовать
                                                    try:
                                                        self.port = int(port_str)
                                                    except ValueError:
                                                        # Стандартные порты для известных сервисов
                                                        port_map = {
                                                            'https': 443, 'http': 80, 'ssh': 22,
                                                            'imaps': 993, 'imap': 143, 'smtp': 25,
                                                            'pop3': 110, 'pop3s': 995, 'ftp': 21
                                                        }
                                                        self.port = port_map.get(port_str, 0)
                                                elif ':' in addr_str and not addr_str.startswith('['):
                                                    # IPv4 адрес в формате IP:port
                                                    parts = addr_str.rsplit(':', 1)
                                                    self.ip = parts[0]
                                                    port_str = parts[1]
                                                    # Если порт - это имя сервиса, пытаемся преобразовать
                                                    try:
                                                        self.port = int(port_str)
                                                    except ValueError:
                                                        # Стандартные порты для известных сервисов
                                                        port_map = {
                                                            'https': 443, 'http': 80, 'ssh': 22,
                                                            'imaps': 993, 'imap': 143, 'smtp': 25,
                                                            'pop3': 110, 'pop3s': 995, 'ftp': 21
                                                        }
                                                        self.port = port_map.get(port_str, 0)
                                                else:
                                                    # Только IP адрес без порта
                                                    self.ip = addr_str.strip('[]')  # Убираем скобки если есть
                                                    self.port = 0
                                        
                                        conn = MockConnection(
                                            local_part, 
                                            remote_part, 
                                            socket.SOCK_DGRAM,  # UDP
                                            None,  # UDP не имеет статуса
                                            pid
                                        )
                                        connections.append(conn)
                                        
                            except (ValueError, IndexError) as e:
                                print(f"⚠️ Ошибка парсинга UDP: {e}")
                                continue
        
        print(f"✅ Получено через lsof: {len(connections)} соединений, {len(tcp_ports)} TCP портов, {len(udp_ports)} UDP портов")
        
        return {
            'connections_all': connections,
            'tcp': tcp_ports,
            'udp': udp_ports
        }
        
    except Exception as e:
        print(f"⚠️ lsof метод для соединений не сработал: {e}")
        return {
            'connections_all': [],
            'tcp': [],
            'udp': []
        }

def get_current_connections(except_ipv6):
    if except_ipv6:
        mode = "inet4"
    else:
        mode = "inet"

    open_connections = []
    listen_ports = []
    udp_ports = []
    icmp_connections = []  # Новый список для ICMP соединений
    psutil_worked = False

    try:
        # Get all my connections
        connections = psutil.net_connections(kind=mode)
        psutil_worked = True
        for connection in connections:
            # Для TCP добавляем только соединения со статусом ESTABLISHED
            # Для UDP добавляем все соединения с удаленным адресом (так как UDP не имеет статуса ESTABLISHED)
            # Для ICMP добавляем raw сокеты
            if (connection.status == psutil.CONN_ESTABLISHED or 
                (connection.type == socket.SOCK_DGRAM and connection.raddr) or
                connection.type == socket.SOCK_RAW):  # Добавлена поддержка ICMP
                open_connections.append(connection)
                
                # Отдельно отслеживаем ICMP соединения
                if connection.type == socket.SOCK_RAW:
                    icmp_connections.append(connection)

            # filter to get only ports equal to LISTEN
            if connection.status == psutil.CONN_LISTEN:
                listen_ports.append(connection.laddr.port)

            # filter udp ports (только локальные порты без удаленного адреса)
            if connection.type == socket.SOCK_DGRAM and not connection.raddr:
                udp_ports.append(connection.laddr.port)
                
    except (psutil.AccessDenied, PermissionError) as e:
        print(f"⚠️ Недостаточно прав для получения сетевых соединений: {e}")
        print(f"💡 Для полного анализа запустите с правами администратора: sudo python3 src/glacier.py")
        
        # Пытаемся получить хотя бы базовую информацию
        try:
            # Получаем только listening порты (обычно доступно без sudo)
            connections = psutil.net_connections(kind=mode)
            for connection in connections:
                if connection.status == psutil.CONN_LISTEN:
                    listen_ports.append(connection.laddr.port)
                elif connection.type == socket.SOCK_DGRAM and not connection.raddr:
                    udp_ports.append(connection.laddr.port)
        except Exception as inner_e:
            print(f"⚠️ Не удалось получить даже базовую информацию о портах: {inner_e}")
    
    except Exception as e:
        print(f"❌ Неожиданная ошибка при получении соединений: {e}")

    # Логируем найденные ICMP соединения
    if icmp_connections:
        print(f"🔍 Найдено ICMP соединений через psutil: {len(icmp_connections)}")

    # Всегда дополняем данные альтернативным методом на macOS для получения UDP соединений
    import platform
    if platform.system() == 'Darwin':
        try:
            if psutil_worked:
                print(f"🔍 Дополняем данные альтернативным методом lsof для UDP соединений...")
            else:
                print(f"🔍 Пытаемся использовать альтернативные методы для macOS...")
            
            # Получаем данные через альтернативный метод
            alternative_result = get_connections_alternative_macos()
            
            # Интегрируем результаты в стандартную структуру
            if alternative_result.get('connections_all'):
                # Добавляем только те соединения, которых еще нет
                existing_connections = set()
                for conn in open_connections:
                    if hasattr(conn, 'laddr') and hasattr(conn, 'raddr'):
                        local_key = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown"
                        remote_key = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "none"
                        existing_connections.add(f"{local_key}->{remote_key}")
                
                new_connections = 0
                for alt_conn in alternative_result['connections_all']:
                    if hasattr(alt_conn, 'laddr') and hasattr(alt_conn, 'raddr'):
                        local_key = f"{alt_conn.laddr.ip}:{alt_conn.laddr.port}" if alt_conn.laddr else "unknown"
                        remote_key = f"{alt_conn.raddr.ip}:{alt_conn.raddr.port}" if alt_conn.raddr else "none"
                        conn_key = f"{local_key}->{remote_key}"
                        
                        if conn_key not in existing_connections:
                            open_connections.append(alt_conn)
                            new_connections += 1
                
                print(f"🔍 Интегрировано из альтернативного метода: {new_connections} новых соединений")
            
            # Дополняем порты
            for port in alternative_result.get('tcp', []):
                if port not in listen_ports:
                    listen_ports.append(port)
            
            for port in alternative_result.get('udp', []):
                if port not in udp_ports:
                    udp_ports.append(port)
                    
        except Exception as alt_e:
            print(f"⚠️ Альтернативный метод не сработал: {alt_e}")

    return {
        'connections_all': open_connections, 
        'tcp': listen_ports, 
        'udp': udp_ports,
        'icmp': icmp_connections  # Добавляем ICMP соединения в возвращаемые данные
    }

def get_ports_alternative_macos():
    """Альтернативный метод получения портов для macOS через lsof"""
    tcp_ports = []
    udp_ports = []
    
    try:
        # Используем lsof для получения всех сетевых соединений
        from analyzer_utils import execute_command
        
        # Получаем все сетевые соединения через lsof
        result = execute_command(['lsof', '-i', '-n'])
        
        for line in result[1:]:  # Пропускаем заголовок
            if line.strip():
                parts = line.split()
                if len(parts) >= 8:
                    protocol_info = parts[7] if len(parts) > 7 else ''
                    node_info = parts[8] if len(parts) > 8 else ''
                    
                    # Парсим TCP LISTEN порты
                    if 'TCP' in protocol_info and 'LISTEN' in line:
                        # Ищем порт в node_info (формат: *:port или ip:port)
                        if ':' in node_info:
                            try:
                                port_str = node_info.split(':')[-1]
                                # Убираем возможные дополнительные символы
                                port_str = port_str.split('(')[0].strip()
                                port = int(port_str)
                                if port not in tcp_ports:
                                    tcp_ports.append(port)
                            except (ValueError, IndexError):
                                continue
                    
                    # Парсим UDP порты (все UDP соединения считаем как listening)
                    elif 'UDP' in protocol_info:
                        if ':' in node_info and '*:*' not in node_info:
                            try:
                                port_str = node_info.split(':')[-1]
                                port_str = port_str.split('(')[0].strip()
                                port = int(port_str)
                                if port not in udp_ports:
                                    udp_ports.append(port)
                            except (ValueError, IndexError):
                                continue
        
        print(f"✅ Получено через lsof: TCP портов: {len(tcp_ports)}, UDP портов: {len(udp_ports)}")
        
    except Exception as e:
        print(f"⚠️ lsof метод не сработал: {e}")
        # Возвращаем хотя бы стандартные порты
        tcp_ports = [22, 80, 443, 5000]
        udp_ports = [53, 67, 68]
        print(f"🔧 Используем стандартные порты для демонстрации")
    
    return tcp_ports, udp_ports

def get_connections(networks: dict, outgoing_ports, local_address, except_ipv6: bool, except_local: bool):
    # Проверяем инициализацию структур
    if 'stored_connections' not in networks:
        networks['stored_connections'] = {}
        
    snapshot_connections = get_current_connections(except_ipv6)
    
    # Если нет реальных соединений, возвращаем пустые структуры вместо демо-данных
    if not snapshot_connections['connections_all'] and not snapshot_connections['tcp'] and not snapshot_connections['udp']:
        print(f"ℹ️ Реальные соединения не обнаружены (возможно, нужны права администратора)")
        # Возвращаем пустые структуры вместо демо-данных
        networks['connections'] = {"incoming": [], "outgoing": []}
        networks['remote'] = {}
        networks['tcp'] = []
        networks['udp'] = []
        return networks
    
    # Обрабатываем соединения через finalize_result
    networks = finalize_result(networks,
                               snapshot_connections,
                               outgoing_ports,
                               local_address,
                               except_local)
    
    # Добавляем отладочную информацию о найденных соединениях
    total_connections = len(networks.get('connections', {}).get('incoming', [])) + len(networks.get('connections', {}).get('outgoing', []))
    udp_connections_count = 0
    tcp_connections_count = 0
    
    for conn_type in ['incoming', 'outgoing']:
        for conn in networks.get('connections', {}).get(conn_type, []):
            if conn.get('protocol') == 'udp':
                udp_connections_count += 1
            elif conn.get('protocol') == 'tcp':
                tcp_connections_count += 1
    
    print(f"🔍 Обработано соединений: всего {total_connections}, TCP: {tcp_connections_count}, UDP: {udp_connections_count}")
    
    # Добавляем UDP соединения из UDP трекера если доступны
    try:
        import platform
        if platform.system() == 'Darwin':
            from udp_tracker_macos import get_udp_information_macos
            udp_info = get_udp_information_macos(debug=False)
        else:
            from udp_tracker_module import get_udp_information
            udp_info = get_udp_information(debug=False)
        
        # Интегрируем UDP соединения в основную структуру
        if udp_info and udp_info.get('udp_connections'):
            print(f"🔍 Добавляем {len(udp_info['udp_connections'])} UDP соединений из трекера")
            for udp_conn in udp_info['udp_connections'][:10]:  # Ограничиваем количество
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
                        networks['connections']['outgoing'].append(conn_info)
                    else:
                        networks['connections']['incoming'].append(conn_info)
    except Exception as e:
        # Если UDP модуль недоступен, продолжаем без него
        print(f"🔍 UDP трекер недоступен: {e}")
    
    return networks

def get_interfaces(local_interfaces):
    data_interfaces = {}
    interfaces = psutil.net_if_addrs()
    for interface in interfaces.keys():
        if interface not in local_interfaces:
            # Для Linux используем /sys/class/net/, для других ОС - значение по умолчанию
            import platform
            if platform.system() == 'Linux':
                result_command = execute_command(['cat',f'/sys/class/net/{interface}/mtu'])
                if result_command:
                    try:
                        mtu = int(result_command[0])
                    except (ValueError, IndexError):
                        mtu = 1500  # значение по умолчанию
                else:
                    mtu = 1500
            else:
                # Для macOS и других ОС используем значение по умолчанию
                mtu = 1500
            
            data_interfaces[interface] = {"mtu": mtu}
    return data_interfaces

def get_routes_information():
    command = ['route','-n']
    routes = []
    result_command = execute_command(command)
    for temp_row in result_command:
        if temp_row[0].isdigit():
            routes.append(temp_row)
    return routes

def create_demo_connections():
    """Создает пустые структуры соединений (демо-данные удалены)"""
    return {"incoming": [], "outgoing": []}, {}