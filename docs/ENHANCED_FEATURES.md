# 🚀 Расширенные функции Glacier v2.3.0

Детальное описание продвинутых возможностей Glacier.

## 🔄 NetFlow v9 поддержка

### RFC 3954 соответствие
Полная реализация стандарта NetFlow Version 9:

```python
# Стандартные поля NetFlow v9
NETFLOW_V9_FIELDS = {
    'IN_BYTES': 1,          # Входящие байты
    'IN_PKTS': 2,           # Входящие пакеты  
    'PROTOCOL': 4,          # IP protocol (TCP=6, UDP=17, ICMP=1)
    'L4_SRC_PORT': 7,       # TCP/UDP source port
    'IPV4_SRC_ADDR': 8,     # IPv4 source address
    'L4_DST_PORT': 11,      # TCP/UDP destination port
    'IPV4_DST_ADDR': 12,    # IPv4 destination address
    'FIRST_SWITCHED': 22,   # First packet timestamp
    'LAST_SWITCHED': 21,    # Last packet timestamp
}
```

### Template Records
```yaml
templates:
  - template_id: 256
    field_count: 7
    field_specs:
      - {field_type: 8, field_length: 4}   # IPV4_SRC_ADDR
      - {field_type: 12, field_length: 4}  # IPV4_DST_ADDR
      - {field_type: 7, field_length: 2}   # L4_SRC_PORT
      - {field_type: 11, field_length: 2}  # L4_DST_PORT
      - {field_type: 4, field_length: 1}   # PROTOCOL
```

### Data Records
```yaml
flows:
  - flow_id: 1
    ipv4_src_addr: "192.168.1.100"
    ipv4_dst_addr: "93.184.216.34"
    l4_src_port: 54321
    l4_dst_port: 443
    protocol: 6  # TCP
    first_switched: 1735123456
    last_switched: 1735123456
```

## 📡 UDP трекинг

### Специализированные модули
- **network_info.py** — TCP/UDP соединения, процессы, порты
- **udp_tracker_{module,macos}.py** — UDP трафик, DNS
- **icmp_tracker.py** — ping, traceroute, ICMP
- **report_enhancer.py** — аналитика, группировка, метрики
- **html_report_generator.py** — HTML генерация, Chart.js

### Методы сбора UDP данных
```python
class UDPTracker:
    def get_udp_connections_ss(self):      # ss command
    def get_udp_connections_proc(self):    # /proc/net/udp
    def get_udp_connections_netstat(self): # netstat fallback
    def monitor_dns_queries(self):         # DNS мониторинг
```

### Форматы UDP записей
```yaml
udp_traffic:
  active_connections:
    - local_addr: "0.0.0.0:53"
      remote_addr: "8.8.8.8:53"
      direction: "outgoing"
      process: "systemd-resolved"
      state: "ESTABLISHED"
  dns_queries:
    - query_type: "A"
      domain: "example.com"
      response_ip: "93.184.216.34"
      timestamp: "2025-01-25 10:30:45"
```

## 🏓 ICMP мониторинг

### ICMPTracker возможности
```python
class ICMPTracker:
    def get_icmp_connections_netstat(self): # netstat ICMP
    def get_icmp_connections_proc(self):    # /proc/net/icmp
    def monitor_ping_activity(self):        # ping процессы
    def get_icmp_connections_lsof(self):    # lsof ICMP sockets
```

### ICMP статистика
```yaml
icmp_data:
  ping_statistics:
    - target: "8.8.8.8"
      packets_sent: 10
      packets_received: 10
      packet_loss: "0%"
      avg_rtt: "15.2ms"
  icmp_types:
    echo_request: 25
    echo_reply: 25
    dest_unreachable: 2
```

## 🎨 HTML отчеты

### Chart.js интеграция
```javascript
// Круговая диаграмма протоколов
new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['TCP', 'UDP', 'ICMP'],
        datasets: [{
            data: [tcp_count, udp_count, icmp_count],
            backgroundColor: ['#007bff', '#28a745', '#ffc107']
        }]
    }
});
```

### Bootstrap компоненты
- **Навигация** — 10 секций с якорными ссылками
- **Таблицы** — интерактивные с сортировкой
- **Карточки** — группировка информации
- **Прогресс-бары** — визуализация метрик

### Секции HTML отчета
1. **📈 Обзор** — диаграммы и статистика
2. **🔗 Соединения** — таблица TCP/UDP
3. **🚪 Порты** — открытые порты
4. **📡 UDP трафик** — UDP детали
5. **📝 История** — временная шкала
6. **🖥️ Хост** — системная информация
7. **💻 Система** — данные ОС
8. **📈 Статистика** — метрики
9. **🔧 О программе** — версия, конфигурация
10. **🛡️ Файрвол** — правила безопасности

## 📊 Аналитический движок

### ReportEnhancer функции
```python
class ReportEnhancer:
    def _analyze_security(self):           # Анализ безопасности
    def _analyze_network(self):            # Сетевой анализ  
    def _analyze_system_health(self):      # Здоровье системы
    def _detect_suspicious_activity(self): # Подозрительная активность
    def _group_by_cloud_provider(self):    # Облачные сервисы
```

### Метрики и инсайты
- **Топ процессы** по количеству соединений
- **Географическое распределение** соединений
- **Облачные провайдеры** (AWS, GCP, Azure)
- **Аномальная активность** (необычные порты)
- **Здоровье системы** (диски, память)

## 🔄 Кумулятивные отчеты

### Структура накопления
```yaml
hostname: server.example.com
os: {name: Linux, version: 5.4.0}
first_run: "2025-01-25 10:00:00"
last_update: "2025-01-25 11:30:00"
total_measurements: 15
total_duration: 5400  # секунды

measurements_history:
  - timestamp: "2025-01-25 10:00:00"
    duration: 45.2
    connections_count: 156
    changes_detected: 8
  - timestamp: "2025-01-25 10:30:00"
    duration: 42.8
    connections_count: 162
    changes_detected: 3

cumulative_statistics:
  total_connections: 318
  unique_processes: 25
  unique_destinations: 48
  total_changes: 11
```

### Отслеживание изменений
```yaml
changes_log:
  - category: "connections"
    timestamp: "2025-01-25 10:15:00"
    change_type: "added"
    description: "New connection: python3 -> google.com:443"
  - category: "ports"
    timestamp: "2025-01-25 10:20:00"
    change_type: "removed"
    description: "Port closed: 8080/tcp"
```

## ☁️ S3 интеграция

### Boto3 реализация
```python
def upload_reports_to_s3(configuration, py_version, yaml_filename, html_filename):
    s3_client = get_client_s3(
        configuration['s3']['url'],
        configuration['s3']['region'],
        configuration['s3']['user'],
        configuration['s3']['access_key'],
        py_version
    )
    
    # Загрузка YAML
    upload_file_s3(s3_client, bucket, yaml_filename, f"reports/{yaml_filename}")
    
    # Загрузка HTML
    upload_file_s3(s3_client, bucket, html_filename, f"reports/{html_filename}")
```

### Расписание загрузки
```python
def write_to_s3_scheduled(yaml_filename, html_filename, upload_time="8:0"):
    current_time = datetime.now().strftime("%H:%M")
    upload_time_formatted = upload_time.replace(":", ":")
    
    if current_time.startswith(upload_time_formatted.split(":")[0]):
        upload_reports_to_s3(config, version, yaml_filename, html_filename)
```

## 🛡️ Группы безопасности

### Автоматическая генерация правил
```python
def generate_security_group_rules(integration_connections):
    security_rules = {
        'inbound_rules': [],
        'outbound_rules': []
    }
    
    for conn in integration_connections:
        if conn['direction'] == 'incoming':
            rule = {
                'protocol': conn['protocol'].upper(),
                'port': conn['remote_port'],
                'source': conn['remote_ip'],
                'description': f"Allow {conn['process']} from {conn['remote_name']}"
            }
            security_rules['inbound_rules'].append(rule)
```

### Форматы вывода
```yaml
security_groups:
  by_process:
    nginx:
      ports: [80, 443]
      protocols: [TCP]
      destinations: ["0.0.0.0/0"]
    postgres:
      ports: [5432]
      protocols: [TCP]
      destinations: ["10.0.0.0/16"]
      
  recommended_rules:
    - direction: "inbound"
      protocol: "TCP"
      port: 443
      source: "0.0.0.0/0"
      description: "HTTPS traffic"
```

## 🔧 Альтернативные методы

### Fallback стратегии
1. **psutil** → **netstat** → **ss** → **lsof**
2. **Приоритет** — современные инструменты
3. **Совместимость** — старые системы
4. **Демо-данные** — последний резерв

### Обнаружение доступных утилит
```python
def get_current_connections(except_ipv6):
    try:
        return psutil.net_connections()
    except (PermissionError, AccessDenied):
        try:
            return get_connections_alternative_macos()
        except:
            return create_demo_connections()
```

## 📊 Производительность

### Оптимизации
- **Лимиты данных** — MAX_CONNECTIONS = 50
- **Параллельный сбор** — многопоточность для модулей
- **Кэширование** — повторное использование соединений
- **Компрессия** — YAML оптимизация

### Метрики производительности
```yaml
performance_metrics:
  total_execution_time: 45.2
  data_collection_time: 15.8
  netflow_generation_time: 8.4
  report_enhancement_time: 12.3
  html_generation_time: 8.7
  memory_usage_mb: 156.7
  cpu_usage_percent: 12.5
```

---