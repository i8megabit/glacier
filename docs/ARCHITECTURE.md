# 🏗️ Архитектура Glacier

## 🎯 Описание

Инструмент для мониторинга сетевой активности серверов. Используется системными администраторами и DevOps-инженерами для анализа сетевых соединений и системного состояния.

## 🧠 Принципы

- **Прозрачность** 📊 — все методы документированы
- **Легальность** 🛡️ — только стандартные системные вызовы  
- **Стандарты** 📈 — соответствие NetFlow v9 (RFC 3954)
- **Читаемость** 🎨 — HTML и YAML отчеты

## 🧠 Архитектура

```
analyzer.py (Главный оркестратор)
    |
    v
Сбор данных (psutil, netstat, lsof, ss)
    |
    v  
NetFlow v9 генератор (RFC 3954)
    |
    v
Аналитика (ReportEnhancer)
    |
    v
┌─────────────┬─────────────┐
│  YAML отчет │  HTML отчет │
│             │ (Chart.js)  │
└─────────────┴─────────────┘
    |
    v
S3 загрузка (опционально)
```

## 🔍 Алгоритм работы

### 1. Сбор данных 📊

**Сетевая информация:**
- `psutil.net_connections()` — TCP/UDP соединения
- `netstat` — fallback для старых систем
- `lsof` — процессы с сетевыми дескрипторами
- `ss` — современная альтернатива netstat

**Системная информация:**
- `psutil` — CPU, память, диски, процессы
- `platform` — информация об ОС
- `/proc/net/` — системные файлы Linux (read-only)
- `dscl` — пользователи macOS

**Безопасность:**
- `iptables -L` — правила файрвола
- `ufw status` — Ubuntu Firewall
- `docker ps` — статус контейнеров

### 2. NetFlow v9 обработка 📡

Строгое соблюдение **RFC 3954**:

```python
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

**Заголовок NetFlow v9:**
- Version = 9
- Count (количество записей)
- SysUptime (время работы системы в мс)
- Unix Secs (timestamp экспорта)
- Sequence Number
- Source ID

### 3. Аналитика 🧐

`ReportEnhancer` обрабатывает данные:

```python
def enhance_report(self, original_report):
    return {
        'metadata': self._create_metadata(),
        'executive_summary': self._create_summary(),
        'security_analysis': self._analyze_security(),
        'network_analysis': self._analyze_network(),
        'system_health': self._analyze_health(),
        'recommendations': self.recommendations,
        'detailed_data': self._structure_data()
    }
```

**Анализируется:**
- Топ процессы по соединениям
- Аномальная активность
- Состояние системы

### 4. Генерация отчетов 📋

**YAML (NetFlow v9):**
```yaml
netflow_data:
  header:
    version: 9
    count: 145
    sys_uptime: 1234567
    unix_secs: 1735123456
  flows:
    - ipv4_src_addr: "192.168.1.100"
      ipv4_dst_addr: "93.184.216.34"
      l4_src_port: 54321
      l4_dst_port: 443
      protocol: 6
```

**HTML:**
- Chart.js диаграммы
- Bootstrap UI
- Интерактивные таблицы
- Адаптивная верстка

### 5. Выгрузка 💾

- Локальные файлы: `hostname_os_report_analyzer.{yaml,html}`
- S3 интеграция (опционально)

## 🛡️ Методы сбора данных

### ✅ Что используем

**Системные вызовы:**
- `psutil` — системная информация
- `socket` — сетевые операции  
- `subprocess` — вызов утилит

**Стандарты:**
- NetFlow v9 (RFC 3954)
- YAML/JSON
- HTML5/CSS3/JS

**Методы:**
1. Пассивный мониторинг (чтение существующих соединений)
2. Системные файлы (/proc/net/, только чтение)
3. Стандартные утилиты (netstat, ss, lsof)
4. Публичные API

### ❌ Что не используем
- Packet capture
- Модификация сетевых настроек
- Установка backdoor'ов
- Сбор паролей/личных данных
- Активное сканирование портов

## 🔄 NetFlow v9 соответствие

### Структура сообщения
```
+--------+--------+--------+--------+
|       Version Number = 9         |  
+--------+--------+--------+--------+
|          Count                   |
+--------+--------+--------+--------+
|         System Uptime            |
+--------+--------+--------+--------+
|         UNIX Seconds             |
+--------+--------+--------+--------+
|       Sequence Number            |
+--------+--------+--------+--------+
|        Source ID                 |
+--------+--------+--------+--------+
```

### Template Records
```python
def create_template_record(self, template_id, fields):
    return {
        'template_id': template_id,
        'field_count': len(fields),
        'field_specs': [
            {'field_type': NETFLOW_V9_FIELDS[field],
             'field_length': FIELD_LENGTHS[field]}
            for field in fields
        ]
    }
```

### Data Records
```python
def convert_connection_to_flow(self, connection):
    return {
        'ipv4_src_addr': self.parse_ip(connection['local']),
        'ipv4_dst_addr': self.parse_ip(connection['remote']),
        'l4_src_port': self.parse_port(connection['local']),
        'l4_dst_port': self.parse_port(connection['remote']),
        'protocol': PROTOCOL_NUMBERS[connection['type']],
        'first_switched': int(time.time()),
        'last_switched': int(time.time())
    }
```

## 🚀 Модули

### analyzer.py — Оркестратор
```python
def main():
    system_data = collect_system_data()
    netflow_data = NetFlowGenerator().generate_netflow_report(system_data)
    enhanced = ReportEnhancer().enhance_report(netflow_data)
    HTMLReportGenerator().generate_html_report(enhanced)
    write_yaml_report(netflow_data)
    upload_to_s3_if_configured()
```

### Специализированные модули
- **network_info.py** — TCP/UDP соединения, процессы, порты
- **udp_tracker_{module,macos}.py** — UDP трафик, DNS
- **icmp_tracker.py** — ping, traceroute, ICMP
- **report_enhancer.py** — аналитика, группировка, метрики
- **html_report_generator.py** — HTML генерация, Chart.js

## 🔧 Технический стек

- **Python 3.6+**
- **psutil** — системная информация
- **PyYAML** — YAML обработка
- **boto3** — S3 интеграция
- **Chart.js** — графики
- **Bootstrap** — UI

## 📊 Форматы данных

```yaml
netflow_data:
  header: {version: 9, count: 156, sys_uptime: 1234567}
system_info:
  hostname: server.example.com
  os: {name: Linux, version: 5.4.0}
connections:
  incoming: [...]
  outgoing: [...]
statistics:
  measurement_count: 10
  duration_seconds: 300
```

## 🔐 Безопасность

**Принципы:**
1. Минимальные привилегии
2. Read-only операции
3. Логирование действий
4. Валидация входных данных

**Обработка данных:**
- IP адреса — только активные подключения
- Процессы — только сетевые, без аргументов
- Пользователи — только активные сессии
- Файлы — не сканируется содержимое

## ✅ Преимущества

- **Модульность** — замена компонентов, тестирование
- **Стандартизация** — совместимость с SIEM (Splunk, Elastic)
- **Читаемость** — визуализация, группировка
- **Масштабируемость** — кумулятивные отчеты, S3, оптимизация

---