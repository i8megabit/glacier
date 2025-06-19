# 📊 Grafana Integration Guide / Руководство по интеграции с Grafana

## 🎯 Цели интеграции

Создание красивых и функциональных дашбордов для визуализации отчетов Glacier в Grafana:
- Автоматическая загрузка YAML отчетов
- Real-time мониторинг сетевых соединений
- Исторические данные и тренды
- Интерактивные фильтры и дрилдауны
- Алерты на аномальную активность

## 🏗️ Архитектурные варианты

### Вариант 1: PostgreSQL + TimescaleDB (Рекомендуется)
```
Анализатор → YAML → Parser → PostgreSQL → Grafana
```

**Преимущества:**
- Полная поддержка SQL
- Отличная производительность для временных рядов
- Развитая экосистема
- Простая интеграция с Grafana

### Вариант 2: InfluxDB (Для метрик реального времени)
```
Анализатор → YAML → Parser → InfluxDB → Grafana
```

**Преимущества:**
- Оптимизирован для временных рядов
- Встроенная поддержка тегов
- Высокая производительность
- Retention policies

### Вариант 3: JSON API (Быстрый старт)
```
Анализатор → YAML → JSON API → Grafana
```

**Преимущества:**
- Быстрая разработка
- Гибкость
- Минимум зависимостей

## 🚀 Реализация (PostgreSQL вариант)

### Docker Compose конфигурация

```yaml
# docker-compose.grafana.yml
version: '3.8'

services:
  postgres:
    image: timescale/timescaledb:latest-pg14
    container_name: analyzer-postgres
    environment:
      POSTGRES_DB: analyzer_metrics
      POSTGRES_USER: analyzer_user
      POSTGRES_PASSWORD: analyzer_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./sql/init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - analyzer-network

  grafana:
    image: grafana/grafana:latest
    container_name: analyzer-grafana
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: analyzer_admin
      GF_INSTALL_PLUGINS: grafana-clock-panel,grafana-simple-json-datasource,grafana-worldmap-panel
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    depends_on:
      - postgres
    networks:
      - analyzer-network

  yaml-processor:
    build: ./yaml-processor
    container_name: analyzer-yaml-processor
    environment:
      POSTGRES_HOST: postgres
      POSTGRES_DB: analyzer_metrics
      POSTGRES_USER: analyzer_user
      POSTGRES_PASSWORD: analyzer_password
      WATCH_DIRECTORY: /app/reports
    volumes:
      - ./reports:/app/reports:ro
      - ./yaml-processor:/app
    depends_on:
      - postgres
    networks:
      - analyzer-network

volumes:
  postgres_data:
  grafana_data:

networks:
  analyzer-network:
    driver: bridge
```

### Схема базы данных

```sql
-- sql/init.sql
-- Включаем TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Основная таблица соединений
CREATE TABLE connections (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    source_address INET,
    destination_address INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT,
    protocol_number INTEGER,
    packet_count BIGINT DEFAULT 0,
    byte_count BIGINT DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    tcp_flags INTEGER,
    direction TEXT, -- incoming/outgoing
    process_name TEXT,
    connection_state TEXT,
    report_id TEXT,
    
    -- Метаданные
    os_name TEXT,
    os_version TEXT,
    analyzer_version TEXT
);

-- Делаем таблицу гипертаблицей TimescaleDB
SELECT create_hypertable('connections', 'time');

-- Агрегированная статистика по протоколам
CREATE TABLE protocol_stats (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    protocol TEXT NOT NULL,
    connection_count INTEGER DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    total_packets BIGINT DEFAULT 0,
    unique_destinations INTEGER DEFAULT 0,
    report_id TEXT
);

SELECT create_hypertable('protocol_stats', 'time');

-- Топ назначений
CREATE TABLE top_destinations (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    destination_address INET,
    destination_port INTEGER,
    connection_count INTEGER DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    protocols TEXT[],
    processes TEXT[],
    report_id TEXT
);

SELECT create_hypertable('top_destinations', 'time');

-- Системная информация
CREATE TABLE system_metrics (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    total_connections INTEGER DEFAULT 0,
    incoming_connections INTEGER DEFAULT 0,
    outgoing_connections INTEGER DEFAULT 0,
    tcp_connections INTEGER DEFAULT 0,
    udp_connections INTEGER DEFAULT 0,
    icmp_connections INTEGER DEFAULT 0,
    unique_processes INTEGER DEFAULT 0,
    unique_destinations INTEGER DEFAULT 0,
    report_generation_time_ms INTEGER DEFAULT 0,
    os_name TEXT,
    os_version TEXT,
    report_id TEXT
);

SELECT create_hypertable('system_metrics', 'time');

-- Индексы для производительности
CREATE INDEX ON connections (hostname, time DESC);
CREATE INDEX ON connections (destination_address, time DESC);
CREATE INDEX ON connections (protocol, time DESC);
CREATE INDEX ON connections (process_name, time DESC);

CREATE INDEX ON protocol_stats (hostname, protocol, time DESC);
CREATE INDEX ON top_destinations (hostname, destination_address, time DESC);
CREATE INDEX ON system_metrics (hostname, time DESC);

-- Политики ретенции (опционально)
SELECT add_retention_policy('connections', INTERVAL '30 days');
SELECT add_retention_policy('protocol_stats', INTERVAL '90 days');
SELECT add_retention_policy('top_destinations', INTERVAL '90 days');
SELECT add_retention_policy('system_metrics', INTERVAL '1 year');
```

### YAML Processor

```python
#!/usr/bin/env python3
"""
YAML to PostgreSQL processor для Grafana
Следит за папкой с отчетами и автоматически загружает их в БД
"""

import os
import yaml
import time
import hashlib
import psycopg2
import logging
from datetime import datetime
from typing import Dict, List, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import ipaddress


class YAMLProcessor:
    def __init__(self, postgres_config: Dict[str, str]):
        self.postgres_config = postgres_config
        self.processed_files = set()
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger('yaml_processor')
    
    def connect_postgres(self):
        """Подключение к PostgreSQL"""
        return psycopg2.connect(
            host=self.postgres_config['host'],
            database=self.postgres_config['database'],
            user=self.postgres_config['user'],
            password=self.postgres_config['password']
        )
    
    def process_yaml_file(self, file_path: str):
        """Обрабатывает YAML файл и загружает данные в PostgreSQL"""
        try:
            self.logger.info(f"Processing {file_path}")
            
            # Проверяем, что файл не обрабатывался ранее
            file_hash = self._get_file_hash(file_path)
            if file_hash in self.processed_files:
                return
            
            # Загружаем YAML
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            # Проверяем формат (NetFlow или legacy)
            if 'netflow_message' in data:
                self._process_netflow_data(data, file_path)
            else:
                self._process_legacy_data(data, file_path)
            
            self.processed_files.add(file_hash)
            self.logger.info(f"Successfully processed {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {e}")
    
    def _process_netflow_data(self, data: Dict, file_path: str):
        """Обрабатывает NetFlow формат данных"""
        netflow = data['netflow_message']
        system_info = data.get('system_information', {})
        
        # Генерируем уникальный ID отчета
        report_id = self._generate_report_id(file_path, data)
        
        # Извлекаем базовую информацию
        hostname = system_info.get('hostname', 'unknown')
        os_info = system_info.get('os', {})
        os_name = os_info.get('name', 'unknown')
        os_version = os_info.get('version', 'unknown')
        
        # Время экспорта
        export_time = datetime.fromtimestamp(
            netflow['header']['export_timestamp']
        )
        
        with self.connect_postgres() as conn:
            with conn.cursor() as cur:
                # 1. Загружаем соединения
                self._insert_connections(cur, netflow['flows'], hostname, 
                                       os_name, os_version, report_id, export_time)
                
                # 2. Загружаем статистику протоколов
                self._insert_protocol_stats(cur, data.get('flow_statistics', {}), 
                                          hostname, report_id, export_time)
                
                # 3. Загружаем системные метрики
                self._insert_system_metrics(cur, netflow, system_info, 
                                          hostname, report_id, export_time)
                
                # 4. Загружаем топ назначений
                self._insert_top_destinations(cur, netflow['flows'], 
                                            hostname, report_id, export_time)
    
    def _insert_connections(self, cur, flows: List[Dict], hostname: str, 
                           os_name: str, os_version: str, report_id: str, 
                           timestamp: datetime):
        """Вставляет данные о соединениях"""
        for flow in flows:
            cur.execute("""
                INSERT INTO connections (
                    time, hostname, source_address, destination_address,
                    source_port, destination_port, protocol, protocol_number,
                    packet_count, byte_count, direction, process_name,
                    tcp_flags, report_id, os_name, os_version
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                timestamp,
                hostname,
                flow.get('source_address'),
                flow.get('destination_address'),
                flow.get('source_port'),
                flow.get('destination_port'),
                flow.get('protocol_name'),
                flow.get('protocol'),
                flow.get('packet_count', 0),
                flow.get('byte_count', 0),
                flow.get('meta', {}).get('direction', 'unknown'),
                flow.get('meta', {}).get('process', 'unknown'),
                flow.get('tcp_flags', 0),
                report_id,
                os_name,
                os_version
            ))
    
    def _insert_protocol_stats(self, cur, flow_stats: Dict, hostname: str, 
                              report_id: str, timestamp: datetime):
        """Вставляет статистику протоколов"""
        protocols = flow_stats.get('protocols', {})
        
        for protocol, count in protocols.items():
            cur.execute("""
                INSERT INTO protocol_stats (
                    time, hostname, protocol, connection_count,
                    total_bytes, total_packets, report_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                timestamp,
                hostname,
                protocol,
                count,
                flow_stats.get('total_bytes', 0),
                flow_stats.get('total_packets', 0),
                report_id
            ))
    
    def _insert_system_metrics(self, cur, netflow: Dict, system_info: Dict,
                              hostname: str, report_id: str, timestamp: datetime):
        """Вставляет системные метрики"""
        flows = netflow.get('flows', [])
        
        # Подсчитываем метрики
        total_connections = len(flows)
        incoming = len([f for f in flows if f.get('meta', {}).get('direction') == 'incoming'])
        outgoing = len([f for f in flows if f.get('meta', {}).get('direction') == 'outgoing'])
        tcp_count = len([f for f in flows if f.get('protocol') == 6])
        udp_count = len([f for f in flows if f.get('protocol') == 17])
        icmp_count = len([f for f in flows if f.get('protocol') == 1])
        
        unique_processes = len(set(
            f.get('meta', {}).get('process', 'unknown') for f in flows
        ))
        unique_destinations = len(set(
            f.get('destination_address') for f in flows if f.get('destination_address')
        ))
        
        cur.execute("""
            INSERT INTO system_metrics (
                time, hostname, total_connections, incoming_connections,
                outgoing_connections, tcp_connections, udp_connections,
                icmp_connections, unique_processes, unique_destinations,
                os_name, os_version, report_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            timestamp, hostname, total_connections, incoming, outgoing,
            tcp_count, udp_count, icmp_count, unique_processes,
            unique_destinations, 
            system_info.get('os', {}).get('name', 'unknown'),
            system_info.get('os', {}).get('version', 'unknown'),
            report_id
        ))
    
    def _insert_top_destinations(self, cur, flows: List[Dict], hostname: str,
                                report_id: str, timestamp: datetime):
        """Вставляет топ назначений"""
        # Группируем по назначениям
        destinations = {}
        for flow in flows:
            dest = flow.get('destination_address')
            port = flow.get('destination_port')
            if not dest:
                continue
                
            key = (dest, port)
            if key not in destinations:
                destinations[key] = {
                    'count': 0,
                    'bytes': 0,
                    'protocols': set(),
                    'processes': set()
                }
            
            destinations[key]['count'] += 1
            destinations[key]['bytes'] += flow.get('byte_count', 0)
            destinations[key]['protocols'].add(flow.get('protocol_name', 'unknown'))
            destinations[key]['processes'].add(
                flow.get('meta', {}).get('process', 'unknown')
            )
        
        # Топ 20 назначений по количеству соединений
        top_destinations = sorted(
            destinations.items(), 
            key=lambda x: x[1]['count'], 
            reverse=True
        )[:20]
        
        for (dest, port), stats in top_destinations:
            cur.execute("""
                INSERT INTO top_destinations (
                    time, hostname, destination_address, destination_port,
                    connection_count, total_bytes, protocols, processes, report_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                timestamp, hostname, dest, port, stats['count'],
                stats['bytes'], list(stats['protocols']), 
                list(stats['processes']), report_id
            ))
    
    def _get_file_hash(self, file_path: str) -> str:
        """Получает хеш файла для предотвращения повторной обработки"""
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    
    def _generate_report_id(self, file_path: str, data: Dict) -> str:
        """Генерирует уникальный ID отчета"""
        file_name = os.path.basename(file_path)
        timestamp = datetime.now().isoformat()
        return f"{file_name}_{timestamp}"


class YAMLWatcher(FileSystemEventHandler):
    """Следит за изменениями в папке с отчетами"""
    
    def __init__(self, processor: YAMLProcessor):
        self.processor = processor
        
    def on_created(self, event):
        if event.is_dir:
            return
            
        if event.src_path.endswith('.yaml') or event.src_path.endswith('.yml'):
            # Небольшая задержка для завершения записи файла
            time.sleep(1)
            self.processor.process_yaml_file(event.src_path)


def main():
    """Основная функция"""
    postgres_config = {
        'host': os.getenv('POSTGRES_HOST', 'localhost'),
        'database': os.getenv('POSTGRES_DB', 'analyzer_metrics'),
        'user': os.getenv('POSTGRES_USER', 'analyzer_user'),
        'password': os.getenv('POSTGRES_PASSWORD', 'analyzer_password')
    }
    
    watch_directory = os.getenv('WATCH_DIRECTORY', './reports')
    
    processor = YAMLProcessor(postgres_config)
    
    # Обрабатываем существующие файлы
    if os.path.exists(watch_directory):
        for filename in os.listdir(watch_directory):
            if filename.endswith(('.yaml', '.yml')):
                file_path = os.path.join(watch_directory, filename)
                processor.process_yaml_file(file_path)
    
    # Начинаем наблюдение за новыми файлами
    event_handler = YAMLWatcher(processor)
    observer = Observer()
    observer.schedule(event_handler, watch_directory, recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == '__main__':
    main()
```

## 📈 Дашборды Grafana

### Конфигурация источника данных

```yaml
# grafana/provisioning/datasources/postgres.yml
apiVersion: 1

datasources:
  - name: GlacierDB
    type: postgres
    access: proxy
    url: postgres:5432
    database: analyzer_metrics
    user: analyzer_user
    secureJsonData:
      password: analyzer_password
    jsonData:
      sslmode: disable
      maxOpenConns: 25
      maxIdleConns: 25
      connMaxLifetime: 14400
      postgresVersion: 1400
      timescaledb: true
```

### Основной дашборд

```json
{
  "dashboard": {
    "id": null,
    "title": "Network Glacier Dashboard",
    "tags": ["analyzer", "network", "security"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Total Connections Over Time",
        "type": "timeseries",
        "targets": [
          {
            "rawSql": "SELECT time, SUM(total_connections) as connections FROM system_metrics WHERE $__timeFilter(time) GROUP BY time ORDER BY time",
            "format": "time_series"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "Protocol Distribution",
        "type": "piechart",
        "targets": [
          {
            "rawSql": "SELECT protocol as metric, SUM(connection_count) as value FROM protocol_stats WHERE $__timeFilter(time) GROUP BY protocol",
            "format": "table"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "id": 3,
        "title": "Top Destinations",
        "type": "table",
        "targets": [
          {
            "rawSql": "SELECT destination_address, destination_port, SUM(connection_count) as connections, SUM(total_bytes) as bytes FROM top_destinations WHERE $__timeFilter(time) GROUP BY destination_address, destination_port ORDER BY connections DESC LIMIT 10",
            "format": "table"
          }
        ],
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
      },
      {
        "id": 4,
        "title": "Network Traffic Volume",
        "type": "timeseries",
        "targets": [
          {
            "rawSql": "SELECT time, SUM(byte_count) as bytes FROM connections WHERE $__timeFilter(time) GROUP BY time ORDER BY time",
            "format": "time_series"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
      },
      {
        "id": 5,
        "title": "Connection Directions",
        "type": "stat",
        "targets": [
          {
            "rawSql": "SELECT direction, COUNT(*) as connections FROM connections WHERE $__timeFilter(time) GROUP BY direction",
            "format": "table"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
      }
    ],
    "time": {
      "from": "now-6h",
      "to": "now"
    },
    "refresh": "5s",
    "schemaVersion": 30
  }
}
```

## 🚀 Запуск и использование

### 1. Подготовка окружения

```bash
# Создаем директории
mkdir -p grafana/{provisioning/datasources,provisioning/dashboards,dashboards}
mkdir -p reports
mkdir -p yaml-processor
mkdir -p sql

# Создаем Dockerfile для YAML процессора
cat > yaml-processor/Dockerfile << 'EOF'
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY yaml_processor.py .

CMD ["python", "yaml_processor.py"]
EOF

# Зависимости для YAML процессора
cat > yaml-processor/requirements.txt << 'EOF'
pyyaml>=6.0
psycopg2-binary>=2.9.0
watchdog>=2.1.0
EOF
```

### 2. Запуск инфраструктуры

```bash
# Запускаем контейнеры
docker-compose -f docker-compose.grafana.yml up -d

# Проверяем статус
docker-compose -f docker-compose.grafana.yml ps
```

### 3. Генерация отчета Glacier

```bash
# Запускаем Glacier (отчет попадет в ./reports/)
cd glacier
python3 src/glacier.py --times 1 --output-dir ../reports/
```

### 4. Доступ к Grafana

```
URL: http://localhost:3000
Логин: admin
Пароль: analyzer_admin
```

## 📊 Возможности дашбордов

### 1. **Overview Dashboard**
- Общая статистика соединений
- Распределение по протоколам
- Тренды во времени
- Топ назначений

### 2. **Security Dashboard**
- Подозрительные соединения
- Новые назначения
- Аномальный трафик
- Алерты безопасности

### 3. **Performance Dashboard**
- Bandwidth utilization
- Connection patterns
- Process analytics
- Geographic distribution

### 4. **Historical Dashboard**
- Долгосрочные тренды
- Сравнение периодов
- Capacity planning
- Growth patterns

## 🔧 Настройки и оптимизация

### Retention Policies
```sql
-- Настройка политик хранения
SELECT add_retention_policy('connections', INTERVAL '30 days');
SELECT add_retention_policy('protocol_stats', INTERVAL '90 days');
```

### Алерты
```yaml
# Пример алерта на аномальную активность
- alert: HighConnectionCount
  expr: max(system_metrics.total_connections) > 1000
  for: 5m
  annotations:
    summary: "High connection count detected"
```

## 📝 Заключение

Эта интеграция обеспечивает:
- ✅ Автоматическую загрузку отчетов
- ✅ Real-time визуализацию
- ✅ Исторические данные
- ✅ Настраиваемые дашборды
- ✅ Алерты и уведомления
- ✅ Масштабируемость 