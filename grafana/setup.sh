#!/bin/bash
set -e

# Цвета для вывода
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Функция для логирования
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Проверяем наличие Docker
if ! command -v docker &> /dev/null; then
    error "Docker не установлен. Установите Docker и попробуйте снова."
fi

if ! command -v docker-compose &> /dev/null; then
    error "Docker Compose не установлен. Установите Docker Compose и попробуйте снова."
fi

log "🚀 Настройка Grafana интеграции для анализатора"

# Создаем необходимые директории
log "📁 Создание структуры директорий..."
mkdir -p {grafana/{provisioning/{datasources,dashboards},dashboards},reports,yaml-processor/logs,sql}

# Создаем конфигурацию источника данных для Grafana
log "🔧 Создание конфигурации источника данных..."
cat > grafana/provisioning/datasources/postgres.yml << 'EOF'
apiVersion: 1

datasources:
  - name: GlacierDB
    type: postgres
    access: proxy
    url: postgres:5432
    database: analyzer_metrics
    user: grafana_reader
    secureJsonData:
      password: grafana_readonly_password
    jsonData:
      sslmode: disable
      maxOpenConns: 25
      maxIdleConns: 25
      connMaxLifetime: 14400
      postgresVersion: 1400
      timescaledb: true
    isDefault: true
    editable: true
EOF

# Создаем конфигурацию дашбордов
log "📊 Создание конфигурации дашбордов..."
cat > grafana/provisioning/dashboards/dashboard.yml << 'EOF'
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
EOF

# Создаем YAML процессор
log "⚙️ Создание YAML процессора..."
cat > yaml-processor/yaml_processor.py << 'EOF'
#!/usr/bin/env python3
"""
Упрощенный YAML to PostgreSQL processor для Grafana
"""

import os
import yaml
import time
import hashlib
import psycopg2
import logging
import json
from datetime import datetime
from typing import Dict, List, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/app/logs/yaml_processor.log')
    ]
)

logger = logging.getLogger('yaml_processor')

class YAMLProcessor:
    def __init__(self, postgres_config: Dict[str, str]):
        self.postgres_config = postgres_config
        self.processed_files = set()
        
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
            logger.info(f"Processing {file_path}")
            
            # Проверяем, что файл не обрабатывался ранее
            file_hash = self._get_file_hash(file_path)
            if file_hash in self.processed_files:
                logger.info(f"File {file_path} already processed, skipping")
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
            logger.info(f"Successfully processed {file_path}")
            
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
    
    def _process_netflow_data(self, data: Dict, file_path: str):
        """Обрабатывает NetFlow формат данных"""
        try:
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
                    # Загружаем соединения
                    flows = netflow.get('flows', [])
                    for flow in flows:
                        try:
                            cur.execute("""
                                INSERT INTO connections (
                                    time, hostname, source_address, destination_address,
                                    source_port, destination_port, protocol, protocol_number,
                                    packet_count, byte_count, direction, process_name,
                                    tcp_flags, report_id, os_name, os_version
                                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """, (
                                export_time,
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
                        except Exception as e:
                            logger.warning(f"Error inserting connection: {e}")
                    
                    # Загружаем системные метрики
                    self._insert_system_metrics(cur, flows, hostname, report_id, export_time, os_name, os_version)
            
            logger.info(f"Processed {len(flows)} connections from NetFlow data")
            
        except Exception as e:
            logger.error(f"Error processing NetFlow data: {e}")
    
    def _process_legacy_data(self, data: Dict, file_path: str):
        """Обрабатывает legacy формат данных"""
        logger.info("Processing legacy format data (not implemented yet)")
        # Можно добавить обработку старого формата при необходимости
    
    def _insert_system_metrics(self, cur, flows: List[Dict], hostname: str,
                              report_id: str, timestamp: datetime, os_name: str, os_version: str):
        """Вставляет системные метрики"""
        try:
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
                unique_destinations, os_name, os_version, report_id
            ))
            
        except Exception as e:
            logger.error(f"Error inserting system metrics: {e}")
    
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
            time.sleep(2)
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
    
    logger.info(f"Starting YAML processor, watching directory: {watch_directory}")
    logger.info(f"PostgreSQL config: {postgres_config['host']}:{postgres_config['database']}")
    
    processor = YAMLProcessor(postgres_config)
    
    # Проверяем подключение к БД
    try:
        with processor.connect_postgres() as conn:
            logger.info("Successfully connected to PostgreSQL")
    except Exception as e:
        logger.error(f"Failed to connect to PostgreSQL: {e}")
        return
    
    # Обрабатываем существующие файлы
    if os.path.exists(watch_directory):
        logger.info(f"Processing existing files in {watch_directory}")
        for filename in os.listdir(watch_directory):
            if filename.endswith(('.yaml', '.yml')):
                file_path = os.path.join(watch_directory, filename)
                processor.process_yaml_file(file_path)
    else:
        logger.warning(f"Watch directory {watch_directory} does not exist")
    
    # Начинаем наблюдение за новыми файлами
    event_handler = YAMLWatcher(processor)
    observer = Observer()
    observer.schedule(event_handler, watch_directory, recursive=False)
    observer.start()
    
    logger.info("YAML processor started successfully")
    
    try:
        while True:
            time.sleep(30)
            logger.debug("YAML processor is running...")
    except KeyboardInterrupt:
        logger.info("Stopping YAML processor...")
        observer.stop()
    observer.join()


if __name__ == '__main__':
    main()
EOF

# Создаем простой дашборд
log "📈 Создание базового дашборда..."
cat > grafana/dashboards/analyzer-overview.json << 'EOF'
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": null,
  "title": "Glacier Overview",
  "tags": ["analyzer", "network", "overview"],
  "timezone": "browser",
  "panels": [
    {
      "datasource": "GlacierDB",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "vis": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": false,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        },
        "tooltip": {
          "mode": "single"
        }
      },
      "targets": [
        {
          "format": "time_series",
          "group": [],
          "metricColumn": "none",
          "rawQuery": true,
          "rawSql": "SELECT\n  time AS \"time\",\n  total_connections AS \"Total Connections\"\nFROM system_metrics\nWHERE\n  $__timeFilter(time)\nORDER BY time",
          "refId": "A",
          "select": [
            [
              {
                "params": [
                  "total_connections"
                ],
                "type": "column"
              }
            ]
          ],
          "table": "system_metrics",
          "timeColumn": "time",
          "timeColumnType": "timestamp",
          "where": [
            {
              "name": "$__timeFilter",
              "params": [],
              "type": "macro"
            }
          ]
        }
      ],
      "title": "Total Connections Over Time",
      "type": "timeseries"
    },
    {
      "datasource": "GlacierDB",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "hideFrom": {
              "tooltip": false,
              "vis": false,
              "legend": false
            }
          },
          "mappings": []
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 0
      },
      "id": 2,
      "options": {
        "reduceOptions": {
          "values": false,
          "calcs": [
            "lastNotNull"
          ],
          "fields": ""
        },
        "pieType": "pie",
        "tooltip": {
          "mode": "single"
        },
        "legend": {
          "displayMode": "list",
          "placement": "bottom"
        }
      },
      "targets": [
        {
          "format": "table",
          "group": [],
          "metricColumn": "none",
          "rawQuery": true,
          "rawSql": "SELECT \n  protocol as metric,\n  COUNT(*) as value\nFROM connections \nWHERE $__timeFilter(time)\nGROUP BY protocol\nORDER BY value DESC",
          "refId": "A",
          "select": [
            [
              {
                "params": [
                  "value"
                ],
                "type": "column"
              }
            ]
          ],
          "timeColumn": "time",
          "where": [
            {
              "name": "$__timeFilter",
              "params": [],
              "type": "macro"
            }
          ]
        }
      ],
      "title": "Protocol Distribution",
      "type": "piechart"
    },
    {
      "datasource": "GlacierDB",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "custom": {
            "align": "auto",
            "displayMode": "auto"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          }
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 24,
        "x": 0,
        "y": 8
      },
      "id": 3,
      "options": {
        "showHeader": true
      },
      "targets": [
        {
          "format": "table",
          "group": [],
          "metricColumn": "none",
          "rawQuery": true,
          "rawSql": "SELECT \n  destination_address as \"Destination\",\n  destination_port as \"Port\",\n  COUNT(*) as \"Connections\",\n  SUM(byte_count) as \"Total Bytes\",\n  string_agg(DISTINCT protocol, ', ') as \"Protocols\"\nFROM connections \nWHERE $__timeFilter(time) AND destination_address IS NOT NULL\nGROUP BY destination_address, destination_port\nORDER BY \"Connections\" DESC\nLIMIT 10",
          "refId": "A",
          "select": [
            [
              {
                "params": [
                  "value"
                ],
                "type": "column"
              }
            ]
          ],
          "timeColumn": "time",
          "where": [
            {
              "name": "$__timeFilter",
              "params": [],
              "type": "macro"
            }
          ]
        }
      ],
      "title": "Top Destinations",
      "type": "table"
    }
  ],
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {},
  "refresh": "30s",
  "schemaVersion": 27,
  "version": 1
}
EOF

# Создаем файл с тестовыми данными
log "📊 Создание тестовых данных..."
cat > sql/sample_data.sql << 'EOF'
-- Вставляем тестовые данные для демонстрации
INSERT INTO connections (time, hostname, source_address, destination_address, source_port, destination_port, protocol, protocol_number, packet_count, byte_count, direction, process_name, os_name, os_version, report_id)
VALUES 
  (NOW() - INTERVAL '1 hour', 'test-host', '192.168.1.100', '8.8.8.8', 54321, 443, 'tcp', 6, 15, 1024, 'outgoing', 'chrome', 'Darwin', '24.5.0', 'test-report-1'),
  (NOW() - INTERVAL '2 hours', 'test-host', '192.168.1.100', '1.1.1.1', 54322, 53, 'udp', 17, 2, 128, 'outgoing', 'resolver', 'Darwin', '24.5.0', 'test-report-2'),
  (NOW() - INTERVAL '30 minutes', 'test-host', '0.0.0.0', '192.168.1.200', 22, 54323, 'tcp', 6, 8, 2048, 'incoming', 'sshd', 'Darwin', '24.5.0', 'test-report-3');

INSERT INTO system_metrics (time, hostname, total_connections, incoming_connections, outgoing_connections, tcp_connections, udp_connections, icmp_connections, unique_processes, unique_destinations, os_name, os_version, report_id)
VALUES 
  (NOW() - INTERVAL '1 hour', 'test-host', 45, 12, 33, 35, 9, 1, 8, 15, 'Darwin', '24.5.0', 'test-report-1'),
  (NOW() - INTERVAL '2 hours', 'test-host', 38, 10, 28, 30, 7, 1, 7, 12, 'Darwin', '24.5.0', 'test-report-2'),
  (NOW() - INTERVAL '30 minutes', 'test-host', 52, 15, 37, 42, 8, 2, 9, 18, 'Darwin', '24.5.0', 'test-report-3');
EOF

# Проверяем права доступа
log "🔐 Настройка прав доступа..."
chmod +x setup.sh

# Запускаем инфраструктуру
log "🐳 Запуск Docker контейнеров..."
docker-compose -f docker-compose.grafana.yml up -d

# Ждем запуска сервисов
log "⏳ Ожидание запуска сервисов..."
sleep 30

# Проверяем статус
log "📋 Проверка статуса сервисов..."
docker-compose -f docker-compose.grafana.yml ps

# Показываем финальную информацию
log "✅ Настройка завершена!"
echo ""
echo -e "${BLUE}🎉 Grafana интеграция готова к использованию!${NC}"
echo ""
echo -e "${YELLOW}📊 Grafana Dashboard:${NC}"
echo "   URL: http://localhost:3000"
echo "   Логин: admin"
echo "   Пароль: analyzer_admin"
echo ""
echo -e "${YELLOW}🗄️ PostgreSQL:${NC}"
echo "   Host: localhost:5432"
echo "   Database: analyzer_metrics"
echo "   User: analyzer_user"
echo "   Password: analyzer_password"
echo ""
echo -e "${YELLOW}📝 Как использовать:${NC}"
echo "   1. Запустите анализатор: cd ../src && python3 analyzer.py --times 1"
echo "   2. Скопируйте YAML отчет в папку: cp *_report_*.yaml ../grafana/reports/"
echo "   3. Откройте Grafana и посмотрите дашборды"
echo ""
echo -e "${GREEN}🔧 Полезные команды:${NC}"
echo "   Остановить: docker-compose -f docker-compose.grafana.yml down"
echo "   Перезапустить: docker-compose -f docker-compose.grafana.yml restart"
echo "   Логи: docker-compose -f docker-compose.grafana.yml logs -f" 