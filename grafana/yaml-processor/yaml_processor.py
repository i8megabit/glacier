#!/usr/bin/env python3
"""
YAML Processor для интеграции с Grafana
Читает YAML отчёты анализатора и загружает данные в PostgreSQL
"""

import os
import time
import yaml
import psycopg2
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import traceback
import json
import shutil

# Настройка логирвоания
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class YAMLProcessor:
    def __init__(self):
        self.db_config = {
            'host': os.getenv('POSTGRES_HOST', 'postgres'),
            'port': int(os.getenv('POSTGRES_PORT', 5432)),
            'database': os.getenv('POSTGRES_DB', 'analyzer_db'),
            'user': os.getenv('POSTGRES_USER', 'grafana_user'),
            'password': os.getenv('POSTGRES_PASSWORD', 'grafana_pass')
        }
        self.watch_dir = Path(os.getenv('YAML_WATCH_DIR', '/data/yaml'))
        self.processed_dir = Path(os.getenv('PROCESSED_DIR', '/data/processed'))
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        
        # Создаём папку для мониторинга если её нет
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Инициализация YAML процессора")
        logger.info(f"База данных: {self.db_config['host']}:{self.db_config['port']}/{self.db_config['database']}")
        logger.info(f"Папка мониторинга: {self.watch_dir}")
        logger.info(f"Папка обработанных: {self.processed_dir}")

    def connect_db(self) -> Optional[psycopg2.extensions.connection]:
        """Подключение к PostgreSQL"""
        try:
            conn = psycopg2.connect(**self.db_config)
            conn.autocommit = True
            return conn
        except Exception as e:
            logger.error(f"Ошибка подключения к БД: {e}")
            return None

    def process_yaml_file(self, file_path: Path) -> bool:
        """Обработка одного YAML файла"""
        try:
            logger.info(f"Обработка файла: {file_path}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data or 'netflow_message' not in data:
                logger.warning(f"Файл не содержит NetFlow данных: {file_path}")
                return False
            
            conn = self.connect_db()
            if not conn:
                return False
            
            try:
                cursor = conn.cursor()
                
                # Извлекаем информацию из YAML
                # Попытаемся извлечь hostname из разных мест
                hostname = 'unknown'
                
                # Проверяем system_information.hostname
                if 'system_information' in data and 'hostname' in data['system_information']:
                    hostname = data['system_information']['hostname']
                # Проверяем host_info.hostname 
                elif 'host_info' in data and 'hostname' in data['host_info']:
                    hostname = data['host_info']['hostname']
                # Проверяем meta.host_info.hostname
                elif 'meta' in data and 'host_info' in data['meta'] and 'hostname' in data['meta']['host_info']:
                    hostname = data['meta']['host_info']['hostname']
                # Используем имя файла как fallback
                elif file_path.name.startswith('MacBook-Pro-Mihail'):
                    hostname = 'MacBook-Pro-Mihail.local'
                else:
                    hostname = data.get('hostname', 'unknown')
                
                logger.info(f"Извлечен hostname: {hostname}")
                
                report_time = datetime.now(timezone.utc)
                netflow_message = data.get('netflow_message', {})
                flows = netflow_message.get('flows', [])
                
                logger.info(f"Найдено {len(flows)} NetFlow записей")
                
                # Обрабатываем каждый flow
                for flow in flows:
                    self.insert_connection(cursor, flow, hostname, report_time)
                
                # Обновляем статистику
                self.update_statistics(cursor, flows, hostname, report_time)
                
                conn.commit()
                logger.info(f"Успешно обработано {len(flows)} записей из {file_path}")
                return True
                
            except Exception as e:
                logger.error(f"Ошибка при обработке данных: {e}")
                conn.rollback()
                return False
            finally:
                cursor.close()
                conn.close()
                
        except Exception as e:
            logger.error(f"Ошибка при чтении файла {file_path}: {e}")
            logger.error(traceback.format_exc())
            return False

    def normalize_ip_address(self, addr: str) -> Optional[str]:
        """Нормализация IP адреса для PostgreSQL INET типа"""
        if not addr or addr == '*' or addr == 'unknown' or addr == 'system':
            return None
        
        # Проверяем на некорректные адреса
        if any(char in addr for char in ['(', ')', 'app', 'Contents', 'MacOS']):
            return None
            
        try:
            # Проверяем валидность IP адреса
            import ipaddress
            ipaddress.ip_address(addr)
            return addr
        except:
            return None

    def insert_connection(self, cursor, flow: Dict, hostname: str, report_time: datetime):
        """Вставка соединения в таблицу connections"""
        try:
            # Извлекаем данные из NetFlow записи
            source_addr = self.normalize_ip_address(flow.get('source_address', ''))
            dest_addr = self.normalize_ip_address(flow.get('destination_address', ''))
            source_port = flow.get('source_port', 0)
            dest_port = flow.get('destination_port', 0)
            protocol = flow.get('protocol_name', 'unknown').lower()
            packets = flow.get('packet_count', 0)
            bytes_count = flow.get('byte_count', 0)
            duration = flow.get('flow_duration', 0)
            
            # Извлекаем имя процесса из метаданных
            meta = flow.get('meta', {})
            process_name = meta.get('process', flow.get('original_process', 'unknown'))
            
            # Определяем направление соединения
            direction = meta.get('direction', 'unknown')
            if direction not in ['incoming', 'outgoing']:
                direction = 'unknown'  # Заменяем 'internal' и другие значения на 'unknown'
            
            # Вставляем в таблицу connections
            insert_query = """
            INSERT INTO connections (
                time, hostname, source_address, destination_address, 
                source_port, destination_port, protocol, direction,
                packet_count, byte_count, duration_ms, process_name
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """
            
            cursor.execute(insert_query, (
                report_time, hostname, source_addr, dest_addr,
                source_port, dest_port, protocol, direction,
                packets, bytes_count, duration, process_name
            ))
            
        except Exception as e:
            logger.error(f"Ошибка при вставке соединения: {e}")
            logger.error(f"Flow data: {flow}")

    def update_statistics(self, cursor, flows: List[Dict], hostname: str, report_time: datetime):
        """Обновление статистических таблиц"""
        try:
            # Статистика по протоколам
            protocol_stats = {}
            destination_stats = {}
            process_stats = {}
            
            for flow in flows:
                protocol = flow.get('protocol_name', 'unknown').lower()
                dest_addr = flow.get('destination_address', 'unknown')
                meta = flow.get('meta', {})
                process = meta.get('process', flow.get('original_process', 'unknown'))
                packets = flow.get('packet_count', 0)
                bytes_count = flow.get('byte_count', 0)
                
                # Статистика протоколов
                if protocol not in protocol_stats:
                    protocol_stats[protocol] = {'connections': 0, 'packets': 0, 'bytes': 0}
                protocol_stats[protocol]['connections'] += 1
                protocol_stats[protocol]['packets'] += packets
                protocol_stats[protocol]['bytes'] += bytes_count
                
                # Статистика назначений
                if dest_addr not in destination_stats:
                    destination_stats[dest_addr] = {'connections': 0, 'packets': 0, 'bytes': 0}
                destination_stats[dest_addr]['connections'] += 1
                destination_stats[dest_addr]['packets'] += packets
                destination_stats[dest_addr]['bytes'] += bytes_count
                
                # Статистика процессов
                if process not in process_stats:
                    process_stats[process] = {'connections': 0, 'packets': 0, 'bytes': 0}
                process_stats[process]['connections'] += 1
                process_stats[process]['packets'] += packets
                process_stats[process]['bytes'] += bytes_count
            
            # Вставляем статистику протоколов
            for protocol, stats in protocol_stats.items():
                cursor.execute("""
                INSERT INTO protocol_stats (time, hostname, protocol, connection_count, total_packets, total_bytes)
                VALUES (%s, %s, %s, %s, %s, %s)
                """, (report_time, hostname, protocol, stats['connections'], stats['packets'], stats['bytes']))
            
            # Вставляем топ назначений (топ 10)
            top_destinations = sorted(destination_stats.items(), key=lambda x: x[1]['connections'], reverse=True)[:10]
            for i, (dest_addr, stats) in enumerate(top_destinations, 1):
                normalized_dest = self.normalize_ip_address(dest_addr)
                if normalized_dest:  # Только если адрес валидный
                    cursor.execute("""
                    INSERT INTO top_destinations (time, hostname, destination_address, connection_count, total_bytes)
                    VALUES (%s, %s, %s, %s, %s)
                    """, (report_time, hostname, normalized_dest, stats['connections'], stats['bytes']))
            
            # Вставляем статистику процессов (топ 10)
            top_processes = sorted(process_stats.items(), key=lambda x: x[1]['connections'], reverse=True)[:10]
            for i, (process, stats) in enumerate(top_processes, 1):
                cursor.execute("""
                INSERT INTO process_stats (time, hostname, process_name, connection_count, total_bytes)
                VALUES (%s, %s, %s, %s, %s)
                """, (report_time, hostname, process, stats['connections'], stats['bytes']))
            
            # Общие системные метрики
            total_connections = len(flows)
            total_packets = sum(flow.get('packet_count', 0) for flow in flows)
            total_bytes = sum(flow.get('byte_count', 0) for flow in flows)
            unique_destinations = len(destination_stats)
            unique_processes = len(process_stats)
            
            cursor.execute("""
            INSERT INTO system_metrics (
                time, hostname, total_connections, unique_destinations, unique_processes
            ) VALUES (%s, %s, %s, %s, %s)
            """, (report_time, hostname, total_connections, unique_destinations, unique_processes))
            
            logger.info(f"Обновлена статистика: {len(protocol_stats)} протоколов, {len(top_destinations)} назначений, {len(top_processes)} процессов")
            
        except Exception as e:
            logger.error(f"Ошибка при обновлении статистики: {e}")
            logger.error(traceback.format_exc())

    def move_processed_file(self, file_path: Path) -> bool:
        """Перемещает обработанный файл в папку processed"""
        try:
            processed_file = self.processed_dir / f"{file_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
            
            # Используем copy + remove для работы между разными файловыми системами
            shutil.copy2(file_path, processed_file)
            file_path.unlink()  # Удаляем оригинальный файл
            
            logger.info(f"Файл перемещен: {file_path} -> {processed_file}")
            return True
        except Exception as e:
            logger.error(f"Ошибка при перемещении файла {file_path}: {e}")
            return False

    def watch_directory(self):
        """Основной цикл мониторинга директории"""
        logger.info(f"Начат мониторинг директории: {self.watch_dir}")
        
        while True:
            try:
                # Ищем YAML файлы
                yaml_files = list(self.watch_dir.glob("*.yaml")) + list(self.watch_dir.glob("*.yml"))
                
                if yaml_files:
                    logger.info(f"Найдено {len(yaml_files)} YAML файлов для обработки")
                    
                    for file_path in yaml_files:
                        if file_path.is_file():
                            if self.process_yaml_file(file_path):
                                self.move_processed_file(file_path)
                            else:
                                logger.error(f"Не удалось обработать файл: {file_path}")
                else:
                    logger.debug("YAML файлы не найдены")
                
                # Ждём перед следующей проверкой
                time.sleep(10)
                
            except KeyboardInterrupt:
                logger.info("Получен сигнал прерывания, завершение работы...")
                break
            except Exception as e:
                logger.error(f"Ошибка в цикле мониторинга: {e}")
                logger.error(traceback.format_exc())
                time.sleep(30)  # Ждём дольше при ошибке

    def test_connection(self) -> bool:
        """Тест подключения к базе данных"""
        conn = self.connect_db()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT version()")
                version = cursor.fetchone()[0]
                logger.info(f"Подключение к PostgreSQL успешно: {version}")
                cursor.close()
                conn.close()
                return True
            except Exception as e:
                logger.error(f"Ошибка при тестировании БД: {e}")
                return False
        return False


def main():
    """Основная функция"""
    logger.info("=== Запуск YAML процессора ===")
    
    processor = YAMLProcessor()
    
    # Тест подключения к БД
    if not processor.test_connection():
        logger.error("Не удалось подключиться к базе данных")
        return 1
    
    # Запуск мониторинга
    try:
        processor.watch_directory()
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        logger.error(traceback.format_exc())
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main()) 