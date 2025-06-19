#!/usr/bin/env python3
"""
Безопасный мониторинг сетевых соединений
Демонстрирует реализацию с учетом требований информационной безопасности
"""

import os
import time
import json
import hashlib
import logging
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
from cryptography.fernet import Fernet
import ipaddress


@dataclass
class SecurityConfig:
    """Конфигурация безопасности мониторинга"""
    # Права доступа
    required_capabilities: List[str] = None
    allowed_users: List[str] = None
    
    # Фильтрация данных
    allowed_processes: List[str] = None
    forbidden_processes: List[str] = None
    sensitive_keywords: List[str] = None
    
    # Шифрование
    encryption_key: Optional[bytes] = None
    data_retention_hours: int = 24
    
    # Аудит
    audit_enabled: bool = True
    audit_log_path: str = './network_monitor_audit.log'  # Локальный файл для демо
    
    # Rate limiting
    max_events_per_second: int = 100
    max_connections_to_track: int = 1000
    
    def __post_init__(self):
        if self.required_capabilities is None:
            self.required_capabilities = []
        if self.allowed_users is None:
            self.allowed_users = ['monitoring', 'security']
        if self.allowed_processes is None:
            self.allowed_processes = ['nginx', 'apache2', 'python3', 'node']
        if self.forbidden_processes is None:
            self.forbidden_processes = ['ssh', 'gpg', 'passwd', 'sudo']
        if self.sensitive_keywords is None:
            self.sensitive_keywords = ['password', 'key', 'token', 'secret', 'auth']
        if self.encryption_key is None:
            self.encryption_key = Fernet.generate_key()


class SecurityValidator:
    """Валидатор безопасности для операций мониторинга"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.audit_logger = self._setup_audit_logger()
        self.cipher = Fernet(config.encryption_key)
    
    def _setup_audit_logger(self) -> logging.Logger:
        """Настройка аудит-логгера"""
        logger = logging.getLogger('security_audit')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.FileHandler(self.config.audit_log_path)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def validate_user_permissions(self) -> bool:
        """Проверяет права пользователя"""
        try:
            current_user = os.getenv('USER') or os.getenv('USERNAME')
            if current_user not in self.config.allowed_users:
                self.audit_logger.warning(
                    f"Unauthorized user attempted monitoring: {current_user}"
                )
                return False
            
            self.audit_logger.info(f"User {current_user} authorized for monitoring")
            return True
        except Exception as e:
            self.audit_logger.error(f"Permission validation error: {e}")
            return False
    
    def validate_process_monitoring(self, process_name: str) -> bool:
        """Проверяет разрешение на мониторинг процесса"""
        if process_name in self.config.forbidden_processes:
            self.audit_logger.warning(
                f"Attempted to monitor forbidden process: {process_name}"
            )
            return False
        
        if self.config.allowed_processes and process_name not in self.config.allowed_processes:
            self.audit_logger.info(
                f"Process not in allowed list: {process_name}"
            )
            return False
        
        return True
    
    def sanitize_connection_data(self, connection_data: Dict) -> Dict:
        """Очищает данные соединения от чувствительной информации"""
        sanitized = connection_data.copy()
        
        # Маскируем приватные IP адреса
        for key in ['source_ip', 'dest_ip', 'local_addr', 'remote_addr']:
            if key in sanitized:
                sanitized[key] = self._mask_private_ip(sanitized[key])
        
        # Фильтруем чувствительные аргументы
        if 'process_args' in sanitized:
            sanitized['process_args'] = self._filter_sensitive_args(
                sanitized['process_args']
            )
        
        # Хешируем некоторые идентификаторы
        if 'process_id' in sanitized:
            sanitized['process_id_hash'] = self._hash_sensitive_data(
                str(sanitized['process_id'])
            )
            del sanitized['process_id']
        
        return sanitized
    
    def _mask_private_ip(self, ip_str: str) -> str:
        """Маскирует приватные IP адреса"""
        try:
            # Извлекаем IP из строки вида "192.168.1.1:8080"
            ip_part = ip_str.split(':')[0] if ':' in ip_str else ip_str
            ip = ipaddress.ip_address(ip_part)
            
            if ip.is_private:
                # Маскируем последний октет для IPv4
                if ip.version == 4:
                    masked = '.'.join(ip_part.split('.')[:-1] + ['XXX'])
                else:
                    masked = '[IPv6_PRIVATE]'
                
                # Добавляем порт обратно, если он был
                if ':' in ip_str:
                    port = ip_str.split(':', 1)[1]
                    return f"{masked}:{port}"
                return masked
            
            return ip_str
        except Exception:
            return '[INVALID_IP]'
    
    def _filter_sensitive_args(self, args: str) -> str:
        """Фильтрует чувствительные аргументы командной строки"""
        for keyword in self.config.sensitive_keywords:
            if keyword.lower() in args.lower():
                return '[CONTAINS_SENSITIVE_DATA]'
        return args
    
    def _hash_sensitive_data(self, data: str) -> str:
        """Создает хеш для чувствительных данных"""
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def encrypt_data(self, data: Dict) -> str:
        """Шифрует данные для хранения"""
        json_data = json.dumps(data, sort_keys=True)
        encrypted = self.cipher.encrypt(json_data.encode())
        return encrypted.decode()
    
    def decrypt_data(self, encrypted_data: str) -> Dict:
        """Расшифровывает данные"""
        try:
            decrypted = self.cipher.decrypt(encrypted_data.encode())
            return json.loads(decrypted.decode())
        except Exception as e:
            self.audit_logger.error(f"Decryption failed: {e}")
            return {}


class RateLimiter:
    """Ограничитель скорости для предотвращения DoS"""
    
    def __init__(self, max_events_per_second: int):
        self.max_events = max_events_per_second
        self.events_timestamps = []
        self.lock = threading.Lock()
    
    def can_process_event(self) -> bool:
        """Проверяет, можно ли обработать событие"""
        with self.lock:
            current_time = time.time()
            
            # Удаляем старые события (старше 1 секунды)
            self.events_timestamps = [
                ts for ts in self.events_timestamps 
                if current_time - ts < 1.0
            ]
            
            # Проверяем лимит
            if len(self.events_timestamps) >= self.max_events:
                return False
            
            # Добавляем текущее событие
            self.events_timestamps.append(current_time)
            return True


class SecureNetworkMonitor:
    """Безопасный мониторинг сетевых соединений"""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.validator = SecurityValidator(config)
        self.rate_limiter = RateLimiter(config.max_events_per_second)
        self.monitoring_active = False
        self.connections_cache = {}
        self.last_cleanup = time.time()
    
    def start_secure_monitoring(self, duration_seconds: int = 60) -> Dict:
        """Запускает безопасный мониторинг"""
        # 1. Проверка разрешений
        if not self.validator.validate_user_permissions():
            raise PermissionError("User not authorized for monitoring")
        
        # 2. Аудит начала мониторинга
        self.validator.audit_logger.info(
            f"Starting secure monitoring for {duration_seconds} seconds"
        )
        
        # 3. Запуск мониторинга
        self.monitoring_active = True
        start_time = time.time()
        collected_data = []
        
        try:
            while time.time() - start_time < duration_seconds and self.monitoring_active:
                # Rate limiting
                if not self.rate_limiter.can_process_event():
                    time.sleep(0.01)  # 10ms пауза при превышении лимита
                    continue
                
                # Сбор данных
                connections = self._collect_secure_connections()
                for conn in connections:
                    # Валидация каждого соединения
                    if self._validate_connection(conn):
                        sanitized_conn = self.validator.sanitize_connection_data(conn)
                        collected_data.append(sanitized_conn)
                
                # Периодическая очистка кеша
                if time.time() - self.last_cleanup > 300:  # Каждые 5 минут
                    self._cleanup_old_data()
                    self.last_cleanup = time.time()
                
                time.sleep(1)  # Пауза между сборами данных
        
        finally:
            self.monitoring_active = False
            self.validator.audit_logger.info("Secure monitoring stopped")
        
        # 4. Анализ и шифрование результатов
        analysis = self._analyze_secure_data(collected_data)
        encrypted_results = self.validator.encrypt_data(analysis)
        
        # 5. Аудит завершения
        self.validator.audit_logger.info(
            f"Monitoring completed. Collected {len(collected_data)} connections"
        )
        
        return {
            'status': 'completed',
            'duration': time.time() - start_time,
            'connections_count': len(collected_data),
            'encrypted_data': encrypted_results,
            'security_events': self._get_security_events()
        }
    
    def _collect_secure_connections(self) -> List[Dict]:
        """Безопасный сбор данных о соединениях"""
        connections = []
        
        try:
            # Используем безопасный метод получения соединений
            result = subprocess.run(
                ['netstat', '-tn'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            for line in result.stdout.split('\n')[1:]:
                if 'ESTABLISHED' in line and 'tcp' in line.lower():
                    conn_data = self._parse_netstat_line(line)
                    if conn_data:
                        connections.append(conn_data)
            
        except subprocess.TimeoutExpired:
            self.validator.audit_logger.warning("Connection collection timeout")
        except Exception as e:
            self.validator.audit_logger.error(f"Connection collection error: {e}")
        
        return connections[:self.config.max_connections_to_track]
    
    def _parse_netstat_line(self, line: str) -> Optional[Dict]:
        """Парсит строку netstat в безопасном режиме"""
        try:
            parts = line.split()
            if len(parts) >= 5:
                return {
                    'protocol': parts[0],
                    'local_addr': parts[3],
                    'remote_addr': parts[4],
                    'state': parts[5] if len(parts) > 5 else 'UNKNOWN',
                    'timestamp': datetime.now().isoformat(),
                    'collection_method': 'netstat'
                }
        except Exception as e:
            self.validator.audit_logger.warning(f"Failed to parse netstat line: {e}")
        
        return None
    
    def _validate_connection(self, connection: Dict) -> bool:
        """Валидирует соединение с точки зрения безопасности"""
        # Проверяем, не является ли это соединением с запрещенными процессами
        process_name = connection.get('process_name', 'unknown')
        if not self.validator.validate_process_monitoring(process_name):
            return False
        
        # Проверяем на подозрительные порты
        remote_addr = connection.get('remote_addr', '')
        if self._is_suspicious_connection(remote_addr):
            self.validator.audit_logger.warning(
                f"Suspicious connection detected: {remote_addr}"
            )
            # Не блокируем, но отмечаем в логах
        
        return True
    
    def _is_suspicious_connection(self, remote_addr: str) -> bool:
        """Проверяет подозрительность соединения"""
        try:
            if ':' in remote_addr:
                ip, port = remote_addr.rsplit(':', 1)
                port_num = int(port)
                
                # Проверяем подозрительные порты
                suspicious_ports = {1337, 31337, 4444, 5555, 6666, 8888}
                if port_num in suspicious_ports:
                    return True
                
                # Проверяем необычные высокие порты
                if port_num > 65000:
                    return True
        
        except Exception:
            pass
        
        return False
    
    def _cleanup_old_data(self):
        """Очищает старые данные согласно политике хранения"""
        current_time = time.time()
        retention_seconds = self.config.data_retention_hours * 3600
        
        # Очищаем кеш соединений
        old_keys = []
        for key, data in self.connections_cache.items():
            if current_time - data.get('timestamp', 0) > retention_seconds:
                old_keys.append(key)
        
        for key in old_keys:
            del self.connections_cache[key]
        
        self.validator.audit_logger.info(f"Cleaned up {len(old_keys)} old entries")
    
    def _analyze_secure_data(self, connections: List[Dict]) -> Dict:
        """Анализирует собранные данные с учетом безопасности"""
        analysis = {
            'summary': {
                'total_connections': len(connections),
                'unique_destinations': len(set(
                    conn.get('remote_addr', '').split(':')[0] 
                    for conn in connections 
                    if conn.get('remote_addr')
                )),
                'protocols': defaultdict(int),
                'suspicious_count': 0
            },
            'security_insights': [],
            'connections_sample': connections[:10],  # Только первые 10 для демонстрации
            'metadata': {
                'collection_time': datetime.now().isoformat(),
                'data_retention_policy': f"{self.config.data_retention_hours}h",
                'security_level': 'high'
            }
        }
        
        # Анализ протоколов
        for conn in connections:
            protocol = conn.get('protocol', 'unknown')
            analysis['summary']['protocols'][protocol] += 1
            
            # Подсчет подозрительных соединений
            if self._is_suspicious_connection(conn.get('remote_addr', '')):
                analysis['summary']['suspicious_count'] += 1
        
        # Безопасностные инсайты
        if analysis['summary']['suspicious_count'] > 0:
            analysis['security_insights'].append({
                'type': 'suspicious_activity',
                'count': analysis['summary']['suspicious_count'],
                'recommendation': 'Review suspicious connections manually'
            })
        
        return analysis
    
    def _get_security_events(self) -> List[Dict]:
        """Возвращает события безопасности"""
        # В реальной реализации здесь был бы анализ логов аудита
        return [
            {
                'type': 'monitoring_session',
                'timestamp': datetime.now().isoformat(),
                'status': 'completed',
                'security_level': 'high'
            }
        ]
    
    def stop_monitoring(self):
        """Безопасная остановка мониторинга"""
        self.monitoring_active = False
        self.validator.audit_logger.info("Monitoring stop requested")


def demonstrate_secure_monitoring():
    """Демонстрация безопасного мониторинга"""
    print("🔒 ДЕМОНСТРАЦИЯ БЕЗОПАСНОГО МОНИТОРИНГА СЕТЕВЫХ СОЕДИНЕНИЙ")
    print("=" * 60)
    
    # Конфигурация безопасности
    config = SecurityConfig(
        allowed_users=['monitoring', 'security', os.getenv('USER', 'unknown')],
        allowed_processes=['python3', 'nginx', 'node', 'chrome', 'firefox'],
        data_retention_hours=1,  # Короткое время для демо
        max_events_per_second=50,
        audit_enabled=True
    )
    
    print(f"✅ Конфигурация безопасности:")
    print(f"   - Разрешенные пользователи: {config.allowed_users}")
    print(f"   - Время хранения данных: {config.data_retention_hours}ч")
    print(f"   - Лимит событий/сек: {config.max_events_per_second}")
    print(f"   - Аудит включен: {config.audit_enabled}")
    
    # Инициализация безопасного монитора
    try:
        monitor = SecureNetworkMonitor(config)
        print(f"\n🔍 Запуск безопасного мониторинга на 10 секунд...")
        
        results = monitor.start_secure_monitoring(duration_seconds=10)
        
        print(f"\n📊 РЕЗУЛЬТАТЫ:")
        print(f"   Статус: {results['status']}")
        print(f"   Продолжительность: {results['duration']:.1f}с")
        print(f"   Соединений собрано: {results['connections_count']}")
        print(f"   Безопасностных событий: {len(results['security_events'])}")
        
        # Расшифровываем результаты для демонстрации
        if results['encrypted_data']:
            print(f"\n🔐 Данные зашифрованы и безопасно сохранены")
            print(f"   Размер зашифрованных данных: {len(results['encrypted_data'])} символов")
            
            # Демонстрируем расшифровку (в продакшене этого не было бы)
            try:
                decrypted = monitor.validator.decrypt_data(results['encrypted_data'])
                summary = decrypted.get('summary', {})
                print(f"\n📈 Краткий анализ (расшифрованный):")
                print(f"   - Всего соединений: {summary.get('total_connections', 0)}")
                print(f"   - Уникальных назначений: {summary.get('unique_destinations', 0)}")
                print(f"   - Подозрительных соединений: {summary.get('suspicious_count', 0)}")
                
                protocols = summary.get('protocols', {})
                if protocols:
                    print(f"   - Протоколы: {dict(protocols)}")
                
            except Exception as e:
                print(f"   ⚠️ Не удалось расшифровать для демонстрации: {e}")
        
        print(f"\n🛡️ События безопасности:")
        for event in results['security_events']:
            print(f"   - {event['type']}: {event['status']} ({event['timestamp']})")
        
        print(f"\n📋 Лог аудита создан: {config.audit_log_path}")
        
    except PermissionError as e:
        print(f"❌ Ошибка прав доступа: {e}")
        print(f"💡 Убедитесь, что пользователь {os.getenv('USER')} в списке разрешенных")
        
    except Exception as e:
        print(f"❌ Ошибка мониторинга: {e}")
    
    print(f"\n" + "=" * 60)
    print(f"✅ Демонстрация безопасного мониторинга завершена")


if __name__ == '__main__':
    demonstrate_secure_monitoring() 