# 🔍 Glacier v2.3.0

Мониторинг сетевой активности с автоматической генерацией YAML/HTML отчетов. Поддержка кумулятивных отчетов, S3 интеграции и стандартной сборки для Linux дистрибутивов.

## 🏗️ Архитектура

```
glacier.py (Главный оркестратор)
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

## 🏗️ Стандартная сборка

Единый бинарник, совместимый со всеми основными Linux дистрибутивами:

### ✅ Поддерживаемые ОС
- **CentOS/RHEL**: 7, 8, 9
- **Ubuntu**: 18.04+, 20.04+, 22.04+, 24.04+
- **Debian**: 9+, 10+, 11+, 12+
- **SUSE**: Enterprise 12+, 15+
- **Amazon Linux**: 2, 2023
- **Oracle Linux**: 7+, 8+, 9+

### 🔧 Требования
- **glibc**: 2.17+ (CentOS 7+)
- **Архитектура**: x86_64
- **Память**: минимум 512MB RAM

### 📦 Установка
```bash
# Загрузка из GitHub Releases
curl -L -o glacier-$VERSION https://github.com/i8megabit/glacier/releases/download/v$VERSION/glacier

# Права выполнения
chmod +x glacier

# Проверка
./glacier --help
```

**📖 Документация:** [BUILD_ARCHITECTURE.md](docs/BUILD_ARCHITECTURE.md)

## 🚀 Запуск

```bash
# Быстрый тест
python3 tests/quicktest.py

# Базовый анализ
python3 src/glacier.py -w 30 -t 5

# С root правами (полные данные)
sudo python3 src/glacier.py -w 60 -t 5

# Локальное тестирование  
python3 test_local_only.py

# Кросс-платформенное тестирование
python3 test_cross_platform.py
```

## 📊 Результат

- Всегда создает оба отчета:
  - 📄 `{hostname}_{os}_glacier.yaml` — кумулятивные данные
  - 🌐 `{hostname}_{os}_glacier.html` — интерактивный веб-отчет
- ☁️ Автоматическая загрузка в S3 (при настройке переменных окружения)

## ✨ Функции

- 🔍 **Сетевые соединения** — TCP/UDP с процессами
- 📊 **Мониторинг портов** — открытые порты и сервисы  
- 🖥️ **Системная информация** — ОС, память, диски, пользователи
- 🐳 **Docker интеграция** — информация о контейнерах
- 🛡️ **Анализ файрвола** — все найденные правила
- 👥 **Пользователи системы** — активные сессии
- 📈 **Кумулятивные отчеты** — накопление данных
- 🎨 **Chart.js диаграммы** — интерактивные графики
- ☁️ **S3 интеграция** — автоматическая загрузка
- 🔄 **UDP трекер** — специальный модуль для UDP
- 🏗️ **Стандартная сборка** — единый бинарник
- 🚀 **Альтернативные методы** — работа без root

## 📋 Параметры

```bash
python3 src/glacier.py [параметры]

| Параметр      | Описание                    | По умолчанию |
| ------------- | --------------------------- | ------------ |
| `-w, --wait`  | Время между измерениями (сек) | `10`   | 
| `-t, --times` | Количество измерений          | `1`    | 
| `--no-s3`     | Отключить загрузку в S3       | `false`| 
| `--force-s3`  | Принудительная загрузка в S3  | `false`| 
| `-v`          | Показать версию               | -      |
```

### 💡 Примеры

```bash
# Быстрая диагностика (5 секунд)
python3 src/glacier.py -w 5 -t 1

# 30 измерений по минуте
sudo python3 src/glacier.py -w 60 -t 30

# 10 измерений по 30 сек
sudo python3 src/glacier.py -w 30 -t 10
```

## 🎨 HTML отчет

Интерактивный веб-интерфейс с навигацией по 10 секциям:

### 📊 Секции
- **📈 Обзор** — диаграммы и статистика
- **🔗 Соединения** — таблица TCP/UDP соединений  
- **🚪 Порты** — открытые TCP и UDP порты
- **📡 UDP трафик** — детальная информация UDP
- **📝 История изменений** — временная шкала
- **🖥️ Хост** — информация о системе
- **💻 Система** — данные об ОС
- **📈 Статистика** — метрики измерений
 - **🔧 О программе** — информация о Glacier
- **🛡️ Правила файрвола** — все обнаруженные правила

### 📊 Диаграммы
- **🍩 Doughnut Chart** — распределение TCP/UDP
- **🥧 Pie Chart** — направление соединений
- **📊 Bar Chart** — топ процессы
- **📈 Line Chart** — активность по времени
- **📏 Progress Bars** — статистика с анимацией

## 🔧 Собираемые данные

### 🌐 Сетевая информация
- **TCP соединения** со статусом ESTABLISHED
- **UDP соединения** и DNS трафик
- **Открытые порты** (TCP listening, UDP active)
- **Процессы** с сетевой активностью и PID
- **Удаленные хосты** и IP адреса

### 🖥️ Системная информация
- **Процессор** (количество ядер)
- **Память** (общий объем в ГБ)
- **Диски** (использование, свободное место, ФС)
- **Время работы** (boot time, uptime)
- **ОС** (название, версия, архитектура)

### 🛡️ Безопасность
- **Файрвол** (UFW, iptables, firewalld)
- **Все правила файрвола** показываются полностью
- **Docker** (статус, количество контейнеров)
- **Пользователи** (активные с UID >= 500/1000)

### 📊 Кумулятивные данные
- **История измерений** с временными метками
- **Журнал изменений** по категориям
- **Статистика** (продолжительность, изменения)
- **Накопленные данные** за все запуски

## ☁️ S3 Интеграция

Автоматическая загрузка отчетов в S3-совместимое хранилище.

### 🔧 Настройка

**1. Переменные окружения:**
```bash
export S3_ENDPOINT_URL="https://your-s3-endpoint.com"
export S3_ACCESS_KEY_ID="your-access-key"
export S3_ACCESS_SECRET_KEY="your-secret-key"
```

**2. Запуск:**
```bash
# Автоматическая загрузка по расписанию (8:00)
python3 src/glacier.py -w 2 -t 1

# Принудительная загрузка сразу
python3 src/glacier.py -w 2 -t 1 --force-s3

# Без загрузки в S3
python3 src/glacier.py -w 2 -t 1 --no-s3
```

### 📂 Структура в S3
```
s3://glacier/
└── reports/
    ├── hostname_darwin_glacier.yaml
    └── hostname_darwin_glacier.html
```

**Поддерживаемые провайдеры:** Amazon S3, MinIO, Yandex Object Storage, DigitalOcean Spaces, Wasabi

📖 **Документация:** [S3_SETUP.md](docs/S3_SETUP.md)

## 🔄 Кумулятивные отчеты

Накопление данных в одном файле:

```yaml
hostname: server.example.com
os: {name: Linux, version: 5.4.0}
first_run: "2025-05-29 10:43:17"
last_update: "2025-05-29 11:02:06"
measurements: 15
total_duration: 900
statistics:
  total_connections: 156
  unique_processes: 23
  changes_detected: 8
```

## 🔍 NetFlow v9 поддержка

Полное соответствие **RFC 3954**:

### 📋 NetFlow структура
```yaml
netflow_data:
  header:
    version: 9
    count: 145
    sys_uptime: 1234567
    unix_secs: 1735123456
    sequence_number: 1
    source_id: 1
  templates:
    - template_id: 256
      field_count: 7
      field_specs: [...]
  flows:
    - ipv4_src_addr: "192.168.1.100"
      ipv4_dst_addr: "93.184.216.34"
      l4_src_port: 54321
      l4_dst_port: 443
      protocol: 6
```

### ✅ Соответствие стандарту
- **Template Records** — описание структуры данных
- **Data Records** — соединения в NetFlow формате
- **Временные метки** — FIRST_SWITCHED, LAST_SWITCHED
- **Стандартные поля** — IN_BYTES, IN_PKTS, PROTOCOL

## 🧪 Тестирование

```bash
# Быстрый тест
python3 tests/quicktest.py

# Локальные тесты
python3 test_local_only.py

# Кросс-платформенные тесты
python3 test_cross_platform.py

# Тестирование UDP трекера
python3 -c "from src.udp_tracker_module import test_udp_tracker; test_udp_tracker()"

# Тестирование ICMP трекера
python3 -c "from src.icmp_tracker import test_icmp_tracker; test_icmp_tracker()"
```

## 📚 Документация

- 🏗️ [ARCHITECTURE.md](docs/ARCHITECTURE.md) — архитектура приложения
- ☁️ [S3_SETUP.md](docs/S3_SETUP.md) — настройка S3 интеграции
- 🚀 [ENHANCED_FEATURES.md](docs/ENHANCED_FEATURES.md) — расширенные функции
- ⚔️ [BATTLE_GUIDE.md](docs/BATTLE_GUIDE.md) — руководство по устранению неполадок

## 🔧 Требования

```bash
# Python зависимости
pip install -r requirements.txt

# Основные:
# - psutil>=5.9.0
# - PyYAML>=6.0
# - boto3>=1.26.0 (для S3)
# - distro>=1.8.0
```
