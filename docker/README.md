# 🐳 Кроссплатформенное тестирование Glacier v2.3.0

Тестирования Glacier на различных операционных системах с использованием Docker.

## 🎯 Поддерживаемые платформы

- **🍎 macOS** (нативное тестирование)
- **🐧 Ubuntu 20.04** (через Docker)
- **🐧 Debian 11** (через Docker)
- **🔴 CentOS 7** (через Docker)

## 📋 Требования

### Для полного тестирования:
- Docker Desktop или Docker Engine
- Python 3.6+
- Права на запуск Docker команд

### Для локального тестирования:
- Python 3.6+
- Зависимости из `requirements.txt`

## 🚀 Запуск тестов

### Полное кроссплатформенное тестирование
```bash
# Запуск всех тестов (macOS + Docker)
python3 test_cross_platform.py
```

### Быстрое тестирование
```bash
# Рекомендуемый быстрый тест
python3 tests/quicktest.py

# Локальный тест с детальным выводом
python3 test_local_only.py
```

### Ручное тестирование в Docker

#### Ubuntu 20.04
```bash
# Сборка образа
docker build -f docker/Dockerfile.ubuntu20 -t analyzer-ubuntu20 .

# Запуск теста
docker run --rm analyzer-ubuntu20

# Интерактивный режим
docker run --rm -it analyzer-ubuntu20 /bin/bash
```

#### Debian 11
```bash
# Сборка образа
docker build -f docker/Dockerfile.debian11 -t analyzer-debian11 .

# Запуск теста
docker run --rm analyzer-debian11

# Интерактивный режим
docker run --rm -it analyzer-debian11 /bin/bash
```

#### CentOS 7
```bash
# Сборка образа
docker build -f docker/Dockerfile.centos7 -t analyzer-centos7 .

# Запуск теста
docker run --rm analyzer-centos7

# Интерактивный режим
docker run --rm -it analyzer-centos7 /bin/bash
```

## 📁 Структура результатов

Все результаты тестирования сохраняются в папке `result/`:

```
result/
├── macos_20250529_123456/          # Результаты macOS
│   ├── MacBook-Pro-Mihail.local_darwin_report_analyzer.yaml
│   └── MacBook-Pro-Mihail.local_darwin_report_analyzer.html
├── ubuntu20_reports/               # Результаты Ubuntu 20.04
│   └── src/
│       ├── ubuntu_hostname_linux_report_analyzer.yaml
│       └── ubuntu_hostname_linux_report_analyzer.html
├── debian11_reports/               # Результаты Debian 11
│   └── src/
│       ├── debian_hostname_linux_report_analyzer.yaml
│       └── debian_hostname_linux_report_analyzer.html
├── centos7_reports/                # Результаты CentOS 7
│   └── src/
│       ├── centos_hostname_linux_report_analyzer.yaml
│       └── centos_hostname_linux_report_analyzer.html
└── test_summary_20250529_123456.txt # Итоговый отчет
```

## 🔍 Что тестируется

### Основная функциональность
- ✅ Запуск Glacier без ошибок (команда: `python3 src/glacier.py -w 10 -t 2`)
- ✅ Генерация YAML отчета (кумулятивного)
- ✅ Генерация HTML отчета (с Chart.js диаграммами)
- ✅ Сбор сетевых соединений (TCP/UDP)
- ✅ Анализ системных ресурсов
- ✅ Работа альтернативных методов (lsof, netstat, ss)
- ✅ Информация о хосте (Docker, файрвол, пользователи)

### Совместимость
- ✅ Python 3.6+ на всех платформах
- ✅ Зависимости устанавливаются корректно
- ✅ Системные команды доступны
- ✅ Права доступа достаточны для базового функционала
- ✅ Альтернативные методы сбора при недостатке прав

## 📊 Интерпретация результатов

### Статусы тестов
- **✅ success** - Тест пройден успешно
- **⚠️ skipped** - Тест пропущен (например, нет Docker)
- **❌ failed** - Тест не пройден
- **⏰ timeout** - Превышено время ожидания (>300 секунд)
- **🔨 build_failed** - Ошибка сборки Docker образа

### Метрики
- **duration** - Время выполнения теста (секунды)
- **output_lines** - Количество строк вывода
- **yaml_files** - Количество YAML отчетов
- **html_files** - Количество HTML отчетов
- **file_sizes** - Размеры созданных файлов

### Ожидаемые результаты
**Успешный тест должен создать:**
- 📄 YAML файл (размер ~5-20 KB)
- 🌐 HTML файл (размер ~100-150 KB с Chart.js)
- ✅ Вывод без критических ошибок
- ⏱️ Выполнение за 10-60 секунд

## 🛠️ Устранение проблем

### Docker не найден
```bash
# Установка Docker на macOS
brew install docker

# Установка Docker на Ubuntu/Debian
sudo apt-get update
sudo apt-get install docker.io

# Установка Docker на CentOS/RHEL
sudo yum install docker
sudo systemctl start docker
```

### Ошибки прав доступа
```bash
# Добавление пользователя в группу docker
sudo usermod -aG docker $USER

# Перезапуск сессии или перелогин
newgrp docker
```

### Ошибки сборки образа
```bash
# Очистка Docker кэша
docker system prune -a

# Принудительная пересборка Ubuntu 20.04
docker build --no-cache -f docker/Dockerfile.ubuntu20 -t analyzer-ubuntu20 .

# Принудительная пересборка Debian 11
docker build --no-cache -f docker/Dockerfile.debian11 -t analyzer-debian11 .
```

### Проблемы с зависимостями
```bash
# Обновление pip в контейнере
python3 -m pip install --upgrade pip

# Проверка установленных зависимостей
pip3 list | grep psutil
pip3 list | grep python-dateutil
```

### Ошибки сети в контейнере
```bash
# Проверка доступности сетевых команд
which lsof
which netstat  
which ss

# Тест базовой функциональности psutil
python3 -c "import psutil; print('psutil OK:', psutil.__version__)"
```

## 🔧 Настройка тестов

### Изменение параметров Glacier
В файлах `test_cross_platform.py` и Dockerfile:
```bash
# Текущие параметры
python3 src/glacier.py -w 10 -t 2

# Для более быстрого тестирования
python3 src/glacier.py -w 5 -t 1

# Для более детального анализа
python3 src/glacier.py -w 30 -t 3
```

### Добавление новой платформы
1. Создать `docker/Dockerfile.newplatform`
2. Добавить в `test_cross_platform.py`:
```python
def test_newplatform(self):
    return self.test_docker_platform('newplatform')
```
3. Обновить список платформ в `main()`

### Настройка timeout'ов
```python
# В test_cross_platform.py
DOCKER_TIMEOUT = 300  # 5 минут на Docker тест
BUILD_TIMEOUT = 600   # 10 минут на сборку образа
```

## 📝 Логи и отладка

### Подробные логи Docker
```bash
# Запуск с выводом всех этапов сборки
docker build --progress=plain -f docker/Dockerfile.ubuntu20 -t analyzer-ubuntu20 .
```

### Отладка в контейнере
```bash
# Запуск интерактивной оболочки Ubuntu
docker run --rm -it analyzer-ubuntu20 /bin/bash

# Ручной запуск Glacier с выводом
cd /analyzer
python3 src/glacier.py -w 5 -t 1

# Проверка создания файлов
ls -la *.yaml *.html
```

### Проверка системных возможностей
```bash
# Внутри контейнера - проверка команд
lsof -v          # Версия lsof
netstat --version # Версия netstat
ss --version     # Версия ss (iproute2)

# Проверка Python зависимостей
python3 -c "
import psutil
import platform
print(f'Platform: {platform.system()} {platform.release()}')
print(f'psutil: {psutil.__version__}')
print(f'CPU count: {psutil.cpu_count()}')
"
```

### Анализ размеров отчетов
```bash
# Проверка размеров файлов
ls -lh *.yaml *.html

# Ожидаемые размеры:
# YAML: 5-50 KB (зависит от количества соединений)
# HTML: 100-150 KB (включает Chart.js код)
```

## 🎯 Цели тестирования

1. **✅ Совместимость** - Анализатор работает на всех целевых ОС
2. **✅ Функциональность** - Все основные функции работают корректно
3. **✅ Производительность** - Приемлемое время выполнения (<60 сек)
4. **✅ Надежность** - Graceful handling ошибок и недостатка прав
5. **✅ Регрессии** - Предотвращение поломки функционала при обновлениях
6. **✅ Качество отчетов** - YAML и HTML отчеты создаются корректно
7. **✅ Кумулятивность** - Система накопления данных работает