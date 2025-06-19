# 📊 Руководство по YAML процессору и дашбордам Grafana

## 🎯 Обзор

YAML процессор автоматически обрабатывает отчеты анализатора и загружает данные в PostgreSQL для визуализации в Grafana. Система поддерживает группировку по хостам и автоматическое обновление дашбордов.

## 🚀 Быстрый старт

### 1. Запуск системы

```bash
# Запуск всех сервисов (PostgreSQL, Redis, Grafana, YAML процессор)
cd analyzer
docker-compose -f grafana/docker-compose.grafana.yml up -d

# Проверка статуса
docker-compose -f grafana/docker-compose.grafana.yml ps
```

### 2. Генерация отчета

```bash
# Генерация YAML отчета анализатором
python3 src/glacier.py --no-s3

# Результат: MacBook-Pro-Mihail.local_darwin_report_analyzer.yaml
```

### 3. Загрузка отчета

```bash
# Копирование YAML файла для обработки
docker cp MacBook-Pro-Mihail.local_darwin_report_analyzer.yaml analyzer-yaml-processor:/app/reports/

# Файл автоматически обработается и переместится в /data/processed/
```

## 📁 Структура файлов

```
grafana/
├── docker-compose.grafana.yml          # Основной файл Docker Compose
├── grafana/
│   ├── dashboards/                     # Дашборды Grafana
│   │   ├── analyzer-overview.json      # Обзорный дашборд
│   │   ├── advanced-network-dashboard.json  # Продвинутый сетевой анализ
│   │   └── security-analysis-dashboard.json # Анализ безопасности
│   └── provisioning/                   # Конфигурация Grafana
│       ├── dashboards/dashboards.yml   # Настройки дашбордов
│       └── datasources/datasources.yml # Источники данных
├── yaml-processor/
│   ├── yaml_processor.py              # Основной код процессора
│   ├── requirements.txt               # Зависимости Python
│   └── Dockerfile                     # Образ контейнера
├── data/
│   ├── uploads/                       # Папка для загрузки файлов
│   └── processed/                     # Обработанные файлы
└── database/
    └── init/                          # SQL скрипты инициализации
```

## 🔄 Как работает YAML процессор

### Автоматическая обработка

1. **Мониторинг папки**: Процессор следит за папкой `/app/reports/` каждые 10 секунд
2. **Обнаружение файлов**: Ищет файлы с расширением `.yaml` и `.yml`
3. **Извлечение данных**: Парсит NetFlow данные и системную информацию
4. **Извлечение hostname**: Автоматически определяет hostname из:
   - `system_information.hostname`
   - `host_info.hostname`
   - `meta.host_info.hostname`
   - Имени файла (fallback)
5. **Загрузка в БД**: Сохраняет данные в PostgreSQL
6. **Архивирование**: Перемещает обработанный файл в `/data/processed/`

### Структура данных

Процессор создает следующие таблицы:

- **connections** - Основные сетевые соединения
- **protocol_stats** - Статистика по протоколам
- **top_destinations** - Топ назначений
- **process_stats** - Статистика процессов
- **system_metrics** - Общие метрики системы

## 📊 Дашборды Grafana

-### 1. Glacier Overview Dashboard
- **URL**: http://localhost:3000/d/glacier-overview
- **Описание**: Базовая статистика соединений
- **Панели**: График соединений по времени

### 2. Advanced Network Dashboard  
- **URL**: http://localhost:3000/d/advanced_network_dashboard
- **Описание**: Детальный анализ сетевого трафика
- **Панели**:
  - 🌐 Трафик по протоколам
  - 📊 Распределение протоколов
  - 🔗 Общее количество соединений
  - 🌍 Уникальные хосты
  - ⚙️ Активные процессы
  - 📈 Передача данных
  - 🎯 Топ назначений
  - 📊 Использование пропускной способности
  - 🕐 Тепловая карта активности

### 3. Security Analysis Dashboard
- **URL**: http://localhost:3000/d/security_soc_dashboard  
- **Описание**: Анализ безопасности и обнаружение угроз
- **Панели**:
  - 🚨 ICMP флуды
  - 🕵️ Подозрительные IP
  - 🔒 Попытки брутфорса
  - 🔍 Сканирование портов
  - 📤 Потенциальная утечка данных
  - ⚠️ Необычная активность портов
  - 🚨 Высокорисковая активность
  - 📈 Временная шкала угроз

## 🏷️ Фильтрация по хостам

### Переменная Hostname

Все дашборды поддерживают фильтрацию по hostname:

1. **Выпадающий список**: В верхней части каждого дашборда
2. **Опции**:
   - `All` - Показать данные всех хостов
   - Конкретный hostname (например, `MacBook-Pro-Mihail.local`)
3. **Автообновление**: Список хостов обновляется автоматически

### Использование

1. Откройте любой дашборд
2. В верхней части найдите выпадающий список "Hostname"
3. Выберите нужный хост или оставьте "All"
4. Все панели автоматически отфильтруются

## 🛠️ Управление отчетами

### Способы загрузки

#### 1. Прямое копирование (Рекомендуется)
```bash
# Копирование файла в контейнер
docker cp report.yaml analyzer-yaml-processor:/app/reports/

# Проверка обработки
docker logs analyzer-yaml-processor --tail 10
```

#### 2. Через volume (если настроен)
```bash
# Копирование в примонтированную папку
cp report.yaml grafana/data/uploads/
```

#### 3. Автоматическая генерация и загрузка
```bash
# Скрипт для автоматизации
#!/bin/bash
echo "🔄 Генерация отчета..."
python3 src/glacier.py --no-s3

echo "📤 Загрузка в процессор..."
docker cp MacBook-Pro-Mihail.local_darwin_report_analyzer.yaml analyzer-yaml-processor:/app/reports/

echo "✅ Готово! Проверьте дашборды через 30 секунд"
```

### Мониторинг обработки

```bash
# Просмотр логов процессора
docker logs analyzer-yaml-processor -f

# Проверка обработанных файлов
docker exec analyzer-yaml-processor ls -la /data/processed/

# Проверка данных в БД
docker exec analyzer-postgres psql -U analyzer_user -d analyzer_metrics -c "SELECT hostname, COUNT(*) FROM connections GROUP BY hostname;"
```

## 🔧 Устранение неполадок

### Проблема: Файл не обрабатывается

**Симптомы**: Файл остается в папке `/app/reports/`

**Решения**:
1. Проверьте логи: `docker logs analyzer-yaml-processor`
2. Убедитесь, что файл имеет расширение `.yaml` или `.yml`
3. Проверьте формат YAML: `python3 -c "import yaml; yaml.safe_load(open('file.yaml'))"`
4. Проверьте подключение к БД

### Проблема: Hostname не извлекается

**Симптомы**: В БД hostname = "unknown"

**Решения**:
1. Проверьте структуру YAML файла
2. Убедитесь, что есть секция `system_information.hostname`
3. Проверьте логи на сообщение "Извлечен hostname"

### Проблема: Дашборды не показывают данные

**Симптомы**: Пустые панели в Grafana

**Решения**:
1. Проверьте временной диапазон (должен быть "Last 30 minutes")
2. Убедитесь, что выбран правильный hostname
3. Проверьте наличие данных в БД
4. Нажмите "Run query" в панели

### Проблема: Переменная hostname не работает

**Симптомы**: Выпадающий список пустой

**Решения**:
1. Проверьте подключение к источнику данных
2. Обновите дашборд: `python3 grafana/update-dashboards-hostname.py`
3. Перезапустите Grafana

## 📈 Оптимизация производительности

### Настройки процессора

```python
# В yaml_processor.py можно настроить:
WATCH_INTERVAL = 10  # Интервал проверки файлов (секунды)
MAX_BATCH_SIZE = 1000  # Максимальный размер пакета для БД
```

### Настройки Grafana

```yaml
# В docker-compose.grafana.yml:
environment:
  - GF_DATABASE_MAX_OPEN_CONN=20
  - GF_DATABASE_MAX_IDLE_CONN=10
```

### Очистка старых данных

```sql
-- Удаление данных старше 30 дней
DELETE FROM connections WHERE time < NOW() - INTERVAL '30 days';
DELETE FROM protocol_stats WHERE time < NOW() - INTERVAL '30 days';
```

## 🔐 Безопасность

### Доступ к Grafana
- **URL**: http://localhost:3000
- **Логин**: admin
- **Пароль**: admin123

### Доступ к PostgreSQL
- **Хост**: localhost:5432
- **База**: analyzer_metrics
- **Пользователь**: analyzer_user
- **Пароль**: analyzer_password

### Рекомендации
1. Измените пароли по умолчанию в production
2. Используйте HTTPS для Grafana
3. Ограничьте сетевой доступ к PostgreSQL
4. Регулярно обновляйте контейнеры

## 📚 Дополнительные ресурсы

### Полезные команды

```bash
# Полная перезагрузка системы
docker-compose -f grafana/docker-compose.grafana.yml down
docker-compose -f grafana/docker-compose.grafana.yml up -d

# Бэкап данных
docker exec analyzer-postgres pg_dump -U analyzer_user analyzer_metrics > backup.sql

# Восстановление данных  
docker exec -i analyzer-postgres psql -U analyzer_user analyzer_metrics < backup.sql

# Экспорт дашбордов
./grafana/export-import-dashboards.sh export

# Импорт дашбордов
./grafana/export-import-dashboards.sh import
```

### Мониторинг системы

```bash
# Статус всех контейнеров
docker-compose -f grafana/docker-compose.grafana.yml ps

# Использование ресурсов
docker stats analyzer-grafana analyzer-postgres analyzer-yaml-processor

# Размер базы данных
docker exec analyzer-postgres psql -U analyzer_user -d analyzer_metrics -c "SELECT pg_size_pretty(pg_database_size('analyzer_metrics'));"
```

## 🆘 Поддержка

При возникновении проблем:

1. Проверьте логи всех сервисов
2. Убедитесь в корректности конфигурации
3. Проверьте сетевую связность между контейнерами
4. Обратитесь к документации Grafana и PostgreSQL

---