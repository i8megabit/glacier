# 🚀 Быстрый старт Grafana интеграции

## 📋 Что это?

Интеграция анализатора с Grafana для красивой визуализации сетевых соединений:
- 📊 Real-time дашборды
- 🕐 Исторические данные
- 📈 Интерактивные графики
- 🔍 Детальная аналитика

## ⚡ Быстрый запуск

### 1. Запустите установку:
```bash
cd analyzer/grafana
./setup.sh
```

### 2. Создайте отчет анализатором:
```bash
cd ../src
python3 analyzer.py --times 1 --no-s3
```

### 3. Скопируйте отчет для обработки:
```bash
cp *.yaml ../grafana/reports/
```

### 4. Откройте Grafana:
```
URL: http://localhost:3000
Логин: admin
Пароль: analyzer_admin
```

## 📊 Доступные дашборды

### Glacier Overview
- Общая статистика соединений
- Распределение протоколов
- Топ назначений
- Тренды по времени

## 🏗️ Архитектура

```
Анализатор → YAML → PostgreSQL + TimescaleDB → Grafana
              ↓
       YAML Processor (автоматический импорт)
```

## 🔧 Управление

### Полезные команды:
```bash
# Запуск
docker-compose -f docker-compose.grafana.yml up -d

# Остановка
docker-compose -f docker-compose.grafana.yml down

# Логи
docker-compose -f docker-compose.grafana.yml logs -f

# Перезапуск
docker-compose -f docker-compose.grafana.yml restart
```

### Проверка статуса:
```bash
docker-compose -f docker-compose.grafana.yml ps
```

## 🗄️ База данных

### Подключение к PostgreSQL:
```bash
docker exec -it analyzer-postgres psql -U analyzer_user -d analyzer_metrics
```

### Основные таблицы:
- `connections` - все сетевые соединения
- `system_metrics` - системная статистика
- `protocol_stats` - статистика по протоколам
- `top_destinations` - популярные назначения

## 📝 Настройка

### Добавление новых дашбордов:
1. Создайте дашборд в Grafana UI
2. Экспортируйте JSON
3. Сохраните в `grafana/dashboards/`
4. Перезапустите Grafana

### Источники данных:
- **GlacierDB**: PostgreSQL с данными Glacier
- **Запросы**: SQL с поддержкой временных рядов

## 🔍 Примеры запросов

### Соединения по времени:
```sql
SELECT 
  time,
  COUNT(*) as connections
FROM connections 
WHERE $__timeFilter(time)
GROUP BY time 
ORDER BY time
```

### Топ процессов:
```sql
SELECT 
  process_name,
  COUNT(*) as connections,
  SUM(byte_count) as total_bytes
FROM connections 
WHERE $__timeFilter(time)
GROUP BY process_name 
ORDER BY connections DESC 
LIMIT 10
```

### Аномалии соединений:
```sql
SELECT * FROM detect_connection_anomalies('hostname', 2.0)
```

## 🚨 Устранение неполадок

### Grafana не запускается:
```bash
# Проверьте логи
docker-compose logs grafana

# Перезапустите
docker-compose restart grafana
```

### YAML процессор не обрабатывает файлы:
```bash
# Проверьте логи
docker-compose logs yaml-processor

# Проверьте права на файлы
ls -la reports/
```

### База данных недоступна:
```bash
# Проверьте состояние PostgreSQL
docker-compose logs postgres

# Проверьте подключение
docker exec -it analyzer-postgres pg_isready
```

## 📚 Дополнительные ресурсы

- [Полная документация](../docs/GRAFANA_INTEGRATION.md)
- [Анализ безопасности](../docs/SECURITY_ANALYSIS.md)
- [NetFlow интеграция](../docs/NETFLOW_GUIDE.md)