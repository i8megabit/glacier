# Управление дашбордами Grafana

## Проблема с provisioning

Дашборды, загруженные через provisioning (из файлов), становятся **read-only** в Grafana. Это означает:
- ✅ Вы можете просматривать и редактировать дашборды 
- ❌ Изменения НЕ сохраняются автоматически
- ❌ После перезапуска Grafana изменения теряются

## Решения

### 1. Экспорт изменений (Рекомендуется)

Когда вы внесли изменения в дашборд:

```bash
# Экспорт всех дашбордов из Grafana в файлы
./grafana/export-import-dashboards.sh export
```

Это сохранит ваши изменения в файлы `grafana/dashboards/*.json`.

### 2. Импорт дашбордов

Чтобы загрузить дашборды из файлов:

```bash
# Импорт дашбордов из файлов в Grafana  
./grafana/export-import-dashboards.sh import
```

### 3. Создание бэкапа

Перед внесением изменений:

```bash
# Создание бэкапа текущих дашбордов
./grafana/export-import-dashboards.sh backup
```

## Рабочий процесс

### Для редактирования дашбордов:

1. **Откройте дашборд** в Grafana (http://localhost:3000)
2. **Внесите изменения** (настройки запросов, панелей, временных диапазонов)
3. **Нажмите "Run query"** для применения изменений
4. **Экспортируйте изменения**:
   ```bash
   ./grafana/export-import-dashboards.sh export
   ```
5. **Зафиксируйте в git** для сохранения:
   ```bash
   git add grafana/dashboards/
   git commit -m "Обновлены настройки дашбордов"
   ```

### При перезапуске Grafana:

```bash
# Перезапуск
docker-compose -f grafana/docker-compose.grafana.yml restart grafana

# Если нужно восстановить последние изменения
./grafana/export-import-dashboards.sh import
```

## Доступные дашборды

### 1. Glacier Overview Dashboard
- **URL**: http://localhost:3000/d/glacier-overview
- **Описание**: Общий обзор сетевой активности
- **Основные панели**: статистика соединений, протоколы, топ процессов

### 2. Advanced Network Dashboard  
- **URL**: http://localhost:3000/d/advanced_network_dashboard
- **Описание**: Детальный анализ сетевого трафика
- **Основные панели**: временные ряды, распределение протоколов, топ назначений

### 3. Security Analysis Dashboard
- **URL**: http://localhost:3000/d/security_soc_dashboard  
- **Описание**: Анализ безопасности и мониторинг угроз
- **Основные панели**: подозрительная активность, анализ рисков, топ атакующих

### 4. Test Simple Dashboard
- **URL**: http://localhost:3000/d/test-simple
- **Описание**: Простой тестовый дашборд для проверки подключения
- **Основные панели**: количество соединений

## Устранение проблем

### Проблема: "No data" в панелях

1. **Проверьте временной диапазон** - установите "Last 30 minutes"
2. **Проверьте данные в базе**:
   ```bash
   docker exec analyzer-postgres psql -U analyzer_user -d analyzer_metrics -c "SELECT COUNT(*) FROM connections WHERE time > NOW() - INTERVAL '30 minutes';"
   ```
3. **Нажмите "Run query"** в панели вручную
4. **Проверьте источник данных** - должен быть `DS_ANALYZER_POSTGRESQL`

### Проблема: Изменения не сохраняются

1. **Экспортируйте изменения**:
   ```bash
   ./grafana/export-import-dashboards.sh export
   ```
2. **Проверьте права на запись** в папку `grafana/dashboards/`

### Проблема: Ошибки подключения к PostgreSQL

1. **Проверьте статус контейнера**:
   ```bash
   docker ps | grep postgres
   ```
2. **Проверьте подключение**:
   ```bash
   docker exec analyzer-postgres pg_isready -U analyzer_user
   ```

## Логи и диагностика

### Просмотр логов Grafana:
```bash
docker logs analyzer-grafana --tail 20
```

### Просмотр логов PostgreSQL:
```bash  
docker logs analyzer-postgres --tail 20
```

### Проверка источников данных:
```bash
docker logs analyzer-grafana 2>&1 | grep -i datasource
```

## Автоматизация

Вы можете добавить экспорт в cron для автоматического сохранения изменений:

```bash
# Добавить в crontab (каждый час)
0 * * * * cd /path/to/analyzer && ./grafana/export-import-dashboards.sh export
```

## Альтернативное решение

Если provisioning не подходит, можно:

1. **Отключить provisioning** дашбордов
2. **Импортировать дашборды вручную** через UI Grafana  
3. **Использовать Grafana API** для программного управления

Но рекомендуется использовать описанный выше workflow с экспортом/импортом. 