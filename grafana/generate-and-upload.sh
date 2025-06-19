#!/bin/bash

# 🚀 Автоматическая генерация и загрузка отчетов в Grafana
# Использование: ./grafana/generate-and-upload.sh

set -e

echo "🔄 Генерация отчета анализатором..."

# Переходим в корневую папку проекта
cd "$(dirname "$0")/.."

# Генерируем отчет
python3 src/analyzer.py --no-s3

# Находим последний созданный YAML файл
YAML_FILE=$(ls -t *.yaml 2>/dev/null | head -n1)

if [ -z "$YAML_FILE" ]; then
    echo "❌ YAML файл не найден!"
    exit 1
fi

echo "📄 Найден файл: $YAML_FILE"

# Проверяем, что YAML процессор запущен
if ! docker ps | grep -q analyzer-yaml-processor; then
    echo "⚠️ YAML процессор не запущен. Запускаю систему..."
    docker-compose -f grafana/docker-compose.grafana.yml up -d
    echo "⏳ Ожидание запуска сервисов..."
    sleep 15
fi

echo "📤 Загрузка файла в YAML процессор..."

# Копируем файл в контейнер
docker cp "$YAML_FILE" analyzer-yaml-processor:/app/reports/

echo "⏳ Ожидание обработки файла..."
sleep 10

# Проверяем логи обработки
echo "📋 Последние логи процессора:"
docker logs analyzer-yaml-processor --tail 5

# Проверяем данные в базе
echo "📊 Проверка данных в базе:"
docker exec analyzer-postgres psql -U analyzer_user -d analyzer_metrics -c "SELECT hostname, COUNT(*) as connections FROM connections GROUP BY hostname ORDER BY connections DESC LIMIT 5;"

echo ""
echo "✅ Готово! Отчет загружен и обработан."
echo ""
echo "🌐 Откройте дашборды Grafana:"
echo "   • Обзор: http://localhost:3000/d/analyzer-overview"
echo "   • Сетевой анализ: http://localhost:3000/d/advanced_network_dashboard"
echo "   • Безопасность: http://localhost:3000/d/security_soc_dashboard"
echo ""
echo "🏷️ Не забудьте выбрать нужный hostname в выпадающем списке!"
echo ""
echo "📚 Подробная инструкция: grafana/YAML_PROCESSOR_GUIDE.md" 