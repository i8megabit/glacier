#!/bin/bash

# Скрипт для экспорта и импорта дашбордов Grafana
# Использование: 
# ./export-import-dashboards.sh export - экспорт всех дашбордов
# ./export-import-dashboards.sh import - импорт дашбордов

GRAFANA_URL="http://localhost:3000"
GRAFANA_USER="admin"
GRAFANA_PASS="admin123"
DASHBOARDS_DIR="./grafana/dashboards"

case "$1" in
  export)
    echo "🔄 Экспорт дашбордов из Grafana..."
    
    # Получаем список всех дашбордов
    DASHBOARDS=$(curl -s -u $GRAFANA_USER:$GRAFANA_PASS "$GRAFANA_URL/api/search?query=&type=dash-db" | jq -r '.[].uid')
    
    for uid in $DASHBOARDS; do
      echo "📤 Экспорт дашборда: $uid"
      curl -s -u $GRAFANA_USER:$GRAFANA_PASS "$GRAFANA_URL/api/dashboards/uid/$uid" | jq '.dashboard' > "$DASHBOARDS_DIR/${uid}.json"
    done
    
    echo "✅ Экспорт завершен. Файлы сохранены в $DASHBOARDS_DIR"
    ;;
    
  import)
    echo "🔄 Импорт дашбордов в Grafana..."
    
    for file in $DASHBOARDS_DIR/*.json; do
      if [ -f "$file" ]; then
        echo "📥 Импорт дашборда: $(basename $file)"
        
        # Подготавливаем JSON для импорта
        DASHBOARD_JSON=$(jq -n --argjson dashboard "$(cat "$file")" '{
          dashboard: $dashboard,
          overwrite: true,
          inputs: [],
          folderId: 0
        }')
        
        # Импортируем дашборд
        curl -s -X POST \
          -H "Content-Type: application/json" \
          -u $GRAFANA_USER:$GRAFANA_PASS \
          -d "$DASHBOARD_JSON" \
          "$GRAFANA_URL/api/dashboards/db" | jq '.'
      fi
    done
    
    echo "✅ Импорт завершен"
    ;;
    
  backup)
    echo "💾 Создание бэкапа текущих дашбордов..."
    mkdir -p "./grafana/backup/$(date +%Y%m%d_%H%M%S)"
    
    DASHBOARDS=$(curl -s -u $GRAFANA_USER:$GRAFANA_PASS "$GRAFANA_URL/api/search?query=&type=dash-db" | jq -r '.[].uid')
    
    for uid in $DASHBOARDS; do
      echo "💾 Бэкап дашборда: $uid"
      curl -s -u $GRAFANA_USER:$GRAFANA_PASS "$GRAFANA_URL/api/dashboards/uid/$uid" \
        > "./grafana/backup/$(date +%Y%m%d_%H%M%S)/${uid}.json"
    done
    
    echo "✅ Бэкап создан в ./grafana/backup/$(date +%Y%m%d_%H%M%S)"
    ;;
    
  *)
    echo "Использование: $0 {export|import|backup}"
    echo ""
    echo "export  - Экспорт всех дашбордов из Grafana в файлы"
    echo "import  - Импорт дашбордов из файлов в Grafana"  
    echo "backup  - Создание бэкапа текущих дашбордов"
    echo ""
    echo "Примеры:"
    echo "  $0 export   # Сохранить изменения из Grafana в файлы"
    echo "  $0 import   # Загрузить дашборды из файлов в Grafana"
    echo "  $0 backup   # Создать бэкап перед изменениями"
    exit 1
    ;;
esac 