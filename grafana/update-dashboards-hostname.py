#!/usr/bin/env python3
"""
Скрипт для добавления переменной hostname и обновления всех SQL запросов в дашбордах Grafana
"""

import json
import re
import os
from pathlib import Path

def add_hostname_variable(dashboard_data):
    """Добавляет переменную hostname в дашборд"""
    if 'templating' not in dashboard_data:
        dashboard_data['templating'] = {'list': []}
    
    # Проверяем, есть ли уже переменная hostname
    hostname_exists = any(var.get('name') == 'hostname' for var in dashboard_data['templating']['list'])
    
    if not hostname_exists:
        hostname_variable = {
            "current": {
                "selected": False,
                "text": "All",
                "value": "$__all"
            },
            "datasource": {
                "type": "postgres",
                "uid": "DS_ANALYZER_POSTGRESQL"
            },
            "definition": "SELECT DISTINCT hostname FROM connections ORDER BY hostname",
            "hide": 0,
            "includeAll": True,
            "label": "Hostname",
            "multi": False,
            "name": "hostname",
            "options": [],
            "query": "SELECT DISTINCT hostname FROM connections ORDER BY hostname",
            "refresh": 1,
            "regex": "",
            "skipUrlSync": False,
            "sort": 0,
            "type": "query"
        }
        dashboard_data['templating']['list'].insert(0, hostname_variable)
        print("✅ Добавлена переменная hostname")
    else:
        print("ℹ️ Переменная hostname уже существует")

def update_sql_queries(dashboard_data):
    """Обновляет все SQL запросы, добавляя фильтр по hostname"""
    updated_count = 0
    
    def process_panel(panel):
        nonlocal updated_count
        
        # Обрабатываем targets в панели
        if 'targets' in panel:
            for target in panel['targets']:
                if 'rawSql' in target and 'FROM connections' in target['rawSql']:
                    old_sql = target['rawSql']
                    
                    # Добавляем фильтр по hostname если его нет
                    if 'hostname IN ($hostname)' not in old_sql and '$hostname' not in old_sql:
                        # Ищем WHERE clause
                        if 'WHERE' in old_sql:
                            # Добавляем AND hostname IN ($hostname)
                            new_sql = old_sql.replace(
                                'WHERE $__timeFilter(time)',
                                'WHERE $__timeFilter(time) AND hostname IN ($hostname)'
                            )
                            # Если нет $__timeFilter, добавляем после первого WHERE
                            if new_sql == old_sql:
                                new_sql = re.sub(
                                    r'WHERE\s+',
                                    'WHERE hostname IN ($hostname) AND ',
                                    old_sql,
                                    count=1
                                )
                        else:
                            # Добавляем WHERE clause
                            new_sql = old_sql.replace(
                                'FROM connections',
                                'FROM connections WHERE hostname IN ($hostname)'
                            )
                        
                        if new_sql != old_sql:
                            target['rawSql'] = new_sql
                            updated_count += 1
                            print(f"🔄 Обновлен запрос в панели: {panel.get('title', 'Без названия')}")
        
        # Рекурсивно обрабатываем вложенные панели
        if 'panels' in panel:
            for sub_panel in panel['panels']:
                process_panel(sub_panel)
    
    # Обрабатываем все панели в дашборде
    if 'panels' in dashboard_data:
        for panel in dashboard_data['panels']:
            process_panel(panel)
    
    return updated_count

def update_dashboard_file(file_path):
    """Обновляет один файл дашборда"""
    print(f"\n📁 Обрабатываю файл: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Если это файл с dashboard внутри
        if 'dashboard' in data:
            dashboard_data = data['dashboard']
        else:
            dashboard_data = data
        
        # Добавляем переменную hostname
        add_hostname_variable(dashboard_data)
        
        # Обновляем SQL запросы
        updated_queries = update_sql_queries(dashboard_data)
        
        # Сохраняем файл
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Файл обновлен. Изменено запросов: {updated_queries}")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при обработке файла {file_path}: {e}")
        return False

def main():
    """Основная функция"""
    print("🚀 Начинаю обновление дашбордов для поддержки фильтрации по hostname")
    
    # Путь к папке с дашбордами
    dashboards_dir = Path("grafana/grafana/dashboards")
    
    if not dashboards_dir.exists():
        print(f"❌ Папка {dashboards_dir} не найдена")
        return
    
    # Находим все JSON файлы дашбордов
    dashboard_files = list(dashboards_dir.glob("*.json"))
    
    if not dashboard_files:
        print(f"❌ JSON файлы дашбордов не найдены в {dashboards_dir}")
        return
    
    print(f"📊 Найдено {len(dashboard_files)} файлов дашбордов")
    
    success_count = 0
    for file_path in dashboard_files:
        if update_dashboard_file(file_path):
            success_count += 1
    
    print(f"\n🎉 Обновление завершено!")
    print(f"✅ Успешно обновлено: {success_count}/{len(dashboard_files)} файлов")
    
    if success_count > 0:
        print("\n📝 Следующие шаги:")
        print("1. Перезапустите Grafana: docker-compose -f grafana/docker-compose.grafana.yml restart grafana")
        print("2. Откройте дашборды в Grafana")
        print("3. Выберите нужный hostname в выпадающем списке вверху дашборда")

if __name__ == "__main__":
    main() 