#!/usr/bin/env python3
"""
HTML генератор отчетов для анализатора
Создает красивые интерактивные HTML отчеты с графиками и таблицами
"""

import json
from datetime import datetime
from typing import Dict, Any, List

class HTMLReportGenerator:
    """Генератор HTML отчетов"""
    
    def __init__(self):
        self.css_styles = self._get_css_styles()
        self.js_scripts = self._get_js_scripts()
    
    def generate_html_report(self, enhanced_report: Dict[str, Any], output_file: str = None) -> str:
        """Генерирует HTML отчет"""
        html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет анализатора - {enhanced_report['metadata']['hostname']}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>{self.css_styles}</style>
</head>
<body>
    <div class="container">
        {self._generate_header(enhanced_report['metadata'])}
        {self._generate_executive_summary(enhanced_report['executive_summary'])}
        {self._generate_network_section(enhanced_report['network_analysis'])}
        {self._generate_system_health_section(enhanced_report['system_health'])}
        {self._generate_recommendations_section(enhanced_report['recommendations'])}
        {self._generate_detailed_data_section(enhanced_report['detailed_data'])}
        {self._generate_footer()}
    </div>
    <script>{self.js_scripts}</script>
    <script>
        // Инициализация графиков
        {self._generate_charts_js(enhanced_report)}
    </script>
</body>
</html>
        """
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
        
        return html_content
    
    def _generate_header(self, metadata: Dict[str, Any]) -> str:
        """Генерирует заголовок отчета"""
        return f"""
        <div class="report-header">
            <div class="header-content">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
                    <h1>🔍 Анализатор сетевой активности</h1>
                    <button onclick="openTechDocs()" class="tech-docs-btn">
                        🚀 Как это работает?
                    </button>
                </div>
                <div class="header-info">
                    <div class="info-item">
                        <strong>📅 Дата анализа:</strong><br>
                        {metadata.get('report_date', 'N/A')}
                    </div>
                    <div class="info-item">
                        <strong>🖥️ Система:</strong><br>
                        {metadata.get('hostname', 'N/A')} ({metadata.get('os_name', 'N/A')} {metadata.get('os_version', 'N/A')})
                    </div>
                    <div class="info-item">
                        <strong>⏱️ Длительность анализа:</strong><br>
                        {metadata.get('analysis_duration_seconds', 0)} сек
                    </div>
                    <div class="info-item">
                        <strong>📊 Версия анализатора:</strong><br>
                        v{metadata.get('analyzer_version', '2.3.0')}
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_executive_summary(self, summary: Dict[str, Any]) -> str:
        """Генерирует краткую сводку"""
        return f"""
        <section class="section">
            <h2>📊 Краткая сводка</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="card-icon">🔗</div>
                    <div class="card-content">
                        <h3>{summary['total_connections']}</h3>
                        <p>Всего соединений</p>
                        <small>{summary['incoming_connections']} входящих, {summary['outgoing_connections']} исходящих</small>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="card-icon">⚙️</div>
                    <div class="card-content">
                        <h3>{summary['unique_processes']}</h3>
                        <p>Уникальных процессов</p>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="card-icon">🌐</div>
                    <div class="card-content">
                        <h3>{summary['unique_remote_hosts']}</h3>
                        <p>Удаленных хостов</p>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="card-icon">🚪</div>
                    <div class="card-content">
                        <h3>{summary['tcp_listening_ports']}</h3>
                        <p>TCP портов</p>
                        <small>{summary['udp_listening_ports']} UDP портов</small>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="card-icon">🏓</div>
                    <div class="card-content">
                        <h3>{summary.get('icmp_connections', 0)}</h3>
                        <p>ICMP соединений</p>
                        <small>ping, traceroute и др.</small>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="card-icon">⚠️</div>
                    <div class="card-content">
                        <h3>{summary['security_alerts_count']}</h3>
                        <p>Предупреждений</p>
                    </div>
                </div>
            </div>
            
            <div class="top-lists">
                <div class="top-list">
                    <h4>🏆 Топ процессов</h4>
                    <ul>
                        {self._generate_top_processes_list(summary['top_processes'])}
                    </ul>
                </div>
                <div class="top-list">
                    <h4>🎯 Топ назначений</h4>
                    <ul>
                        {self._generate_top_destinations_list(summary['top_destinations'])}
                    </ul>
                </div>
            </div>
        </section>
        """
    
    def _generate_network_section(self, network: Dict[str, Any]) -> str:
        """Генерирует секцию сетевого анализа"""
        return f"""
        <section class="section">
            <h2>🌐 Сетевой анализ</h2>
            
            <div class="network-grid">
                <div class="network-card">
                    <h4>☁️ Облачные сервисы</h4>
                    {self._generate_cloud_services(network['cloud_services'])}
                </div>
                
                <div class="network-card">
                    <h4>📊 Протоколы</h4>
                    <canvas id="protocolChart" width="300" height="200"></canvas>
                </div>
                
                <div class="network-card">
                    <h4>🌍 География</h4>
                    <canvas id="geographyChart" width="300" height="200"></canvas>
                </div>
                
                <div class="network-card">
                    <h4>📡 Пропускная способность</h4>
                    {self._generate_bandwidth_info(network['bandwidth_analysis'])}
                </div>
            </div>
        </section>
        """
    
    def _generate_system_health_section(self, health: Dict[str, Any]) -> str:
        """Генерирует секцию здоровья системы"""
        score = health['overall_health_score']
        score_color = 'success' if score > 80 else 'warning' if score > 60 else 'danger'
        
        return f"""
        <section class="section">
            <h2>💚 Здоровье системы</h2>
            
            <div class="health-overview">
                <div class="health-score">
                    <div class="score-circle score-{score_color}">
                        <span class="score-value">{score}</span>
                        <span class="score-label">из 100</span>
                    </div>
                    <p>Общий балл здоровья</p>
                </div>
            </div>
            
            <div class="health-details">
                <div class="health-card">
                    <h4>💾 Дисковое пространство</h4>
                    {self._generate_disk_health(health['disk_health'])}
                </div>
                
                <div class="health-card">
                    <h4>🔌 Сетевые интерфейсы</h4>
                    {self._generate_network_interfaces(health['network_interfaces'])}
                </div>
                
                <div class="health-card">
                    <h4>⚙️ Сервисы</h4>
                    {self._generate_services_status(health['services_status'])}
                </div>
            </div>
        </section>
        """
    
    def _generate_recommendations_section(self, recommendations: List[Dict[str, Any]]) -> str:
        """Генерирует секцию рекомендаций"""
        if not recommendations:
            return """
            <section class="section">
                <h2>💡 Рекомендации</h2>
                <div class="no-recommendations">
                    <p>✅ Критических проблем не обнаружено. Система работает стабильно.</p>
                </div>
            </section>
            """
        
        recommendations_html = ""
        for rec in recommendations:
            priority_color = {
                'HIGH': 'danger',
                'MEDIUM': 'warning',
                'LOW': 'info'
            }.get(rec['priority'], 'secondary')
            
            recommendations_html += f"""
            <div class="recommendation-item">
                <span class="badge badge-{priority_color}">{rec['priority']}</span>
                <span class="category">{rec['category']}</span>
                <p>{rec['message']}</p>
            </div>
            """
        
        return f"""
        <section class="section">
            <h2>💡 Рекомендации</h2>
            <div class="recommendations">
                {recommendations_html}
            </div>
        </section>
        """
    
    def _generate_detailed_data_section(self, detailed: Dict[str, Any]) -> str:
        """Генерирует секцию детальных данных"""
        return f"""
        <section class="section">
            <h2>📋 Детальные данные</h2>
            
            <div class="tabs">
                <div class="tab-buttons">
                    <button class="tab-button active" onclick="showTab('connections')">Соединения</button>
                    <button class="tab-button" onclick="showTab('icmp')">🏓 ICMP трафик</button>
                    <button class="tab-button" onclick="showTab('services')">Сервисы</button>
                    <button class="tab-button" onclick="showTab('security-groups')">Группы Безопасности</button>
                    <button class="tab-button" onclick="showTab('resources')">Ресурсы</button>
                </div>
                
                <div id="connections" class="tab-content active">
                    {self._generate_connections_tables(detailed)}
                </div>
                
                <div id="icmp" class="tab-content">
                    {self._generate_icmp_section(detailed)}
                </div>
                
                <div id="services" class="tab-content">
                    {self._generate_services_table(detailed['listening_services'])}
                </div>
                
                <div id="security-groups" class="tab-content">
                    {self._generate_security_groups_table(detailed)}
                </div>
                
                <div id="resources" class="tab-content">
                    {self._generate_resources_info(detailed['system_resources'])}
                </div>
            </div>
        </section>
        """
    
    def _generate_footer(self) -> str:
        """Генерирует подвал отчета"""
        return f"""
        <footer class="report-footer">
            <p>Отчет сгенерирован {datetime.now().strftime('%d.%m.%Y в %H:%M:%S')} | Анализатор системы v2.0</p>
        </footer>
        """
    
    def _generate_top_processes_list(self, processes: List[Dict]) -> str:
        """Генерирует список топ процессов"""
        if not processes:
            return "<li>Нет данных</li>"
        
        items = []
        for proc in processes:
            items.append(f"<li><strong>{proc['process']}</strong> - {proc['connections']} соединений</li>")
        
        return "".join(items)
    
    def _generate_top_destinations_list(self, destinations: List[Dict]) -> str:
        """Генерирует список топ назначений"""
        if not destinations:
            return "<li>Нет данных</li>"
        
        items = []
        for dest in destinations:
            items.append(f"<li><strong>{dest['destination']}</strong> - {dest['connections']} соединений</li>")
        
        return "".join(items)
    
    def _generate_ports_analysis(self, ports_analysis: Dict[str, Any]) -> str:
        """Генерирует анализ портов"""
        critical_ports = ports_analysis.get('critical_tcp_ports', [])
        standard_ports = ports_analysis.get('standard_tcp_ports', [])
        
        html = ""
        
        if critical_ports:
            html += f"""
            <div class="alert alert-warning">
                <strong>⚠️ Критические порты:</strong> {', '.join(map(str, critical_ports))}
            </div>
            """
        
        if standard_ports:
            html += f"""
            <div class="port-list">
                <strong>Стандартные TCP порты:</strong> {', '.join(map(str, standard_ports[:10]))}
                {f'... и еще {len(standard_ports) - 10}' if len(standard_ports) > 10 else ''}
            </div>
            """
        
        udp_summary = ports_analysis.get('udp_ports_summary', {})
        if udp_summary.get('total', 0) > 0:
            html += f"""
            <div class="port-list">
                <strong>UDP порты:</strong> {udp_summary['total']} всего
            </div>
            """
        
        return html or "<p>Нет открытых портов</p>"
    
    def _generate_suspicious_activity(self, activities: List[Dict]) -> str:
        """Генерирует список подозрительной активности"""
        if not activities:
            return "<p class='text-success'>✅ Подозрительной активности не обнаружено</p>"
        
        html = ""
        for activity in activities:
            severity_color = {
                'HIGH': 'danger',
                'MEDIUM': 'warning',
                'LOW': 'info'
            }.get(activity['severity'], 'secondary')
            
            html += f"""
            <div class="alert alert-{severity_color}">
                <strong>{activity['type']}:</strong> {activity['description']}
            </div>
            """
        
        return html
    
    def _generate_cloud_services(self, cloud_services: Dict[str, List]) -> str:
        """Генерирует информацию об облачных сервисах"""
        if not cloud_services:
            return "<p>Соединений с облачными сервисами не обнаружено</p>"
        
        html = ""
        for provider, connections in cloud_services.items():
            html += f"""
            <div class="cloud-provider">
                <h5>{provider} ({len(connections)} соединений)</h5>
                <ul class="connection-list">
            """
            
            for conn in connections[:3]:  # Показываем только первые 3
                html += f"<li>{conn['destination']} ({conn['process']})</li>"
            
            if len(connections) > 3:
                html += f"<li><em>... и еще {len(connections) - 3}</em></li>"
            
            html += "</ul></div>"
        
        return html
    
    def _generate_bandwidth_info(self, bandwidth: Dict[str, Any]) -> str:
        """Генерирует информацию о пропускной способности"""
        return f"""
        <div class="bandwidth-stats">
            <div class="stat-item">
                <strong>Входящий трафик:</strong> {bandwidth.get('total_packets_in', 0):,} пакетов
            </div>
            <div class="stat-item">
                <strong>Исходящий трафик:</strong> {bandwidth.get('total_packets_out', 0):,} пакетов
            </div>
            <div class="stat-item">
                <strong>Соотношение:</strong> {bandwidth.get('traffic_ratio', 0)}
            </div>
        </div>
        
        <div class="active-interfaces">
            <h6>Активные интерфейсы:</h6>
            <ul>
        """
        
        for iface in bandwidth.get('active_interfaces', [])[:3]:
            html += f"<li><strong>{iface['interface']}:</strong> {iface['total_packets']:,} пакетов</li>"
        
        return html + "</ul></div>"
    
    def _generate_disk_health(self, disk_health: Dict[str, Any]) -> str:
        """Генерирует информацию о здоровье дисков"""
        status_color = {
            'GOOD': 'success',
            'WARNING': 'warning',
            'CRITICAL': 'danger'
        }.get(disk_health['health_status'], 'secondary')
        
        html = f"""
        <div class="disk-overview">
            <span class="badge badge-{status_color}">{disk_health['health_status']}</span>
            <div class="disk-stats">
                <div>Всего: {disk_health['total_space_gb']} ГБ</div>
                <div>Использовано: {disk_health['used_space_gb']} ГБ ({disk_health['usage_percent']}%)</div>
                <div>Свободно: {disk_health['free_space_gb']} ГБ</div>
            </div>
        </div>
        """
        
        critical_disks = disk_health.get('critical_disks', [])
        if critical_disks:
            html += "<div class='alert alert-danger'><strong>Критические диски:</strong><ul>"
            for disk in critical_disks:
                html += f"<li>{disk['disk']}: {disk['usage_percent']}% заполнен</li>"
            html += "</ul></div>"
        
        return html
    
    def _generate_network_interfaces(self, interfaces: Dict[str, Any]) -> str:
        """Генерирует информацию о сетевых интерфейсах"""
        active = interfaces.get('active_interfaces', [])
        
        html = f"""
        <div class="interfaces-stats">
            <div>Всего интерфейсов: {interfaces['total_interfaces']}</div>
            <div>Активных: {len(active)}</div>
            <div>Неактивных: {interfaces['inactive_interfaces_count']}</div>
        </div>
        """
        
        if active:
            html += "<div class='active-interfaces'><h6>Активные интерфейсы:</h6><ul>"
            for iface in active[:3]:
                html += f"<li><strong>{iface['name']}:</strong> {iface['total_packets']:,} пакетов</li>"
            html += "</ul></div>"
        
        return html
    
    def _generate_services_status(self, services: Dict[str, Any]) -> str:
        """Генерирует статус сервисов"""
        html = ""
        
        for service_name, service_info in services.items():
            status = service_info['status']
            status_color = 'success' if status == 'active' else 'warning' if status == 'configured' else 'secondary'
            
            html += f"""
            <div class="service-item">
                <span class="badge badge-{status_color}">{status}</span>
                <strong>{service_name.title()}</strong>
            """
            
            if service_name == 'postgresql' and service_info.get('databases_count', 0) > 0:
                html += f" - {service_info['databases_count']} БД"
            elif service_name == 'docker' and service_info.get('containers_count', 0) > 0:
                html += f" - {service_info['containers_count']} контейнеров"
            
            html += "</div>"
        
        return html
    
    def _generate_connections_tables(self, detailed: Dict[str, Any]) -> str:
        """Генерирует таблицы соединений"""
        by_process = detailed.get('connections_by_process', {})
        
        html = "<div class='connections-by-process'>"
        
        for process, connections in list(by_process.items())[:10]:  # Топ 10 процессов
            html += f"""
            <div class="process-group">
                <h5>🔧 {process} ({len(connections)} соединений)</h5>
                <table class="connections-table">
                    <thead>
                        <tr>
                            <th>Локальный адрес</th>
                            <th>Удаленный адрес</th>
                            <th>Протокол</th>
                            <th>Последнее соединение</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for conn in connections[:5]:  # Первые 5 соединений
                remote_name = conn.get('remote', {}).get('name', 'unknown')
                remote_addr = conn.get('remote', {}).get('address', 'unknown')
                
                html += f"""
                <tr>
                    <td>{conn.get('local', 'unknown')}</td>
                    <td title="{remote_addr}">{remote_name}</td>
                    <td>{conn.get('protocol', 'unknown').upper()}</td>
                    <td>{conn.get('last_seen', 'unknown')}</td>
                </tr>
                """
            
            html += "</tbody></table></div>"
        
        html += "</div>"
        return html
    
    def _generate_icmp_section(self, detailed: Dict[str, Any]) -> str:
        """Генерирует секцию ICMP трафика"""
        icmp_data = detailed.get('icmp_traffic', {})
        icmp_connections = icmp_data.get('connections', [])
        icmp_stats = icmp_data.get('statistics', {})
        ping_activity = icmp_data.get('ping_activity', [])
        
        html = f"""
        <div class="icmp-overview">
            <h4>🏓 Обзор ICMP трафика</h4>
            <div class="stats-grid">
                <div class="stat-item">
                    <strong>ICMP соединений:</strong> {len(icmp_connections)}
                </div>
                <div class="stat-item">
                    <strong>Echo Request:</strong> {icmp_stats.get('echo_request', 0)}
                </div>
                <div class="stat-item">
                    <strong>Echo Reply:</strong> {icmp_stats.get('echo_reply', 0)}
                </div>
                <div class="stat-item">
                    <strong>Ping процессов:</strong> {len(ping_activity)}
                </div>
            </div>
        </div>
        """
        
        # Таблица ICMP соединений
        if icmp_connections:
            html += f"""
            <div class="icmp-connections">
                <h5>📡 ICMP соединения</h5>
                <table class="connections-table">
                    <thead>
                        <tr>
                            <th>Локальный адрес</th>
                            <th>Удаленный адрес</th>
                            <th>Тип ICMP</th>
                            <th>Процесс</th>
                            <th>Последнее соединение</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for conn in icmp_connections[:20]:  # Ограничиваем количество
                icmp_type = conn.get('icmp_type', 'unknown')
                icmp_type_name = {
                    '8': 'Echo Request (ping)',
                    '0': 'Echo Reply (pong)',
                    '3': 'Destination Unreachable',
                    '11': 'Time Exceeded',
                    '5': 'Redirect'
                }.get(str(icmp_type), f'Type {icmp_type}')
                
                html += f"""
                <tr>
                    <td>{conn.get('local_address', 'unknown')}</td>
                    <td>{conn.get('remote_address', 'unknown')}</td>
                    <td>{icmp_type_name}</td>
                    <td>{conn.get('process', 'unknown')}</td>
                    <td>{conn.get('last_seen', 'unknown')}</td>
                </tr>
                """
            
            html += "</tbody></table></div>"
        else:
            html += "<div class='alert alert-info'>📭 ICMP соединения не обнаружены</div>"
        
        # Ping активность
        if ping_activity:
            html += f"""
            <div class="ping-activity">
                <h5>🎯 Ping активность</h5>
                <table class="connections-table">
                    <thead>
                        <tr>
                            <th>Процесс</th>
                            <th>Назначение</th>
                            <th>Статус</th>
                            <th>Время</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for ping in ping_activity[:15]:  # Ограничиваем количество
                status_class = 'success' if ping.get('status') == 'active' else 'warning'
                html += f"""
                <tr>
                    <td><strong>{ping.get('process', 'unknown')}</strong></td>
                    <td>{ping.get('destination', 'unknown')}</td>
                    <td><span class="badge badge-{status_class}">{ping.get('status', 'unknown')}</span></td>
                    <td>{ping.get('timestamp', 'unknown')}</td>
                </tr>
                """
            
            html += "</tbody></table></div>"
        
        # ICMP статистика
        if icmp_stats:
            html += f"""
            <div class="icmp-statistics">
                <h5>📊 Статистика ICMP</h5>
                <div class="stats-detailed">
                    <div class="stat-group">
                        <h6>Входящий трафик</h6>
                        <ul>
                            <li>Echo Request: {icmp_stats.get('echo_request_in', 0)}</li>
                            <li>Echo Reply: {icmp_stats.get('echo_reply_in', 0)}</li>
                            <li>Destination Unreachable: {icmp_stats.get('dest_unreachable_in', 0)}</li>
                        </ul>
                    </div>
                    <div class="stat-group">
                        <h6>Исходящий трафик</h6>
                        <ul>
                            <li>Echo Request: {icmp_stats.get('echo_request_out', 0)}</li>
                            <li>Echo Reply: {icmp_stats.get('echo_reply_out', 0)}</li>
                            <li>Destination Unreachable: {icmp_stats.get('dest_unreachable_out', 0)}</li>
                        </ul>
                    </div>
                </div>
            </div>
            """
        
        return html
    
    def _generate_services_table(self, services: Dict[str, Any]) -> str:
        """Генерирует таблицу сервисов"""
        tcp_services = services.get('tcp_services', [])
        udp_services = services.get('udp_services', [])
        
        html = f"""
        <div class="services-overview">
            <h4>📊 Обзор сервисов</h4>
            <div class="stats-grid">
                <div class="stat-item">
                    <strong>TCP сервисы:</strong> {len(tcp_services)}
                </div>
                <div class="stat-item">
                    <strong>UDP сервисы:</strong> {len(udp_services)}
                </div>
            </div>
        </div>
        
        <div class="services-tables">
            <div class="service-table-container">
                <h5>🔌 TCP Сервисы</h5>
                <table class="services-table">
                    <thead>
                        <tr>
                            <th>Порт</th>
                            <th>Сервис</th>
                            <th>Статус</th>
                            <th>Описание</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for service in tcp_services[:20]:  # Ограничиваем количество
            status_class = 'success' if service.get('status') == 'active' else 'warning'
            html += f"""
            <tr>
                <td>{service.get('port', 'unknown')}</td>
                <td><strong>{service.get('service_name', 'unknown')}</strong></td>
                <td><span class="badge badge-{status_class}">{service.get('status', 'unknown')}</span></td>
                <td>{service.get('description', 'Нет описания')}</td>
            </tr>
            """
        
        html += """
                    </tbody>
                </table>
            </div>
            
            <div class="service-table-container">
                <h5>📡 UDP Сервисы</h5>
                <table class="services-table">
                    <thead>
                        <tr>
                            <th>Порт</th>
                            <th>Сервис</th>
                            <th>Статус</th>
                            <th>Описание</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for service in udp_services[:20]:  # Ограничиваем количество
            status_class = 'success' if service.get('status') == 'active' else 'warning'
            html += f"""
            <tr>
                <td>{service.get('port', 'unknown')}</td>
                <td><strong>{service.get('service_name', 'unknown')}</strong></td>
                <td><span class="badge badge-{status_class}">{service.get('status', 'unknown')}</span></td>
                <td>{service.get('description', 'Нет описания')}</td>
            </tr>
            """
        
        html += """
                    </tbody>
                </table>
            </div>
        </div>
        """
        
        return html
    
    def _generate_security_groups_table(self, detailed: Dict[str, Any]) -> str:
        """Генерирует таблицу групп безопасности"""
        # Получаем данные о соединениях для формирования групп
        connections = detailed.get('connections_by_process', {})
        
        html = f"""
        <div class="security-groups-overview">
            <h4>🛡️ Группы Безопасности</h4>
            <p class="description">
                Анализ сетевых соединений для формирования групп безопасности и правил доступа.
                Данные могут быть использованы для согласования сетевых политик в корпоративной среде.
            </p>
        </div>
        
        <div class="security-groups-content">
            <div class="group-summary">
                <h5>📊 Сводка по группам</h5>
                <div class="stats-grid">
                    <div class="stat-item">
                        <strong>Исходящие соединения:</strong> {self._count_outgoing_connections(connections)}
                    </div>
                    <div class="stat-item">
                        <strong>Уникальных назначений:</strong> {self._count_unique_destinations(connections)}
                    </div>
                    <div class="stat-item">
                        <strong>Используемых портов:</strong> {self._count_unique_ports(connections)}
                    </div>
                </div>
            </div>
            
            <div class="groups-by-process">
                <h5>⚙️ Группы по процессам</h5>
                {self._generate_process_security_groups(connections)}
            </div>
            
            <div class="groups-by-destination">
                <h5>🎯 Группы по назначениям</h5>
                {self._generate_destination_security_groups(connections)}
            </div>
            
            <div class="recommended-rules">
                <h5>📋 Рекомендуемые правила</h5>
                {self._generate_recommended_security_rules(connections)}
            </div>
        </div>
        """
        
        return html
    
    def _generate_resources_info(self, resources: Dict[str, Any]) -> str:
        """Генерирует информацию о ресурсах"""
        return f"""
        <div class="resources-info">
            <div class="resource-group">
                <h4>Система</h4>
                <ul>
                    <li><strong>Хост:</strong> {resources['hostname']}</li>
                    <li><strong>ОС:</strong> {resources['os'].get('name', 'unknown')} {resources['os'].get('version', '')}</li>
                </ul>
            </div>
            
            <div class="resource-group">
                <h4>Сетевые интерфейсы</h4>
                <ul>
                    <li><strong>Всего:</strong> {resources['interfaces_summary']['total']}</li>
                    <li><strong>Активных:</strong> {resources['interfaces_summary']['active']}</li>
                </ul>
            </div>
            
            <div class="resource-group">
                <h4>Хранилище</h4>
                <ul>
                    <li><strong>Дисков:</strong> {resources['storage_summary']['total_disks']}</li>
                    <li><strong>Общий объем:</strong> {resources['storage_summary']['total_space_gb']} ГБ</li>
                </ul>
            </div>
        </div>
        """
    
    def _generate_charts_js(self, enhanced_report: Dict[str, Any]) -> str:
        """Генерирует JavaScript для графиков"""
        network_analysis = enhanced_report.get('network_analysis', {})
        protocol_dist = network_analysis.get('protocol_distribution', {})
        geo_dist = network_analysis.get('geographic_distribution', {})
        
        security_analysis = enhanced_report.get('security_analysis', {})
        connection_patterns = security_analysis.get('connection_patterns', {})
        connection_types = connection_patterns.get('connection_types', {})
        
        return f"""
        // График протоколов
        if (document.getElementById('protocolChart')) {{
            const protocolCtx = document.getElementById('protocolChart').getContext('2d');
            new Chart(protocolCtx, {{
                type: 'doughnut',
                data: {{
                    labels: {json.dumps(list(protocol_dist.keys()))},
                    datasets: [{{
                        data: {json.dumps(list(protocol_dist.values()))},
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40']
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ position: 'bottom' }}
                    }}
                }}
            }});
        }}
        
        // График географии
        if (document.getElementById('geographyChart')) {{
            const geoCtx = document.getElementById('geographyChart').getContext('2d');
            new Chart(geoCtx, {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(list(geo_dist.keys()))},
                    datasets: [{{
                        label: 'Соединения',
                        data: {json.dumps(list(geo_dist.values()))},
                        backgroundColor: '#36A2EB'
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ display: false }}
                    }},
                    scales: {{
                        y: {{ beginAtZero: true }}
                    }}
                }}
            }});
        }}
        
        // График типов соединений
        if (document.getElementById('connectionTypesChart')) {{
            const connTypesCtx = document.getElementById('connectionTypesChart').getContext('2d');
            new Chart(connTypesCtx, {{
                type: 'pie',
                data: {{
                    labels: {json.dumps(list(connection_types.keys()))},
                    datasets: [{{
                        data: {json.dumps(list(connection_types.values()))},
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ position: 'bottom' }}
                    }}
                }}
            }});
        }}
        """
    
    def _get_css_styles(self) -> str:
        """Возвращает CSS стили"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .report-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header-content h1 {
            font-size: 2.5em;
            margin-bottom: 20px;
        }
        
        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .info-item {
            background: rgba(255,255,255,0.1);
            padding: 10px;
            border-radius: 5px;
        }
        
        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            font-size: 1.8em;
            margin-bottom: 25px;
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
            transition: transform 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
        }
        
        .card-icon {
            font-size: 2em;
        }
        
        .card-content h3 {
            font-size: 2em;
            margin-bottom: 5px;
        }
        
        .card-content p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .card-content small {
            font-size: 0.9em;
            opacity: 0.8;
        }
        
        .top-lists {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        
        .top-list {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }
        
        .top-list h4 {
            margin-bottom: 15px;
            color: #2c3e50;
        }
        
        .top-list ul {
            list-style: none;
        }
        
        .top-list li {
            padding: 8px 0;
            border-bottom: 1px solid #dee2e6;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.875em;
            font-weight: 500;
            text-align: center;
            white-space: nowrap;
        }
        
        .badge-large {
            padding: 8px 16px;
            font-size: 1.1em;
        }
        
        .badge-success { background-color: #28a745; color: white; }
        .badge-warning { background-color: #ffc107; color: #212529; }
        .badge-danger { background-color: #dc3545; color: white; }
        .badge-info { background-color: #17a2b8; color: white; }
        .badge-secondary { background-color: #6c757d; color: white; }
        
        .security-overview {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .security-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .security-card, .network-card, .health-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        
        .network-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .health-overview {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .score-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            display: inline-flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin-bottom: 10px;
            border: 8px solid;
        }
        
        .score-circle.score-success { border-color: #28a745; }
        .score-circle.score-warning { border-color: #ffc107; }
        .score-circle.score-danger { border-color: #dc3545; }
        
        .score-value {
            font-size: 2em;
            font-weight: bold;
        }
        
        .score-label {
            font-size: 0.9em;
            opacity: 0.8;
        }
        
        .health-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .alert {
            padding: 12px 16px;
            margin-bottom: 15px;
            border-radius: 6px;
            border-left: 4px solid;
        }
        
        .alert-success {
            background-color: #d4edda;
            border-color: #28a745;
            color: #155724;
        }
        
        .alert-warning {
            background-color: #fff3cd;
            border-color: #ffc107;
            color: #856404;
        }
        
        .alert-danger {
            background-color: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }
        
        .tabs {
            margin-top: 20px;
        }
        
        .tab-buttons {
            display: flex;
            border-bottom: 2px solid #dee2e6;
            margin-bottom: 20px;
        }
        
        .tab-button {
            background: none;
            border: none;
            padding: 12px 24px;
            cursor: pointer;
            font-size: 1em;
            color: #6c757d;
            border-bottom: 3px solid transparent;
            transition: all 0.3s ease;
        }
        
        .tab-button.active {
            color: #3498db;
            border-bottom-color: #3498db;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .connections-table, .services-table, .security-groups-table, .security-rules-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .connections-table th, .connections-table td,
        .services-table th, .services-table td,
        .security-groups-table th, .security-groups-table td,
        .security-rules-table th, .security-rules-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        .connections-table th, .services-table th, .security-groups-table th, .security-rules-table th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .security-groups-overview {
            margin-bottom: 25px;
        }
        
        .security-groups-overview .description {
            color: #6c757d;
            font-style: italic;
            margin-top: 10px;
        }
        
        .security-groups-content {
            margin-top: 20px;
        }
        
        .group-summary, .groups-by-process, .groups-by-destination, .recommended-rules {
            margin-bottom: 30px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }
        
        .stat-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }
        
        .rules-explanation {
            background: #e7f3ff;
            border: 1px solid #b3d9ff;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 20px;
        }
        
        .text-center {
            text-align: center;
        }
        
        .process-group {
            margin-bottom: 30px;
        }
        
        .process-group h5 {
            margin-bottom: 15px;
            color: #2c3e50;
        }
        
        .report-footer {
            text-align: center;
            padding: 20px;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
            margin-top: 30px;
        }
        
        .text-success { color: #28a745; }
        .text-warning { color: #ffc107; }
        .text-danger { color: #dc3545; }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header-info {
                grid-template-columns: 1fr;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .top-lists {
                grid-template-columns: 1fr;
            }
            
            .security-details, .network-grid, .health-details {
                grid-template-columns: 1fr;
            }
        }
        
        /* ICMP секция стили */
        .icmp-overview {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 25px;
        }
        
        /* Кнопка техдокументации */
        .tech-docs-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 25px;
            font-weight: 600;
            font-size: 0.95em;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .tech-docs-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
        }
        
        .tech-docs-btn:active {
            transform: translateY(0);
        }
        
        .recommendation-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #17a2b8;
        }
        
        .recommendation-item .badge {
            margin-right: 10px;
        }
        
        .recommendation-item .category {
            font-weight: 600;
            color: #495057;
            margin-right: 10px;
        }
        
        .no-recommendations {
            text-align: center;
            padding: 50px;
            color: #6c757d;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        
        tr:hover {
            background-color: #f8f9fa;
        }
        
        .tab-container {
            margin-top: 30px;
        }
        
        .tab-buttons {
            display: flex;
            gap: 5px;
            margin-bottom: 20px;
            border-bottom: 2px solid #dee2e6;
        }
        
        .tab-button {
            background: none;
            border: none;
            padding: 12px 24px;
            cursor: pointer;
            border-radius: 8px 8px 0 0;
            font-weight: 500;
            color: #6c757d;
            transition: all 0.3s ease;
        }
        
        .tab-button:hover {
            background-color: #f8f9fa;
            color: #495057;
        }
        
        .tab-button.active {
            background-color: #3498db;
            color: white;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @media (max-width: 768px) {
            .summary-grid, .security-details, .network-grid, .health-details {
                grid-template-columns: 1fr;
            }
            
            .top-lists {
                grid-template-columns: 1fr;
            }
            
            .header-info {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 10px;
            }
            
            .report-header {
                padding: 20px;
            }
            
            .header-content h1 {
                font-size: 2em;
            }
            
            .tech-docs-btn {
                padding: 10px 20px;
                font-size: 0.9em;
            }
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
        }
        
        .connections-table {
            overflow-x: auto;
        }
        
        .listening-ports {
            background: #e8f5e8;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        
        .security-recommendation {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-left: 4px solid #f39c12;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
        }
        
        .process-group {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin: 15px 0;
            overflow: hidden;
        }
        
        .process-group-header {
            background: #e9ecef;
            padding: 15px;
            font-weight: 600;
            border-bottom: 1px solid #dee2e6;
        }
        
        .process-group-content {
            padding: 15px;
        }
        
        .security-group-rule {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .rule-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .rule-name {
            font-weight: 600;
            color: #2c3e50;
        }
        
        .rule-type {
            font-size: 0.9em;
            color: #6c757d;
        }
        
        .rule-details {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-size: 0.9em;
        }
        """
    
    def _get_js_scripts(self) -> str:
        """Возвращает JavaScript скрипты"""
        return """
        function showTab(tabName) {
            // Скрываем все вкладки
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(tab => tab.classList.remove('active'));
            
            // Убираем активный класс с кнопок
            const tabButtons = document.querySelectorAll('.tab-button');
            tabButtons.forEach(button => button.classList.remove('active'));
            
            // Показываем выбранную вкладку
            document.getElementById(tabName).classList.add('active');
            
            // Активируем соответствующую кнопку
            event.target.classList.add('active');
        }
        
        function openTechDocs() {
            // Создаем техническую документацию
            const techDocsContent = `
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔥 Как работает анализатор | Tech Docs v2.3.0</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6; color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .hero-section {
            text-align: center; color: white; padding: 60px 20px; margin-bottom: 40px;
        }
        .hero-section h1 {
            font-size: 3.5em; margin-bottom: 20px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .hero-section p { font-size: 1.4em; opacity: 0.9; margin-bottom: 30px; }
        .tech-badge {
            display: inline-block; background: rgba(255,255,255,0.2);
            padding: 10px 20px; border-radius: 50px; margin: 5px;
            backdrop-filter: blur(10px);
        }
        .main-content {
            background: white; border-radius: 20px; padding: 40px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1); margin-bottom: 40px;
        }
        .section { margin-bottom: 50px; }
        .section h2 {
            font-size: 2.2em; margin-bottom: 25px; color: #2c3e50;
            position: relative; padding-left: 50px;
        }
        .section h2:before { content: "🚀"; position: absolute; left: 0; font-size: 1.2em; }
        .architecture-diagram {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border-radius: 15px; padding: 40px; margin: 30px 0; color: white;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        .flow-diagram {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            border-radius: 15px; padding: 30px; margin: 30px 0; color: white;
        }
        .netflow-section {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
            border-radius: 15px; padding: 30px; margin: 30px 0; color: #1a1a1a;
        }
        .code-block {
            background: #1a1a1a; color: #00ff00; padding: 20px;
            border-radius: 10px; font-family: 'Courier New', monospace;
            margin: 20px 0; overflow-x: auto;
        }
        .back-button {
            position: fixed; top: 20px; left: 20px;
            background: rgba(255,255,255,0.2); color: white;
            padding: 10px 20px; border-radius: 50px;
            text-decoration: none; backdrop-filter: blur(10px);
            transition: all 0.3s ease; border: none; cursor: pointer;
        }
        .back-button:hover {
            background: rgba(255,255,255,0.3); transform: translateX(-5px);
        }
        .fun-fact {
            background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
            padding: 20px; border-radius: 15px; margin: 20px 0;
            border-left: 5px solid #ff6b6b;
        }
        .fun-fact::before { content: "💡 "; font-size: 1.5em; }
        .tech-stack {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px; margin: 30px 0;
        }
        .tech-item {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; padding: 20px; border-radius: 15px;
            text-align: center;
        }
        .ascii-small { font-size: 0.8em; line-height: 1.2; }
    </style>
</head>
<body>
    <button onclick="window.close()" class="back-button">← Назад к отчету</button>
    
    <div class="container">
        <div class="hero-section">
            <h1>🔥 Как работает анализатор</h1>
            <p>Техническая документация для DevOps и SRE</p>
            <div>
                <span class="tech-badge">🐍 Python 3.6+</span>
                <span class="tech-badge">📡 NetFlow v9</span>
                <span class="tech-badge">🎨 Chart.js</span>
                <span class="tech-badge">☁️ S3 Ready</span>
                <span class="tech-badge">🔧 Cross-Platform</span>
            </div>
        </div>
        
        <div class="main-content">
            <div class="section">
                <h2>Архитектура системы</h2>
                <div class="architecture-diagram">
                    <h3>🏗️ Детальная архитектурная схема</h3>
                    <pre class="ascii-small">
ANALYZER v2.3.0 - NETWORK ACTIVITY ANALYZER
=============================================

LAYER 1: DATA INPUT    ->    LAYER 2: PROCESSING    ->    LAYER 3: OUTPUT
      |                            |                           |
      v                            v                           v
Data Sources                Analytics Engine            Report Generation
- psutil                    - ReportEnhancer           - HTMLReportGenerator
- netstat                   - NetFlow v9               - YAML formatter
- ss                        - Security scan            - Chart.js visualizer
- lsof                      - Health check             - S3 uploader
- /proc/net                 - GeoIP lookup             - Legacy converter
      |                            |                           |
      v                            v                           v
Network Modules             Security Analysis           Cloud Integration
- ICMPTracker               - Firewall rules           - AWS S3
- UDPTracker                - Port analysis            - MinIO
- TCP Monitor               - Process audit            - Yandex Cloud
- IPv6 Support              - Anomaly detect           - Docker support

TECHNICAL STACK:
Backend: Python 3.6+, psutil, PyYAML, boto3
Analytics: pandas-style logic, GeoIP2, Pattern matching
Frontend: Chart.js 3.x, Bootstrap 5, Responsive CSS
Cloud: Docker containers, GitLab CI/CD, S3 API
SIEM: Splunk ready, Elastic compatible, Grafana integration
                    </pre>
                </div>
            </div>
            
            <div class="section">
                <h2>Алгоритм работы</h2>
                <div class="flow-diagram">
                    <h3>🔄 5-шаговый процесс анализа</h3>
                    <pre>
STEP 1: DATA COLLECTION -> STEP 2: NETFLOW V9 -> STEP 3: ANALYSIS -> STEP 4: REPORTS -> STEP 5: EXPORT
      |                        |                    |                 |                |
      v                        v                    v                 v                v
  - netstat                - RFC 3954          - Security        - HTML + CSS    - S3 Upload
  - ss                     - Templates         - Health check    - YAML format   - Docker logs
  - lsof                   - Flow records      - GeoIP lookup    - Chart.js viz  - API endpoints
  - psutil                 - Timestamps        - Pattern match   - Responsive UI - Webhook notify
  - /proc                  - Packet count      - Anomaly detect  - Print friendly - Log shipping
                    </pre>
                </div>
            </div>
            
            <div class="section">
                <h2>NetFlow v9 — стандарт индустрии</h2>
                <div class="netflow-section">
                    <h3>🎯 RFC 3954 Compliance</h3>
                    <p>Полная совместимость с NetFlow v9 для интеграции в корпоративные SIEM системы!</p>
                    
                    <div class="fun-fact">
                        <strong>Industry Standard:</strong> Данные совместимы с Splunk, Elastic, QRadar, ArcSight, Graylog!
                    </div>
                    
                    <div class="code-block">
NetFlow v9 Message Structure (RFC 3954)
========================================

NETFLOW HEADER:
Version=9 | Count | SysUptime | Timestamp
Sequence | Source ID

TEMPLATE RECORD:
FlowSet ID=0 | Length | Template ID
Field Count | Field Type | Field Len

DATA RECORD:
FlowSet ID=256 | Length
SrcAddr | DstAddr | SrcPort | DstPort
Protocol | Packets | Bytes | Flags
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Принципы безопасности</h2>
                <div style="background: #ffe6e6; padding: 20px; border-radius: 10px;">
                    <h4 style="color: #d63384; margin-bottom: 15px;">❌ Что НЕ собираем:</h4>
                    <ul style="color: #d63384;">
                        <li>🚫 Содержимое пакетов (packet capture)</li>
                        <li>🚫 HTTP payload или POST данные</li>
                        <li>🚫 Пароли, токены, API ключи</li>
                        <li>🚫 Содержимое файлов пользователей</li>
                        <li>🚫 Браузерную историю или cookies</li>
                    </ul>
                </div>
                
                <div style="background: #e6ffe6; padding: 20px; border-radius: 10px; margin-top: 20px;">
                    <h4 style="color: #28a745; margin-bottom: 15px;">✅ Собираем только метаданные:</h4>
                    <ul style="color: #28a745;">
                        <li>✅ IP адреса активных соединений</li>
                        <li>✅ Номера портов (source/destination)</li>
                        <li>✅ Имена процессов (без аргументов командной строки)</li>
                        <li>✅ Системные метрики (CPU, RAM, disk)</li>
                        <li>✅ Статистику сетевых интерфейсов</li>
                    </ul>
                </div>
            </div>
            
            <div class="section">
                <h2>Технический стек в деталях</h2>
                <div class="tech-stack">
                    <div class="tech-item">
                        <h4>🐍 Backend</h4>
                        <p>Python 3.6+<br>psutil, PyYAML<br>boto3, distro</p>
                    </div>
                    <div class="tech-item">
                        <h4>📊 Analytics</h4>
                        <p>ReportEnhancer<br>Pattern matching<br>Security scanning</p>
                    </div>
                    <div class="tech-item">
                        <h4>🎨 Frontend</h4>
                        <p>Chart.js 3.x<br>Bootstrap 5<br>Responsive CSS</p>
                    </div>
                    <div class="tech-item">
                        <h4>☁️ Cloud</h4>
                        <p>AWS S3<br>MinIO<br>Yandex Cloud</p>
                    </div>
                    <div class="tech-item">
                        <h4>🔧 DevOps</h4>
                        <p>Docker<br>GitLab CI<br>systemd</p>
                    </div>
                    <div class="tech-item">
                        <h4>🛡️ Security</h4>
                        <p>iptables<br>ufw<br>Process audit</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Поддерживаемые платформы</h2>
                <div class="code-block">
🐧 Linux Distributions:
   • Ubuntu 18.04+ LTS
   • CentOS 7/8, RHEL 7/8
   • Debian 10/11
   • Amazon Linux 2
   • Alpine Linux 3.14+

🍎 macOS:
   • macOS 10.15+ (Catalina)
   • Apple Silicon (M1/M2) ready
   • Intel x86_64 compatible

🐳 Containers:
   • Docker 20.10+
   • Podman 3.0+
   • Kubernetes ready
                </div>
            </div>
        </div>
    </div>
</body>
</html>
            `;
            
            // Открываем в новом окне
            const techWindow = window.open('', '_blank', 'width=1400,height=900,scrollbars=yes,resizable=yes');
            techWindow.document.write(techDocsContent);
            techWindow.document.close();
        }
        
        // Анимация появления карточек
        document.addEventListener('DOMContentLoaded', function() {
            const cards = document.querySelectorAll('.summary-card, .security-card, .network-card, .health-card');
            cards.forEach((card, index) => {
                card.style.opacity = '0';
                card.style.transform = 'translateY(20px)';
                
                setTimeout(() => {
                    card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }, index * 100);
            });
        });
        """
    
    def _count_outgoing_connections(self, connections: Dict[str, List]) -> int:
        """Подсчитывает количество исходящих соединений"""
        total = 0
        for process_connections in connections.values():
            for conn in process_connections:
                if conn.get('protocol') in ['tcp', 'udp']:
                    total += 1
        return total
    
    def _count_unique_destinations(self, connections: Dict[str, List]) -> int:
        """Подсчитывает количество уникальных назначений"""
        destinations = set()
        for process_connections in connections.values():
            for conn in process_connections:
                remote = conn.get('remote', {})
                if 'address' in remote:
                    destinations.add(remote['address'].split(':')[0])  # Только IP без порта
        return len(destinations)
    
    def _count_unique_ports(self, connections: Dict[str, List]) -> int:
        """Подсчитывает количество уникальных портов"""
        ports = set()
        for process_connections in connections.values():
            for conn in process_connections:
                remote = conn.get('remote', {})
                if 'address' in remote and ':' in remote['address']:
                    try:
                        port = remote['address'].split(':')[1]
                        ports.add(port)
                    except IndexError:
                        continue
        return len(ports)
    
    def _generate_process_security_groups(self, connections: Dict[str, List]) -> str:
        """Генерирует группы безопасности по процессам"""
        if not connections:
            return "<p>Нет данных о соединениях</p>"
        
        html = """
        <table class="security-groups-table">
            <thead>
                <tr>
                    <th>Процесс</th>
                    <th>Соединения</th>
                    <th>Назначения</th>
                    <th>Порты</th>
                    <th>Рекомендуемая группа</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for process, process_connections in list(connections.items())[:10]:
            destinations = set()
            ports = set()
            
            for conn in process_connections:
                remote = conn.get('remote', {})
                if 'name' in remote:
                    destinations.add(remote['name'])
                if 'address' in remote and ':' in remote['address']:
                    try:
                        port = remote['address'].split(':')[1]
                        ports.add(port)
                    except IndexError:
                        continue
            
            # Определяем рекомендуемую группу
            group_name = self._suggest_security_group_name(process, destinations, ports)
            
            html += f"""
            <tr>
                <td><strong>{process}</strong></td>
                <td>{len(process_connections)}</td>
                <td>{len(destinations)}</td>
                <td>{', '.join(sorted(ports)[:5])}{' ...' if len(ports) > 5 else ''}</td>
                <td><span class="badge badge-info">{group_name}</span></td>
            </tr>
            """
        
        html += "</tbody></table>"
        return html
    
    def _generate_destination_security_groups(self, connections: Dict[str, List]) -> str:
        """Генерирует группы безопасности по назначениям"""
        # Группируем по назначениям
        destinations_map = {}
        
        for process, process_connections in connections.items():
            for conn in process_connections:
                remote = conn.get('remote', {})
                if 'name' in remote:
                    dest_name = remote['name']
                    if dest_name not in destinations_map:
                        destinations_map[dest_name] = {
                            'processes': set(),
                            'ports': set(),
                            'connections': 0
                        }
                    
                    destinations_map[dest_name]['processes'].add(process)
                    destinations_map[dest_name]['connections'] += 1
                    
                    if 'address' in remote and ':' in remote['address']:
                        try:
                            port = remote['address'].split(':')[1]
                            destinations_map[dest_name]['ports'].add(port)
                        except IndexError:
                            continue
        
        if not destinations_map:
            return "<p>Нет данных о назначениях</p>"
        
        html = """
        <table class="security-groups-table">
            <thead>
                <tr>
                    <th>Назначение</th>
                    <th>Процессы</th>
                    <th>Порты</th>
                    <th>Соединения</th>
                    <th>Тип доступа</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for dest_name, dest_info in list(destinations_map.items())[:10]:
            access_type = self._determine_access_type(dest_info['ports'])
            
            html += f"""
            <tr>
                <td><strong>{dest_name}</strong></td>
                <td>{len(dest_info['processes'])}</td>
                <td>{', '.join(sorted(dest_info['ports'])[:3])}{' ...' if len(dest_info['ports']) > 3 else ''}</td>
                <td>{dest_info['connections']}</td>
                <td><span class="badge badge-secondary">{access_type}</span></td>
            </tr>
            """
        
        html += "</tbody></table>"
        return html
    
    def _generate_recommended_security_rules(self, connections: Dict[str, List]) -> str:
        """Генерирует рекомендуемые правила безопасности"""
        rules = []
        
        # Анализируем соединения и формируем правила
        for process, process_connections in connections.items():
            for conn in process_connections:
                remote = conn.get('remote', {})
                protocol = conn.get('protocol', 'tcp').upper()
                
                if 'address' in remote and ':' in remote['address']:
                    try:
                        ip, port = remote['address'].rsplit(':', 1)
                        rule = {
                            'source': 'HOST',
                            'destination': ip,
                            'port': port,
                            'protocol': protocol,
                            'process': process,
                            'action': 'ALLOW'
                        }
                        rules.append(rule)
                    except ValueError:
                        continue
        
        if not rules:
            return "<p>Нет данных для формирования правил</p>"
        
        html = """
        <div class="rules-explanation">
            <p><strong>Примечание:</strong> Правила сформированы на основе обнаруженных соединений. 
            Рекомендуется проверить и адаптировать их под корпоративные политики безопасности.</p>
        </div>
        
        <table class="security-rules-table">
            <thead>
                <tr>
                    <th>Источник</th>
                    <th>Назначение</th>
                    <th>Порт</th>
                    <th>Протокол</th>
                    <th>Процесс</th>
                    <th>Действие</th>
                </tr>
            </thead>
            <tbody>
        """
        
        # Показываем первые 15 правил
        for rule in rules[:15]:
            html += f"""
            <tr>
                <td>{rule['source']}</td>
                <td>{rule['destination']}</td>
                <td>{rule['port']}</td>
                <td>{rule['protocol']}</td>
                <td>{rule['process']}</td>
                <td><span class="badge badge-success">{rule['action']}</span></td>
            </tr>
            """
        
        if len(rules) > 15:
            html += f"""
            <tr>
                <td colspan="6" class="text-center">
                    <em>... и еще {len(rules) - 15} правил</em>
                </td>
            </tr>
            """
        
        html += "</tbody></table>"
        return html
    
    def _suggest_security_group_name(self, process: str, destinations: set, ports: set) -> str:
        """Предлагает имя группы безопасности на основе процесса и соединений"""
        process_lower = process.lower()
        
        # Определяем тип группы на основе процесса
        if 'browser' in process_lower or 'chrome' in process_lower or 'firefox' in process_lower:
            return "WEB_BROWSING"
        elif 'git' in process_lower:
            return "DEV_TOOLS"
        elif 'python' in process_lower or 'node' in process_lower:
            return "DEV_RUNTIME"
        elif 'ssh' in process_lower:
            return "REMOTE_ACCESS"
        elif 'curl' in process_lower or 'wget' in process_lower:
            return "HTTP_CLIENT"
        elif any('443' in str(p) for p in ports):
            return "HTTPS_ACCESS"
        elif any('80' in str(p) for p in ports):
            return "HTTP_ACCESS"
        else:
            return f"{process.upper()}_ACCESS"
    
    def _determine_access_type(self, ports: set) -> str:
        """Определяет тип доступа на основе портов"""
        port_list = [int(p) for p in ports if p.isdigit()]
        
        if 443 in port_list:
            return "HTTPS"
        elif 80 in port_list:
            return "HTTP"
        elif 22 in port_list:
            return "SSH"
        elif 53 in port_list:
            return "DNS"
        elif any(p in [25, 587, 993, 995] for p in port_list):
            return "EMAIL"
        elif any(p >= 1024 for p in port_list):
            return "CUSTOM"
        else:
            return "STANDARD"


def generate_html_report_from_data(original_report: Dict[str, Any], output_file: str = None) -> str:
    """Функция для интеграции в основной анализатор"""
    from report_enhancer import enhance_analyzer_report
    
    # Улучшаем отчет
    enhanced_report = enhance_analyzer_report(original_report)
    
    # Генерируем HTML
    generator = HTMLReportGenerator()
    return generator.generate_html_report(enhanced_report, output_file)


if __name__ == "__main__":
    # Тестирование генератора
    print("=== Тест HTML генератора ===")
    
    # Создаем тестовый отчет
    test_report = {
        'hostname': 'test-server',
        'os': {'name': 'Ubuntu', 'version': '20.04'},
        'start': '01.01.2025 12:00:00',
        'end': '01.01.2025 12:30:00',
        'worktime': 1800,
        'connections': {
            'incoming': [],
            'outgoing': [
                {
                    'local': '192.168.1.100:12345',
                    'remote': {'name': 'example.com', 'address': '93.184.216.34:443'},
                    'process': 'curl',
                    'protocol': 'tcp',
                    'first_seen': '01.01.2025 12:00:00',
                    'last_seen': '01.01.2025 12:00:30',
                    'count': 1
                }
            ]
        },
        'listen_ports': {'tcp': [22, 80, 443], 'udp': [53]},
        'interfaces': {'eth0': {'mtu': 1500}},
        'disks': {'/dev/sda1': {'total': 100, 'used': 50}},
        'firewall': {},
        'postgresql': {},
        'docker': []
    }
    
    html_content = generate_html_report_from_data(test_report, 'test_report.html')
    print("HTML отчет сгенерирован: test_report.html") 