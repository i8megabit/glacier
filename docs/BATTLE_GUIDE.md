# ⚔️ Боевое руководство Glacier v2.3.0

Практическое руководство для развертывания Glacier в рабочем окружении.

## 🎯 Быстрый старт

### 1. Получение Glacier
```bash
curl -L -o glacier-v2.3.0 https://github.com/i8megabit/glacier/releases/download/v2.3.0/glacier

chmod +x glacier-v2.3.0

ln -s glacier-v2.3.0 glacier
```

### 2. Первый запуск
```bash
# Быстрый анализ (1 измерение)
./analyzer -w 30 -t 1

# Результат:
# ✅ MacBook-Pro.local_darwin_report_analyzer.yaml
# ✅ MacBook-Pro.local_darwin_report_analyzer.html
```

## 🏗️ Сценарии развертывания

### 🖥️ Одиночный сервер

```bash
# Полный анализ
./analyzer -w 30 -t 10

# С S3 интеграцией
export S3_ENDPOINT_URL="https://s3.amazonaws.com"
export S3_ACCESS_KEY_ID="your-key"
export S3_ACCESS_SECRET_KEY="your-secret"
./analyzer -w 30 -t 5
```

### 🔄 Автоматизированный мониторинг

```bash
# Cron каждые 30 минут
echo "*/30 * * * * cd /opt/analyzer && ./analyzer -w 30 -t 1" | crontab -

# SystemD сервис
sudo tee /etc/systemd/system/glacier.service << EOF
[Unit]
Description=Network Glacier
After=network.target

[Service]
Type=simple
User=analyzer
WorkingDirectory=/opt/analyzer
ExecStart=/opt/analyzer/analyzer -w 30 -t 5
Restart=always
RestartSec=1800

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable analyzer
sudo systemctl start analyzer
```

### 📦 Контейнеризация

```dockerfile
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3 python3-pip
COPY analyzer /usr/local/bin/
RUN chmod +x /usr/local/bin/analyzer
CMD ["/usr/local/bin/analyzer", "-w", "30", "-t", "5"]
```

```bash
# Сборка образа
docker build -t glacier:v2.3.0 .

# Запуск
docker run -d --name analyzer \
  --network host \
  -v /opt/analyzer/reports:/reports \
  glacier:v2.3.0
```

## 🌐 Интеграция с S3

### AWS S3
```bash
export S3_ENDPOINT_URL="https://s3.amazonaws.com"
export S3_REGION="us-east-1"
export S3_ACCESS_KEY_ID="AKIA..."
export S3_ACCESS_SECRET_KEY="..."
export S3_BUCKET="company-analyzer"
```

### MinIO
```bash
export S3_ENDPOINT_URL="https://minio.company.com:9000"
export S3_REGION="us-east-1"
export S3_ACCESS_KEY_ID="minio-user"
export S3_ACCESS_SECRET_KEY="minio-password"
```

### Yandex Cloud
```bash
export S3_ENDPOINT_URL="https://storage.yandexcloud.net"
export S3_REGION="ru-central1"
export S3_ACCESS_KEY_ID="YCAJEx..."
export S3_ACCESS_SECRET_KEY="..."
```

## 📊 SIEM интеграция

### Splunk
```bash
# Мониторинг YAML файлов
[monitor:///opt/analyzer/*_report_analyzer.yaml]
disabled = false
sourcetype = analyzer_yaml
index = security

# Поиск NetFlow данных
index=security sourcetype=analyzer_yaml netflow_data.flows
| table _time, flows{}.ipv4_src_addr, flows{}.ipv4_dst_addr, flows{}.l4_dst_port
```

### Elastic Stack
```yaml
# Filebeat конфигурация
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /opt/glacier/*_glacier.yaml
  fields:
    source: glacier
    version: v2.3.0
  json.keys_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "analyzer-%{+yyyy.MM.dd}"
```

### Graylog
```json
{
  "version": "1",
  "inputs": [{
    "title": "Glacier Reports",
    "type": "org.graylog2.inputs.beats.BeatsInput",
    "configuration": {
      "bind_address": "0.0.0.0",
      "port": 5044
    }
  }]
}
```

## 🔧 Мониторинг и алертинг

### Prometheus метрики
```python
# Создание экспортера метрик
#!/usr/bin/env python3
import yaml
from prometheus_client import start_http_server, Gauge

connections_gauge = Gauge('analyzer_connections_total', 'Total connections')
uptime_gauge = Gauge('analyzer_uptime_seconds', 'System uptime')

def collect_metrics():
    with open('report.yaml') as f:
        data = yaml.safe_load(f)
    
    connections = len(data.get('connections', {}).get('outgoing', []))
    connections_gauge.set(connections)

start_http_server(8000)
```

### Grafana дашборд
```json
{
  "dashboard": {
    "title": "Network Glacier Dashboard",
    "panels": [
      {
        "title": "Active Connections",
        "type": "stat",
        "targets": [{"expr": "analyzer_connections_total"}]
      },
      {
        "title": "Connection Timeline",
        "type": "graph",
        "targets": [{"expr": "rate(analyzer_connections_total[5m])"}]
      }
    ]
  }
}
```

### Alertmanager правила
```yaml
groups:
- name: analyzer
  rules:
  - alert: HighConnectionCount
    expr: analyzer_connections_total > 100
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High connection count detected"
      
  - alert: GlacierDown
    expr: up{job="glacier"} == 0
    for: 1m
    labels:
      severity: critical
```

## 🐛 Устранение неполадок

### Ошибки прав доступа
```bash
# Проблема: Permission denied
sudo setcap cap_net_raw+ep ./analyzer

# Альтернатива: запуск от root
sudo ./analyzer -w 30 -t 1

# Или создание группы
sudo groupadd analyzer
sudo usermod -a -G analyzer $USER
```

### Недоступность сетевых данных
```bash
# Проверка psutil
python3 -c "import psutil; print(psutil.net_connections())"

# Проверка netstat
netstat -tuln

# Проверка ss
ss -tuln
```

### Проблемы с S3
```bash
# Тест подключения
curl -I $S3_ENDPOINT_URL

# Проверка переменных
env | grep S3_

# Тест загрузки
aws s3 ls s3://$S3_BUCKET/reports/ --endpoint-url $S3_ENDPOINT_URL
```

### Ошибки Docker
```bash
# Проверка доступности Docker
docker ps

# Проверка без Docker
./analyzer -w 30 -t 1  # Docker опционален
```

## 📈 Масштабирование

### Многосерверное развертывание
```bash
# Ansible playbook
---
- hosts: all
  tasks:
    - name: Copy analyzer
      copy:
        src: analyzer
        dest: /usr/local/bin/analyzer
        mode: '0755'
    
    - name: Setup cron
      cron:
        name: "Network analyzer"
        minute: "*/30"
        job: "cd /opt/analyzer && ./analyzer -w 30 -t 1"
```

### Централизованный сбор
```bash
# S3 с префиксами по серверам
export S3_REPORTS_PREFIX="reports/$(hostname)/"

# Rsync в центральное хранилище
rsync -av *.yaml reports@central-server:/data/analyzer/
```

### Load balancing
```nginx
upstream analyzer-api {
    server analyzer1.company.com:8000;
    server analyzer2.company.com:8000;
    server analyzer3.company.com:8000;
}

server {
    listen 80;
    location /analyzer/ {
        proxy_pass http://analyzer-api;
    }
}
```

## 🔐 Безопасность в продакшене

### Минимальные привилегии
```bash
# Создание пользователя analyzer
sudo useradd -r -s /bin/false analyzer

# Права только на чтение
sudo setfacl -m u:analyzer:r /proc/net/
```

### Сетевая изоляция
```bash
# Ограничение доступа только к S3
iptables -A OUTPUT -p tcp --dport 443 -d s3.amazonaws.com -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j DROP
```

### Аудит и логирование
```bash
# Логирование всех запусков
echo "$(date): analyzer started by $(whoami)" >> /var/log/analyzer.log

# Мониторинг изменений файлов
auditctl -w /opt/analyzer/analyzer -p x
```

## 📋 Чек-листы

### ✅ Предварительные проверки
- [ ] Python 3.6+ установлен
- [ ] Права на чтение /proc/net/ (Linux)
- [ ] Доступ к сетевым утилитам (netstat, ss, lsof)
- [ ] Свободное место (100MB) для отчетов
- [ ] S3 переменные настроены (опционально)

### ✅ После развертывания
- [ ] Анализатор запускается без ошибок
- [ ] YAML отчет генерируется
- [ ] HTML отчет открывается в браузере
- [ ] S3 загрузка работает (если настроена)
- [ ] Логи не содержат ошибок

### ✅ Мониторинг
- [ ] Cron/SystemD работает по расписанию
- [ ] Метрики собираются
- [ ] Алерты настроены
- [ ] Дашборды отображают данные

---