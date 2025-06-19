# ☁️ S3 интеграция v2.3.0

Автоматическая загрузка YAML/HTML отчетов в S3-совместимое хранилище.

## 🔧 Настройка

### 1. Переменные окружения

```bash
export S3_ENDPOINT_URL="https://your-s3-endpoint.com"
export S3_ACCESS_KEY_ID="your-access-key"
export S3_ACCESS_SECRET_KEY="your-secret-key"
export S3_REGION="us-east-1"  # опционально
export S3_BUCKET="analyzer"   # опционально, по умолчанию "analyzer"
```

### 2. Проверка подключения

```bash
# Тест S3 соединения
python3 -c "
from src.S3Client import get_client_s3
s3 = get_client_s3('$S3_ENDPOINT_URL', '$S3_REGION', '$S3_ACCESS_KEY_ID', '$S3_ACCESS_SECRET_KEY', '3.9')
print('✅ S3 подключение успешно')
"
```

## 🚀 Режимы работы

### Автоматический режим (по расписанию)
```bash
# Загрузка в 8:00 утра
python3 src/glacier.py -w 30 -t 5

# Проверяет время и загружает если 8:00
```

### Принудительная загрузка
```bash
# Загрузка сразу после анализа
python3 src/glacier.py -w 30 -t 5 --force-s3
```

### Отключение S3
```bash
# Только локальные файлы
python3 src/glacier.py -w 30 -t 5 --no-s3
```

## 📂 Структура в S3

```
s3://analyzer/
└── reports/
    ├── hostname_linux_report_analyzer.yaml
    ├── hostname_linux_report_analyzer.html
    ├── hostname_darwin_report_analyzer.yaml
    └── hostname_darwin_report_analyzer.html
```

## ☁️ Поддерживаемые провайдеры

### Amazon S3
```bash
export S3_ENDPOINT_URL="https://s3.amazonaws.com"
export S3_REGION="us-east-1"
```

### MinIO
```bash
export S3_ENDPOINT_URL="https://minio.example.com"
export S3_REGION="us-east-1"
```

### Yandex Object Storage
```bash
export S3_ENDPOINT_URL="https://storage.yandexcloud.net"
export S3_REGION="ru-central1"
```

### DigitalOcean Spaces
```bash
export S3_ENDPOINT_URL="https://fra1.digitaloceanspaces.com"
export S3_REGION="fra1"
```

## 🔐 Безопасность

### IAM права (AWS)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::analyzer",
                "arn:aws:s3:::analyzer/*"
            ]
        }
    ]
}
```

### Bucket policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:user/analyzer"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::analyzer/reports/*"
        }
    ]
}
```

## 🧪 Тестирование

### Проверка конфигурации
```bash
# Тест переменных окружения
python3 -c "
import os
required = ['S3_ENDPOINT_URL', 'S3_ACCESS_KEY_ID', 'S3_ACCESS_SECRET_KEY']
for var in required:
    if var not in os.environ:
        print(f'❌ {var} не установлен')
    else:
        print(f'✅ {var} установлен')
"
```

### Тест загрузки
```bash
# Создание тестового файла
echo "test" > test_upload.txt

# Загрузка через Glacier
python3 -c "
from src.S3Client import get_client_s3, upload_file_s3
s3 = get_client_s3('$S3_ENDPOINT_URL', '$S3_REGION', '$S3_ACCESS_KEY_ID', '$S3_ACCESS_SECRET_KEY', '3.9')
upload_file_s3(s3, 'analyzer', 'test_upload.txt', 'test/test_upload.txt')
print('✅ Тестовая загрузка успешна')
"

# Удаление тестового файла
rm test_upload.txt
```

## ⚠️ Устранение неполадок

### Ошибка подключения
```
❌ ConnectionError: Unable to connect to S3
```
**Решение:**
1. Проверить `S3_ENDPOINT_URL`
2. Проверить сетевое подключение
3. Проверить SSL сертификаты

### Ошибка авторизации
```
❌ AccessDenied: Access Denied
```
**Решение:**
1. Проверить `S3_ACCESS_KEY_ID` и `S3_ACCESS_SECRET_KEY`
2. Проверить права доступа к bucket
3. Проверить bucket policy

### Ошибка bucket
```
❌ NoSuchBucket: The specified bucket does not exist
```
**Решение:**
1. Создать bucket `analyzer`
2. Установить `S3_BUCKET` на существующий bucket

## 📊 Мониторинг

### Логи загрузки
```bash
# Просмотр логов последней загрузки
tail -f /var/log/analyzer.log | grep S3
```

### Статистика загрузок
```bash
# Количество файлов в S3
aws s3 ls s3://analyzer/reports/ --recursive | wc -l

# Размер всех отчетов
aws s3 ls s3://analyzer/reports/ --recursive --human-readable --summarize
```

---