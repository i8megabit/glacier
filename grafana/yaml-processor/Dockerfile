FROM python:3.11-slim

LABEL maintainer="Glacier Team"
LABEL description="YAML to PostgreSQL processor for Grafana integration"

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Создаем пользователя для приложения
RUN groupadd -r analyzer && useradd -r -g analyzer analyzer

WORKDIR /app

# Копируем зависимости и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY yaml_processor.py .

# Создаем директории
RUN mkdir -p /data/yaml /data/processed && \
    chown -R analyzer:analyzer /data

# Переключаемся на непривилегированного пользователя
USER analyzer

# Настройки окружения
ENV PYTHONPATH=/app
ENV POSTGRES_HOST=postgres
ENV POSTGRES_PORT=5432
ENV POSTGRES_DB=analyzer_db
ENV POSTGRES_USER=grafana_user
ENV POSTGRES_PASSWORD=grafana_pass
ENV YAML_WATCH_DIR=/data/yaml
ENV PROCESSED_DIR=/data/processed

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import psycopg2; psycopg2.connect(host='postgres', port=5432, database='analyzer_db', user='grafana_user', password='grafana_pass')" || exit 1

# Запускаем приложение
CMD ["python", "yaml_processor.py"] 