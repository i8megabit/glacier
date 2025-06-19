-- Инициализация базы данных для Grafana интеграции
-- Включаем TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Функция для логирования
CREATE OR REPLACE FUNCTION log_message(level text, message text) 
RETURNS void AS $$
BEGIN
    RAISE NOTICE '[%] %: %', now(), level, message;
END;
$$ LANGUAGE plpgsql;

SELECT log_message('INFO', 'Starting database initialization...');

-- Основная таблица соединений
CREATE TABLE IF NOT EXISTS connections (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    source_address INET,
    destination_address INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT,
    protocol_number INTEGER,
    packet_count BIGINT DEFAULT 0,
    byte_count BIGINT DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    tcp_flags INTEGER,
    direction TEXT CHECK (direction IN ('incoming', 'outgoing', 'unknown')),
    process_name TEXT,
    connection_state TEXT,
    report_id TEXT,
    
    -- Метаданные
    os_name TEXT,
    os_version TEXT,
    analyzer_version TEXT DEFAULT '1.0'
);

SELECT log_message('INFO', 'Created connections table');

-- Создаем гипертаблицу TimescaleDB
SELECT create_hypertable('connections', 'time', if_not_exists => TRUE);

SELECT log_message('INFO', 'Created connections hypertable');

-- Агрегированная статистика по протоколам
CREATE TABLE IF NOT EXISTS protocol_stats (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    protocol TEXT NOT NULL,
    connection_count INTEGER DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    total_packets BIGINT DEFAULT 0,
    unique_destinations INTEGER DEFAULT 0,
    report_id TEXT
);

SELECT create_hypertable('protocol_stats', 'time', if_not_exists => TRUE);

SELECT log_message('INFO', 'Created protocol_stats hypertable');

-- Топ назначений
CREATE TABLE IF NOT EXISTS top_destinations (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    destination_address INET,
    destination_port INTEGER,
    connection_count INTEGER DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    protocols TEXT[],
    processes TEXT[],
    report_id TEXT
);

SELECT create_hypertable('top_destinations', 'time', if_not_exists => TRUE);

SELECT log_message('INFO', 'Created top_destinations hypertable');

-- Системная информация
CREATE TABLE IF NOT EXISTS system_metrics (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    total_connections INTEGER DEFAULT 0,
    incoming_connections INTEGER DEFAULT 0,
    outgoing_connections INTEGER DEFAULT 0,
    tcp_connections INTEGER DEFAULT 0,
    udp_connections INTEGER DEFAULT 0,
    icmp_connections INTEGER DEFAULT 0,
    unique_processes INTEGER DEFAULT 0,
    unique_destinations INTEGER DEFAULT 0,
    report_generation_time_ms INTEGER DEFAULT 0,
    os_name TEXT,
    os_version TEXT,
    report_id TEXT
);

SELECT create_hypertable('system_metrics', 'time', if_not_exists => TRUE);

SELECT log_message('INFO', 'Created system_metrics hypertable');

-- Процессы и их соединения
CREATE TABLE IF NOT EXISTS process_stats (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    process_name TEXT NOT NULL,
    connection_count INTEGER DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    unique_destinations INTEGER DEFAULT 0,
    protocols TEXT[],
    report_id TEXT
);

SELECT create_hypertable('process_stats', 'time', if_not_exists => TRUE);

SELECT log_message('INFO', 'Created process_stats hypertable');

-- География соединений (для WorldMap панели)
CREATE TABLE IF NOT EXISTS geographic_stats (
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname TEXT NOT NULL,
    country_code TEXT,
    country_name TEXT,
    connection_count INTEGER DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    latitude NUMERIC(9,6),
    longitude NUMERIC(9,6),
    report_id TEXT
);

SELECT create_hypertable('geographic_stats', 'time', if_not_exists => TRUE);

SELECT log_message('INFO', 'Created geographic_stats hypertable');

-- Индексы для производительности
DO $$
BEGIN
    -- Connections индексы
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'connections' AND indexname = 'connections_hostname_time_idx') THEN
        CREATE INDEX connections_hostname_time_idx ON connections (hostname, time DESC);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'connections' AND indexname = 'connections_destination_time_idx') THEN
        CREATE INDEX connections_destination_time_idx ON connections (destination_address, time DESC);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'connections' AND indexname = 'connections_protocol_time_idx') THEN
        CREATE INDEX connections_protocol_time_idx ON connections (protocol, time DESC);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'connections' AND indexname = 'connections_process_time_idx') THEN
        CREATE INDEX connections_process_time_idx ON connections (process_name, time DESC);
    END IF;
    
    -- Protocol stats индексы
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'protocol_stats' AND indexname = 'protocol_stats_hostname_protocol_time_idx') THEN
        CREATE INDEX protocol_stats_hostname_protocol_time_idx ON protocol_stats (hostname, protocol, time DESC);
    END IF;
    
    -- Top destinations индексы
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'top_destinations' AND indexname = 'top_destinations_hostname_time_idx') THEN
        CREATE INDEX top_destinations_hostname_time_idx ON top_destinations (hostname, destination_address, time DESC);
    END IF;
    
    -- System metrics индексы
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'system_metrics' AND indexname = 'system_metrics_hostname_time_idx') THEN
        CREATE INDEX system_metrics_hostname_time_idx ON system_metrics (hostname, time DESC);
    END IF;
    
    -- Process stats индексы
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'process_stats' AND indexname = 'process_stats_hostname_process_time_idx') THEN
        CREATE INDEX process_stats_hostname_process_time_idx ON process_stats (hostname, process_name, time DESC);
    END IF;
    
    -- Geographic stats индексы
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'geographic_stats' AND indexname = 'geographic_stats_hostname_country_time_idx') THEN
        CREATE INDEX geographic_stats_hostname_country_time_idx ON geographic_stats (hostname, country_code, time DESC);
    END IF;
END $$;

SELECT log_message('INFO', 'Created performance indexes');

-- Функции для аналитики
CREATE OR REPLACE FUNCTION get_top_talkers(
    p_hostname TEXT,
    p_start_time TIMESTAMPTZ,
    p_end_time TIMESTAMPTZ,
    p_limit INTEGER DEFAULT 10
)
RETURNS TABLE (
    destination_address INET,
    total_bytes BIGINT,
    connection_count BIGINT,
    protocols TEXT[]
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.destination_address,
        SUM(c.byte_count) as total_bytes,
        COUNT(*) as connection_count,
        ARRAY_AGG(DISTINCT c.protocol) as protocols
    FROM connections c
    WHERE c.hostname = p_hostname
        AND c.time >= p_start_time
        AND c.time <= p_end_time
        AND c.destination_address IS NOT NULL
    GROUP BY c.destination_address
    ORDER BY total_bytes DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

SELECT log_message('INFO', 'Created get_top_talkers function');

-- Функция для получения аномалий
CREATE OR REPLACE FUNCTION detect_connection_anomalies(
    p_hostname TEXT,
    p_threshold NUMERIC DEFAULT 2.0
)
RETURNS TABLE (
    destination_address INET,
    current_connections BIGINT,
    avg_connections NUMERIC,
    deviation NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    WITH recent_stats AS (
        SELECT 
            c.destination_address,
            COUNT(*) as current_connections
        FROM connections c
        WHERE c.hostname = p_hostname
            AND c.time >= NOW() - INTERVAL '1 hour'
        GROUP BY c.destination_address
    ),
    historical_stats AS (
        SELECT 
            c.destination_address,
            AVG(hourly_count) as avg_connections,
            STDDEV(hourly_count) as stddev_connections
        FROM (
            SELECT 
                c.destination_address,
                date_trunc('hour', c.time) as hour,
                COUNT(*) as hourly_count
            FROM connections c
            WHERE c.hostname = p_hostname
                AND c.time >= NOW() - INTERVAL '7 days'
                AND c.time < NOW() - INTERVAL '1 hour'
            GROUP BY c.destination_address, date_trunc('hour', c.time)
        ) c
        GROUP BY c.destination_address
        HAVING COUNT(*) >= 24 -- минимум 24 часа данных
    )
    SELECT 
        r.destination_address,
        r.current_connections,
        h.avg_connections,
        (r.current_connections - h.avg_connections) / NULLIF(h.stddev_connections, 0) as deviation
    FROM recent_stats r
    JOIN historical_stats h ON r.destination_address = h.destination_address
    WHERE ABS((r.current_connections - h.avg_connections) / NULLIF(h.stddev_connections, 0)) > p_threshold
    ORDER BY deviation DESC;
END;
$$ LANGUAGE plpgsql;

SELECT log_message('INFO', 'Created detect_connection_anomalies function');

-- Политики ретенции (опционально, можно настроить позже)
-- SELECT add_retention_policy('connections', INTERVAL '30 days');
-- SELECT add_retention_policy('protocol_stats', INTERVAL '90 days');
-- SELECT add_retention_policy('top_destinations', INTERVAL '90 days');
-- SELECT add_retention_policy('system_metrics', INTERVAL '1 year');

-- Материализованные представления для агрегации
CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_connection_summary AS
SELECT 
    date_trunc('hour', time) as hour,
    hostname,
    protocol,
    COUNT(*) as connection_count,
    SUM(byte_count) as total_bytes,
    COUNT(DISTINCT destination_address) as unique_destinations,
    COUNT(DISTINCT process_name) as unique_processes
FROM connections
WHERE time >= NOW() - INTERVAL '7 days'
GROUP BY date_trunc('hour', time), hostname, protocol;

CREATE UNIQUE INDEX IF NOT EXISTS hourly_connection_summary_idx 
ON hourly_connection_summary (hour, hostname, protocol);

SELECT log_message('INFO', 'Created materialized views');

-- Функция для обновления материализованных представлений
CREATE OR REPLACE FUNCTION refresh_materialized_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY hourly_connection_summary;
    RAISE NOTICE 'Materialized views refreshed at %', now();
END;
$$ LANGUAGE plpgsql;

-- Пользователь для Grafana (только чтение)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'grafana_reader') THEN
        CREATE USER grafana_reader WITH PASSWORD 'grafana_readonly_password';
    END IF;
END $$;

-- Права для Grafana пользователя
GRANT CONNECT ON DATABASE analyzer_metrics TO grafana_reader;
GRANT USAGE ON SCHEMA public TO grafana_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_reader;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO grafana_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_reader;

SELECT log_message('INFO', 'Created grafana_reader user with permissions');

-- Триггер для автоматического обновления материализованных представлений
CREATE OR REPLACE FUNCTION auto_refresh_views()
RETURNS trigger AS $$
BEGIN
    -- Обновляем представления каждый час
    IF EXTRACT(MINUTE FROM NEW.time) = 0 THEN
        PERFORM refresh_materialized_views();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Применяем триггер только если его еще нет
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trigger_refresh_views') THEN
        CREATE TRIGGER trigger_refresh_views
            AFTER INSERT ON connections
            FOR EACH ROW
            WHEN (EXTRACT(MINUTE FROM NEW.time) = 0)
            EXECUTE FUNCTION auto_refresh_views();
    END IF;
END $$;

SELECT log_message('INFO', 'Created auto-refresh trigger');

-- Финальная статистика
SELECT log_message('INFO', 'Database initialization completed successfully');

-- Показываем созданные таблицы
SELECT 
    schemaname,
    tablename,
    hasindexes,
    hasrules,
    hastriggers
FROM pg_tables 
WHERE schemaname = 'public' 
ORDER BY tablename; 