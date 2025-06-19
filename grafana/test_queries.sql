-- Тест исправленных запросов из дашборда analyzer-overview

-- 1. Проверка запроса распределения протоколов
SELECT 
  protocol as "Protocol",
  SUM(connection_count) as "Connections"
FROM protocol_stats
WHERE time >= NOW() - INTERVAL '1 hour'
GROUP BY protocol
ORDER BY "Connections" DESC;

-- 2. Проверка запроса топ назначений  
SELECT
  destination_address as "Destination",
  SUM(connection_count) as "Connections",
  SUM(total_bytes) as "Bytes"
FROM top_destinations
WHERE time >= NOW() - INTERVAL '1 hour'
GROUP BY destination_address
ORDER BY "Connections" DESC
LIMIT 10;

-- 3. Общая статистика
SELECT 
  COUNT(*) as total_protocol_records,
  COUNT(DISTINCT hostname) as unique_hosts,
  MIN(time) as earliest_record,
  MAX(time) as latest_record
FROM protocol_stats;

-- 4. Статистика по таблице connections
SELECT 
  COUNT(*) as total_connections,
  COUNT(DISTINCT hostname) as unique_hosts,
  COUNT(DISTINCT protocol) as protocols,
  MIN(time) as earliest_record,
  MAX(time) as latest_record
FROM connections; 