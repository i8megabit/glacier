-- Тестирование исправленных запросов с inet операторами

-- 1. Тест запроса на Data Exfiltration (исправленный)
SELECT COUNT(*) as test_data_exfiltration
FROM connections 
WHERE time >= NOW() - INTERVAL '1 hour'
  AND byte_count > 1000000
  AND NOT (destination_address << '192.168.0.0/16' OR destination_address << '10.0.0.0/8' OR destination_address << '172.16.0.0/12');

-- 2. Тест запроса на Attacker Analysis (исправленный)  
SELECT COUNT(*) as test_attacker_analysis
FROM connections 
WHERE time >= NOW() - INTERVAL '1 hour'
  AND source_address IS NOT NULL
  AND source_address NOT IN ('127.0.0.1', '::1')
  AND NOT (source_address << '192.168.0.0/16' OR source_address << '10.0.0.0/8' OR source_address << '172.16.0.0/12');

-- 3. Проверка что операторы работают правильно
SELECT 
  destination_address,
  destination_address << '192.168.0.0/16' as is_192_168,
  destination_address << '10.0.0.0/8' as is_10_x,
  destination_address << '172.16.0.0/12' as is_172_16
FROM connections 
WHERE destination_address IS NOT NULL
LIMIT 10;

-- 4. Общая статистика по внешним адресам
SELECT 
  COUNT(*) as total_external_connections,
  COUNT(DISTINCT destination_address) as unique_external_hosts
FROM connections 
WHERE destination_address IS NOT NULL
  AND NOT (destination_address << '192.168.0.0/16' OR destination_address << '10.0.0.0/8' OR destination_address << '172.16.0.0/12'); 